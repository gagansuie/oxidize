//! ROHC Compressor - Enhanced Pure Rust implementation
//!
//! Supports: IPv4, IPv6, UDP, TCP with W-LSB encoding

use super::encoding::{Sdvl, WlsbEncoder};
use super::profiles::Profile;
use super::FlowId;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Compression state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompState {
    /// Initial state - send IR packets
    Ir,
    /// First order - send IR-DYN or compressed
    Fo,
    /// Second order - fully compressed
    So,
}

/// Compression context for a single flow
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CompressionContext {
    /// Context ID
    cid: u8,
    /// Current compression state
    state: CompState,
    /// Profile for this context
    profile: Profile,
    /// Number of packets sent in this context
    packet_count: u32,
    /// IR packets sent (for state transition)
    ir_count: u8,
    /// W-LSB encoder for IP-ID
    ip_id_encoder: WlsbEncoder,
    /// W-LSB encoder for sequence numbers (TCP)
    seq_encoder: WlsbEncoder,
    /// W-LSB encoder for ack numbers (TCP)
    ack_encoder: WlsbEncoder,
    /// Last seen dynamic fields
    last_ip_id: u16,
    last_ttl: u8,
    last_seq: u32,
    last_ack: u32,
    last_window: u16,
    /// Static fields (don't change within flow)
    src_addr: [u8; 16], // Supports IPv4 (4 bytes) and IPv6 (16 bytes)
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    is_ipv6: bool,
}

impl CompressionContext {
    fn new(cid: u8, profile: Profile) -> Self {
        CompressionContext {
            cid,
            state: CompState::Ir,
            profile,
            packet_count: 0,
            ir_count: 0,
            ip_id_encoder: WlsbEncoder::new(0),
            seq_encoder: WlsbEncoder::new(-1),
            ack_encoder: WlsbEncoder::new(-1),
            last_ip_id: 0,
            last_ttl: 64,
            last_seq: 0,
            last_ack: 0,
            last_window: 0,
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
        }
    }

    fn advance_state(&mut self) {
        match self.state {
            CompState::Ir => {
                self.ir_count += 1;
                if self.ir_count >= 3 {
                    self.state = CompState::Fo;
                }
            }
            CompState::Fo => {
                if self.packet_count >= 10 {
                    self.state = CompState::So;
                }
            }
            CompState::So => {}
        }
    }
}

/// ROHC packet types
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum PacketType {
    /// IR (Initialization/Refresh) - full headers
    Ir = 0xFD,
    /// IR-DYN - dynamic fields only
    IrDyn = 0xF8,
    /// UO-0 - minimal compressed (1 byte header)
    Uo0 = 0x00,
    /// UO-1 - compressed with some fields (2-3 bytes)
    Uo1 = 0x80,
    /// UOR-2 - compressed with extension
    Uor2 = 0xC0,
}

/// ROHC Compressor
pub struct RohcCompressor {
    /// Maximum number of contexts
    max_contexts: usize,
    /// Active compression contexts by flow
    contexts: HashMap<FlowId, CompressionContext>,
    /// Next context ID to assign
    next_cid: u8,
    /// Statistics
    packets_compressed: u64,
    bytes_saved: i64,
}

impl RohcCompressor {
    pub fn new(max_contexts: usize) -> Self {
        RohcCompressor {
            max_contexts,
            contexts: HashMap::new(),
            next_cid: 0,
            packets_compressed: 0,
            bytes_saved: 0,
        }
    }

    /// Compress a packet
    pub fn compress(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(anyhow!("Cannot compress empty packet"));
        }

        let profile = Profile::detect(packet);

        match profile {
            Profile::Tcp | Profile::Ipv6Tcp => self.compress_tcp(packet, profile),
            Profile::Udp | Profile::Ipv6Udp | Profile::Rtp | Profile::UdpLite => {
                self.compress_udp(packet, profile)
            }
            Profile::Ip | Profile::Esp => self.compress_ip(packet, profile),
            Profile::Uncompressed => self.compress_uncompressed(packet),
        }
    }

    /// Compress using TCP profile (web traffic, SSH, etc.)
    fn compress_tcp(&mut self, packet: &[u8], profile: Profile) -> Result<Vec<u8>> {
        let flow_id =
            FlowId::from_ipv4_packet(packet).ok_or_else(|| anyhow!("Failed to extract flow ID"))?;

        let ihl = ((packet[0] & 0xF) as usize) * 4;
        let tcp_offset = ihl;

        if packet.len() < tcp_offset + 20 {
            return self.compress_uncompressed(packet);
        }

        // Extract TCP fields
        let seq = u32::from_be_bytes([
            packet[tcp_offset + 4],
            packet[tcp_offset + 5],
            packet[tcp_offset + 6],
            packet[tcp_offset + 7],
        ]);
        let ack = u32::from_be_bytes([
            packet[tcp_offset + 8],
            packet[tcp_offset + 9],
            packet[tcp_offset + 10],
            packet[tcp_offset + 11],
        ]);
        let data_offset = ((packet[tcp_offset + 12] >> 4) as usize) * 4;
        let flags = packet[tcp_offset + 13];
        let window = u16::from_be_bytes([packet[tcp_offset + 14], packet[tcp_offset + 15]]);

        if let Some(ctx) = self.contexts.get_mut(&flow_id) {
            ctx.packet_count += 1;
            ctx.advance_state();

            let ip_id = u16::from_be_bytes([packet[4], packet[5]]);
            let seq_delta = seq.wrapping_sub(ctx.last_seq);
            let ack_delta = ack.wrapping_sub(ctx.last_ack);

            ctx.last_ip_id = ip_id;
            ctx.last_seq = seq;
            ctx.last_ack = ack;
            ctx.last_window = window;

            let payload = &packet[tcp_offset + data_offset..];

            // In SO state, use highly compressed format
            if ctx.state == CompState::So && seq_delta < 256 && ack_delta < 256 {
                // Compressed TCP: [CID:4|flags:4][seq_delta:8][ack_delta:8][payload]
                let mut compressed = Vec::with_capacity(3 + payload.len());
                compressed.push((ctx.cid << 4) | (flags & 0x0F));
                compressed.push(seq_delta as u8);
                compressed.push(ack_delta as u8);
                compressed.extend_from_slice(payload);

                self.packets_compressed += 1;
                self.bytes_saved += packet.len() as i64 - compressed.len() as i64;
                return Ok(compressed);
            }

            // FO state: include more context
            let mut compressed = Vec::with_capacity(8 + payload.len());
            compressed.push(PacketType::Uo1 as u8 | ctx.cid);
            compressed.push(flags);
            compressed.extend_from_slice(&Sdvl::encode(seq_delta));
            compressed.extend_from_slice(&Sdvl::encode(ack_delta));
            compressed.extend_from_slice(&window.to_be_bytes());
            compressed.extend_from_slice(payload);

            self.packets_compressed += 1;
            self.bytes_saved += packet.len() as i64 - compressed.len() as i64;
            Ok(compressed)
        } else {
            self.create_ir_packet(packet, flow_id, profile)
        }
    }

    /// Compress using UDP profile
    fn compress_udp(&mut self, packet: &[u8], profile: Profile) -> Result<Vec<u8>> {
        let flow_id =
            FlowId::from_ipv4_packet(packet).ok_or_else(|| anyhow!("Failed to extract flow ID"))?;

        let ihl = ((packet[0] & 0xF) as usize) * 4;

        if let Some(ctx) = self.contexts.get_mut(&flow_id) {
            // Existing context - send compressed
            ctx.packet_count += 1;
            ctx.advance_state();

            let ip_id = u16::from_be_bytes([packet[4], packet[5]]);
            let ip_id_delta = ip_id.wrapping_sub(ctx.last_ip_id);
            ctx.last_ip_id = ip_id;

            // Payload starts after IP + UDP headers
            let payload = &packet[ihl + 8..];

            // UO-0 format: 1 byte header + payload
            // Format: [0][CID:4][SN:3] where SN is sequence number mod 8
            if ip_id_delta == 1 && payload.len() < 1400 {
                let sn = (ctx.packet_count & 0x7) as u8;
                let header = (ctx.cid << 3) | sn;

                let mut compressed = Vec::with_capacity(1 + payload.len());
                compressed.push(header);
                compressed.extend_from_slice(payload);

                self.packets_compressed += 1;
                self.bytes_saved += packet.len() as i64 - compressed.len() as i64;

                return Ok(compressed);
            }

            // UO-1 format: 2 byte header with IP-ID delta
            // Format: [1][CID:4][IP-ID:3] [IP-ID:8]
            let header1 = 0x80 | (ctx.cid << 3) | ((ip_id_delta >> 8) as u8 & 0x7);
            let header2 = (ip_id_delta & 0xFF) as u8;

            let mut compressed = Vec::with_capacity(2 + payload.len());
            compressed.push(header1);
            compressed.push(header2);
            compressed.extend_from_slice(payload);

            self.packets_compressed += 1;
            self.bytes_saved += packet.len() as i64 - compressed.len() as i64;

            Ok(compressed)
        } else {
            // New flow - send IR packet with full headers
            self.create_ir_packet(packet, flow_id, profile)
        }
    }

    /// Compress using IP-only profile
    fn compress_ip(&mut self, packet: &[u8], profile: Profile) -> Result<Vec<u8>> {
        let flow_id =
            FlowId::from_ipv4_packet(packet).ok_or_else(|| anyhow!("Failed to extract flow ID"))?;

        let ihl = ((packet[0] & 0xF) as usize) * 4;

        if let Some(ctx) = self.contexts.get_mut(&flow_id) {
            ctx.packet_count += 1;
            ctx.advance_state();

            let ip_id = u16::from_be_bytes([packet[4], packet[5]]);
            ctx.last_ip_id = ip_id;

            // Payload is everything after IP header
            let payload = &packet[ihl..];

            // Compressed: CID + payload
            let mut compressed = Vec::with_capacity(1 + payload.len());
            compressed.push(ctx.cid);
            compressed.extend_from_slice(payload);

            self.packets_compressed += 1;
            self.bytes_saved += packet.len() as i64 - compressed.len() as i64;

            Ok(compressed)
        } else {
            self.create_ir_packet(packet, flow_id, profile)
        }
    }

    /// Fallback: minimal compression for unknown packets
    fn compress_uncompressed(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // Uncompressed profile: just add a 2-byte header
        // [0xFD][Profile=0x00] + original packet
        let mut compressed = Vec::with_capacity(2 + packet.len());
        compressed.push(0xFD); // IR marker
        compressed.push(Profile::Uncompressed as u8);
        compressed.extend_from_slice(packet);
        Ok(compressed)
    }

    /// Create IR (Initialization/Refresh) packet with full context
    fn create_ir_packet(
        &mut self,
        packet: &[u8],
        flow_id: FlowId,
        profile: Profile,
    ) -> Result<Vec<u8>> {
        // Allocate new context
        let cid = self.allocate_cid();
        let ihl = ((packet[0] & 0xF) as usize) * 4;

        let mut ctx = CompressionContext::new(cid, profile);
        ctx.last_ip_id = u16::from_be_bytes([packet[4], packet[5]]);
        ctx.last_ttl = packet[8];
        ctx.src_addr[..4].copy_from_slice(&flow_id.src_addr.to_be_bytes());
        ctx.dst_addr[..4].copy_from_slice(&flow_id.dst_addr.to_be_bytes());
        ctx.src_port = flow_id.src_port;
        ctx.dst_port = flow_id.dst_port;
        ctx.protocol = flow_id.protocol;

        self.contexts.insert(flow_id, ctx);

        // IR packet format:
        // [0xFD][Profile][CID][Static chain][Dynamic chain][Payload]
        let mut ir = Vec::with_capacity(packet.len() + 10);

        // Header
        ir.push(PacketType::Ir as u8);
        ir.push(profile as u8);
        ir.push(cid);

        // Static chain: addresses + ports (for UDP)
        ir.extend_from_slice(&flow_id.src_addr.to_be_bytes());
        ir.extend_from_slice(&flow_id.dst_addr.to_be_bytes());
        ir.push(flow_id.protocol);

        if profile.is_udp() {
            ir.extend_from_slice(&flow_id.src_port.to_be_bytes());
            ir.extend_from_slice(&flow_id.dst_port.to_be_bytes());
        } else if profile.is_tcp() {
            ir.extend_from_slice(&flow_id.src_port.to_be_bytes());
            ir.extend_from_slice(&flow_id.dst_port.to_be_bytes());
            // Include initial seq/ack for TCP
            if packet.len() >= ihl + 12 {
                ir.extend_from_slice(&packet[ihl + 4..ihl + 12]); // seq + ack
            }
        }

        // Dynamic chain: TTL, IP-ID
        ir.push(packet[8]); // TTL
        ir.extend_from_slice(&packet[4..6]); // IP-ID

        // Payload offset depends on profile
        let payload_offset = if profile.is_udp() {
            ihl + 8
        } else if profile.is_tcp() {
            let data_offset = if packet.len() > ihl + 12 {
                ((packet[ihl + 12] >> 4) as usize) * 4
            } else {
                20
            };
            ihl + data_offset
        } else {
            ihl
        };
        ir.extend_from_slice(&packet[payload_offset..]);

        Ok(ir)
    }

    fn allocate_cid(&mut self) -> u8 {
        let cid = self.next_cid;
        self.next_cid = (self.next_cid + 1) % (self.max_contexts as u8);

        // Evict old context if needed
        if self.contexts.len() >= self.max_contexts {
            // Simple LRU: remove first entry
            if let Some(key) = self.contexts.keys().next().cloned() {
                self.contexts.remove(&key);
            }
        }

        cid
    }

    /// Get compression statistics
    pub fn stats(&self) -> (u64, i64) {
        (self.packets_compressed, self.bytes_saved)
    }
}
