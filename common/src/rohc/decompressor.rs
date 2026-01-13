//! ROHC Decompressor - Pure Rust implementation

use super::profiles::Profile;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Decompression context for a single flow
#[derive(Debug, Clone)]
struct DecompressionContext {
    /// Profile for this context
    profile: Profile,
    /// Packet count for sequence tracking
    packet_count: u32,
    /// Static fields
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    /// Dynamic fields
    last_ip_id: u16,
    last_ttl: u8,
}

/// ROHC Decompressor
#[allow(dead_code)]
pub struct RohcDecompressor {
    /// Maximum number of contexts
    max_contexts: usize,
    /// Active decompression contexts by CID
    contexts: HashMap<u8, DecompressionContext>,
    /// Statistics
    packets_decompressed: u64,
}

impl RohcDecompressor {
    pub fn new(max_contexts: usize) -> Self {
        RohcDecompressor {
            max_contexts,
            contexts: HashMap::new(),
            packets_decompressed: 0,
        }
    }

    /// Decompress a ROHC packet
    pub fn decompress(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.is_empty() {
            return Err(anyhow!("Cannot decompress empty packet"));
        }

        let first_byte = compressed[0];

        // Detect packet type
        if first_byte == 0xFD {
            // IR packet
            self.decompress_ir(compressed)
        } else if first_byte == 0xF8 {
            // IR-DYN packet
            self.decompress_ir_dyn(compressed)
        } else if (first_byte & 0x80) == 0 {
            // UO-0: [0][CID:4][SN:3]
            self.decompress_uo0(compressed)
        } else {
            // UO-1: [1][CID:4][...]
            self.decompress_uo1(compressed)
        }
    }

    /// Decompress IR (Initialization/Refresh) packet
    fn decompress_ir(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.len() < 3 {
            return Err(anyhow!("IR packet too short"));
        }

        let profile = Profile::from_u8(compressed[1])
            .ok_or_else(|| anyhow!("Unknown profile: {}", compressed[1]))?;
        let cid = compressed[2];

        match profile {
            Profile::Uncompressed => {
                // Just return the original packet
                Ok(compressed[3..].to_vec())
            }
            Profile::Udp | Profile::Ipv6Udp | Profile::Rtp | Profile::UdpLite => {
                self.decompress_ir_udp(compressed, cid)
            }
            Profile::Tcp | Profile::Ipv6Tcp => self.decompress_ir_tcp(compressed, cid),
            Profile::Ip | Profile::Esp => self.decompress_ir_ip(compressed, cid),
        }
    }

    /// Decompress IR packet for TCP profile
    fn decompress_ir_tcp(&mut self, compressed: &[u8], cid: u8) -> Result<Vec<u8>> {
        // IR format: [0xFD][Profile][CID][src_addr:4][dst_addr:4][proto:1][src_port:2][dst_port:2][seq:4][ack:4][ttl:1][ip_id:2][payload]
        if compressed.len() < 26 {
            return Err(anyhow!("IR-TCP packet too short"));
        }

        let src_addr =
            u32::from_be_bytes([compressed[3], compressed[4], compressed[5], compressed[6]]);
        let dst_addr =
            u32::from_be_bytes([compressed[7], compressed[8], compressed[9], compressed[10]]);
        let protocol = compressed[11];
        let src_port = u16::from_be_bytes([compressed[12], compressed[13]]);
        let dst_port = u16::from_be_bytes([compressed[14], compressed[15]]);
        let _seq = u32::from_be_bytes([
            compressed[16],
            compressed[17],
            compressed[18],
            compressed[19],
        ]);
        let _ack = u32::from_be_bytes([
            compressed[20],
            compressed[21],
            compressed[22],
            compressed[23],
        ]);
        let ttl = compressed[24];
        let ip_id = u16::from_be_bytes([compressed[25], compressed[26]]);
        let payload = &compressed[27..];

        let ctx = DecompressionContext {
            profile: Profile::Tcp,
            packet_count: 1,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            last_ip_id: ip_id,
            last_ttl: ttl,
        };
        self.contexts.insert(cid, ctx);

        // For now, return payload as-is (TCP reconstruction would need full state)
        // In production, we'd reconstruct the full TCP packet
        self.build_tcp_packet(
            src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id, payload,
        )
    }

    /// Decompress IR packet for UDP profile
    fn decompress_ir_udp(&mut self, compressed: &[u8], cid: u8) -> Result<Vec<u8>> {
        // IR format: [0xFD][Profile][CID][src_addr:4][dst_addr:4][proto:1][src_port:2][dst_port:2][ttl:1][ip_id:2][payload]
        if compressed.len() < 18 {
            return Err(anyhow!("IR-UDP packet too short"));
        }

        let src_addr =
            u32::from_be_bytes([compressed[3], compressed[4], compressed[5], compressed[6]]);
        let dst_addr =
            u32::from_be_bytes([compressed[7], compressed[8], compressed[9], compressed[10]]);
        let protocol = compressed[11];
        let src_port = u16::from_be_bytes([compressed[12], compressed[13]]);
        let dst_port = u16::from_be_bytes([compressed[14], compressed[15]]);
        let ttl = compressed[16];
        let ip_id = u16::from_be_bytes([compressed[17], compressed[18]]);
        let payload = &compressed[19..];

        // Create context
        let ctx = DecompressionContext {
            profile: Profile::Udp,
            packet_count: 1,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            last_ip_id: ip_id,
            last_ttl: ttl,
        };
        self.contexts.insert(cid, ctx);

        // Reconstruct packet
        self.build_udp_packet(
            src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id, payload,
        )
    }

    /// Decompress IR packet for IP profile
    fn decompress_ir_ip(&mut self, compressed: &[u8], cid: u8) -> Result<Vec<u8>> {
        // IR format: [0xFD][Profile][CID][src_addr:4][dst_addr:4][proto:1][ttl:1][ip_id:2][payload]
        if compressed.len() < 14 {
            return Err(anyhow!("IR-IP packet too short"));
        }

        let src_addr =
            u32::from_be_bytes([compressed[3], compressed[4], compressed[5], compressed[6]]);
        let dst_addr =
            u32::from_be_bytes([compressed[7], compressed[8], compressed[9], compressed[10]]);
        let protocol = compressed[11];
        let ttl = compressed[12];
        let ip_id = u16::from_be_bytes([compressed[13], compressed[14]]);
        let payload = &compressed[15..];

        // Create context
        let ctx = DecompressionContext {
            profile: Profile::Ip,
            packet_count: 1,
            src_addr,
            dst_addr,
            src_port: 0,
            dst_port: 0,
            protocol,
            last_ip_id: ip_id,
            last_ttl: ttl,
        };
        self.contexts.insert(cid, ctx);

        // Reconstruct IP packet
        self.build_ip_packet(src_addr, dst_addr, protocol, ttl, ip_id, payload)
    }

    /// Decompress IR-DYN packet
    /// IR-DYN updates dynamic fields for an existing context
    fn decompress_ir_dyn(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        // IR-DYN format: [0xF8][Profile][CID][dynamic_chain][payload]
        if compressed.len() < 4 {
            return Err(anyhow!("IR-DYN packet too short"));
        }

        let profile = Profile::from_u8(compressed[1])
            .ok_or_else(|| anyhow!("Unknown profile: {}", compressed[1]))?;
        let cid = compressed[2];

        // Extract context data to avoid borrow issues
        let ctx_data = {
            let ctx = self.contexts.get_mut(&cid)
                .ok_or_else(|| anyhow!("IR-DYN requires existing context for CID {}", cid))?;
            ctx.packet_count += 1;
            (ctx.src_addr, ctx.dst_addr, ctx.src_port, ctx.dst_port, ctx.protocol)
        };
        
        match profile {
            Profile::Udp | Profile::Ipv6Udp => {
                // Dynamic chain for UDP: [ip_id:2][ttl:1][checksum:2]
                if compressed.len() < 8 {
                    return Err(anyhow!("IR-DYN UDP packet too short"));
                }
                let ip_id = u16::from_be_bytes([compressed[3], compressed[4]]);
                let ttl = compressed[5];
                let payload = &compressed[8..];

                // Update context
                if let Some(ctx) = self.contexts.get_mut(&cid) {
                    ctx.last_ip_id = ip_id;
                    ctx.last_ttl = ttl;
                }
                self.packets_decompressed += 1;
                self.build_udp_packet(
                    ctx_data.0, ctx_data.1, ctx_data.2, ctx_data.3,
                    ctx_data.4, ttl, ip_id, payload,
                )
            }
            Profile::Ip => {
                // Dynamic chain for IP: [ip_id:2][ttl:1]
                if compressed.len() < 6 {
                    return Err(anyhow!("IR-DYN IP packet too short"));
                }
                let ip_id = u16::from_be_bytes([compressed[3], compressed[4]]);
                let ttl = compressed[5];
                let payload = &compressed[6..];

                // Update context
                if let Some(ctx) = self.contexts.get_mut(&cid) {
                    ctx.last_ip_id = ip_id;
                    ctx.last_ttl = ttl;
                }
                self.packets_decompressed += 1;
                self.build_ip_packet(ctx_data.0, ctx_data.1, ctx_data.4, ttl, ip_id, payload)
            }
            Profile::Tcp | Profile::Ipv6Tcp => {
                // Dynamic chain for TCP: [ip_id:2][ttl:1][seq_delta:4][ack_delta:4]
                if compressed.len() < 14 {
                    return Err(anyhow!("IR-DYN TCP packet too short"));
                }
                let ip_id = u16::from_be_bytes([compressed[3], compressed[4]]);
                let ttl = compressed[5];
                let payload = &compressed[14..];

                // Update context
                if let Some(ctx) = self.contexts.get_mut(&cid) {
                    ctx.last_ip_id = ip_id;
                    ctx.last_ttl = ttl;
                }
                self.packets_decompressed += 1;
                self.build_tcp_packet(
                    ctx_data.0, ctx_data.1, ctx_data.2, ctx_data.3,
                    ctx_data.4, ttl, ip_id, payload,
                )
            }
            _ => Err(anyhow!("IR-DYN not supported for profile {:?}", profile)),
        }
    }

    /// Decompress UO-0 packet (minimal 1-byte header)
    fn decompress_uo0(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.is_empty() {
            return Err(anyhow!("UO-0 packet too short"));
        }

        let header = compressed[0];
        let cid = (header >> 3) & 0x0F;
        let _sn = header & 0x07;
        let payload = &compressed[1..];

        // Extract context data to avoid borrow issues
        let (profile, src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id) = {
            let ctx = self
                .contexts
                .get_mut(&cid)
                .ok_or_else(|| anyhow!("No context for CID {}", cid))?;
            ctx.packet_count += 1;
            ctx.last_ip_id = ctx.last_ip_id.wrapping_add(1);
            (
                ctx.profile,
                ctx.src_addr,
                ctx.dst_addr,
                ctx.src_port,
                ctx.dst_port,
                ctx.protocol,
                ctx.last_ttl,
                ctx.last_ip_id,
            )
        };

        self.packets_decompressed += 1;

        match profile {
            Profile::Udp | Profile::Ipv6Udp | Profile::Rtp | Profile::UdpLite => self
                .build_udp_packet(
                    src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id, payload,
                ),
            Profile::Tcp | Profile::Ipv6Tcp => self.build_tcp_packet(
                src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id, payload,
            ),
            Profile::Ip | Profile::Esp => {
                self.build_ip_packet(src_addr, dst_addr, protocol, ttl, ip_id, payload)
            }
            Profile::Uncompressed => Ok(payload.to_vec()),
        }
    }

    /// Decompress UO-1 packet (2-byte header with IP-ID)
    fn decompress_uo1(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.len() < 2 {
            return Err(anyhow!("UO-1 packet too short"));
        }

        let header1 = compressed[0];
        let header2 = compressed[1];
        let cid = (header1 >> 3) & 0x0F;
        let ip_id_delta = (((header1 & 0x07) as u16) << 8) | (header2 as u16);
        let payload = &compressed[2..];

        // Extract context data to avoid borrow issues
        let (profile, src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id) = {
            let ctx = self
                .contexts
                .get_mut(&cid)
                .ok_or_else(|| anyhow!("No context for CID {}", cid))?;
            ctx.packet_count += 1;
            ctx.last_ip_id = ctx.last_ip_id.wrapping_add(ip_id_delta);
            (
                ctx.profile,
                ctx.src_addr,
                ctx.dst_addr,
                ctx.src_port,
                ctx.dst_port,
                ctx.protocol,
                ctx.last_ttl,
                ctx.last_ip_id,
            )
        };

        self.packets_decompressed += 1;

        match profile {
            Profile::Udp | Profile::Ipv6Udp | Profile::Rtp | Profile::UdpLite => self
                .build_udp_packet(
                    src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id, payload,
                ),
            Profile::Tcp | Profile::Ipv6Tcp => self.build_tcp_packet(
                src_addr, dst_addr, src_port, dst_port, protocol, ttl, ip_id, payload,
            ),
            Profile::Ip | Profile::Esp => {
                self.build_ip_packet(src_addr, dst_addr, protocol, ttl, ip_id, payload)
            }
            Profile::Uncompressed => Ok(payload.to_vec()),
        }
    }

    /// Build a complete IPv4/TCP packet from components
    #[allow(clippy::too_many_arguments)]
    fn build_tcp_packet(
        &self,
        src_addr: u32,
        dst_addr: u32,
        src_port: u16,
        dst_port: u16,
        _protocol: u8,
        ttl: u8,
        ip_id: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        // Minimal TCP header (20 bytes) + IP header (20 bytes)
        let tcp_header_len = 20;
        let total_len = 20 + tcp_header_len + payload.len();
        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&ip_id.to_be_bytes());
        packet.push(0x40);
        packet.push(0x00);
        packet.push(ttl);
        packet.push(6); // TCP protocol
        packet.push(0x00);
        packet.push(0x00);
        packet.extend_from_slice(&src_addr.to_be_bytes());
        packet.extend_from_slice(&dst_addr.to_be_bytes());

        // IP checksum
        let checksum = self.ip_checksum(&packet[0..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;

        // Minimal TCP header
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]); // Sequence number
        packet.extend_from_slice(&[0, 0, 0, 0]); // Ack number
        packet.push(0x50); // Data offset (5 * 4 = 20 bytes)
        packet.push(0x00); // Flags
        packet.extend_from_slice(&[0xFF, 0xFF]); // Window
        packet.extend_from_slice(&[0, 0]); // Checksum (0 for now)
        packet.extend_from_slice(&[0, 0]); // Urgent pointer

        // Payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    /// Build a complete IPv4/UDP packet from components
    #[allow(clippy::too_many_arguments)]
    fn build_udp_packet(
        &self,
        src_addr: u32,
        dst_addr: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        ttl: u8,
        ip_id: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let total_len = 20 + 8 + payload.len(); // IP + UDP + payload
        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&ip_id.to_be_bytes());
        packet.push(0x40); // Flags: Don't Fragment
        packet.push(0x00); // Fragment offset
        packet.push(ttl);
        packet.push(protocol);
        packet.push(0x00); // Checksum (will calculate)
        packet.push(0x00);
        packet.extend_from_slice(&src_addr.to_be_bytes());
        packet.extend_from_slice(&dst_addr.to_be_bytes());

        // Calculate IP header checksum
        let checksum = self.ip_checksum(&packet[0..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;

        // UDP header (8 bytes)
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = 8 + payload.len();
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.push(0x00); // Checksum (optional for IPv4)
        packet.push(0x00);

        // Payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    /// Build a complete IPv4 packet from components
    fn build_ip_packet(
        &self,
        src_addr: u32,
        dst_addr: u32,
        protocol: u8,
        ttl: u8,
        ip_id: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let total_len = 20 + payload.len();
        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header (20 bytes)
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&ip_id.to_be_bytes());
        packet.push(0x40);
        packet.push(0x00);
        packet.push(ttl);
        packet.push(protocol);
        packet.push(0x00);
        packet.push(0x00);
        packet.extend_from_slice(&src_addr.to_be_bytes());
        packet.extend_from_slice(&dst_addr.to_be_bytes());

        // Calculate checksum
        let checksum = self.ip_checksum(&packet[0..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;

        // Payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    /// Calculate IP header checksum
    fn ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for i in (0..header.len()).step_by(2) {
            let word = if i + 1 < header.len() {
                ((header[i] as u32) << 8) | (header[i + 1] as u32)
            } else {
                (header[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Get decompression statistics
    pub fn stats(&self) -> u64 {
        self.packets_decompressed
    }
}
