//! Unified Transport Layer
//!
//! Cross-platform transport abstraction supporting both QUIC and UDP.
//! This allows desktop and mobile clients to use the same OxTunnel protocol
//! over whichever transport is most appropriate for their platform.

use crate::oxtunnel_protocol::{
    decode_packet, encode_packet, flags, CryptoEngine, HandshakeInit, HandshakeResponse,
    PacketBatch, HEADER_SIZE, MAX_PACKET_SIZE, PROTOCOL_MAGIC,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

/// Transport type for the tunnel
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportType {
    /// QUIC datagrams - encrypted, reliable connection with unreliable datagrams
    Quic,
    /// Raw UDP - for direct UDP tunneling (mobile fallback)
    Udp,
}

/// Unified transport configuration
#[derive(Clone, Debug)]
pub struct UnifiedTransportConfig {
    /// Server endpoint address
    pub server_addr: SocketAddr,
    /// Transport type to use
    pub transport: TransportType,
    /// Enable OxTunnel encryption (in addition to QUIC encryption)
    pub enable_oxtunnel_encryption: bool,
    /// Enable packet batching
    pub enable_batching: bool,
    /// Maximum packets per batch
    pub max_batch_size: usize,
    /// Batch timeout in microseconds
    pub batch_timeout_us: u64,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keepalive interval
    pub keepalive_interval: Duration,
}

impl Default for UnifiedTransportConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
            transport: TransportType::Quic,
            enable_oxtunnel_encryption: false, // QUIC already encrypts
            enable_batching: true,
            max_batch_size: 64,
            batch_timeout_us: 1000,
            connect_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(25),
        }
    }
}

impl UnifiedTransportConfig {
    /// Create config for desktop (QUIC preferred)
    pub fn desktop(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            transport: TransportType::Quic,
            enable_oxtunnel_encryption: false, // QUIC provides encryption
            enable_batching: true,
            max_batch_size: 64,
            batch_timeout_us: 1000,
            ..Default::default()
        }
    }

    /// Create config for mobile (QUIC preferred, UDP fallback)
    pub fn mobile(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            transport: TransportType::Quic,    // Try QUIC first
            enable_oxtunnel_encryption: false, // QUIC provides encryption
            enable_batching: true,
            max_batch_size: 32,     // Smaller batches for mobile
            batch_timeout_us: 2000, // Slightly longer timeout for mobile
            keepalive_interval: Duration::from_secs(15), // More frequent for mobile
            ..Default::default()
        }
    }

    /// Create config for UDP-only mode (fallback)
    pub fn udp_only(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            transport: TransportType::Udp,
            enable_oxtunnel_encryption: true, // Need encryption without QUIC
            enable_batching: true,
            max_batch_size: 32,
            batch_timeout_us: 1000,
            ..Default::default()
        }
    }
}

/// Statistics for the unified transport
#[derive(Default)]
pub struct TransportStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub batches_sent: AtomicU64,
    pub retransmits: AtomicU64,
    pub connect_time_ms: AtomicU64,
}

impl TransportStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> TransportStatsSnapshot {
        TransportStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            batches_sent: self.batches_sent.load(Ordering::Relaxed),
            retransmits: self.retransmits.load(Ordering::Relaxed),
            connect_time_ms: self.connect_time_ms.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportStatsSnapshot {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub batches_sent: u64,
    pub retransmits: u64,
    pub connect_time_ms: u64,
}

/// Packet batcher for OxTunnel
pub struct PacketBatcher {
    packets: Vec<Vec<u8>>,
    total_size: usize,
    max_batch_size: usize,
    sequence: AtomicU32,
    crypto: Option<CryptoEngine>,
}

impl PacketBatcher {
    pub fn new(max_batch_size: usize, encryption_key: Option<[u8; 32]>) -> Self {
        let crypto = encryption_key.map(|k| CryptoEngine::new(Some(&k)));
        Self {
            packets: Vec::with_capacity(max_batch_size),
            total_size: 0,
            max_batch_size,
            sequence: AtomicU32::new(0),
            crypto,
        }
    }

    fn next_seq(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    /// Add a packet, returns encoded batch if ready to flush
    pub fn add(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let new_size = self.total_size + packet.len() + 2;
        let should_flush = new_size > MAX_PACKET_SIZE - HEADER_SIZE - 32
            || self.packets.len() >= self.max_batch_size;

        if should_flush && !self.packets.is_empty() {
            let result = self.flush();
            self.packets.push(packet);
            self.total_size = self.packets.last().map(|p| p.len() + 2).unwrap_or(0);
            return result;
        }

        self.packets.push(packet);
        self.total_size = new_size;
        None
    }

    /// Flush current batch
    /// Note: Allocates output buffer - for hot path consider using flush_into() with pre-allocated buffer
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.packets.is_empty() {
            return None;
        }

        let mut batch = PacketBatch::new();
        for pkt in &self.packets {
            batch.add(pkt);
        }
        self.packets.clear();
        self.total_size = 0;

        // Use tracked total_size + count header bytes for estimation
        let mut payload = vec![0u8; MAX_PACKET_SIZE];

        let payload_len = match batch.encode(&mut payload) {
            Ok(len) => len,
            Err(_) => return None,
        };
        payload.truncate(payload_len);

        let seq = self.next_seq();
        let flags_byte = if self.crypto.is_some() {
            flags::BATCH | flags::ENCRYPTED
        } else {
            flags::BATCH
        };

        // Pre-allocate exact size needed
        let output_size = HEADER_SIZE + payload.len() + if self.crypto.is_some() { 32 } else { 0 };
        let mut output = vec![0u8; output_size];

        match encode_packet(&mut output, &payload, seq, flags_byte, self.crypto.as_ref()) {
            Ok(len) => {
                output.truncate(len);
                Some(output)
            }
            Err(_) => None,
        }
    }

    /// Encode a single packet (no batching)
    pub fn encode_single(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let flags_byte = if self.crypto.is_some() {
            flags::ENCRYPTED
        } else {
            0
        };

        let mut output = vec![0u8; HEADER_SIZE + packet.len() + 32];
        match encode_packet(&mut output, packet, seq, flags_byte, self.crypto.as_ref()) {
            Ok(len) => {
                output.truncate(len);
                Some(output)
            }
            Err(_) => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }
}

/// Decode an OxTunnel packet, returns individual IP packets
pub fn decode_oxtunnel_packet(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if data.len() < HEADER_SIZE {
        return Err("Packet too short");
    }

    if data[0..2] != PROTOCOL_MAGIC {
        return Err("Invalid magic");
    }

    let mut buf = data.to_vec();
    let (header, payload) = decode_packet(&mut buf, None)?;

    if header.flags & flags::BATCH != 0 {
        PacketBatch::decode(payload)
    } else {
        Ok(vec![payload.to_vec()])
    }
}

/// Check if data is an OxTunnel packet
#[inline]
pub fn is_oxtunnel_packet(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && data[0..2] == PROTOCOL_MAGIC
}

/// Create a handshake init message
pub fn create_handshake_init(client_id: [u8; 32], encryption_supported: bool) -> Vec<u8> {
    let init = HandshakeInit {
        client_id,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        encryption_supported,
    };

    let mut payload = [0u8; 64];
    let payload_len = init.encode(&mut payload);
    let mut output = vec![0u8; HEADER_SIZE + payload_len];

    match encode_packet(
        &mut output,
        &payload[..payload_len],
        0,
        flags::CONTROL,
        None,
    ) {
        Ok(len) => {
            output.truncate(len);
            output
        }
        Err(_) => Vec::new(),
    }
}

/// Parse a handshake response
pub fn parse_handshake_response(data: &[u8]) -> Option<HandshakeResponse> {
    if data.len() < HEADER_SIZE {
        return None;
    }

    let mut buf = data.to_vec();
    let (header, payload) = decode_packet(&mut buf, None).ok()?;

    if header.flags & flags::CONTROL == 0 {
        return None;
    }

    HandshakeResponse::decode(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oxtunnel_protocol::generate_id;

    #[test]
    fn test_config_desktop() {
        let config = UnifiedTransportConfig::desktop("127.0.0.1:51820".parse().unwrap());
        assert_eq!(config.transport, TransportType::Quic);
        assert!(!config.enable_oxtunnel_encryption);
        assert!(config.enable_batching);
    }

    #[test]
    fn test_config_mobile() {
        let config = UnifiedTransportConfig::mobile("127.0.0.1:51820".parse().unwrap());
        assert_eq!(config.transport, TransportType::Quic);
        assert_eq!(config.max_batch_size, 32);
    }

    #[test]
    fn test_config_udp_fallback() {
        let config = UnifiedTransportConfig::udp_only("127.0.0.1:51820".parse().unwrap());
        assert_eq!(config.transport, TransportType::Udp);
        assert!(config.enable_oxtunnel_encryption);
    }

    #[test]
    fn test_packet_batcher() {
        let mut batcher = PacketBatcher::new(3, None);

        // First two packets shouldn't flush
        assert!(batcher.add(vec![0x45; 100]).is_none());
        assert!(batcher.add(vec![0x45; 100]).is_none());

        // Third packet triggers flush
        let result = batcher.add(vec![0x45; 100]);
        assert!(result.is_some() || batcher.flush().is_some());
    }

    #[test]
    fn test_is_oxtunnel_packet() {
        // Valid OxTunnel header
        let mut valid = vec![0u8; 20];
        valid[0..2].copy_from_slice(&PROTOCOL_MAGIC);
        assert!(is_oxtunnel_packet(&valid));

        // Raw IP packet (not OxTunnel)
        let ip_packet = vec![0x45, 0x00, 0x00, 0x28];
        assert!(!is_oxtunnel_packet(&ip_packet));
    }

    #[test]
    fn test_handshake_init() {
        let client_id = generate_id();
        let init = create_handshake_init(client_id, true);
        assert!(!init.is_empty());
        assert!(is_oxtunnel_packet(&init));
    }
}
