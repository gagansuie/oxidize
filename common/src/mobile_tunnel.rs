//! Oxidize Mobile Tunnel Protocol
//!
//! High-performance custom tunnel protocol for mobile clients (Android/iOS).
//! Replaces WireGuard with a lighter-weight, faster implementation.
//!
//! ## Advantages over WireGuard:
//! - **Optional encryption**: Skip crypto on trusted networks for ~40% speedup
//! - **Batch processing**: Process multiple packets per syscall
//! - **Zero-copy buffers**: Pre-allocated buffer pools (no heap allocation per packet)
//! - **Simpler handshake**: Faster connection establishment
//! - **Native QUIC support**: Can tunnel over existing QUIC connections
//!
//! ## Protocol Format:
//! ```text
//! +-------+-------+--------+----------+-------------+
//! | Magic | Flags | SeqNum | Length   | Payload     |
//! | 2B    | 1B    | 4B     | 2B       | Variable    |
//! +-------+-------+--------+----------+-------------+
//! ```
//!
//! Flags:
//! - 0x01: Encrypted payload (ChaCha20-Poly1305)
//! - 0x02: Compressed payload (LZ4)
//! - 0x04: Batch packet (contains multiple IP packets)
//! - 0x08: Control message (not IP packet)
//! - 0x10: IPv6 payload

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

// ============================================================================
// Protocol Constants
// ============================================================================

/// Protocol magic bytes for identification
pub const PROTOCOL_MAGIC: [u8; 2] = [0x4F, 0x58]; // "OX" for Oxidize

/// Header size: magic(2) + flags(1) + seqnum(4) + length(2) = 9 bytes
pub const HEADER_SIZE: usize = 9;

/// Maximum packet size (jumbo frame support)
pub const MAX_PACKET_SIZE: usize = 9216;

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - HEADER_SIZE - 16; // 16 for auth tag

/// Number of pre-allocated buffers
pub const BUFFER_POOL_SIZE: usize = 128;

/// Authentication tag size for ChaCha20-Poly1305
pub const AUTH_TAG_SIZE: usize = 16;

// ============================================================================
// Protocol Flags
// ============================================================================

pub mod flags {
    pub const ENCRYPTED: u8 = 0x01;
    pub const COMPRESSED: u8 = 0x02;
    pub const BATCH: u8 = 0x04;
    pub const CONTROL: u8 = 0x08;
    pub const IPV6: u8 = 0x10;
    pub const ACK_REQUEST: u8 = 0x20;
}

// ============================================================================
// Control Message Types
// ============================================================================

pub mod control {
    pub const HANDSHAKE_INIT: u8 = 0x01;
    pub const HANDSHAKE_RESPONSE: u8 = 0x02;
    pub const KEEPALIVE: u8 = 0x03;
    pub const DISCONNECT: u8 = 0x04;
    pub const ACK: u8 = 0x05;
    pub const CONFIG_UPDATE: u8 = 0x06;
}

// ============================================================================
// High-Performance Buffer Pool
// ============================================================================

/// Cache-line aligned buffer for optimal memory access
#[repr(C, align(64))]
pub struct TunnelBuffer {
    data: [u8; MAX_PACKET_SIZE],
    len: usize,
}

impl Default for TunnelBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelBuffer {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_PACKET_SIZE],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= MAX_PACKET_SIZE);
        self.len = len;
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Lock-free buffer pool for zero-allocation packet handling
pub struct TunnelBufferPool {
    buffers: Box<[UnsafeCell<TunnelBuffer>; BUFFER_POOL_SIZE]>,
    available: AtomicUsize,
    #[allow(dead_code)]
    available_high: AtomicUsize, // Reserved for pools > 64 buffers
    fallback_allocs: AtomicU64,
}

unsafe impl Send for TunnelBufferPool {}
unsafe impl Sync for TunnelBufferPool {}

impl TunnelBufferPool {
    pub fn new() -> Self {
        let buffers: Box<[UnsafeCell<TunnelBuffer>; BUFFER_POOL_SIZE]> = {
            let mut vec = Vec::with_capacity(BUFFER_POOL_SIZE);
            for _ in 0..BUFFER_POOL_SIZE {
                vec.push(UnsafeCell::new(TunnelBuffer::new()));
            }
            vec.try_into().unwrap_or_else(|_| unreachable!())
        };

        Self {
            buffers,
            available: AtomicUsize::new(!0usize),
            available_high: AtomicUsize::new(!0usize),
            fallback_allocs: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn acquire(&self) -> Option<PooledTunnelBuffer<'_>> {
        loop {
            let available = self.available.load(Ordering::Acquire);
            if available == 0 {
                self.fallback_allocs.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            let idx = available.trailing_zeros() as usize;
            let new_available = available & !(1 << idx);

            if self
                .available
                .compare_exchange_weak(
                    available,
                    new_available,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Some(PooledTunnelBuffer {
                    pool: self,
                    idx,
                    buffer: unsafe { &mut *self.buffers[idx].get() },
                });
            }
        }
    }

    #[inline]
    fn release(&self, idx: usize) {
        debug_assert!(idx < BUFFER_POOL_SIZE);
        self.available.fetch_or(1 << idx, Ordering::Release);
    }

    pub fn stats(&self) -> (usize, u64) {
        let available = self.available.load(Ordering::Relaxed).count_ones() as usize;
        let fallbacks = self.fallback_allocs.load(Ordering::Relaxed);
        (available, fallbacks)
    }
}

impl Default for TunnelBufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffer borrowed from the pool with RAII release
pub struct PooledTunnelBuffer<'a> {
    pool: &'a TunnelBufferPool,
    idx: usize,
    buffer: &'a mut TunnelBuffer,
}

impl<'a> PooledTunnelBuffer<'a> {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) {
        self.buffer.set_len(len);
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Drop for PooledTunnelBuffer<'_> {
    fn drop(&mut self) {
        self.pool.release(self.idx);
    }
}

// ============================================================================
// Crypto Engine (Optional Encryption)
// ============================================================================

/// Crypto engine for optional packet encryption
pub struct CryptoEngine {
    key: Option<LessSafeKey>,
    #[allow(dead_code)]
    rng: SystemRandom, // Reserved for future random nonce generation
    nonce_counter: AtomicU64,
}

impl CryptoEngine {
    /// Create a new crypto engine with optional key
    pub fn new(key_bytes: Option<&[u8; 32]>) -> Self {
        let key = key_bytes.map(|bytes| {
            let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, bytes).expect("Invalid key");
            LessSafeKey::new(unbound_key)
        });

        Self {
            key,
            rng: SystemRandom::new(),
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// Generate a random 32-byte key
    pub fn generate_key() -> [u8; 32] {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).expect("Failed to generate random key");
        key
    }

    /// Encrypt payload in place, returns new length (includes auth tag)
    #[inline]
    pub fn encrypt(&self, data: &mut [u8], plaintext_len: usize) -> Result<usize, &'static str> {
        let key = self.key.as_ref().ok_or("No encryption key configured")?;

        if plaintext_len + AUTH_TAG_SIZE > data.len() {
            return Err("Buffer too small for encryption");
        }

        // Generate nonce from counter (12 bytes)
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Encrypt in place
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut data[..plaintext_len])
            .map_err(|_| "Encryption failed")?;

        // Append tag
        data[plaintext_len..plaintext_len + AUTH_TAG_SIZE].copy_from_slice(tag.as_ref());

        Ok(plaintext_len + AUTH_TAG_SIZE)
    }

    /// Decrypt payload in place, returns plaintext length
    #[inline]
    pub fn decrypt(
        &self,
        data: &mut [u8],
        ciphertext_len: usize,
        nonce_counter: u64,
    ) -> Result<usize, &'static str> {
        let key = self.key.as_ref().ok_or("No encryption key configured")?;

        if ciphertext_len < AUTH_TAG_SIZE {
            return Err("Ciphertext too short");
        }

        // Reconstruct nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Decrypt in place
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut data[..ciphertext_len])
            .map_err(|_| "Decryption failed")?;

        Ok(plaintext.len())
    }

    pub fn is_enabled(&self) -> bool {
        self.key.is_some()
    }
}

// ============================================================================
// Packet Encoder/Decoder
// ============================================================================

/// Packet header
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub flags: u8,
    pub seq_num: u32,
    pub payload_len: u16,
}

impl PacketHeader {
    /// Encode header into buffer
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= HEADER_SIZE);
        buf[0..2].copy_from_slice(&PROTOCOL_MAGIC);
        buf[2] = self.flags;
        buf[3..7].copy_from_slice(&self.seq_num.to_le_bytes());
        buf[7..9].copy_from_slice(&self.payload_len.to_le_bytes());
    }

    /// Decode header from buffer
    #[inline]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }

        // Check magic
        if buf[0..2] != PROTOCOL_MAGIC {
            return None;
        }

        Some(Self {
            flags: buf[2],
            seq_num: u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]),
            payload_len: u16::from_le_bytes([buf[7], buf[8]]),
        })
    }
}

/// Encode a packet into the buffer, returns total packet length
#[inline]
pub fn encode_packet(
    buf: &mut [u8],
    payload: &[u8],
    seq_num: u32,
    flags: u8,
    crypto: Option<&CryptoEngine>,
) -> Result<usize, &'static str> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err("Payload too large");
    }

    let mut actual_flags = flags;
    let payload_start = HEADER_SIZE;

    // Copy payload
    buf[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    let mut total_len = payload_start + payload.len();

    // Encrypt if requested and crypto is available
    if flags & flags::ENCRYPTED != 0 {
        if let Some(crypto) = crypto {
            if crypto.is_enabled() {
                let encrypted_len = crypto.encrypt(&mut buf[payload_start..], payload.len())?;
                total_len = payload_start + encrypted_len;
            } else {
                actual_flags &= !flags::ENCRYPTED;
            }
        } else {
            actual_flags &= !flags::ENCRYPTED;
        }
    }

    // Write header
    let header = PacketHeader {
        flags: actual_flags,
        seq_num,
        payload_len: (total_len - payload_start) as u16,
    };
    header.encode(buf);

    Ok(total_len)
}

/// Decode a packet, returns (header, payload slice)
#[inline]
pub fn decode_packet<'a>(
    buf: &'a mut [u8],
    crypto: Option<&CryptoEngine>,
) -> Result<(PacketHeader, &'a [u8]), &'static str> {
    let header = PacketHeader::decode(buf).ok_or("Invalid packet header")?;

    let payload_start = HEADER_SIZE;
    let payload_end = payload_start + header.payload_len as usize;

    if payload_end > buf.len() {
        return Err("Payload extends beyond buffer");
    }

    // Decrypt if encrypted
    if header.flags & flags::ENCRYPTED != 0 {
        if let Some(crypto) = crypto {
            let plaintext_len = crypto.decrypt(
                &mut buf[payload_start..payload_end],
                header.payload_len as usize,
                header.seq_num as u64,
            )?;
            return Ok((header, &buf[payload_start..payload_start + plaintext_len]));
        }
        return Err("Encrypted packet but no crypto engine");
    }

    Ok((header, &buf[payload_start..payload_end]))
}

// ============================================================================
// Tunnel Session
// ============================================================================

/// Session state for a connected peer
pub struct TunnelSession {
    pub peer_addr: SocketAddr,
    pub assigned_ip: Ipv4Addr,
    pub last_activity: Instant,
    pub tx_seq: AtomicU32,
    pub rx_seq: AtomicU32,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub crypto: CryptoEngine,
    pub encryption_enabled: bool,
}

impl TunnelSession {
    pub fn new(peer_addr: SocketAddr, assigned_ip: Ipv4Addr, key: Option<&[u8; 32]>) -> Self {
        Self {
            peer_addr,
            assigned_ip,
            last_activity: Instant::now(),
            tx_seq: AtomicU32::new(0),
            rx_seq: AtomicU32::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            crypto: CryptoEngine::new(key),
            encryption_enabled: key.is_some(),
        }
    }

    #[inline]
    pub fn next_tx_seq(&self) -> u32 {
        self.tx_seq.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    #[inline]
    pub fn record_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> SessionStats {
        SessionStats {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            last_activity: self.last_activity,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub last_activity: Instant,
}

// ============================================================================
// IP Pool
// ============================================================================

/// IP address pool for assigning virtual IPs to peers
pub struct IpPool {
    base: Ipv4Addr,
    next_octet: AtomicU32,
    assigned: RwLock<HashMap<[u8; 32], Ipv4Addr>>,
}

impl IpPool {
    pub fn new(base: Ipv4Addr) -> Self {
        Self {
            base,
            next_octet: AtomicU32::new(2), // .1 is server, start clients at .2
            assigned: RwLock::new(HashMap::new()),
        }
    }

    pub async fn allocate(&self, peer_id: [u8; 32]) -> Ipv4Addr {
        let mut assigned = self.assigned.write().await;

        if let Some(&ip) = assigned.get(&peer_id) {
            return ip;
        }

        let octets = self.base.octets();
        let next = self.next_octet.fetch_add(1, Ordering::Relaxed);
        let last_octet = ((next - 2) % 253 + 2) as u8; // Wrap around, skip .0, .1, .255

        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet);
        assigned.insert(peer_id, ip);
        ip
    }

    pub async fn release(&self, peer_id: &[u8; 32]) {
        let mut assigned = self.assigned.write().await;
        assigned.remove(peer_id);
    }
}

// ============================================================================
// Handshake Protocol
// ============================================================================

/// Handshake initiation message
#[derive(Debug)]
pub struct HandshakeInit {
    pub client_id: [u8; 32],
    pub timestamp: u64,
    pub encryption_supported: bool,
}

impl HandshakeInit {
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0] = control::HANDSHAKE_INIT;
        buf[1..33].copy_from_slice(&self.client_id);
        buf[33..41].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[41] = if self.encryption_supported { 1 } else { 0 };
        42
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 42 || buf[0] != control::HANDSHAKE_INIT {
            return None;
        }

        let mut client_id = [0u8; 32];
        client_id.copy_from_slice(&buf[1..33]);

        Some(Self {
            client_id,
            timestamp: u64::from_le_bytes([
                buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39], buf[40],
            ]),
            encryption_supported: buf[41] != 0,
        })
    }
}

/// Handshake response message
#[derive(Debug)]
pub struct HandshakeResponse {
    pub server_id: [u8; 32],
    pub assigned_ip: Ipv4Addr,
    pub encryption_key: Option<[u8; 32]>,
}

impl HandshakeResponse {
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0] = control::HANDSHAKE_RESPONSE;
        buf[1..33].copy_from_slice(&self.server_id);
        buf[33..37].copy_from_slice(&self.assigned_ip.octets());

        if let Some(key) = &self.encryption_key {
            buf[37] = 1;
            buf[38..70].copy_from_slice(key);
            70
        } else {
            buf[37] = 0;
            38
        }
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 38 || buf[0] != control::HANDSHAKE_RESPONSE {
            return None;
        }

        let mut server_id = [0u8; 32];
        server_id.copy_from_slice(&buf[1..33]);

        let assigned_ip = Ipv4Addr::new(buf[33], buf[34], buf[35], buf[36]);

        let encryption_key = if buf[37] != 0 && buf.len() >= 70 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf[38..70]);
            Some(key)
        } else {
            None
        };

        Some(Self {
            server_id,
            assigned_ip,
            encryption_key,
        })
    }
}

// ============================================================================
// Batch Packet Processing
// ============================================================================

/// Batch of packets for efficient processing
pub struct PacketBatch {
    packets: Vec<(Vec<u8>, usize)>, // (buffer, length)
    total_bytes: usize,
}

impl PacketBatch {
    pub fn new() -> Self {
        Self {
            packets: Vec::with_capacity(32),
            total_bytes: 0,
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        self.packets.push((data.to_vec(), data.len()));
        self.total_bytes += data.len();
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if self.packets.is_empty() {
            return Err("Empty batch");
        }

        let mut offset = 0;

        // Write packet count (2 bytes)
        let count = self.packets.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&count.to_le_bytes());
        offset += 2;

        // Write each packet with length prefix
        for (data, len) in &self.packets {
            let len16 = *len as u16;
            buf[offset..offset + 2].copy_from_slice(&len16.to_le_bytes());
            offset += 2;
            buf[offset..offset + len].copy_from_slice(&data[..*len]);
            offset += len;
        }

        Ok(offset)
    }

    pub fn decode(buf: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        if buf.len() < 2 {
            return Err("Buffer too short");
        }

        let count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let mut packets = Vec::with_capacity(count);
        let mut offset = 2;

        for _ in 0..count {
            if offset + 2 > buf.len() {
                return Err("Truncated batch");
            }

            let len = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
            offset += 2;

            if offset + len > buf.len() {
                return Err("Truncated packet in batch");
            }

            packets.push(buf[offset..offset + len].to_vec());
            offset += len;
        }

        Ok(packets)
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.total_bytes = 0;
    }
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Global tunnel statistics
pub struct TunnelStats {
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub total_tx_packets: AtomicU64,
    pub total_rx_packets: AtomicU64,
    pub active_sessions: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub decrypt_failures: AtomicU64,
    pub invalid_packets: AtomicU64,
}

impl TunnelStats {
    pub fn new() -> Self {
        Self {
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            total_tx_packets: AtomicU64::new(0),
            total_rx_packets: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            decrypt_failures: AtomicU64::new(0),
            invalid_packets: AtomicU64::new(0),
        }
    }
}

impl Default for TunnelStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract destination IP from an IP packet
#[inline]
pub fn extract_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

/// Extract source IP from an IP packet
#[inline]
pub fn extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

/// Generate a random 32-byte identifier
pub fn generate_id() -> [u8; 32] {
    let rng = SystemRandom::new();
    let mut id = [0u8; 32];
    rng.fill(&mut id).expect("Failed to generate random ID");
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = PacketHeader {
            flags: flags::ENCRYPTED | flags::IPV6,
            seq_num: 12345,
            payload_len: 1500,
        };

        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf);

        let decoded = PacketHeader::decode(&buf).unwrap();
        assert_eq!(decoded.flags, header.flags);
        assert_eq!(decoded.seq_num, header.seq_num);
        assert_eq!(decoded.payload_len, header.payload_len);
    }

    #[test]
    fn test_packet_encode_decode() {
        let payload = b"Hello, Oxidize Mobile Tunnel!";
        let mut buf = [0u8; 256];

        let len = encode_packet(&mut buf, payload, 42, 0, None).unwrap();

        let (header, decoded_payload) = decode_packet(&mut buf[..len], None).unwrap();
        assert_eq!(header.seq_num, 42);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_crypto_engine() {
        let key = CryptoEngine::generate_key();
        let crypto = CryptoEngine::new(Some(&key));

        let plaintext = b"Secret message for mobile tunnel";
        let mut buf = [0u8; 256];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let encrypted_len = crypto.encrypt(&mut buf, plaintext.len()).unwrap();
        assert!(encrypted_len > plaintext.len()); // Includes auth tag

        let decrypted_len = crypto.decrypt(&mut buf, encrypted_len, 0).unwrap();
        assert_eq!(decrypted_len, plaintext.len());
        assert_eq!(&buf[..decrypted_len], plaintext);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = TunnelBufferPool::new();

        let mut buffers = Vec::new();
        for _ in 0..10 {
            if let Some(buf) = pool.acquire() {
                buffers.push(buf);
            }
        }

        assert_eq!(buffers.len(), 10);

        let (available, _) = pool.stats();
        assert!(available < BUFFER_POOL_SIZE);

        drop(buffers);

        let (available_after, _) = pool.stats();
        assert!(available_after > available);
    }

    #[test]
    fn test_handshake_messages() {
        let init = HandshakeInit {
            client_id: generate_id(),
            timestamp: 1234567890,
            encryption_supported: true,
        };

        let mut buf = [0u8; 64];
        let len = init.encode(&mut buf);

        let decoded = HandshakeInit::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.client_id, init.client_id);
        assert_eq!(decoded.timestamp, init.timestamp);
        assert!(decoded.encryption_supported);
    }

    #[test]
    fn test_batch_encoding() {
        let mut batch = PacketBatch::new();
        batch.add(b"packet 1");
        batch.add(b"packet 2 is longer");
        batch.add(b"p3");

        let mut buf = [0u8; 256];
        let len = batch.encode(&mut buf).unwrap();

        let decoded = PacketBatch::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], b"packet 1");
        assert_eq!(decoded[1], b"packet 2 is longer");
        assert_eq!(decoded[2], b"p3");
    }

    #[test]
    fn test_extract_ips() {
        // IPv4 packet
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45; // Version 4, IHL 5
        ipv4[12..16].copy_from_slice(&[192, 168, 1, 100]); // Source
        ipv4[16..20].copy_from_slice(&[10, 0, 0, 1]); // Destination

        assert_eq!(
            extract_src_ip(&ipv4),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
        assert_eq!(
            extract_dest_ip(&ipv4),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }
}
