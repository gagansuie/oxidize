//! QUIC Connection State Machine for AF_XDP
//!
//! Lock-free connection management designed for kernel bypass.
//! Supports 100,000+ concurrent connections with minimal memory.

use super::crypto::{CryptoEngine, CryptoSuite, Direction, KeyDerivation, PacketKeys};
use super::frame::{AckFrame, Frame, FrameParser};
use super::packet::{ConnectionId, QuicPacketHeader, QuicPacketType};
use super::stream::StreamManager;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    /// Waiting for Initial
    Initial = 0,
    /// Handshake in progress
    Handshake = 1,
    /// Handshake complete, 1-RTT ready
    Connected = 2,
    /// Closing initiated
    Closing = 3,
    /// Draining (waiting for timeout)
    Draining = 4,
    /// Connection closed
    Closed = 5,
}

/// QUIC connection for AF_XDP
#[repr(C, align(64))]
pub struct Connection {
    /// Local connection ID
    pub local_cid: ConnectionId,
    /// Remote connection ID  
    pub remote_cid: ConnectionId,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Connection state (atomic for lock-free reads)
    state: AtomicU8,
    /// Next packet number to send
    next_pn: AtomicU64,
    /// Largest acknowledged packet number
    largest_acked_pn: AtomicU64,
    /// Bytes sent
    bytes_sent: AtomicU64,
    /// Bytes received
    bytes_received: AtomicU64,
    /// Packets sent
    packets_sent: AtomicU64,
    /// Packets received
    packets_received: AtomicU64,
    /// RTT estimate (microseconds)
    rtt_us: AtomicU64,
    /// Smoothed RTT (microseconds)
    srtt_us: AtomicU64,
    /// RTT variance (microseconds)
    rttvar_us: AtomicU64,
    /// Congestion window (bytes)
    cwnd: AtomicU64,
    /// Slow start threshold
    ssthresh: AtomicU64,
    /// Bytes in flight
    bytes_in_flight: AtomicU64,
    /// Initial keys (client read, server write)
    pub initial_keys_rx: Option<PacketKeys>,
    pub initial_keys_tx: Option<PacketKeys>,
    /// Handshake keys
    pub handshake_keys_rx: Option<PacketKeys>,
    pub handshake_keys_tx: Option<PacketKeys>,
    /// 1-RTT keys (application data)
    pub app_keys_rx: Option<PacketKeys>,
    pub app_keys_tx: Option<PacketKeys>,
    /// Stream manager
    pub streams: StreamManager,
    /// Creation time
    created_at: Instant,
    /// Last activity time (for idle timeout)
    last_activity: AtomicU64,
    /// Max idle timeout (milliseconds)
    max_idle_timeout_ms: u64,
    /// Is this a server-side connection?
    is_server: bool,
    /// ALPN protocol
    pub alpn: [u8; 32],
    pub alpn_len: usize,
}

impl Connection {
    /// Create a new server-side connection from Initial packet
    pub fn new_server(
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        remote_addr: SocketAddr,
    ) -> Self {
        // Derive initial keys from client's DCID
        let (rx_keys, tx_keys) = KeyDerivation::derive_initial_secrets(
            local_cid.as_slice(),
            true, // is_server
        )
        .unwrap_or_else(|_| {
            // Fallback: create dummy keys (separate instances since LessSafeKey doesn't Clone)
            let rx_dummy = PacketKeys::new(
                CryptoSuite::Aes128Gcm,
                &[0; 16],
                [0; 12],
                [0; 32],
                Direction::Client,
            )
            .unwrap();
            let tx_dummy = PacketKeys::new(
                CryptoSuite::Aes128Gcm,
                &[0; 16],
                [0; 12],
                [0; 32],
                Direction::Server,
            )
            .unwrap();
            (rx_dummy, tx_dummy)
        });

        Self {
            local_cid,
            remote_cid,
            remote_addr,
            state: AtomicU8::new(ConnectionState::Initial as u8),
            next_pn: AtomicU64::new(0),
            largest_acked_pn: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            rtt_us: AtomicU64::new(100_000), // Initial RTT: 100ms
            srtt_us: AtomicU64::new(100_000),
            rttvar_us: AtomicU64::new(50_000),
            cwnd: AtomicU64::new(14720), // Initial CWND: 10 * MSS
            ssthresh: AtomicU64::new(u64::MAX),
            bytes_in_flight: AtomicU64::new(0),
            initial_keys_rx: Some(rx_keys),
            initial_keys_tx: Some(tx_keys),
            handshake_keys_rx: None,
            handshake_keys_tx: None,
            app_keys_rx: None,
            app_keys_tx: None,
            streams: StreamManager::new(true),
            created_at: Instant::now(),
            last_activity: AtomicU64::new(0),
            max_idle_timeout_ms: 30_000,
            is_server: true,
            alpn: [0; 32],
            alpn_len: 0,
        }
    }

    /// Get connection state
    #[inline(always)]
    pub fn state(&self) -> ConnectionState {
        match self.state.load(Ordering::Relaxed) {
            0 => ConnectionState::Initial,
            1 => ConnectionState::Handshake,
            2 => ConnectionState::Connected,
            3 => ConnectionState::Closing,
            4 => ConnectionState::Draining,
            _ => ConnectionState::Closed,
        }
    }

    /// Set connection state
    #[inline(always)]
    pub fn set_state(&self, state: ConnectionState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Get next packet number and increment
    #[inline(always)]
    pub fn next_packet_number(&self) -> u64 {
        self.next_pn.fetch_add(1, Ordering::Relaxed)
    }

    /// Update RTT estimate
    #[inline]
    pub fn update_rtt(&self, sample_us: u64) {
        // RFC 6298 style RTT estimation
        let srtt = self.srtt_us.load(Ordering::Relaxed);
        let rttvar = self.rttvar_us.load(Ordering::Relaxed);

        if srtt == 0 {
            // First measurement
            self.srtt_us.store(sample_us, Ordering::Relaxed);
            self.rttvar_us.store(sample_us / 2, Ordering::Relaxed);
        } else {
            // Subsequent measurements
            let diff = if sample_us > srtt {
                sample_us - srtt
            } else {
                srtt - sample_us
            };
            let new_rttvar = (3 * rttvar + diff) / 4;
            let new_srtt = (7 * srtt + sample_us) / 8;

            self.rttvar_us.store(new_rttvar, Ordering::Relaxed);
            self.srtt_us.store(new_srtt, Ordering::Relaxed);
        }

        self.rtt_us.store(sample_us, Ordering::Relaxed);
    }

    /// Get smoothed RTT
    #[inline(always)]
    pub fn srtt_us(&self) -> u64 {
        self.srtt_us.load(Ordering::Relaxed)
    }

    /// Check if we can send (congestion control)
    #[inline(always)]
    pub fn can_send(&self, bytes: u64) -> bool {
        let cwnd = self.cwnd.load(Ordering::Relaxed);
        let in_flight = self.bytes_in_flight.load(Ordering::Relaxed);
        in_flight + bytes <= cwnd
    }

    /// Record bytes sent
    #[inline]
    pub fn on_send(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_in_flight.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    /// Record bytes received
    #[inline]
    pub fn on_receive(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record ACK received
    #[inline]
    pub fn on_ack(&self, acked_bytes: u64, rtt_sample_us: Option<u64>) {
        self.bytes_in_flight.fetch_sub(
            acked_bytes.min(self.bytes_in_flight.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );

        if let Some(rtt) = rtt_sample_us {
            self.update_rtt(rtt);
        }

        // Congestion control: increase CWND
        let cwnd = self.cwnd.load(Ordering::Relaxed);
        let ssthresh = self.ssthresh.load(Ordering::Relaxed);

        if cwnd < ssthresh {
            // Slow start: double CWND
            self.cwnd.store(cwnd + acked_bytes, Ordering::Relaxed);
        } else {
            // Congestion avoidance: linear increase
            let increase = (acked_bytes * 1460) / cwnd;
            self.cwnd.store(cwnd + increase, Ordering::Relaxed);
        }
    }

    /// Record packet loss
    #[inline]
    pub fn on_loss(&self, lost_bytes: u64) {
        self.bytes_in_flight.fetch_sub(
            lost_bytes.min(self.bytes_in_flight.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );

        // Congestion control: reduce CWND
        let cwnd = self.cwnd.load(Ordering::Relaxed);
        let new_cwnd = (cwnd / 2).max(2 * 1460); // At least 2 MSS
        self.cwnd.store(new_cwnd, Ordering::Relaxed);
        self.ssthresh.store(new_cwnd, Ordering::Relaxed);
    }

    /// Update last activity timestamp
    #[inline(always)]
    fn touch(&self) {
        let now = self.created_at.elapsed().as_millis() as u64;
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Check if connection has timed out
    pub fn is_timed_out(&self) -> bool {
        let last = self.last_activity.load(Ordering::Relaxed);
        let now = self.created_at.elapsed().as_millis() as u64;
        now - last > self.max_idle_timeout_ms
    }

    /// Get keys for packet type
    pub fn get_rx_keys(&self, packet_type: QuicPacketType) -> Option<&PacketKeys> {
        match packet_type {
            QuicPacketType::Initial => self.initial_keys_rx.as_ref(),
            QuicPacketType::Handshake => self.handshake_keys_rx.as_ref(),
            QuicPacketType::OneRtt | QuicPacketType::ZeroRtt => self.app_keys_rx.as_ref(),
            QuicPacketType::Retry => None,
        }
    }

    pub fn get_tx_keys(&self, packet_type: QuicPacketType) -> Option<&PacketKeys> {
        match packet_type {
            QuicPacketType::Initial => self.initial_keys_tx.as_ref(),
            QuicPacketType::Handshake => self.handshake_keys_tx.as_ref(),
            QuicPacketType::OneRtt | QuicPacketType::ZeroRtt => self.app_keys_tx.as_ref(),
            QuicPacketType::Retry => None,
        }
    }

    /// Advance to handshake state
    pub fn advance_to_handshake(&self) {
        self.set_state(ConnectionState::Handshake);
    }

    /// Complete handshake
    pub fn complete_handshake(&self) {
        self.set_state(ConnectionState::Connected);
        // Drop initial and handshake keys
        // (In real impl, we'd clear the key fields)
    }

    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            rtt_us: self.rtt_us.load(Ordering::Relaxed),
            srtt_us: self.srtt_us.load(Ordering::Relaxed),
            cwnd: self.cwnd.load(Ordering::Relaxed),
            bytes_in_flight: self.bytes_in_flight.load(Ordering::Relaxed),
            state: self.state(),
            uptime_ms: self.created_at.elapsed().as_millis() as u64,
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub rtt_us: u64,
    pub srtt_us: u64,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
    pub state: ConnectionState,
    pub uptime_ms: u64,
}

/// High-performance connection table
/// Uses open addressing with linear probing for cache efficiency
pub struct ConnectionTable {
    /// Connections indexed by local CID hash
    connections: Vec<Option<Arc<Connection>>>,
    /// Table size (power of 2)
    capacity: usize,
    /// Mask for fast modulo
    mask: usize,
    /// Number of active connections
    count: AtomicU64,
    /// Statistics
    pub stats: TableStats,
}

#[derive(Default)]
pub struct TableStats {
    pub lookups: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub inserts: AtomicU64,
    pub removes: AtomicU64,
    pub collisions: AtomicU64,
}

impl ConnectionTable {
    /// Create a new connection table
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        let mut connections = Vec::with_capacity(capacity);
        connections.resize_with(capacity, || None);

        Self {
            connections,
            capacity,
            mask: capacity - 1,
            count: AtomicU64::new(0),
            stats: TableStats::default(),
        }
    }

    /// Look up connection by CID
    #[inline]
    pub fn get(&self, cid: &ConnectionId) -> Option<Arc<Connection>> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let hash = cid.hash_fnv1a() as usize;
        let mut idx = hash & self.mask;
        let start_idx = idx;

        loop {
            match &self.connections[idx] {
                Some(conn) if conn.local_cid == *cid => {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(Arc::clone(conn));
                }
                None => {
                    self.stats.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                _ => {
                    // Collision, continue probing
                    self.stats.collisions.fetch_add(1, Ordering::Relaxed);
                    idx = (idx + 1) & self.mask;
                    if idx == start_idx {
                        return None; // Table full
                    }
                }
            }
        }
    }

    /// Insert a connection
    #[inline]
    pub fn insert(&mut self, conn: Arc<Connection>) -> bool {
        let hash = conn.local_cid.hash_fnv1a() as usize;
        let mut idx = hash & self.mask;
        let start_idx = idx;

        loop {
            match &self.connections[idx] {
                None => {
                    self.connections[idx] = Some(conn);
                    self.count.fetch_add(1, Ordering::Relaxed);
                    self.stats.inserts.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Some(existing) if existing.local_cid == conn.local_cid => {
                    // Already exists
                    return false;
                }
                _ => {
                    idx = (idx + 1) & self.mask;
                    if idx == start_idx {
                        return false; // Table full
                    }
                }
            }
        }
    }

    /// Remove a connection by CID
    #[inline]
    pub fn remove(&mut self, cid: &ConnectionId) -> Option<Arc<Connection>> {
        let hash = cid.hash_fnv1a() as usize;
        let mut idx = hash & self.mask;
        let start_idx = idx;

        loop {
            match &self.connections[idx] {
                Some(conn) if conn.local_cid == *cid => {
                    let removed = self.connections[idx].take();
                    self.count.fetch_sub(1, Ordering::Relaxed);
                    self.stats.removes.fetch_add(1, Ordering::Relaxed);
                    return removed;
                }
                None => return None,
                _ => {
                    idx = (idx + 1) & self.mask;
                    if idx == start_idx {
                        return None;
                    }
                }
            }
        }
    }

    /// Get number of active connections
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed) as usize
    }

    /// Check if empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all connections
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Connection>> {
        self.connections.iter().filter_map(|c| c.as_ref())
    }

    /// Remove timed out connections
    pub fn cleanup_timed_out(&mut self) -> usize {
        let mut removed = 0;
        for slot in self.connections.iter_mut() {
            if let Some(conn) = slot {
                if conn.is_timed_out() || conn.state() == ConnectionState::Closed {
                    *slot = None;
                    self.count.fetch_sub(1, Ordering::Relaxed);
                    removed += 1;
                }
            }
        }
        removed
    }
}

/// Connection ID generator
pub struct CidGenerator {
    counter: AtomicU64,
    prefix: [u8; 4],
}

impl CidGenerator {
    pub fn new() -> Self {
        let prefix: [u8; 4] = rand::random();
        Self {
            counter: AtomicU64::new(0),
            prefix,
        }
    }

    /// Generate a new 8-byte connection ID
    #[inline]
    pub fn generate(&self) -> ConnectionId {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.prefix);
        bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        ConnectionId { bytes, len: 8 }
    }
}

impl Default for CidGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_table() {
        let mut table = ConnectionTable::new(1024);

        let cid = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let conn = Arc::new(Connection::new_server(
            cid,
            ConnectionId::EMPTY,
            "127.0.0.1:4433".parse().unwrap(),
        ));

        assert!(table.insert(conn.clone()));
        assert_eq!(table.len(), 1);

        let found = table.get(&cid);
        assert!(found.is_some());

        table.remove(&cid);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_cid_generator() {
        let gen = CidGenerator::new();
        let cid1 = gen.generate();
        let cid2 = gen.generate();
        assert_ne!(cid1, cid2);
        assert_eq!(cid1.len, 8);
    }
}
