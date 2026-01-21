//! DPDK QUIC Connection State Machine
//!
//! High-performance connection management for DPDK-based QUIC.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

use super::packet::{IpAddr, QuicPacketType};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Waiting for Initial from client
    Idle,
    /// Initial received, sending Initial + Handshake
    InitialReceived,
    /// Handshake in progress
    Handshaking,
    /// Handshake complete, 1-RTT ready
    Connected,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
}

/// QUIC Connection for DPDK
pub struct DpdkConnection {
    /// Connection ID (destination)
    pub dcid: Vec<u8>,
    /// Connection ID (source)
    pub scid: Vec<u8>,
    /// Original DCID from client Initial
    pub original_dcid: Vec<u8>,
    /// Current state
    pub state: ConnectionState,
    /// Remote address
    pub remote_addr: RemoteAddr,
    /// Next packet number to send (per space)
    pub next_pn: [AtomicU64; 3], // Initial, Handshake, 1-RTT
    /// Largest acknowledged packet number (per space)
    pub largest_acked: [AtomicU64; 3],
    /// Creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// TLS state (simplified)
    pub tls_complete: bool,
    /// Initial secrets (for encryption/decryption)
    pub initial_secrets: Option<InitialSecrets>,
    /// Handshake secrets
    pub handshake_secrets: Option<HandshakeSecrets>,
    /// Application secrets (1-RTT)
    pub app_secrets: Option<AppSecrets>,
}

/// Remote address (supports both IPv4 and IPv6)
#[derive(Debug, Clone)]
pub struct RemoteAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub mac: [u8; 6],
}

/// Initial encryption secrets
#[derive(Clone)]
pub struct InitialSecrets {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub client_hp: [u8; 16],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
    pub server_hp: [u8; 16],
}

/// Handshake encryption secrets
#[derive(Clone)]
pub struct HandshakeSecrets {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub client_hp: [u8; 16],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
    pub server_hp: [u8; 16],
}

/// Application (1-RTT) secrets
#[derive(Clone)]
pub struct AppSecrets {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub client_hp: [u8; 16],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
    pub server_hp: [u8; 16],
}

impl DpdkConnection {
    pub fn new(dcid: Vec<u8>, scid: Vec<u8>, remote_addr: RemoteAddr) -> Self {
        Self {
            original_dcid: dcid.clone(),
            dcid,
            scid,
            state: ConnectionState::Idle,
            remote_addr,
            next_pn: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            largest_acked: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            created_at: Instant::now(),
            last_activity: Instant::now(),
            tls_complete: false,
            initial_secrets: None,
            handshake_secrets: None,
            app_secrets: None,
        }
    }

    /// Get next packet number for a packet type
    pub fn next_packet_number(&self, pkt_type: QuicPacketType) -> u64 {
        let space = match pkt_type {
            QuicPacketType::Initial => 0,
            QuicPacketType::Handshake => 1,
            _ => 2, // 1-RTT
        };
        self.next_pn[space].fetch_add(1, Ordering::SeqCst)
    }

    /// Update state machine
    pub fn transition(&mut self, new_state: ConnectionState) {
        self.state = new_state;
        self.last_activity = Instant::now();
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Check if connection is alive
    pub fn is_alive(&self) -> bool {
        !matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Closed
        )
    }

    /// Derive initial secrets from DCID
    pub fn derive_initial_secrets(&mut self) {
        // QUIC v1 initial salt
        const INITIAL_SALT: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];

        // Simplified key derivation (real implementation uses HKDF)
        // This is a placeholder - actual TLS 1.3 key derivation is more complex
        let mut client_key = [0u8; 16];
        let mut client_iv = [0u8; 12];
        let mut client_hp = [0u8; 16];
        let mut server_key = [0u8; 16];
        let mut server_iv = [0u8; 12];
        let mut server_hp = [0u8; 16];

        // Simple XOR derivation for demo (NOT SECURE - use proper HKDF in production)
        for (i, &b) in self.original_dcid.iter().enumerate() {
            client_key[i % 16] ^= b;
            server_key[i % 16] ^= b.wrapping_add(1);
            if i < 12 {
                client_iv[i] ^= b.wrapping_add(2);
                server_iv[i] ^= b.wrapping_add(3);
            }
            client_hp[i % 16] ^= b.wrapping_add(4);
            server_hp[i % 16] ^= b.wrapping_add(5);
        }

        self.initial_secrets = Some(InitialSecrets {
            client_key,
            client_iv,
            client_hp,
            server_key,
            server_iv,
            server_hp,
        });
    }
}

/// Connection ID generator
pub struct CidGenerator {
    counter: AtomicU64,
}

impl CidGenerator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(rand::random()),
        }
    }

    /// Generate a new 8-byte connection ID
    pub fn generate(&self) -> Vec<u8> {
        let val = self.counter.fetch_add(1, Ordering::SeqCst);
        val.to_be_bytes().to_vec()
    }
}

impl Default for CidGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection table with lock-free lookup
pub struct DpdkConnectionTable {
    /// Map from DCID to connection index
    by_dcid: RwLock<HashMap<Vec<u8>, usize>>,
    /// Connection storage
    connections: RwLock<Vec<Option<DpdkConnection>>>,
    /// Free list of connection indices
    free_list: RwLock<Vec<usize>>,
    /// Maximum connections
    max_connections: usize,
    /// Active connection count
    active_count: AtomicU64,
}

impl DpdkConnectionTable {
    pub fn new(max_connections: usize) -> Self {
        Self {
            by_dcid: RwLock::new(HashMap::with_capacity(max_connections)),
            connections: RwLock::new((0..max_connections).map(|_| None).collect()),
            free_list: RwLock::new((0..max_connections).collect()),
            max_connections,
            active_count: AtomicU64::new(0),
        }
    }

    /// Insert a new connection
    pub fn insert(&self, conn: DpdkConnection) -> Option<usize> {
        let mut free = self.free_list.write();
        let idx = free.pop()?;

        let dcid = conn.dcid.clone();
        let scid = conn.scid.clone();

        {
            let mut conns = self.connections.write();
            conns[idx] = Some(conn);
        }

        {
            let mut by_dcid = self.by_dcid.write();
            by_dcid.insert(dcid, idx);
            by_dcid.insert(scid, idx);
        }

        self.active_count.fetch_add(1, Ordering::SeqCst);
        Some(idx)
    }

    /// Lookup by DCID
    pub fn get_by_dcid(&self, dcid: &[u8]) -> Option<usize> {
        let by_dcid = self.by_dcid.read();
        by_dcid.get(dcid).copied()
    }

    /// Get connection by index
    pub fn get(
        &self,
        idx: usize,
    ) -> Option<parking_lot::RwLockReadGuard<'_, Vec<Option<DpdkConnection>>>> {
        let conns = self.connections.read();
        if idx < self.max_connections && conns[idx].is_some() {
            Some(conns)
        } else {
            None
        }
    }

    /// Get mutable connection by index
    pub fn get_mut(
        &self,
        idx: usize,
    ) -> Option<parking_lot::RwLockWriteGuard<'_, Vec<Option<DpdkConnection>>>> {
        let conns = self.connections.write();
        if idx < self.max_connections && conns[idx].is_some() {
            Some(conns)
        } else {
            None
        }
    }

    /// Remove connection
    pub fn remove(&self, idx: usize) {
        let mut conns = self.connections.write();
        if let Some(conn) = conns[idx].take() {
            let mut by_dcid = self.by_dcid.write();
            by_dcid.remove(&conn.dcid);
            by_dcid.remove(&conn.scid);

            let mut free = self.free_list.write();
            free.push(idx);

            self.active_count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Get active connection count
    pub fn len(&self) -> usize {
        self.active_count.load(Ordering::SeqCst) as usize
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lookup connection by CID (alias for get_by_dcid)
    pub fn lookup_by_cid(&self, cid: &[u8]) -> Option<usize> {
        self.get_by_dcid(cid)
    }

    /// Get active connection count
    pub fn active_count(&self) -> usize {
        self.len()
    }
}
