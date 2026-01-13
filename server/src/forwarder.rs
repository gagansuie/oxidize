//! Packet Forwarder
//!
//! Handles forwarding decoded packets to their destinations.
//! This is a simplified forwarder that works with standard sockets.
//! For bare metal deployment, use DPDK feature for 40+ Gbps throughput.

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

/// Shared packet forwarder for all connections
pub struct SharedForwarder {
    /// Outbound UDP socket for forwarding
    socket: Arc<UdpSocket>,
    /// Response channels per connection ID
    response_channels: Arc<RwLock<HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Statistics
    stats: ForwarderStats,
}

#[derive(Debug, Default)]
pub struct ForwarderStats {
    pub packets_forwarded: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_forwarded: AtomicU64,
    pub bytes_received: AtomicU64,
    pub forward_errors: AtomicU64,
}

impl SharedForwarder {
    /// Create a new shared forwarder
    pub async fn new() -> Result<Arc<Self>> {
        // Bind to any available port for outbound traffic
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            response_channels: Arc::new(RwLock::new(HashMap::new())),
            stats: ForwarderStats::default(),
        }))
    }

    /// Register a connection and return a receiver for responses
    pub async fn register_connection(&self, conn_id: u64) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(1024);
        self.response_channels.write().await.insert(conn_id, tx);
        rx
    }

    /// Unregister a connection
    pub async fn unregister_connection(&self, conn_id: u64) {
        self.response_channels.write().await.remove(&conn_id);
    }

    /// Forward a packet to its destination
    pub async fn forward(&self, _conn_id: u64, packet: Vec<u8>) -> Result<()> {
        // Parse destination from IP header
        if packet.len() < 20 {
            return Ok(()); // Too short to be valid IP
        }

        // Check IP version
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            debug!("Non-IPv4 packet, skipping");
            return Ok(());
        }

        // Parse destination IP and check protocol
        let protocol = packet[9];
        if protocol != 17 {
            // Only handle UDP
            return Ok(());
        }

        let ip_header_len = ((packet[0] & 0x0F) * 4) as usize;
        if packet.len() < ip_header_len + 8 {
            return Ok(()); // Too short for UDP header
        }

        // Extract destination
        let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst_port = u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
        let dst_addr = SocketAddr::from((dst_ip, dst_port));

        // Forward the UDP payload (skip IP + UDP headers)
        let payload_offset = ip_header_len + 8;
        if packet.len() > payload_offset {
            let payload = &packet[payload_offset..];
            match self.socket.send_to(payload, dst_addr).await {
                Ok(n) => {
                    self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_forwarded
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    self.stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                    warn!("Forward error to {}: {}", dst_addr, e);
                }
            }
        }

        Ok(())
    }

    /// Get forwarder statistics
    pub fn stats(&self) -> &ForwarderStats {
        &self.stats
    }
}

// Type alias for backward compatibility
pub type SharedTunForwarder = SharedForwarder;
