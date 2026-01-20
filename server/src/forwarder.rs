//! Packet Forwarder
//!
//! Handles forwarding decoded packets to their destinations AND receiving responses.
//! Supports both UDP and TCP traffic tunneled through QUIC.

use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Tracks a forwarded packet's original source for response routing
#[derive(Clone, Debug)]
struct PacketMapping {
    conn_id: u64,
    /// Original source IP from the client's packet
    src_ip: Ipv4Addr,
    /// Original source port from the client's packet
    src_port: u16,
}

/// TCP connection key for connection pooling
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct TcpConnKey {
    conn_id: u64,
    src_port: u16,
    dst_addr: SocketAddr,
}

/// Shared packet forwarder for all connections
pub struct SharedForwarder {
    /// Outbound UDP socket for forwarding
    socket: Arc<UdpSocket>,
    /// Response channels per connection ID
    response_channels: Arc<RwLock<HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Mapping from (dst_ip, dst_port) to connection for response routing
    /// Key: destination address we forwarded TO
    /// Value: connection info to route responses back
    packet_mappings: Arc<RwLock<HashMap<SocketAddr, PacketMapping>>>,
    /// Active TCP connections (conn_id + src_port + dst -> TcpStream write half)
    tcp_connections: Arc<RwLock<HashMap<TcpConnKey, mpsc::Sender<Vec<u8>>>>>,
    /// Statistics
    stats: Arc<ForwarderStats>,
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
    /// Create a new shared forwarder with response listener
    pub async fn new() -> Result<Arc<Self>> {
        // Bind to any available port for outbound traffic
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;
        info!("Forwarder bound to {}", local_addr);

        let forwarder = Arc::new(Self {
            socket: Arc::new(socket),
            response_channels: Arc::new(RwLock::new(HashMap::new())),
            packet_mappings: Arc::new(RwLock::new(HashMap::new())),
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(ForwarderStats::default()),
        });

        // Start response listener task
        let forwarder_clone = forwarder.clone();
        tokio::spawn(async move {
            forwarder_clone.response_listener().await;
        });

        Ok(forwarder)
    }

    /// Background task that receives UDP responses and routes them to clients
    async fn response_listener(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        info!("Response listener started");
        let mut response_count: u64 = 0;
        let mut last_log = std::time::Instant::now();

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    response_count += 1;
                    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    // Log periodically to see if we're receiving responses
                    if last_log.elapsed().as_secs() >= 10 {
                        info!("📥 Forwarder received {} responses total", response_count);
                        last_log = std::time::Instant::now();
                    }

                    // Look up which connection this response belongs to
                    let mapping = {
                        let mappings = self.packet_mappings.read().await;
                        mappings.get(&src_addr).cloned()
                    };

                    if let Some(mapping) = mapping {
                        // Build IP packet with response (reconstruct headers)
                        let response_packet = self.build_ip_packet(
                            src_addr,
                            mapping.src_ip,
                            mapping.src_port,
                            &buf[..len],
                        );

                        // Send to the connection's response channel
                        let channels = self.response_channels.read().await;
                        if let Some(tx) = channels.get(&mapping.conn_id) {
                            if let Err(e) = tx.try_send(response_packet) {
                                debug!(
                                    "Failed to send response to conn {}: {}",
                                    mapping.conn_id, e
                                );
                            } else {
                                debug!(
                                    "✅ Routed {} bytes response to conn {}",
                                    len, mapping.conn_id
                                );
                            }
                        } else {
                            debug!("No channel for conn {}", mapping.conn_id);
                        }
                    } else {
                        debug!("No mapping for response from {}", src_addr);
                    }
                }
                Err(e) => {
                    warn!("Response recv error: {}", e);
                }
            }
        }
    }

    /// Build an IP+UDP packet from response data
    fn build_ip_packet(
        &self,
        src_addr: SocketAddr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let src_ip = match src_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => return Vec::new(), // Skip IPv6 for now
        };
        let src_port = src_addr.port();

        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut packet = vec![0u8; ip_len];

        // IP Header (20 bytes, no options)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00; // DSCP/ECN
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes()); // Total length
        packet[4..6].copy_from_slice(&[0x00, 0x00]); // ID
        packet[6..8].copy_from_slice(&[0x40, 0x00]); // Flags (DF), Fragment offset
        packet[8] = 64; // TTL
        packet[9] = 17; // Protocol: UDP
                        // Checksum at [10..12] - set to 0, will be calculated or offloaded
        packet[12..16].copy_from_slice(&src_ip.octets()); // Source IP
        packet[16..20].copy_from_slice(&dst_ip.octets()); // Destination IP

        // Calculate IP header checksum
        let checksum = self.ip_checksum(&packet[0..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        // UDP Header (8 bytes)
        packet[20..22].copy_from_slice(&src_port.to_be_bytes()); // Source port
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes()); // Dest port
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes()); // Length
        packet[26..28].copy_from_slice(&[0x00, 0x00]); // Checksum (0 = disabled)

        // Payload
        packet[28..].copy_from_slice(payload);

        packet
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
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
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

    /// Forward a packet to its destination and store mapping for responses
    /// Supports both UDP (protocol 17) and TCP (protocol 6)
    pub async fn forward(&self, conn_id: u64, packet: Vec<u8>) -> Result<()> {
        // Parse destination from IP header
        if packet.len() < 20 {
            return Ok(()); // Too short to be valid IP
        }

        // Check IP version
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return Ok(()); // Only IPv4 supported
        }

        let protocol = packet[9];
        let ip_header_len = ((packet[0] & 0x0F) * 4) as usize;

        // Extract source and destination
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        match protocol {
            17 => {
                // UDP forwarding
                if packet.len() < ip_header_len + 8 {
                    return Ok(());
                }
                let src_port =
                    u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
                let dst_port =
                    u16::from_be_bytes([packet[ip_header_len + 2], packet[ip_header_len + 3]]);
                let dst_addr = SocketAddr::from((dst_ip, dst_port));

                // Store mapping for response routing
                {
                    let mut mappings = self.packet_mappings.write().await;
                    mappings.insert(
                        dst_addr,
                        PacketMapping {
                            conn_id,
                            src_ip,
                            src_port,
                        },
                    );
                }

                // Forward the UDP payload
                let payload_offset = ip_header_len + 8;
                if packet.len() > payload_offset {
                    let payload = &packet[payload_offset..];
                    match self.socket.send_to(payload, dst_addr).await {
                        Ok(n) => {
                            let count =
                                self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                            self.stats
                                .bytes_forwarded
                                .fetch_add(n as u64, Ordering::Relaxed);
                            // Log every 1000th packet to see forwarding activity
                            if count.is_multiple_of(1000) {
                                info!(
                                    "📤 Forwarded {} UDP packets (latest: {} bytes to {})",
                                    count, n, dst_addr
                                );
                            }
                        }
                        Err(e) => {
                            self.stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                            warn!("UDP forward error to {}: {}", dst_addr, e);
                        }
                    }
                }
            }
            6 => {
                // TCP forwarding - proxy through established connections
                if packet.len() < ip_header_len + 20 {
                    return Ok(()); // TCP header is at least 20 bytes
                }
                let src_port =
                    u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
                let dst_port =
                    u16::from_be_bytes([packet[ip_header_len + 2], packet[ip_header_len + 3]]);
                let dst_addr = SocketAddr::from((dst_ip, dst_port));

                let tcp_header_len = ((packet[ip_header_len + 12] >> 4) * 4) as usize;
                let payload_offset = ip_header_len + tcp_header_len;

                // TCP flags
                let flags = packet[ip_header_len + 13];
                let syn = (flags & 0x02) != 0;
                let fin = (flags & 0x01) != 0;
                let rst = (flags & 0x04) != 0;

                let key = TcpConnKey {
                    conn_id,
                    src_port,
                    dst_addr,
                };

                if syn && (flags & 0x10) == 0 {
                    // SYN packet - establish new TCP connection
                    self.establish_tcp_connection(conn_id, src_ip, src_port, dst_addr)
                        .await;
                } else if fin || rst {
                    // FIN or RST - close connection
                    let mut conns = self.tcp_connections.write().await;
                    conns.remove(&key);
                    debug!(
                        "TCP: Connection closed {}:{} -> {}",
                        src_ip, src_port, dst_addr
                    );
                } else if packet.len() > payload_offset {
                    // Data packet - forward payload
                    let payload = packet[payload_offset..].to_vec();
                    if !payload.is_empty() {
                        let conns = self.tcp_connections.read().await;
                        if let Some(tx) = conns.get(&key) {
                            if tx.try_send(payload).is_ok() {
                                self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                                self.stats.bytes_forwarded.fetch_add(
                                    (packet.len() - payload_offset) as u64,
                                    Ordering::Relaxed,
                                );
                            }
                        }
                    }
                }
            }
            _ => {
                // Other protocols (ICMP, etc.) - skip for now
            }
        }

        Ok(())
    }

    /// Establish a TCP connection to destination and set up bidirectional proxy
    async fn establish_tcp_connection(
        &self,
        conn_id: u64,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_addr: SocketAddr,
    ) {
        let key = TcpConnKey {
            conn_id,
            src_port,
            dst_addr,
        };

        // Check if connection already exists
        {
            let conns = self.tcp_connections.read().await;
            if conns.contains_key(&key) {
                return;
            }
        }

        // Connect to destination
        let stream = match TcpStream::connect(dst_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("TCP connect to {} failed: {}", dst_addr, e);
                return;
            }
        };

        info!("TCP: Connected to {} for {}:{}", dst_addr, src_ip, src_port);

        let (mut read_half, mut write_half) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        // Store the write channel
        {
            let mut conns = self.tcp_connections.write().await;
            conns.insert(key.clone(), tx);
        }

        // Spawn task to write data to TCP connection
        let tcp_conns = self.tcp_connections.clone();
        let key_clone = key.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if write_half.write_all(&data).await.is_err() {
                    break;
                }
            }
            // Cleanup on disconnect
            let mut conns = tcp_conns.write().await;
            conns.remove(&key_clone);
        });

        // Spawn task to read responses and send back to client
        let response_channels = self.response_channels.clone();
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        // Build response IP packet
                        let response =
                            Self::build_tcp_response(dst_addr, src_ip, src_port, &buf[..n]);

                        // Send to client
                        let channels = response_channels.read().await;
                        if let Some(tx) = channels.get(&conn_id) {
                            let _ = tx.try_send(response);
                            stats.packets_received.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    /// Build a TCP response packet (simplified - just IP + TCP headers + payload)
    fn build_tcp_response(
        src_addr: SocketAddr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let src_ip = match src_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => return Vec::new(),
        };
        let src_port = src_addr.port();

        let tcp_header_len = 20; // Minimal TCP header
        let ip_len = 20 + tcp_header_len + payload.len();
        let mut packet = vec![0u8; ip_len];

        // IP Header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&[0x40, 0x00]); // DF flag
        packet[8] = 64; // TTL
        packet[9] = 6; // Protocol: TCP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // TCP Header (minimal)
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[32] = 0x50; // Data offset: 5 (20 bytes)
        packet[33] = 0x18; // Flags: PSH + ACK

        // Payload
        packet[40..].copy_from_slice(payload);

        packet
    }

    /// Get forwarder statistics
    pub fn stats(&self) -> &ForwarderStats {
        &self.stats
    }
}

// Type alias for backward compatibility
pub type SharedTunForwarder = SharedForwarder;
