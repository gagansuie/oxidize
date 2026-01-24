//! Mobile Tunnel Server
//!
//! High-performance server endpoint for mobile clients using the custom
//! Oxidize Mobile Tunnel Protocol. Replaces WireGuard with faster, lighter implementation.

use anyhow::{Context, Result};
use oxidize_common::oxtunnel_protocol::{
    control, decode_packet, encode_packet, flags, generate_id, CryptoEngine, HandshakeInit,
    HandshakeResponse, IpPool, PacketBatch, PacketHeader, TunnelBufferPool, TunnelSession,
    TunnelStats, HEADER_SIZE, MAX_PACKET_SIZE, PROTOCOL_MAGIC,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

// ============================================================================
// Packet Forwarder
// ============================================================================

/// Packet forwarder for sending decrypted packets to destinations
struct PacketForwarder {
    #[cfg(unix)]
    raw_socket_v4: Option<std::os::unix::io::RawFd>,
    #[cfg(unix)]
    raw_socket_v6: Option<std::os::unix::io::RawFd>,
    #[cfg(not(unix))]
    _phantom: std::marker::PhantomData<()>,
}

impl PacketForwarder {
    #[cfg(unix)]
    fn new() -> Self {
        let raw_socket_v4 = Self::create_raw_socket_v4();
        let raw_socket_v6 = Self::create_raw_socket_v6();

        if raw_socket_v4.is_none() {
            warn!("Failed to create IPv4 raw socket - packet forwarding may be limited");
        }
        if raw_socket_v6.is_none() {
            warn!("Failed to create IPv6 raw socket - IPv6 forwarding may be limited");
        }

        Self {
            raw_socket_v4,
            raw_socket_v6,
        }
    }

    #[cfg(not(unix))]
    fn new() -> Self {
        warn!("Raw socket forwarding not available on this platform");
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    #[cfg(unix)]
    fn create_raw_socket_v4() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;
        match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => {
                if sock.set_header_included_v4(true).is_err() {
                    warn!("Failed to set IP_HDRINCL");
                }
                Some(sock.into_raw_fd())
            }
            Err(e) => {
                debug!(
                    "Failed to create raw IPv4 socket: {} (requires CAP_NET_RAW)",
                    e
                );
                None
            }
        }
    }

    #[cfg(unix)]
    fn create_raw_socket_v6() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;
        match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => Some(sock.into_raw_fd()),
            Err(e) => {
                debug!(
                    "Failed to create raw IPv6 socket: {} (requires CAP_NET_RAW)",
                    e
                );
                None
            }
        }
    }

    #[cfg(unix)]
    async fn forward_ipv4(&self, packet: &[u8], dest: Ipv4Addr) -> Result<()> {
        if packet.len() < 20 {
            return Err(anyhow::anyhow!("IPv4 packet too short"));
        }

        if let Some(fd) = self.raw_socket_v4 {
            let dest_addr = socket2::SockAddr::from(SocketAddr::new(IpAddr::V4(dest), 0));

            let result = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    dest_addr.as_ptr(),
                    dest_addr.len() as libc::socklen_t,
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                debug!("Raw socket send failed: {}, falling back to UDP relay", err);
                return self.forward_via_udp_relay(packet, IpAddr::V4(dest)).await;
            }

            debug!(
                "Forwarded {} bytes to {} via raw socket",
                packet.len(),
                dest
            );
            Ok(())
        } else {
            self.forward_via_udp_relay(packet, IpAddr::V4(dest)).await
        }
    }

    #[cfg(not(unix))]
    async fn forward_ipv4(&self, packet: &[u8], dest: Ipv4Addr) -> Result<()> {
        if packet.len() < 20 {
            return Err(anyhow::anyhow!("IPv4 packet too short"));
        }
        self.forward_via_udp_relay(packet, IpAddr::V4(dest)).await
    }

    #[cfg(unix)]
    async fn forward_ipv6(&self, packet: &[u8], dest: Ipv6Addr) -> Result<()> {
        if packet.len() < 40 {
            return Err(anyhow::anyhow!("IPv6 packet too short"));
        }

        if let Some(fd) = self.raw_socket_v6 {
            let dest_addr = socket2::SockAddr::from(SocketAddr::new(IpAddr::V6(dest), 0));

            let result = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    dest_addr.as_ptr(),
                    dest_addr.len() as libc::socklen_t,
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                debug!("Raw socket send failed: {}, falling back to UDP relay", err);
                return self.forward_via_udp_relay(packet, IpAddr::V6(dest)).await;
            }

            debug!(
                "Forwarded {} bytes to {} via raw socket",
                packet.len(),
                dest
            );
            Ok(())
        } else {
            self.forward_via_udp_relay(packet, IpAddr::V6(dest)).await
        }
    }

    #[cfg(not(unix))]
    async fn forward_ipv6(&self, packet: &[u8], dest: Ipv6Addr) -> Result<()> {
        if packet.len() < 40 {
            return Err(anyhow::anyhow!("IPv6 packet too short"));
        }
        self.forward_via_udp_relay(packet, IpAddr::V6(dest)).await
    }

    async fn forward_via_udp_relay(&self, packet: &[u8], dest: IpAddr) -> Result<()> {
        let (protocol, payload, dest_port) = match dest {
            IpAddr::V4(_) => {
                if packet.len() < 20 {
                    return Err(anyhow::anyhow!("Packet too short"));
                }
                let ihl = ((packet[0] & 0x0F) * 4) as usize;
                let protocol = packet[9];
                let payload = &packet[ihl..];
                let dest_port = if payload.len() >= 4 {
                    u16::from_be_bytes([payload[2], payload[3]])
                } else {
                    0
                };
                (protocol, payload, dest_port)
            }
            IpAddr::V6(_) => {
                if packet.len() < 40 {
                    return Err(anyhow::anyhow!("IPv6 packet too short"));
                }
                let protocol = packet[6];
                let payload = &packet[40..];
                let dest_port = if payload.len() >= 4 {
                    u16::from_be_bytes([payload[2], payload[3]])
                } else {
                    0
                };
                (protocol, payload, dest_port)
            }
        };

        match protocol {
            17 => {
                // UDP
                if payload.len() < 8 {
                    return Err(anyhow::anyhow!("UDP payload too short"));
                }
                let udp_payload = &payload[8..];
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.send_to(udp_payload, (dest, dest_port)).await?;
                debug!("Relayed UDP packet to {}:{}", dest, dest_port);
            }
            6 => {
                // TCP
                if payload.len() < 20 {
                    return Err(anyhow::anyhow!("TCP payload too short"));
                }
                let tcp_payload = &payload[20..];
                if !tcp_payload.is_empty() {
                    use tokio::io::AsyncWriteExt;
                    match tokio::net::TcpStream::connect((dest, dest_port)).await {
                        Ok(mut stream) => {
                            stream.write_all(tcp_payload).await?;
                            debug!("Relayed TCP data to {}:{}", dest, dest_port);
                        }
                        Err(e) => {
                            debug!("TCP relay connection failed: {}", e);
                        }
                    }
                }
            }
            1 | 58 => {
                debug!("ICMP packet to {} (requires raw socket)", dest);
            }
            _ => {
                debug!("Unsupported protocol {} for relay fallback", protocol);
            }
        }

        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PacketForwarder {
    fn drop(&mut self) {
        if let Some(fd) = self.raw_socket_v4 {
            unsafe {
                libc::close(fd);
            }
        }
        if let Some(fd) = self.raw_socket_v6 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

// ============================================================================
// Mobile Tunnel Server
// ============================================================================

/// Configuration for the mobile tunnel server
#[derive(Clone)]
pub struct MobileServerConfig {
    pub listen_addr: SocketAddr,
    pub enable_encryption: bool,
    pub session_timeout: Duration,
    pub keepalive_interval: Duration,
    pub ip_pool_base: Ipv4Addr,
}

impl Default for MobileServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:51820".parse().unwrap(),
            enable_encryption: true,
            session_timeout: Duration::from_secs(300),
            keepalive_interval: Duration::from_secs(25),
            ip_pool_base: Ipv4Addr::new(10, 0, 0, 0),
        }
    }
}

/// Mobile tunnel server for handling mobile client connections
pub struct MobileTunnelServer {
    config: MobileServerConfig,
    socket: Arc<UdpSocket>,
    server_id: [u8; 32],
    sessions: Arc<RwLock<HashMap<[u8; 32], TunnelSession>>>,
    ip_pool: Arc<IpPool>,
    forwarder: Arc<PacketForwarder>,
    buffer_pool: Arc<TunnelBufferPool>,
    stats: Arc<TunnelStats>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    #[allow(clippy::type_complexity)]
    response_rx: Arc<RwLock<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
}

impl MobileTunnelServer {
    /// Create a new mobile tunnel server
    pub async fn new(config: MobileServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.listen_addr)
            .await
            .context("Failed to bind mobile tunnel socket")?;

        let (response_tx, response_rx) = mpsc::channel(4096);

        info!("Mobile tunnel server listening on {}", config.listen_addr);

        Ok(Self {
            server_id: generate_id(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ip_pool: Arc::new(IpPool::new(config.ip_pool_base)),
            forwarder: Arc::new(PacketForwarder::new()),
            buffer_pool: Arc::new(TunnelBufferPool::new()),
            stats: Arc::new(TunnelStats::new()),
            socket: Arc::new(socket),
            response_tx,
            response_rx: Arc::new(RwLock::new(response_rx)),
            config,
        })
    }

    /// Run the mobile tunnel server
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        // Spawn cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let ip_pool_cleanup = Arc::clone(&self.ip_pool);
        let stats_cleanup = Arc::clone(&self.stats);
        let timeout = self.config.session_timeout;
        tokio::spawn(async move {
            Self::cleanup_stale_sessions(sessions_cleanup, ip_pool_cleanup, stats_cleanup, timeout)
                .await;
        });

        // Spawn response sender task
        let socket_tx = Arc::clone(&self.socket);
        let response_rx = Arc::clone(&self.response_rx);
        let stats_tx = Arc::clone(&self.stats);
        tokio::spawn(async move {
            let mut rx = response_rx.write().await;
            while let Some((data, addr)) = rx.recv().await {
                if let Err(e) = socket_tx.send_to(&data, addr).await {
                    error!("Failed to send response to {}: {}", addr, e);
                } else {
                    stats_tx
                        .total_tx_bytes
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    stats_tx.total_tx_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        // Spawn keepalive task
        let sessions_ka = Arc::clone(&self.sessions);
        let response_tx_ka = self.response_tx.clone();
        let interval = self.config.keepalive_interval;
        tokio::spawn(async move {
            Self::send_keepalives(sessions_ka, response_tx_ka, interval).await;
        });

        info!(
            "Mobile tunnel server started, server_id: {:?}",
            &self.server_id[..8]
        );

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    self.stats
                        .total_rx_bytes
                        .fetch_add(len as u64, Ordering::Relaxed);
                    self.stats.total_rx_packets.fetch_add(1, Ordering::Relaxed);

                    let packet = buf[..len].to_vec();
                    let handler = self.clone_handler();

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_packet(&packet, peer_addr).await {
                            debug!("Error handling packet from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                }
            }
        }
    }

    fn clone_handler(&self) -> MobileServerHandler {
        MobileServerHandler {
            server_id: self.server_id,
            sessions: Arc::clone(&self.sessions),
            ip_pool: Arc::clone(&self.ip_pool),
            forwarder: Arc::clone(&self.forwarder),
            buffer_pool: Arc::clone(&self.buffer_pool),
            stats: Arc::clone(&self.stats),
            response_tx: self.response_tx.clone(),
            enable_encryption: self.config.enable_encryption,
        }
    }

    async fn cleanup_stale_sessions(
        sessions: Arc<RwLock<HashMap<[u8; 32], TunnelSession>>>,
        ip_pool: Arc<IpPool>,
        stats: Arc<TunnelStats>,
        timeout: Duration,
    ) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let mut sessions_lock = sessions.write().await;
            let stale_keys: Vec<_> = sessions_lock
                .iter()
                .filter(|(_, session)| session.last_activity.elapsed() >= timeout)
                .map(|(k, session)| {
                    info!("Removing stale session from {:?}", session.peer_addr);
                    *k
                })
                .collect();

            for key in &stale_keys {
                sessions_lock.remove(key);
                ip_pool.release(key).await;
                stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
            }

            if !stale_keys.is_empty() {
                info!("Cleaned up {} stale sessions", stale_keys.len());
            }
        }
    }

    async fn send_keepalives(
        sessions: Arc<RwLock<HashMap<[u8; 32], TunnelSession>>>,
        response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        interval: Duration,
    ) {
        loop {
            tokio::time::sleep(interval).await;

            let sessions_lock = sessions.read().await;
            for (_, session) in sessions_lock.iter() {
                let mut buf = [0u8; HEADER_SIZE + 1];
                buf[HEADER_SIZE] = control::KEEPALIVE;

                if let Ok(len) = encode_packet(
                    &mut buf,
                    &[control::KEEPALIVE],
                    session.tx_seq.load(Ordering::Relaxed),
                    flags::CONTROL,
                    None,
                ) {
                    let _ = response_tx
                        .send((buf[..len].to_vec(), session.peer_addr))
                        .await;
                }
            }
        }
    }

    /// Get server statistics
    pub fn stats(&self) -> Arc<TunnelStats> {
        Arc::clone(&self.stats)
    }

    /// Get active session count
    pub async fn active_sessions(&self) -> usize {
        self.sessions.read().await.len()
    }
}

// ============================================================================
// Packet Handler
// ============================================================================

struct MobileServerHandler {
    server_id: [u8; 32],
    sessions: Arc<RwLock<HashMap<[u8; 32], TunnelSession>>>,
    ip_pool: Arc<IpPool>,
    forwarder: Arc<PacketForwarder>,
    #[allow(dead_code)]
    buffer_pool: Arc<TunnelBufferPool>, // Reserved for zero-copy path
    stats: Arc<TunnelStats>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    enable_encryption: bool,
}

impl MobileServerHandler {
    async fn handle_packet(&self, packet: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // Check minimum size and magic
        if packet.len() < HEADER_SIZE {
            self.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Packet too short"));
        }

        if packet[0..2] != PROTOCOL_MAGIC {
            self.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Invalid protocol magic"));
        }

        let mut buf = packet.to_vec();
        let (header, payload) =
            decode_packet(&mut buf, None).map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;

        if header.flags & flags::CONTROL != 0 {
            self.handle_control_message(&header, payload, peer_addr)
                .await
        } else {
            self.handle_data_packet(&header, payload, peer_addr).await
        }
    }

    async fn handle_control_message(
        &self,
        _header: &PacketHeader,
        payload: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        if payload.is_empty() {
            return Err(anyhow::anyhow!("Empty control message"));
        }

        match payload[0] {
            control::HANDSHAKE_INIT => self.handle_handshake_init(payload, peer_addr).await,
            control::KEEPALIVE => {
                debug!("Received keepalive from {}", peer_addr);
                // Update session activity
                self.update_session_activity(peer_addr).await;
                Ok(())
            }
            control::DISCONNECT => {
                info!("Client {} disconnecting", peer_addr);
                self.remove_session_by_addr(peer_addr).await;
                Ok(())
            }
            control::ACK => {
                debug!("Received ACK from {}", peer_addr);
                Ok(())
            }
            _ => {
                debug!("Unknown control message type: {}", payload[0]);
                Ok(())
            }
        }
    }

    async fn handle_handshake_init(&self, payload: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let init = HandshakeInit::decode(payload)
            .ok_or_else(|| anyhow::anyhow!("Invalid handshake init"))?;

        info!(
            "Handshake init from {}, client_id: {:?}",
            peer_addr,
            &init.client_id[..8]
        );

        // Allocate IP for this client
        let assigned_ip = self.ip_pool.allocate(init.client_id).await;

        // Generate encryption key if both sides support it
        let encryption_key = if self.enable_encryption && init.encryption_supported {
            Some(CryptoEngine::generate_key())
        } else {
            None
        };

        // Create session
        let session = TunnelSession::new(peer_addr, assigned_ip, encryption_key.as_ref());

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(init.client_id, session);
        }

        self.stats.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats
            .handshakes_completed
            .fetch_add(1, Ordering::Relaxed);

        // Send response
        let response = HandshakeResponse {
            server_id: self.server_id,
            assigned_ip,
            encryption_key,
        };

        // Encode payload first to avoid borrow conflict
        let mut payload_buf = [0u8; 70];
        let payload_len = response.encode(&mut payload_buf);

        let mut response_buf = [0u8; 128];
        let total_len = encode_packet(
            &mut response_buf,
            &payload_buf[..payload_len],
            0,
            flags::CONTROL,
            None,
        )
        .map_err(|e| anyhow::anyhow!("Encode error: {}", e))?;

        self.response_tx
            .send((response_buf[..total_len].to_vec(), peer_addr))
            .await
            .context("Failed to queue handshake response")?;

        info!(
            "Handshake completed with {}, assigned IP: {}, encryption: {}",
            peer_addr,
            assigned_ip,
            encryption_key.is_some()
        );

        Ok(())
    }

    async fn handle_data_packet(
        &self,
        header: &PacketHeader,
        payload: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // Update session activity
        self.update_session_activity(peer_addr).await;

        // Handle batch packets
        if header.flags & flags::BATCH != 0 {
            let packets = PacketBatch::decode(payload)
                .map_err(|e| anyhow::anyhow!("Batch decode error: {}", e))?;

            for packet_data in packets {
                self.forward_ip_packet(&packet_data).await?;
            }
            return Ok(());
        }

        // Single packet
        self.forward_ip_packet(payload).await
    }

    async fn forward_ip_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        let version = packet[0] >> 4;

        match version {
            4 => {
                if packet.len() < 20 {
                    return Err(anyhow::anyhow!("IPv4 packet too short"));
                }
                let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let forwarder = Arc::clone(&self.forwarder);
                let packet_owned = packet.to_vec();
                tokio::spawn(async move {
                    if let Err(e) = forwarder.forward_ipv4(&packet_owned, dest).await {
                        debug!("Failed to forward IPv4 packet: {}", e);
                    }
                });
            }
            6 => {
                if packet.len() < 40 {
                    return Err(anyhow::anyhow!("IPv6 packet too short"));
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&packet[24..40]);
                let dest = Ipv6Addr::from(addr_bytes);

                let forwarder = Arc::clone(&self.forwarder);
                let packet_owned = packet.to_vec();
                tokio::spawn(async move {
                    if let Err(e) = forwarder.forward_ipv6(&packet_owned, dest).await {
                        debug!("Failed to forward IPv6 packet: {}", e);
                    }
                });
            }
            _ => {
                debug!("Unknown IP version: {}", version);
            }
        }

        Ok(())
    }

    async fn update_session_activity(&self, peer_addr: SocketAddr) {
        let mut sessions = self.sessions.write().await;
        for session in sessions.values_mut() {
            if session.peer_addr == peer_addr {
                session.last_activity = Instant::now();
                break;
            }
        }
    }

    async fn remove_session_by_addr(&self, peer_addr: SocketAddr) {
        let mut sessions = self.sessions.write().await;
        let key_to_remove: Option<[u8; 32]> = sessions
            .iter()
            .find(|(_, s)| s.peer_addr == peer_addr)
            .map(|(k, _)| *k);

        if let Some(key) = key_to_remove {
            sessions.remove(&key);
            self.ip_pool.release(&key).await;
            self.stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
            info!("Session removed for {}", peer_addr);
        }
    }
}

// ============================================================================
// Config Generation (for mobile app)
// ============================================================================

/// Generate mobile client configuration
pub fn generate_mobile_config(
    server_endpoint: &str,
    server_id: &[u8; 32],
    encryption_enabled: bool,
) -> String {
    let server_id_hex: String = server_id.iter().map(|b| format!("{:02x}", b)).collect();

    format!(
        r#"{{
  "server_endpoint": "{}",
  "server_id": "{}",
  "encryption_enabled": {},
  "protocol": "oxidize-mobile-tunnel",
  "version": 1
}}"#,
        server_endpoint, server_id_hex, encryption_enabled
    )
}

/// Generate server keypair (for compatibility with existing CLI)
pub fn generate_server_config() -> Result<(String, String, [u8; 32])> {
    let server_id = generate_id();
    let server_id_hex: String = server_id.iter().map(|b| format!("{:02x}", b)).collect();

    info!("Generated mobile tunnel server ID");
    info!("Server ID: {}", server_id_hex);

    Ok((server_id_hex.clone(), server_id_hex, server_id))
}

/// Generate client config (for compatibility with existing CLI)
pub fn generate_client_config(
    server_endpoint: &str,
    server_id: &str,
    _client_key: Option<&str>,
) -> Result<String> {
    Ok(format!(
        r#"{{
  "server_endpoint": "{}",
  "server_id": "{}",
  "encryption_enabled": true,
  "protocol": "oxidize-mobile-tunnel",
  "version": 1
}}"#,
        server_endpoint, server_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_generation() {
        let server_id = generate_id();
        let config = generate_mobile_config("relay.example.com:51820", &server_id, true);

        assert!(config.contains("relay.example.com:51820"));
        assert!(config.contains("oxidize-mobile-tunnel"));
        assert!(config.contains("\"encryption_enabled\": true"));
    }

    #[tokio::test]
    async fn test_ip_pool() {
        let pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 0));

        let id1 = generate_id();
        let id2 = generate_id();

        let ip1 = pool.allocate(id1).await;
        let ip2 = pool.allocate(id2).await;

        assert_ne!(ip1, ip2);
        assert_eq!(ip1.octets()[0..3], [10, 0, 0]);
        assert_eq!(ip2.octets()[0..3], [10, 0, 0]);

        // Same ID should get same IP
        let ip1_again = pool.allocate(id1).await;
        assert_eq!(ip1, ip1_again);
    }
}
