//! OxTunnel Server
//!
//! High-performance server endpoint for all clients (desktop, mobile, CLI) using the
//! OxTunnel Protocol with AF_XDP/FLASH zero-copy I/O on Linux bare metal.
//!
//! Transport: AF_XDP/FLASH (Linux) with kernel bypass for 18-25 Gbps throughput,
//! or standard UDP sockets on other platforms.

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use oxidize_common::af_xdp::{FlashSocket, XdpConfig};
use oxidize_common::auth::ServerAuthConfig;
use oxidize_common::oxtunnel_protocol::{
    control, decode_packet, encode_packet, flags, generate_id, AuthenticatedHandshakeInit,
    CryptoEngine, HandshakeInit, HandshakeResponse, IpPool, PacketBatch, PacketHeader,
    TunnelBufferPool, TunnelSession, TunnelStats, HEADER_SIZE, MAX_PACKET_SIZE, PROTOCOL_MAGIC,
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
// Rate Limiter
// ============================================================================

/// Rate limiting configuration
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Max packets per second per IP
    pub max_packets_per_sec: u32,
    /// Max new connections per minute per IP
    pub max_connections_per_min: u32,
    /// Max total concurrent sessions per IP
    pub max_sessions_per_ip: u32,
    /// Ban duration for violating rate limits
    pub ban_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_packets_per_sec: 1000,              // 1000 pps per IP
            max_connections_per_min: 10,            // 10 new connections/min per IP
            max_sessions_per_ip: 5,                 // 5 concurrent sessions per IP
            ban_duration: Duration::from_secs(300), // 5 minute ban
        }
    }
}

/// Per-IP rate limiting state
struct IpRateState {
    packet_count: u32,
    last_packet_time: Instant,
    connection_attempts: u32,
    last_connection_time: Instant,
    active_sessions: u32,
    banned_until: Option<Instant>,
}

impl Default for IpRateState {
    fn default() -> Self {
        Self {
            packet_count: 0,
            last_packet_time: Instant::now(),
            connection_attempts: 0,
            last_connection_time: Instant::now(),
            active_sessions: 0,
            banned_until: None,
        }
    }
}

/// Rate limiter for DDoS protection
pub struct RateLimiter {
    config: RateLimitConfig,
    ip_states: RwLock<HashMap<IpAddr, IpRateState>>,
    stats: RateLimiterStats,
}

/// Rate limiter statistics
#[derive(Default)]
pub struct RateLimiterStats {
    pub packets_dropped: std::sync::atomic::AtomicU64,
    pub connections_rejected: std::sync::atomic::AtomicU64,
    pub ips_banned: std::sync::atomic::AtomicU64,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_states: RwLock::new(HashMap::new()),
            stats: RateLimiterStats::default(),
        }
    }

    /// Check if a packet from this IP should be allowed
    pub async fn check_packet(&self, ip: IpAddr) -> bool {
        let mut states = self.ip_states.write().await;
        let state = states.entry(ip).or_default();
        let now = Instant::now();

        // Check if IP is banned
        if let Some(banned_until) = state.banned_until {
            if now < banned_until {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            } else {
                state.banned_until = None;
            }
        }

        // Reset counter if more than 1 second has passed
        if now.duration_since(state.last_packet_time) >= Duration::from_secs(1) {
            state.packet_count = 0;
            state.last_packet_time = now;
        }

        state.packet_count += 1;

        // Check rate limit
        if state.packet_count > self.config.max_packets_per_sec {
            warn!(
                "Rate limit exceeded for {} ({} pps)",
                ip, state.packet_count
            );
            self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);

            // Ban if significantly over limit
            if state.packet_count > self.config.max_packets_per_sec * 2 {
                state.banned_until = Some(now + self.config.ban_duration);
                self.stats.ips_banned.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "IP {} banned for {} seconds",
                    ip,
                    self.config.ban_duration.as_secs()
                );
            }
            return false;
        }

        true
    }

    /// Check if a new connection from this IP should be allowed
    pub async fn check_connection(&self, ip: IpAddr) -> bool {
        let mut states = self.ip_states.write().await;
        let state = states.entry(ip).or_default();
        let now = Instant::now();

        // Check if IP is banned
        if let Some(banned_until) = state.banned_until {
            if now < banned_until {
                self.stats
                    .connections_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            } else {
                state.banned_until = None;
            }
        }

        // Check session limit
        if state.active_sessions >= self.config.max_sessions_per_ip {
            warn!(
                "Max sessions exceeded for {} ({} sessions)",
                ip, state.active_sessions
            );
            self.stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Reset connection counter if more than 1 minute has passed
        if now.duration_since(state.last_connection_time) >= Duration::from_secs(60) {
            state.connection_attempts = 0;
            state.last_connection_time = now;
        }

        state.connection_attempts += 1;

        // Check connection rate limit
        if state.connection_attempts > self.config.max_connections_per_min {
            warn!(
                "Connection rate limit exceeded for {} ({}/min)",
                ip, state.connection_attempts
            );
            self.stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);

            // Ban if significantly over limit
            if state.connection_attempts > self.config.max_connections_per_min * 3 {
                state.banned_until = Some(now + self.config.ban_duration);
                self.stats.ips_banned.fetch_add(1, Ordering::Relaxed);
                warn!("IP {} banned for connection flooding", ip);
            }
            return false;
        }

        true
    }

    /// Increment active session count for an IP
    pub async fn add_session(&self, ip: IpAddr) {
        let mut states = self.ip_states.write().await;
        let state = states.entry(ip).or_default();
        state.active_sessions = state.active_sessions.saturating_add(1);
    }

    /// Decrement active session count for an IP
    pub async fn remove_session(&self, ip: IpAddr) {
        let mut states = self.ip_states.write().await;
        if let Some(state) = states.get_mut(&ip) {
            state.active_sessions = state.active_sessions.saturating_sub(1);
        }
    }

    /// Get rate limiter statistics
    pub fn stats(&self) -> &RateLimiterStats {
        &self.stats
    }

    /// Cleanup old entries (call periodically)
    pub async fn cleanup(&self) {
        let mut states = self.ip_states.write().await;
        let now = Instant::now();
        let stale_threshold = Duration::from_secs(600); // 10 minutes

        states.retain(|_, state| {
            // Keep if has active sessions or was recently active
            state.active_sessions > 0
                || now.duration_since(state.last_packet_time) < stale_threshold
        });
    }
}

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
// OxTunnel Server
// ============================================================================

/// Configuration for the OxTunnel server
#[derive(Clone)]
pub struct OxTunnelServerConfig {
    pub listen_addr: SocketAddr,
    pub enable_encryption: bool,
    pub session_timeout: Duration,
    pub keepalive_interval: Duration,
    pub ip_pool_base: Ipv4Addr,
    /// Network interface for XDP (auto-detected if None)
    pub xdp_interface: Option<String>,
    /// XDP queue ID (usually 0)
    pub xdp_queue_id: u32,
}

impl Default for OxTunnelServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:51820".parse().unwrap(),
            enable_encryption: true,
            session_timeout: Duration::from_secs(300),
            keepalive_interval: Duration::from_secs(25),
            ip_pool_base: Ipv4Addr::new(10, 0, 0, 0),
            xdp_interface: None, // Auto-detect on Linux
            xdp_queue_id: 0,
        }
    }
}

/// OxTunnel server for handling all client connections (desktop, mobile, CLI)
#[allow(dead_code)]
pub struct OxTunnelServer {
    config: OxTunnelServerConfig,
    socket: Arc<UdpSocket>,
    server_id: [u8; 32],
    sessions: Arc<RwLock<HashMap<[u8; 32], TunnelSession>>>,
    ip_pool: Arc<IpPool>,
    forwarder: Arc<PacketForwarder>,
    buffer_pool: Arc<TunnelBufferPool>,
    stats: Arc<TunnelStats>,
    rate_limiter: Arc<RateLimiter>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    #[allow(clippy::type_complexity)]
    response_rx: Arc<RwLock<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
    /// Authentication configuration (None = allow unauthenticated connections)
    auth_config: Option<Arc<ServerAuthConfig>>,
}

impl OxTunnelServer {
    /// Create a new OxTunnel server
    pub async fn new(config: OxTunnelServerConfig) -> Result<Self> {
        Self::with_auth(config, None).await
    }

    /// Create a new OxTunnel server with authentication
    pub async fn with_auth(
        config: OxTunnelServerConfig,
        auth_config: Option<ServerAuthConfig>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(config.listen_addr)
            .await
            .context("Failed to bind OxTunnel socket")?;

        let (response_tx, response_rx) = mpsc::channel(4096);

        if auth_config.is_some() {
            info!(
                "OxTunnel server listening on {} (authentication ENABLED)",
                config.listen_addr
            );
        } else {
            info!(
                "OxTunnel server listening on {} (authentication DISABLED)",
                config.listen_addr
            );
        }

        Ok(Self {
            server_id: generate_id(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ip_pool: Arc::new(IpPool::new(config.ip_pool_base)),
            forwarder: Arc::new(PacketForwarder::new()),
            buffer_pool: Arc::new(TunnelBufferPool::new()),
            stats: Arc::new(TunnelStats::new()),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
            socket: Arc::new(socket),
            response_tx,
            response_rx: Arc::new(RwLock::new(response_rx)),
            auth_config: auth_config.map(Arc::new),
            config,
        })
    }

    /// Run the OxTunnel server
    pub async fn run(self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let interface = self
                .config
                .xdp_interface
                .clone()
                .unwrap_or_else(Self::detect_default_interface);
            self.run_with_xdp(interface).await
        }

        #[cfg(not(target_os = "linux"))]
        self.run_standard().await
    }

    /// Auto-detect the default network interface
    #[cfg(target_os = "linux")]
    fn detect_default_interface() -> String {
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 2 && fields[1] == "00000000" {
                    return fields[0].to_string();
                }
            }
        }
        "eth0".to_string()
    }

    /// Run with FLASH AF_XDP zero-copy I/O (Linux only, 18-25 Gbps)
    /// FLASH = Fast Linked AF_XDP Sockets - multi-queue for linear scaling
    #[cfg(target_os = "linux")]
    async fn run_with_xdp(self, interface: String) -> Result<()> {
        use oxidize_common::af_xdp::XdpProgram;

        info!("🚀 Starting FLASH AF_XDP mode on interface: {}", interface);

        let port = self.config.listen_addr.port();
        let xdp_config = XdpConfig {
            interface: interface.clone(),
            queue_id: self.config.xdp_queue_id,
            quic_port: port,
            enable_flash: true,
            num_queues: 0, // Auto-detect
            ..XdpConfig::high_throughput(&interface)
        };

        // Create FLASH AF_XDP sockets
        let mut flash_socket =
            FlashSocket::new(xdp_config).context("Failed to create FLASH AF_XDP socket")?;

        let num_queues = flash_socket.num_queues();
        info!(
            "✅ FLASH AF_XDP sockets created on {} with {} queues",
            interface, num_queues
        );

        // Load XDP BPF program to redirect packets to AF_XDP sockets
        let mut xdp_prog = match XdpProgram::new(&interface, port, num_queues.max(64)) {
            Ok(prog) => prog,
            Err(e) => {
                warn!(
                    "Failed to load XDP program: {} - falling back to standard UDP",
                    e
                );
                return self.run_standard().await;
            }
        };

        // Attach XDP program to interface
        if let Err(e) = xdp_prog.attach(false) {
            warn!("Failed to attach XDP program: {} - trying SKB mode", e);
            if let Err(e2) = xdp_prog.attach(true) {
                warn!(
                    "SKB mode also failed: {} - falling back to standard UDP",
                    e2
                );
                return self.run_standard().await;
            }
        }

        // Register AF_XDP sockets in XSKMAP for each queue
        let socket_fds = flash_socket.socket_fds();
        info!(
            "📋 Registering {} AF_XDP sockets in XSKMAP",
            socket_fds.len()
        );
        for (queue_id, socket_fd) in &socket_fds {
            match xdp_prog.register_socket(*queue_id, *socket_fd) {
                Ok(_) => info!("  ✅ Queue {} -> fd {}", queue_id, socket_fd),
                Err(e) => warn!("  ❌ Queue {} failed: {}", queue_id, e),
            }
        }

        info!("✅ XDP program loaded and attached to {}", interface);
        info!("🔥 FLASH AF_XDP ready - zero-copy packet processing enabled");

        // CRITICAL: Populate fill ring BEFORE processing packets
        // Without frames in the fill ring, XDP has nowhere to redirect packets
        let initial_frames = flash_socket.populate_fill_rings();
        info!("📦 Populated fill rings with {} frames", initial_frames);

        // Spawn background tasks
        self.spawn_background_tasks();

        info!(
            "OxTunnel server started with FLASH AF_XDP, server_id: {:?}",
            &self.server_id[..8]
        );

        // FLASH packet processing loop
        let mut poll_count = 0u64;
        loop {
            poll_count += 1;
            #[allow(clippy::manual_is_multiple_of)]
            if poll_count % 10000 == 0 {
                debug!("AF_XDP poll iteration {}", poll_count);
            }

            if flash_socket.poll(100) {
                let packets = flash_socket.recv(128);
                if !packets.is_empty() {
                    info!("📦 AF_XDP received {} packets", packets.len());
                }
                let addrs: Vec<u64> = packets.iter().map(|p| p.frame_addr).collect();

                for pkt in packets {
                    self.stats
                        .total_rx_bytes
                        .fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
                    self.stats.total_rx_packets.fetch_add(1, Ordering::Relaxed);

                    // Parse source address from raw packet (Eth + IP + UDP)
                    // Returns (peer_addr, payload_offset) for both IPv4 and IPv6
                    if let Some((peer_addr, payload_offset)) = Self::parse_packet_addr(&pkt.data) {
                        let payload = &pkt.data[payload_offset..];

                        // Fast path: Handle UDP ping for latency measurement (no rate limit)
                        if payload.len() >= 4
                            && payload[..4] == oxidize_common::oxtunnel_protocol::PING_MAGIC
                        {
                            // Respond via standard socket (XDP is RX only)
                            let mut pong = vec![0u8; payload.len()];
                            pong[..4]
                                .copy_from_slice(&oxidize_common::oxtunnel_protocol::PONG_MAGIC);
                            if payload.len() > 4 {
                                pong[4..].copy_from_slice(&payload[4..]);
                            }
                            let _ = self.socket.send_to(&pong, peer_addr).await;
                            continue;
                        }

                        if !self.rate_limiter.check_packet(peer_addr.ip()).await {
                            continue;
                        }

                        let handler = self.clone_handler();
                        if pkt.data.len() > payload_offset {
                            let packet = pkt.data[payload_offset..].to_vec();
                            tokio::spawn(async move {
                                if let Err(e) = handler.handle_packet(&packet, peer_addr).await {
                                    debug!("Error handling packet from {}: {}", peer_addr, e);
                                }
                            });
                        }
                    }
                }

                flash_socket.return_frames(&addrs);
            }

            tokio::task::yield_now().await;
        }
    }

    /// Parse source address and payload offset from raw AF_XDP packet
    /// Supports both IPv4 and IPv6
    /// Returns (peer_addr, payload_offset) where payload starts after UDP header
    #[cfg(target_os = "linux")]
    fn parse_packet_addr(data: &[u8]) -> Option<(SocketAddr, usize)> {
        const ETH_HDR_LEN: usize = 14;
        const IPV4_MIN_LEN: usize = ETH_HDR_LEN + 20 + 8; // Eth + IPv4 + UDP
        const IPV6_MIN_LEN: usize = ETH_HDR_LEN + 40 + 8; // Eth + IPv6 + UDP

        if data.len() < IPV4_MIN_LEN {
            return None;
        }

        // Check ethertype (offset 12-13 in Ethernet header)
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            0x0800 => {
                // IPv4
                let ip_start = ETH_HDR_LEN;
                let version = (data[ip_start] >> 4) & 0xF;
                if version != 4 {
                    return None;
                }

                let ihl = (data[ip_start] & 0xF) as usize * 4;
                if data.len() < ip_start + ihl + 8 {
                    return None;
                }

                // Source IP at offset 12-15 in IP header
                let src_ip = Ipv4Addr::new(
                    data[ip_start + 12],
                    data[ip_start + 13],
                    data[ip_start + 14],
                    data[ip_start + 15],
                );

                // UDP source port at start of UDP header
                let udp_start = ip_start + ihl;
                let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
                let payload_offset = udp_start + 8; // After UDP header

                Some((
                    SocketAddr::new(IpAddr::V4(src_ip), src_port),
                    payload_offset,
                ))
            }
            0x86DD => {
                // IPv6
                if data.len() < IPV6_MIN_LEN {
                    return None;
                }

                let ip_start = ETH_HDR_LEN;

                // Check next header is UDP (17)
                let next_header = data[ip_start + 6];
                if next_header != 17 {
                    return None; // Not UDP (extension headers not supported)
                }

                // Source IP at offset 8-23 in IPv6 header
                let mut src_bytes = [0u8; 16];
                src_bytes.copy_from_slice(&data[ip_start + 8..ip_start + 24]);
                let src_ip = Ipv6Addr::from(src_bytes);

                // UDP header starts after 40-byte IPv6 header
                let udp_start = ip_start + 40;
                let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
                let payload_offset = udp_start + 8; // After UDP header

                Some((
                    SocketAddr::new(IpAddr::V6(src_ip), src_port),
                    payload_offset,
                ))
            }
            _ => None, // Unknown ethertype
        }
    }

    fn spawn_background_tasks(&self) {
        // Response sender task - sends queued responses via UDP socket
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

        // Cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let ip_pool_cleanup = Arc::clone(&self.ip_pool);
        let stats_cleanup = Arc::clone(&self.stats);
        let timeout = self.config.session_timeout;
        tokio::spawn(async move {
            Self::cleanup_stale_sessions(sessions_cleanup, ip_pool_cleanup, stats_cleanup, timeout)
                .await;
        });

        // Keepalive task
        let sessions_ka = Arc::clone(&self.sessions);
        let response_tx_ka = self.response_tx.clone();
        let interval = self.config.keepalive_interval;
        tokio::spawn(async move {
            Self::send_keepalives(sessions_ka, response_tx_ka, interval).await;
        });

        // Rate limiter cleanup
        let rate_limiter_cleanup = Arc::clone(&self.rate_limiter);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                rate_limiter_cleanup.cleanup().await;
            }
        });
    }

    /// Run with standard UDP sockets (non-Linux platforms)
    #[allow(dead_code)]
    async fn run_standard(self) -> Result<()> {
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

        // Spawn rate limiter cleanup task
        let rate_limiter_cleanup = Arc::clone(&self.rate_limiter);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                rate_limiter_cleanup.cleanup().await;
            }
        });

        info!(
            "OxTunnel server started, server_id: {:?}",
            &self.server_id[..8]
        );

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    // Fast path: Handle UDP ping for latency measurement (no rate limit)
                    if len >= 4 && buf[..4] == oxidize_common::oxtunnel_protocol::PING_MAGIC {
                        // Respond immediately with PONG (echo back any extra data for timing)
                        let mut pong = vec![0u8; len];
                        pong[..4].copy_from_slice(&oxidize_common::oxtunnel_protocol::PONG_MAGIC);
                        if len > 4 {
                            pong[4..].copy_from_slice(&buf[4..len]);
                        }
                        let _ = self.socket.send_to(&pong, peer_addr).await;
                        continue;
                    }

                    // Rate limit check - drop packet if rate exceeded
                    if !self.rate_limiter.check_packet(peer_addr.ip()).await {
                        debug!("Rate limited packet from {}", peer_addr);
                        continue;
                    }

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
            rate_limiter: Arc::clone(&self.rate_limiter),
            response_tx: self.response_tx.clone(),
            enable_encryption: self.config.enable_encryption,
            auth_config: self.auth_config.clone(),
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
    rate_limiter: Arc<RateLimiter>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    enable_encryption: bool,
    auth_config: Option<Arc<ServerAuthConfig>>,
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
            control::HANDSHAKE_INIT_AUTH => {
                self.handle_authenticated_handshake(payload, peer_addr)
                    .await
            }
            control::HANDSHAKE_INIT => {
                // Legacy unauthenticated handshake - reject if auth is required
                if self.auth_config.is_some() {
                    warn!(
                        "Rejecting unauthenticated handshake from {} - auth required",
                        peer_addr
                    );
                    self.send_auth_rejected(peer_addr, "Authentication required")
                        .await;
                    return Err(anyhow::anyhow!("Authentication required"));
                }
                self.handle_handshake_init(payload, peer_addr).await
            }
            control::KEEPALIVE => {
                debug!("Received keepalive from {}", peer_addr);
                // Update session activity
                self.update_session_activity(peer_addr).await;

                // Send ACK response for client RTT measurement
                let mut buf = [0u8; HEADER_SIZE + 1];
                if let Ok(len) = encode_packet(
                    &mut buf,
                    &[control::ACK],
                    0, // Sequence doesn't matter for ACK
                    flags::CONTROL,
                    None,
                ) {
                    let _ = self
                        .response_tx
                        .send((buf[..len].to_vec(), peer_addr))
                        .await;
                }
                Ok(())
            }
            control::DISCONNECT => {
                info!("Client {} disconnecting", peer_addr);
                self.remove_session_by_addr(peer_addr).await;
                self.rate_limiter.remove_session(peer_addr.ip()).await;
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
        // Rate limit connection attempts
        if !self.rate_limiter.check_connection(peer_addr.ip()).await {
            warn!("Connection rate limited for {}", peer_addr);
            return Err(anyhow::anyhow!("Rate limited"));
        }

        let init = HandshakeInit::decode(payload)
            .ok_or_else(|| anyhow::anyhow!("Invalid handshake init"))?;

        info!(
            "Handshake init from {}, client_id: {:?}",
            peer_addr,
            &init.client_id[..8]
        );

        // Track session for this IP
        self.rate_limiter.add_session(peer_addr.ip()).await;

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

    async fn handle_authenticated_handshake(
        &self,
        payload: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // Rate limit connection attempts
        if !self.rate_limiter.check_connection(peer_addr.ip()).await {
            warn!("Connection rate limited for {}", peer_addr);
            return Err(anyhow::anyhow!("Rate limited"));
        }

        let init = AuthenticatedHandshakeInit::decode(payload)
            .ok_or_else(|| anyhow::anyhow!("Invalid authenticated handshake"))?;

        info!(
            "Authenticated handshake from {}, client_id: {:?}",
            peer_addr,
            &init.client_id[..8]
        );

        // Verify authentication if configured
        if let Some(ref auth_config) = self.auth_config {
            let auth_payload = init.to_auth_payload();
            if let Err(e) = auth_payload.verify(auth_config) {
                warn!("Authentication failed for {}: {:?}", peer_addr, e);
                self.send_auth_rejected(peer_addr, &format!("{:?}", e))
                    .await;
                return Err(anyhow::anyhow!("Authentication failed: {:?}", e));
            }
            info!("✅ Authentication verified for {}", peer_addr);
        }

        // Track session for this IP
        self.rate_limiter.add_session(peer_addr.ip()).await;

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
            "✅ Authenticated handshake completed with {}, assigned IP: {}, encryption: {}",
            peer_addr,
            assigned_ip,
            encryption_key.is_some()
        );

        Ok(())
    }

    async fn send_auth_rejected(&self, peer_addr: SocketAddr, _reason: &str) {
        let mut response_buf = [0u8; 64];
        if let Ok(len) = encode_packet(
            &mut response_buf,
            &[control::AUTH_REJECTED],
            0,
            flags::CONTROL,
            None,
        ) {
            let _ = self
                .response_tx
                .send((response_buf[..len].to_vec(), peer_addr))
                .await;
        }
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
