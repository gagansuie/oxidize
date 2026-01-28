//! OxTunnel Client
//!
//! High-performance tunnel client using OxTunnel protocol.
//!
//! ## Transport Layer
//! - **Linux**: AF_XDP/FLASH kernel bypass for maximum performance
//! - **Other platforms**: Optimized UDP with batching

#![allow(dead_code)]

use anyhow::{Context, Result};
use oxidize_common::auth::ClientAuthConfig;
use oxidize_common::compression::compress_data;
use oxidize_common::oxtunnel_client::ResponseInjector;
use oxidize_common::oxtunnel_protocol::{
    control, decode_packet, encode_packet, flags, generate_id, AuthenticatedHandshakeInit,
    CryptoEngine, HandshakeInit, HandshakeResponse, HEADER_SIZE, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE,
    PROTOCOL_MAGIC,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
use oxidize_common::af_xdp::XdpConfig;

/// Transport mode for tunnel connection
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// UDP only (default, fastest)
    Udp,
    /// TCP fallback for restrictive networks
    Tcp,
    /// Auto-detect: try UDP first, fall back to TCP if blocked
    #[default]
    Auto,
}

/// Client configuration
#[derive(Clone)]
pub struct ClientConfig {
    /// Server address for UDP (default port 51820)
    pub server_addr: SocketAddr,
    /// TCP fallback server address (default port 51821)
    pub tcp_fallback_addr: Option<SocketAddr>,
    /// Transport mode selection
    pub transport_mode: TransportMode,
    pub enable_encryption: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub enable_compression: bool,
    pub keepalive_interval: Duration,
    pub connection_timeout: Duration,
    /// Network interface for AF_XDP (Linux only, requires root)
    #[cfg(target_os = "linux")]
    pub xdp_interface: Option<String>,
    /// Authentication configuration (None = unauthenticated mode)
    pub auth_config: Option<ClientAuthConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let server_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        Self {
            server_addr,
            // TCP fallback on port 51821 (same host)
            tcp_fallback_addr: Some(SocketAddr::new(server_addr.ip(), 51821)),
            transport_mode: TransportMode::Auto,
            enable_encryption: true,
            encryption_key: None,
            enable_compression: true,
            keepalive_interval: Duration::from_secs(25),
            connection_timeout: Duration::from_secs(30),
            #[cfg(target_os = "linux")]
            xdp_interface: None, // Auto-detect or use UDP fallback
            auth_config: None, // Unauthenticated by default
        }
    }
}

/// Client statistics
#[derive(Debug, Default)]
pub struct ClientStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub handshakes_completed: AtomicU64,
    // ML/optimization metrics
    pub compression_saved: AtomicU64,
    pub fec_recovered: AtomicU64,
    pub fec_sent: AtomicU64,
    pub loss_predictions: AtomicU64,
    pub congestion_adjustments: AtomicU64,
    pub path_switches: AtomicU64,
    // UDP tunnel latency (measured via keepalive RTT, in microseconds)
    pub tunnel_latency_us: AtomicU64,
    // Oversized packet handling
    pub oversized_packets: AtomicU64,
    pub oversized_packets_fragmented: AtomicU64,
    pub oversized_packets_dropped: AtomicU64,
    pub oversized_fragments_sent: AtomicU64,
}

impl ClientStats {
    pub fn new() -> Self {
        Self::default()
    }
}

/// OxTunnel relay client
pub struct RelayClient {
    config: ClientConfig,
    socket: Arc<UdpSocket>,
    client_id: [u8; 32],
    crypto: Arc<RwLock<Option<CryptoEngine>>>,
    stats: Arc<ClientStats>,
    connected: Arc<AtomicBool>,
    sequence: AtomicU32,
    /// Timestamp (in microseconds) when last keepalive was sent, for RTT measurement
    keepalive_sent_us: Arc<AtomicU64>,
}

impl RelayClient {
    /// Create a new OxTunnel client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Bind to appropriate address based on server address type (IPv4 or IPv6)
        let bind_addr = if config.server_addr.is_ipv6() {
            "[::]:0" // IPv6 any address
        } else {
            "0.0.0.0:0" // IPv4 any address
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(&config.server_addr).await?;

        let client_id = generate_id();

        let addr_type = if config.server_addr.is_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        };
        info!(
            "🌐 OxTunnel client created ({} mode), server: {}",
            addr_type, config.server_addr
        );

        if let Some(ref tcp_addr) = config.tcp_fallback_addr {
            info!("🔄 TCP fallback available: {}", tcp_addr);
        }

        Ok(Self {
            config,
            socket: Arc::new(socket),
            client_id,
            crypto: Arc::new(RwLock::new(None)),
            stats: Arc::new(ClientStats::new()),
            connected: Arc::new(AtomicBool::new(false)),
            sequence: AtomicU32::new(0),
            keepalive_sent_us: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Connect to the server (perform handshake)
    /// Uses authenticated handshake if auth_config is set, otherwise legacy handshake
    pub async fn connect(&self) -> Result<()> {
        info!("Connecting to OxTunnel server...");

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build handshake packet - authenticated or legacy
        let mut packet_buf = [0u8; MAX_PACKET_SIZE];
        let packet_len = if let Some(ref auth_config) = self.config.auth_config {
            // Authenticated handshake
            info!("Using authenticated handshake");
            let auth_payload =
                oxidize_common::auth::AuthPayload::create(self.client_id, auth_config);

            let handshake = AuthenticatedHandshakeInit {
                client_id: self.client_id,
                timestamp,
                encryption_supported: self.config.enable_encryption,
                app_signature: auth_payload.app_signature,
                api_key: auth_payload.api_key,
                api_signature: auth_payload.api_signature,
            };

            let mut payload_buf = [0u8; AuthenticatedHandshakeInit::ENCODED_SIZE + 16];
            let payload_len = handshake.encode(&mut payload_buf);

            encode_packet(
                &mut packet_buf,
                &payload_buf[..payload_len],
                0,
                flags::CONTROL,
                None,
            )
            .map_err(|e| anyhow::anyhow!("Failed to encode authenticated handshake: {}", e))?
        } else {
            // Legacy unauthenticated handshake
            let handshake = HandshakeInit {
                client_id: self.client_id,
                timestamp,
                encryption_supported: self.config.enable_encryption,
            };

            let mut payload_buf = [0u8; 64];
            let payload_len = handshake.encode(&mut payload_buf);

            encode_packet(
                &mut packet_buf,
                &payload_buf[..payload_len],
                0,
                flags::CONTROL,
                None,
            )
            .map_err(|e| anyhow::anyhow!("Failed to encode handshake: {}", e))?
        };

        // Send handshake
        self.socket.send(&packet_buf[..packet_len]).await?;
        debug!("Sent handshake init ({} bytes)", packet_len);

        // Wait for response
        let mut response_buf = [0u8; 256];
        let recv_len = tokio::time::timeout(self.config.connection_timeout, async {
            self.socket.recv(&mut response_buf).await
        })
        .await
        .context("Handshake timeout")?
        .context("Failed to receive handshake response")?;

        // Decode OxTunnel packet first
        let (_header, payload) = decode_packet(&mut response_buf[..recv_len], None)
            .map_err(|e| anyhow::anyhow!("Failed to decode response packet: {}", e))?;

        // Check for auth rejection
        if !payload.is_empty() && payload[0] == control::AUTH_REJECTED {
            return Err(anyhow::anyhow!("Authentication rejected by server"));
        }

        // Parse handshake response from payload
        let response = HandshakeResponse::decode(payload)
            .ok_or_else(|| anyhow::anyhow!("Invalid handshake response"))?;

        // Store encryption key if provided
        if let Some(ref key) = response.encryption_key {
            let crypto = CryptoEngine::new(Some(key));
            let mut crypto_guard = self.crypto.write().await;
            *crypto_guard = Some(crypto);
        }

        self.connected.store(true, Ordering::SeqCst);
        self.stats
            .handshakes_completed
            .fetch_add(1, Ordering::Relaxed);

        info!(
            "✅ Connected to OxTunnel server (assigned IP: {})",
            response.assigned_ip
        );

        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Send a packet through the tunnel
    pub async fn send_packet(&self, data: &[u8]) -> Result<()> {
        if !self.is_connected() {
            anyhow::bail!("Not connected");
        }

        if data.len() > MAX_PAYLOAD_SIZE {
            return self.handle_oversized_packet(data).await;
        }

        self.send_encoded_packet(data).await
    }

    async fn handle_oversized_packet(&self, data: &[u8]) -> Result<()> {
        self.stats.oversized_packets.fetch_add(1, Ordering::Relaxed);

        match Self::fragment_ipv4_packet(data, MAX_PAYLOAD_SIZE) {
            Ok(fragments) => {
                self.stats
                    .oversized_packets_fragmented
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .oversized_fragments_sent
                    .fetch_add(fragments.len() as u64, Ordering::Relaxed);

                debug!(
                    "Fragmented oversized IPv4 packet ({} bytes) into {} fragments",
                    data.len(),
                    fragments.len()
                );

                for fragment in fragments {
                    self.send_encoded_packet(&fragment).await?;
                }
            }
            Err(err) => {
                self.stats
                    .oversized_packets_dropped
                    .fetch_add(1, Ordering::Relaxed);
                debug!("Dropping oversized packet: {}", err);
            }
        }

        Ok(())
    }

    async fn send_encoded_packet(&self, data: &[u8]) -> Result<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let original_size = data.len();

        // Encode packet with OxTunnel framing
        let mut packet_flags = 0u8;
        if self.config.enable_encryption {
            packet_flags |= flags::ENCRYPTED;
        }

        // Compress data if enabled and worthwhile (min 64 bytes to avoid overhead)
        let (payload, compressed) = if self.config.enable_compression && original_size >= 64 {
            match compress_data(data) {
                Ok(compressed_data) if compressed_data.len() < original_size => {
                    packet_flags |= flags::COMPRESSED;
                    (compressed_data, true)
                }
                _ => (data.to_vec(), false),
            }
        } else {
            (data.to_vec(), false)
        };

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let crypto = self.crypto.read().await;

        let len = encode_packet(&mut buf, &payload, seq, packet_flags, crypto.as_ref())
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        self.socket.send(&buf[..len]).await?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);

        // Track compression savings
        if compressed {
            let saved = original_size.saturating_sub(payload.len()) as u64;
            self.stats
                .compression_saved
                .fetch_add(saved, Ordering::Relaxed);
        }

        Ok(())
    }

    fn fragment_ipv4_packet(
        packet: &[u8],
        max_packet_len: usize,
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        if packet.len() < 20 {
            return Err("IPv4 packet too short");
        }

        let version = packet[0] >> 4;
        if version != 4 {
            return Err("Not an IPv4 packet");
        }

        let header_len = ((packet[0] & 0x0F) as usize) * 4;
        if header_len < 20 || packet.len() < header_len {
            return Err("Invalid IPv4 header length");
        }

        let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
        let existing_offset = flags_fragment & 0x1FFF;
        let more_fragments = (flags_fragment & 0x2000) != 0;
        let dont_fragment = (flags_fragment & 0x4000) != 0;
        if existing_offset != 0 || more_fragments {
            return Err("IPv4 packet already fragmented");
        }
        if dont_fragment {
            return Err("IPv4 DF flag set");
        }

        if max_packet_len <= header_len {
            return Err("Max packet length too small for IPv4 header");
        }

        let max_fragment_payload = (max_packet_len - header_len) & !7;
        if max_fragment_payload == 0 {
            return Err("Max fragment payload too small");
        }

        let declared_total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if declared_total < header_len {
            return Err("Invalid IPv4 total length");
        }
        let total_len = declared_total.min(packet.len());
        let payload = &packet[header_len..total_len];
        if payload.is_empty() {
            return Err("IPv4 payload empty");
        }

        let mut fragments = Vec::new();
        let mut offset = 0usize;

        while offset < payload.len() {
            let remaining = payload.len() - offset;
            let frag_payload_len = remaining.min(max_fragment_payload);
            let more = offset + frag_payload_len < payload.len();

            let mut fragment = Vec::with_capacity(header_len + frag_payload_len);
            fragment.extend_from_slice(&packet[..header_len]);

            let total_len = (header_len + frag_payload_len) as u16;
            fragment[2..4].copy_from_slice(&total_len.to_be_bytes());

            let frag_offset = (offset / 8) as u16;
            let mut flags = 0u16;
            if more {
                flags |= 0x2000; // More Fragments
            }
            let frag_field = flags | frag_offset;
            fragment[6..8].copy_from_slice(&frag_field.to_be_bytes());

            fragment[10] = 0;
            fragment[11] = 0;
            let checksum = Self::ipv4_checksum(&fragment[..header_len]);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());

            fragment.extend_from_slice(&payload[offset..offset + frag_payload_len]);
            fragments.push(fragment);

            offset += frag_payload_len;
        }

        Ok(fragments)
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i + 1 < header.len() {
            let word = u16::from_be_bytes([header[i], header[i + 1]]) as u32;
            sum += word;
            i += 2;
        }

        if i < header.len() {
            sum += (header[i] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Send a keepalive packet and record timestamp for RTT measurement
    pub async fn send_keepalive(&self) -> Result<()> {
        if !self.is_connected() {
            return Ok(());
        }

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut buf = [0u8; 64];

        // OxTunnel header: magic(2) + flags(1) + seqnum(4) + length(2) = 9 bytes
        buf[0..2].copy_from_slice(&PROTOCOL_MAGIC);
        buf[2] = flags::CONTROL; // Control message
        buf[3..7].copy_from_slice(&seq.to_le_bytes());
        buf[7..9].copy_from_slice(&1u16.to_le_bytes()); // Payload length = 1

        // Payload: just the keepalive control byte
        buf[HEADER_SIZE] = control::KEEPALIVE;

        let packet_len = HEADER_SIZE + 1;

        // Record send timestamp for RTT measurement
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        self.keepalive_sent_us.store(now_us, Ordering::Relaxed);

        self.socket.send(&buf[..packet_len]).await?;
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(packet_len as u64, Ordering::Relaxed);

        debug!("Sent keepalive (seq={})", seq);
        Ok(())
    }

    /// Process incoming packet and check for keepalive ACK to measure RTT
    fn process_control_packet(&self, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }

        if payload[0] == control::ACK {
            // Only use ACK for RTT measurement (not server-initiated KEEPALIVE)
            let sent_us = self.keepalive_sent_us.load(Ordering::Relaxed);
            if sent_us > 0 {
                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;

                if now_us > sent_us {
                    let rtt_us = now_us - sent_us;
                    // Use exponential moving average for smoother latency
                    let prev = self.stats.tunnel_latency_us.load(Ordering::Relaxed);
                    let smoothed = if prev == 0 {
                        rtt_us
                    } else {
                        (prev * 7 + rtt_us) / 8 // EMA with alpha=0.125
                    };
                    self.stats
                        .tunnel_latency_us
                        .store(smoothed, Ordering::Relaxed);
                    debug!("Keepalive RTT: {}us (smoothed: {}us)", rtt_us, smoothed);
                }
                // Reset sent timestamp
                self.keepalive_sent_us.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Receive a packet from the tunnel
    pub async fn recv_packet(&self) -> Result<Vec<u8>> {
        if !self.is_connected() {
            anyhow::bail!("Not connected");
        }

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let len = self.socket.recv(&mut buf).await?;

        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(len as u64, Ordering::Relaxed);

        let crypto = self.crypto.read().await;
        let (_header, payload) = decode_packet(&mut buf[..len], crypto.as_ref())
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        Ok(payload.to_vec())
    }

    /// Run the client with a packet capture receiver
    pub async fn run_with_capture(&self, mut capture_rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
        info!("Starting OxTunnel client loop...");

        let socket = self.socket.clone();
        let stats = self.stats.clone();
        let connected = self.connected.clone();
        let keepalive_sent_us = self.keepalive_sent_us.clone();

        // Spawn receive task with control packet processing for RTT measurement
        let recv_socket = socket.clone();
        let recv_connected = connected.clone();
        let recv_stats = stats.clone();
        let recv_keepalive_sent_us = keepalive_sent_us.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            while recv_connected.load(Ordering::SeqCst) {
                match recv_socket.recv(&mut buf).await {
                    Ok(len) => {
                        recv_stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        recv_stats
                            .bytes_received
                            .fetch_add(len as u64, Ordering::Relaxed);

                        // Check if this is a control packet (for RTT measurement)
                        // Header: magic(2) + flags(1) + seqnum(4) + length(2) = 9 bytes
                        if len >= HEADER_SIZE && buf[0..2] == PROTOCOL_MAGIC {
                            let flags_byte = buf[2];
                            if flags_byte & flags::CONTROL != 0 && len > HEADER_SIZE {
                                let control_type = buf[HEADER_SIZE];
                                // Only use ACK for RTT measurement, NOT server-initiated KEEPALIVE
                                // Server sends proactive KEEPALIVE packets which are unrelated to
                                // client keepalives and would cause incorrect RTT calculations
                                if control_type == control::ACK {
                                    // Measure RTT from keepalive ACK response
                                    let sent_us = recv_keepalive_sent_us.load(Ordering::Relaxed);
                                    if sent_us > 0 {
                                        let now_us = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_micros()
                                            as u64;

                                        if now_us > sent_us {
                                            let rtt_us = now_us - sent_us;
                                            // Exponential moving average for smoother latency
                                            let prev = recv_stats
                                                .tunnel_latency_us
                                                .load(Ordering::Relaxed);
                                            let smoothed = if prev == 0 {
                                                rtt_us
                                            } else {
                                                (prev * 7 + rtt_us) / 8
                                            };
                                            recv_stats
                                                .tunnel_latency_us
                                                .store(smoothed, Ordering::Relaxed);
                                            debug!(
                                                "Keepalive RTT: {}us (smoothed: {}us, {}ms)",
                                                rtt_us,
                                                smoothed,
                                                smoothed / 1000
                                            );
                                        }
                                        recv_keepalive_sent_us.store(0, Ordering::Relaxed);
                                    }
                                }
                            }
                        }

                        debug!("Received {} bytes from server", len);
                    }
                    Err(e) => {
                        warn!("Receive error: {}", e);
                    }
                }
            }
        });

        // Spawn keepalive task - sends keepalive every interval for RTT measurement
        let ka_socket = socket.clone();
        let ka_connected = connected.clone();
        let ka_stats = stats.clone();
        let ka_keepalive_sent_us = keepalive_sent_us.clone();
        let ka_sequence = Arc::new(AtomicU32::new(1000000)); // Separate sequence space
        let keepalive_interval = self.config.keepalive_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            interval.tick().await; // Skip first immediate tick

            while ka_connected.load(Ordering::SeqCst) {
                interval.tick().await;

                if !ka_connected.load(Ordering::SeqCst) {
                    break;
                }

                // Build keepalive control packet
                // Header format: magic(2) + flags(1) + seqnum(4) + length(2) = 9 bytes
                let seq = ka_sequence.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0u8; 64];

                buf[0..2].copy_from_slice(&PROTOCOL_MAGIC);
                buf[2] = flags::CONTROL;
                buf[3..7].copy_from_slice(&seq.to_le_bytes());
                buf[7..9].copy_from_slice(&1u16.to_le_bytes()); // Payload length = 1
                buf[HEADER_SIZE] = control::KEEPALIVE;

                let packet_len = HEADER_SIZE + 1;

                // Record send timestamp
                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;
                ka_keepalive_sent_us.store(now_us, Ordering::Relaxed);

                match ka_socket.send(&buf[..packet_len]).await {
                    Ok(_) => {
                        ka_stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                        ka_stats
                            .bytes_sent
                            .fetch_add(packet_len as u64, Ordering::Relaxed);
                        debug!("Sent keepalive (seq={})", seq);
                    }
                    Err(e) => {
                        warn!("Failed to send keepalive: {}", e);
                    }
                }
            }
        });

        // Main send loop - also handles case where capture fails
        loop {
            tokio::select! {
                packet = capture_rx.recv() => {
                    match packet {
                        Some(data) => {
                            if let Err(e) = self.send_packet(&data).await {
                                warn!("Failed to send packet: {}", e);
                            }
                        }
                        None => {
                            // Capture channel closed - but keep running for keepalives
                            info!("Capture channel closed, continuing with keepalive only mode");
                            // Wait until disconnected
                            while self.connected.load(Ordering::SeqCst) {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            break;
                        }
                    }
                }
                _ = async {
                    while self.connected.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => {
                    info!("Disconnect requested");
                    break;
                }
            }
        }

        self.connected.store(false, Ordering::SeqCst);
        info!("Client loop ended");

        Ok(())
    }

    /// Run the client with packet capture AND response injection
    /// This is the full tunnel mode - captures outbound packets, sends through tunnel,
    /// receives responses from tunnel, and injects them into the local network stack
    pub async fn run_with_injection(
        &self,
        mut capture_rx: mpsc::Receiver<Vec<u8>>,
        response_injector: Arc<ResponseInjector>,
    ) -> Result<()> {
        info!("Starting OxTunnel client loop with response injection...");

        let socket = self.socket.clone();
        let stats = self.stats.clone();
        let connected = self.connected.clone();
        let keepalive_sent_us = self.keepalive_sent_us.clone();
        let crypto = self.crypto.clone();

        // Spawn receive task with response injection
        let recv_socket = socket.clone();
        let recv_connected = connected.clone();
        let recv_stats = stats.clone();
        let recv_keepalive_sent_us = keepalive_sent_us.clone();
        let recv_crypto = crypto.clone();
        let recv_injector = response_injector.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let mut injected_count: u64 = 0;
            let mut last_log = std::time::Instant::now();

            while recv_connected.load(Ordering::SeqCst) {
                match recv_socket.recv(&mut buf).await {
                    Ok(len) => {
                        recv_stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        recv_stats
                            .bytes_received
                            .fetch_add(len as u64, Ordering::Relaxed);

                        // Validate and decode packet
                        if len >= HEADER_SIZE && buf[0..2] == PROTOCOL_MAGIC {
                            let flags_byte = buf[2];

                            // Handle control packets (keepalive ACK, etc.)
                            if flags_byte & flags::CONTROL != 0 && len > HEADER_SIZE {
                                let control_type = buf[HEADER_SIZE];
                                if control_type == control::ACK {
                                    // Measure RTT from keepalive ACK response
                                    let sent_us = recv_keepalive_sent_us.load(Ordering::Relaxed);
                                    if sent_us > 0 {
                                        let now_us = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_micros()
                                            as u64;

                                        if now_us > sent_us {
                                            let rtt_us = now_us - sent_us;
                                            let prev = recv_stats
                                                .tunnel_latency_us
                                                .load(Ordering::Relaxed);
                                            let smoothed = if prev == 0 {
                                                rtt_us
                                            } else {
                                                (prev * 7 + rtt_us) / 8
                                            };
                                            recv_stats
                                                .tunnel_latency_us
                                                .store(smoothed, Ordering::Relaxed);
                                            debug!(
                                                "Keepalive RTT: {}us (smoothed: {}us)",
                                                rtt_us, smoothed
                                            );
                                        }
                                        recv_keepalive_sent_us.store(0, Ordering::Relaxed);
                                    }
                                }
                                continue; // Control packet handled, skip injection
                            }

                            // Data packet - decode and inject into local network stack
                            // Use try_read to avoid blocking the async runtime
                            let crypto_opt = recv_crypto.try_read().ok();
                            let crypto_ref = crypto_opt.as_ref().and_then(|g| g.as_ref());
                            match decode_packet(&mut buf[..len], crypto_ref) {
                                Ok((_header, payload)) => {
                                    if !payload.is_empty() {
                                        // Inject the IP packet into local network stack
                                        match recv_injector.inject(payload) {
                                            Ok(()) => {
                                                injected_count += 1;

                                                // Log periodically
                                                if last_log.elapsed().as_secs() >= 10 {
                                                    let injector_stats = recv_injector.stats();
                                                    info!(
                                                        "📥 Injected {} packets ({} total, {} errors)",
                                                        injected_count,
                                                        injector_stats.packets_injected.load(Ordering::Relaxed),
                                                        injector_stats.injection_errors.load(Ordering::Relaxed)
                                                    );
                                                    last_log = std::time::Instant::now();
                                                }
                                            }
                                            Err(e) => {
                                                debug!("Failed to inject packet: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to decode packet: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Receive error: {}", e);
                    }
                }
            }

            let injector_stats = recv_injector.stats();
            info!(
                "📥 Response injection stopped: {} packets injected, {} errors",
                injector_stats.packets_injected.load(Ordering::Relaxed),
                injector_stats.injection_errors.load(Ordering::Relaxed)
            );
        });

        // Spawn keepalive task
        let ka_socket = socket.clone();
        let ka_connected = connected.clone();
        let ka_stats = stats.clone();
        let ka_keepalive_sent_us = keepalive_sent_us.clone();
        let ka_sequence = Arc::new(AtomicU32::new(1000000));
        let keepalive_interval = self.config.keepalive_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            interval.tick().await;

            while ka_connected.load(Ordering::SeqCst) {
                interval.tick().await;

                if !ka_connected.load(Ordering::SeqCst) {
                    break;
                }

                let seq = ka_sequence.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0u8; 64];

                buf[0..2].copy_from_slice(&PROTOCOL_MAGIC);
                buf[2] = flags::CONTROL;
                buf[3..7].copy_from_slice(&seq.to_le_bytes());
                buf[7..9].copy_from_slice(&1u16.to_le_bytes());
                buf[HEADER_SIZE] = control::KEEPALIVE;

                let packet_len = HEADER_SIZE + 1;

                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;
                ka_keepalive_sent_us.store(now_us, Ordering::Relaxed);

                match ka_socket.send(&buf[..packet_len]).await {
                    Ok(_) => {
                        ka_stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                        ka_stats
                            .bytes_sent
                            .fetch_add(packet_len as u64, Ordering::Relaxed);
                        debug!("Sent keepalive (seq={})", seq);
                    }
                    Err(e) => {
                        warn!("Failed to send keepalive: {}", e);
                    }
                }
            }
        });

        // Main send loop
        loop {
            tokio::select! {
                packet = capture_rx.recv() => {
                    match packet {
                        Some(data) => {
                            if let Err(e) = self.send_packet(&data).await {
                                warn!("Failed to send packet: {}", e);
                            }
                        }
                        None => {
                            info!("Capture channel closed, continuing with keepalive only mode");
                            while self.connected.load(Ordering::SeqCst) {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            break;
                        }
                    }
                }
                _ = async {
                    while self.connected.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => {
                    info!("Disconnect requested");
                    break;
                }
            }
        }

        self.connected.store(false, Ordering::SeqCst);
        info!("Client loop ended");

        Ok(())
    }

    /// Get client statistics
    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    /// Get shared stats handle for external monitoring
    pub fn stats_handle(&self) -> Arc<ClientStats> {
        Arc::clone(&self.stats)
    }

    /// Disconnect from server - sends DISCONNECT message to server
    pub async fn disconnect(&self) {
        if !self.connected.load(Ordering::SeqCst) {
            return;
        }

        // Send DISCONNECT control packet to server so it can clean up session
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut buf = [0u8; 64];

        buf[0..2].copy_from_slice(&PROTOCOL_MAGIC);
        buf[2] = flags::CONTROL;
        buf[3..7].copy_from_slice(&seq.to_le_bytes());
        buf[7..9].copy_from_slice(&1u16.to_le_bytes()); // Payload length = 1
        buf[HEADER_SIZE] = control::DISCONNECT;

        let packet_len = HEADER_SIZE + 1;

        // Best effort - don't fail if send fails
        if let Err(e) = self.socket.send(&buf[..packet_len]).await {
            warn!("Failed to send disconnect packet: {}", e);
        } else {
            debug!("Sent DISCONNECT to server");
        }

        self.connected.store(false, Ordering::SeqCst);
        info!("Disconnected from OxTunnel server");
    }
}
