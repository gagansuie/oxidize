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
use oxidize_common::oxtunnel_protocol::{
    control, decode_packet, encode_packet, flags, generate_id, AuthenticatedHandshakeInit,
    CryptoEngine, HandshakeInit, HandshakeResponse, HEADER_SIZE, MAX_PACKET_SIZE, PROTOCOL_MAGIC,
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

/// Client configuration
#[derive(Clone)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
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
        Self {
            server_addr: "127.0.0.1:4433".parse().unwrap(),
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
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&config.server_addr).await?;

        let client_id = generate_id();

        info!("OxTunnel client created, server: {}", config.server_addr);

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

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        // Encode packet with OxTunnel framing
        let mut packet_flags = 0u8;
        if self.config.enable_encryption {
            packet_flags |= flags::ENCRYPTED;
        }
        if self.config.enable_compression {
            packet_flags |= flags::COMPRESSED;
        }

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let crypto = self.crypto.read().await;

        let len = encode_packet(&mut buf, data, seq, packet_flags, crypto.as_ref())
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        self.socket.send(&buf[..len]).await?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Send a keepalive packet and record timestamp for RTT measurement
    pub async fn send_keepalive(&self) -> Result<()> {
        if !self.is_connected() {
            return Ok(());
        }

        // Build keepalive control packet with OxTunnel framing
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

        match payload[0] {
            control::ACK | control::KEEPALIVE => {
                // Measure RTT from keepalive response
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
            _ => {}
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
                                if control_type == control::ACK
                                    || control_type == control::KEEPALIVE
                                {
                                    // Measure RTT from keepalive response
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

    /// Get client statistics
    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    /// Get shared stats handle for external monitoring
    pub fn stats_handle(&self) -> Arc<ClientStats> {
        Arc::clone(&self.stats)
    }

    /// Disconnect from server
    pub async fn disconnect(&self) {
        self.connected.store(false, Ordering::SeqCst);
        info!("Disconnected from OxTunnel server");
    }
}
