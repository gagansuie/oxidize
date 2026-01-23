//! OxTunnel Client
//!
//! High-performance tunnel client using the OxTunnel protocol over raw UDP.
//! Replaces the previous QUIC-based implementation with a lighter-weight transport.

use anyhow::{Context, Result};
use oxidize_common::oxtunnel_protocol::{
    decode_packet, encode_packet, flags, generate_id, CryptoEngine, HandshakeInit,
    HandshakeResponse, MAX_PACKET_SIZE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Client configuration
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub enable_encryption: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub enable_compression: bool,
    pub keepalive_interval: Duration,
    pub connection_timeout: Duration,
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
        })
    }

    /// Connect to the server (perform handshake)
    pub async fn connect(&self) -> Result<()> {
        info!("Connecting to OxTunnel server...");

        // Build handshake init packet
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let handshake = HandshakeInit {
            client_id: self.client_id,
            timestamp,
            encryption_supported: self.config.enable_encryption,
        };

        let mut buf = [0u8; 128];
        let len = handshake.encode(&mut buf);

        // Send handshake
        self.socket.send(&buf[..len]).await?;
        debug!("Sent handshake init");

        // Wait for response
        let mut response_buf = [0u8; 256];
        let recv_len = tokio::time::timeout(self.config.connection_timeout, async {
            self.socket.recv(&mut response_buf).await
        })
        .await
        .context("Handshake timeout")?
        .context("Failed to receive handshake response")?;

        // Parse response
        let response = HandshakeResponse::decode(&response_buf[..recv_len])
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

        // Spawn receive task
        let recv_socket = socket.clone();
        let recv_connected = connected.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            while recv_connected.load(Ordering::SeqCst) {
                match recv_socket.recv(&mut buf).await {
                    Ok(len) => {
                        stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        stats
                            .bytes_received
                            .fetch_add(len as u64, Ordering::Relaxed);
                        // TODO: Forward received packets to TUN/TAP or NFQUEUE
                        debug!("Received {} bytes from server", len);
                    }
                    Err(e) => {
                        warn!("Receive error: {}", e);
                    }
                }
            }
        });

        // Main send loop
        while let Some(packet) = capture_rx.recv().await {
            if let Err(e) = self.send_packet(&packet).await {
                warn!("Failed to send packet: {}", e);
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

    /// Disconnect from server
    pub async fn disconnect(&self) {
        self.connected.store(false, Ordering::SeqCst);
        info!("Disconnected from OxTunnel server");
    }
}
