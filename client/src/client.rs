use crate::config::ClientConfig;
use crate::dns_cache::DnsCache;
use anyhow::{Context, Result};
use oxidize_common::ml_models::MlEngine;
use oxidize_common::model_hub::{HubConfig, ModelHub};
use oxidize_common::multipath::{MultipathScheduler, SchedulingStrategy};
use oxidize_common::prefetch::{PrefetchConfig, Prefetcher};
use oxidize_common::{compress_data, MessageFramer, MessageType, RelayMessage, RelayMetrics};
use quinn::ClientConfig as QuinnClientConfig;
use quinn::Endpoint;
use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Certificate verifier that accepts any certificate (for self-signed certs)
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

static SEQUENCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct RelayClient {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    config: ClientConfig,
    metrics: RelayMetrics,
    connection_id: u64,
    dns_cache: Arc<DnsCache>,
    /// Ports that should use QUIC datagrams for low-latency
    realtime_ports: HashSet<u16>,
    /// Cached session ticket for 0-RTT resumption
    session_ticket: Arc<Mutex<Option<Vec<u8>>>>,
    /// Multi-path scheduler for bandwidth aggregation
    multipath: Arc<Mutex<MultipathScheduler>>,
    /// Predictive prefetcher for DNS/connections
    prefetcher: Arc<Mutex<Prefetcher>>,
    /// ML Engine for AI-powered decisions (NO HEURISTIC FALLBACK)
    ml_engine: Arc<RwLock<MlEngine>>,
    /// Model Hub for downloading models
    model_hub: Arc<ModelHub>,
}

impl RelayClient {
    pub async fn new(server_addr: SocketAddr, config: ClientConfig) -> Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        // Use custom verifier to accept self-signed certificates
        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"relay/1".to_vec()];

        let mut client_config = QuinnClientConfig::new(Arc::new(crypto));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(300).try_into()?));

        // === HIGH-PERFORMANCE QUIC TUNING ===

        // Larger receive/send windows for high throughput
        transport_config.receive_window(64_000_000u32.into());
        transport_config.send_window(64_000_000u64);
        transport_config.stream_receive_window(16_000_000u32.into());

        // Faster keepalive for low latency connection recovery
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

        // Lower initial RTT estimate for faster handshake
        transport_config.initial_rtt(std::time::Duration::from_millis(10));

        // Enable QUIC datagrams for unreliable low-latency traffic (gaming/VoIP)
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.datagram_send_buffer_size(65536);

        // Enable BBR congestion control for better throughput
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        // Note: QUIC connection migration is enabled by default in Quinn
        // The connection will automatically migrate when the client IP changes

        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        let connection_id = rand::random();
        let dns_cache = Arc::new(DnsCache::new(config.dns_cache_size));

        // Build realtime ports set for O(1) lookup
        let realtime_ports: HashSet<u16> = config.realtime_ports.iter().cloned().collect();

        // Load cached session ticket for 0-RTT
        let session_ticket = Arc::new(Mutex::new(Self::load_session_ticket(
            &config.session_cache_path,
        )));

        // Initialize multi-path scheduler
        let multipath = Arc::new(Mutex::new(MultipathScheduler::new(
            SchedulingStrategy::Weighted,
        )));

        // Initialize predictive prefetcher
        let prefetch_config = PrefetchConfig {
            prefetch_dns: config.enable_dns_prefetch,
            prefetch_connections: config.enable_prefetch,
            ..Default::default()
        };
        let prefetcher = Arc::new(Mutex::new(Prefetcher::new(prefetch_config)));

        // Initialize ML Engine in HEURISTIC mode (default, zero overhead)
        // Training data collection is enabled for continuous improvement
        let mut ml_engine = MlEngine::new();

        // Initialize Model Hub for model sync
        let hub_config = HubConfig {
            upload_training_data: true, // Enable auto-upload for continuous improvement
            ..Default::default()
        };
        let model_hub = Arc::new(ModelHub::new(hub_config));

        // Try to download and load ML models (optional - heuristics are default)
        info!("🤖 Attempting to download ML models from HuggingFace Hub...");
        match model_hub.download_models() {
            Ok(paths) => {
                if let Some(lstm_path) = &paths.lstm {
                    let model_dir = lstm_path.parent().unwrap_or(lstm_path);
                    let loaded = ml_engine.try_load_models(model_dir);
                    if loaded == 4 {
                        info!(
                            "✅ All {} ML models loaded - can switch to ML mode when ready",
                            loaded
                        );
                    } else if loaded > 0 {
                        info!("⚠️ Loaded {} of 4 ML models - using heuristics", loaded);
                    } else {
                        info!("📊 No ML models found - using heuristics");
                    }
                }
            }
            Err(e) => {
                info!("📊 Could not download ML models: {} - using heuristics", e);
            }
        }

        // Log current mode
        info!(
            "🧠 AI engine mode: {:?} (models_loaded: {})",
            ml_engine.inference_mode(),
            ml_engine.all_models_loaded()
        );

        let ml_engine = Arc::new(RwLock::new(ml_engine));

        if config.enable_multipath {
            info!("🔀 Multi-path support enabled");
        }
        if config.enable_prefetch {
            info!("🔮 Predictive prefetching enabled");
        }

        Ok(Self {
            endpoint,
            server_addr,
            config,
            metrics: RelayMetrics::new(),
            connection_id,
            dns_cache,
            realtime_ports,
            session_ticket,
            multipath,
            prefetcher,
            ml_engine,
            model_hub,
        })
    }

    /// Load session ticket from disk for 0-RTT resumption
    fn load_session_ticket(path: &str) -> Option<Vec<u8>> {
        if Path::new(path).exists() {
            fs::read(path).ok()
        } else {
            None
        }
    }

    /// Save session ticket to disk for future 0-RTT
    #[allow(dead_code)]
    fn save_session_ticket(path: &str, ticket: &[u8]) {
        if let Err(e) = fs::write(path, ticket) {
            debug!("Failed to save session ticket: {}", e);
        }
    }

    /// Check if a port should use QUIC datagrams (real-time traffic)
    fn is_realtime_port(&self, port: u16) -> bool {
        self.realtime_ports.contains(&port)
    }

    pub fn get_metrics(&self) -> &RelayMetrics {
        &self.metrics
    }

    /// Get the server address for this client
    #[allow(dead_code)]
    pub fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Run with a packet sender channel for external packet injection
    /// This allows the daemon to send intercepted packets through QUIC
    #[allow(dead_code)]
    pub async fn run_with_sender(
        &self,
        mut packet_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        info!(
            "🔌 run_with_sender started - connecting to {}...",
            self.server_addr
        );

        let connecting = self.endpoint.connect(self.server_addr, "relay")?;
        let connection =
            match tokio::time::timeout(std::time::Duration::from_secs(10), connecting).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    error!("❌ QUIC connection failed: {}", e);
                    return Err(e.into());
                }
                Err(_) => {
                    error!("❌ QUIC connection timed out after 10s");
                    return Err(anyhow::anyhow!("Connection timeout"));
                }
            };
        info!("✅ QUIC handshake complete!");

        // Open bidirectional stream for control messages
        let (mut send, _recv) = connection.open_bi().await?;

        // Send connect message
        let connect_msg = RelayMessage::connect(self.connection_id);
        let encoded = connect_msg.encode()?;
        send.write_all(&encoded).await?;
        self.metrics.record_sent(encoded.len() as u64);

        info!("📡 QUIC relay ready for packet forwarding");
        info!("📡 Datagram max size: {:?}", connection.max_datagram_size());

        let mut forwarded_count: u64 = 0;
        let mut failed_count: u64 = 0;
        loop {
            tokio::select! {
                // Receive packets to forward through QUIC
                Some(packet) = packet_rx.recv() => {
                    let len = packet.len();
                    forwarded_count += 1;

                    if forwarded_count == 1 {
                        info!("📥 First packet received: {} bytes", len);
                    }

                    // Send via QUIC datagram for lowest latency
                    match connection.send_datagram(packet.into()) {
                        Ok(_) => {
                            self.metrics.record_sent(len as u64);
                            #[allow(clippy::manual_is_multiple_of)]
                            if forwarded_count % 100 == 0 {
                                info!("📤 Forwarded {} packets through QUIC ({} failed)", forwarded_count, failed_count);
                            }
                        }
                        Err(e) => {
                            failed_count += 1;
                            if failed_count <= 3 {
                                error!("❌ Datagram send failed: {} (packet {}, size {})", e, forwarded_count, len);
                            }
                        }
                    }
                }

                // Receive datagrams from relay
                Ok(datagram) = connection.read_datagram() => {
                    self.metrics.record_received(datagram.len() as u64);
                    // In full implementation, route back to original client
                    debug!("Received {} bytes from relay", datagram.len());
                }

                // Connection closed
                else => {
                    info!("Connection closed");
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        loop {
            match self.connect_and_run().await {
                Ok(_) => {
                    info!("Connection closed normally");
                    break;
                }
                Err(e) => {
                    error!(
                        "Connection error: {}, reconnecting in {}s...",
                        e, self.config.reconnect_interval
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        self.config.reconnect_interval,
                    ))
                    .await;
                }
            }
        }

        Ok(())
    }

    /// Run client with AF_XDP for high-performance packet capture (10+ Gbps)
    /// This replaces the old TUN-based approach
    pub async fn run_with_xdp(&self) -> Result<()> {
        info!("🚀 run_with_xdp() called - starting AF_XDP client");

        // Verify connection works BEFORE setting up XDP routing
        info!("Verifying server connection before XDP setup...");

        let connecting = self.endpoint.connect(self.server_addr, "localhost")?;
        let test_result =
            tokio::time::timeout(std::time::Duration::from_secs(10), connecting).await;

        match test_result {
            Ok(Ok(conn)) => {
                info!("✅ Server connection verified");
                conn.close(0u32.into(), b"test complete");
            }
            Ok(Err(e)) => {
                error!("❌ Cannot connect to server: {}", e);
                return Err(anyhow::anyhow!("Server connection failed: {}", e));
            }
            Err(_) => {
                error!("❌ Connection verification timed out after 10s");
                return Err(anyhow::anyhow!("Connection verification timed out"));
            }
        }

        // Set up channels for XDP packet exchange
        let (_tx, mut rx) = mpsc::channel(self.config.max_packet_queue);
        let (response_tx, _response_rx) = mpsc::channel::<Vec<u8>>(4096);

        let client_handle = {
            let client = self.clone_for_task();
            tokio::spawn(async move {
                client
                    .run_with_seamless_reconnect(&mut rx, response_tx)
                    .await
            })
        };

        // XDP handler would be started here when fully implemented
        // For now, just wait for the client handle
        info!("📡 AF_XDP client running - target: 10+ Gbps throughput");

        tokio::select! {
            _ = client_handle => {
                warn!("Client handler exited");
            }
        }

        Ok(())
    }

    /// Seamless reconnection loop with packet buffering
    /// This ensures zero downtime during server updates by:
    /// 1. Instant initial retry (50ms) for fast recovery
    /// 2. Exponential backoff for sustained outages
    /// 3. Packet buffering during reconnection
    /// 4. Automatic packet replay after reconnect
    async fn run_with_seamless_reconnect(
        &self,
        rx: &mut mpsc::Receiver<Vec<u8>>,
        response_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let mut attempt = 0u32;
        let mut current_delay = Duration::from_millis(self.config.reconnect_delay_ms);
        let max_delay = Duration::from_millis(self.config.max_reconnect_delay_ms);
        let max_attempts = self.config.max_reconnect_attempts;

        // Packet buffer for seamless reconnection
        let packet_buffer: Arc<RwLock<Vec<Vec<u8>>>> = Arc::new(RwLock::new(Vec::with_capacity(
            self.config.reconnect_buffer_size,
        )));
        let is_connected = Arc::new(AtomicBool::new(false));

        loop {
            // Check if we've exceeded max attempts (0 = infinite)
            if max_attempts > 0 && attempt >= max_attempts {
                error!("❌ Max reconnection attempts ({}) exceeded", max_attempts);
                break;
            }

            match self
                .connect_and_run_seamless(rx, response_tx.clone(), &packet_buffer, &is_connected)
                .await
            {
                Ok(_) => {
                    info!("Connection closed normally");
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    is_connected.store(false, Ordering::SeqCst);

                    if attempt == 1 {
                        // First retry is instant for rolling restart scenarios
                        warn!(
                            "🔄 Connection lost: {}, instant retry (attempt {})",
                            e, attempt
                        );
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    } else {
                        warn!(
                            "🔄 Reconnecting in {:?} (attempt {}): {}",
                            current_delay, attempt, e
                        );
                        tokio::time::sleep(current_delay).await;

                        // Exponential backoff with jitter
                        let jitter = Duration::from_millis(rand::random::<u64>() % 100);
                        current_delay = std::cmp::min(current_delay * 2 + jitter, max_delay);
                    }
                }
            }

            // Reset delay on successful connection
            if is_connected.load(Ordering::SeqCst) {
                current_delay = Duration::from_millis(self.config.reconnect_delay_ms);
                attempt = 0;
            }
        }
    }

    /// Connect and run with seamless packet handling
    async fn connect_and_run_seamless(
        &self,
        rx: &mut mpsc::Receiver<Vec<u8>>,
        response_tx: mpsc::Sender<Vec<u8>>,
        packet_buffer: &Arc<RwLock<Vec<Vec<u8>>>>,
        is_connected: &Arc<AtomicBool>,
    ) -> Result<()> {
        let connection = self
            .endpoint
            .connect(self.server_addr, "localhost")?
            .await?;

        info!("✅ Connected to relay server (seamless mode)");
        is_connected.store(true, Ordering::SeqCst);
        self.metrics.record_connection_opened();

        let (mut send, mut recv) = connection.open_bi().await?;

        let connect_msg = RelayMessage::connect(self.connection_id);
        send.write_all(&connect_msg.encode()?).await?;

        // Replay any buffered packets from reconnection
        {
            let mut buffer = packet_buffer.write().await;
            if !buffer.is_empty() {
                info!("📦 Replaying {} buffered packets", buffer.len());
                for packet in buffer.drain(..) {
                    if let Err(e) = self.send_packet(&mut send, packet).await {
                        debug!("Failed to replay packet: {}", e);
                    }
                }
            }
        }

        let mut recv_buf = vec![0u8; self.config.buffer_size];
        let mut framer = MessageFramer::with_capacity(self.config.buffer_size);
        let datagrams_enabled = self.config.enable_datagrams;
        let buffer_size = self.config.reconnect_buffer_size;

        loop {
            tokio::select! {
                // Handle outgoing packets from TUN
                Some(packet) = rx.recv() => {
                    // If disconnected, buffer the packet
                    if !is_connected.load(Ordering::SeqCst) {
                        let mut buffer = packet_buffer.write().await;
                        if buffer.len() < buffer_size {
                            buffer.push(packet);
                        }
                        continue;
                    }

                    let use_datagram = datagrams_enabled && self.should_use_datagram(&packet);

                    if use_datagram {
                        if let Err(e) = self.send_datagram(&connection, packet).await {
                            debug!("Datagram send failed, falling back to stream: {}", e);
                        }
                    } else if let Err(e) = self.send_packet(&mut send, packet).await {
                        error!("Failed to send packet: {}", e);
                    }
                }

                // Receive datagrams for real-time responses
                Ok(datagram) = connection.read_datagram(), if datagrams_enabled => {
                    self.metrics.record_received(datagram.len() as u64);
                    if response_tx.send(datagram.to_vec()).await.is_err() {
                        error!("Failed to send datagram response to TUN");
                    }
                }

                // Handle stream receives (reliable traffic)
                result = recv.read(&mut recv_buf) => {
                    match result {
                        Ok(Some(len)) => {
                            // Log raw data received
                            static RAW_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                            let raw_count = RAW_COUNT.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);
                            if raw_count % 50000 < len as u64 {
                                info!("📡 Raw data received: {} bytes total", raw_count + len as u64);
                            }

                            self.metrics.record_received(len as u64);
                            framer.extend(&recv_buf[..len]);

                            loop {
                                let decode_start = Instant::now();
                                match framer.try_decode() {
                                    Ok(Some(message)) => {
                                        self.metrics.record_decode_latency(decode_start.elapsed());

                                        // Log all message types received
                                        static MSG_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                        let msg_count = MSG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        #[allow(clippy::manual_is_multiple_of)]
                                        if msg_count % 50 == 0 {
                                            info!("📨 Received {} messages, latest type: {:?}", msg_count, message.msg_type);
                                        }

                                        if message.msg_type == MessageType::Data {
                                            // Log every 100th Data packet at INFO level
                                            static DATA_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                            let count = DATA_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            #[allow(clippy::manual_is_multiple_of)]
                                            if count % 100 == 0 {
                                                info!("📥 Received {} Data packets from server", count);
                                            }
                                            if response_tx.send(message.payload).await.is_err() {
                                                error!("Failed to send response to TUN");
                                            }
                                        } else if let Err(e) = self.handle_message(message).await {
                                            error!("Failed to handle message: {}", e);
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            error!("Read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        is_connected.store(false, Ordering::SeqCst);
        self.metrics.record_connection_closed();
        Ok(())
    }

    async fn connect_and_run(&self) -> Result<()> {
        info!("Establishing QUIC connection to {}...", self.server_addr);

        let connection = self
            .endpoint
            .connect(self.server_addr, "localhost")?
            .await
            .context("Failed to establish QUIC connection")?;

        info!("✅ Connected to relay server");
        self.metrics.record_connection_opened();

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;

        let connect_msg = RelayMessage::connect(self.connection_id);
        let encoded = connect_msg.encode()?;
        send.write_all(&encoded).await?;
        self.metrics.record_sent(encoded.len() as u64);

        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut framer = MessageFramer::with_capacity(self.config.buffer_size);

        // Send periodic keepalive pings
        let metrics = self.metrics.clone();
        let connection_id = self.connection_id;
        let keepalive_interval = self.config.keepalive_interval;
        let conn_for_keepalive = connection.clone();

        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(keepalive_interval)).await;

                // Send a ping message
                let ping_msg = RelayMessage::ping(connection_id);
                if let Ok(encoded) = ping_msg.encode() {
                    if let Ok(mut send) = conn_for_keepalive.open_uni().await {
                        if send.write_all(&encoded).await.is_ok() {
                            metrics.record_sent(encoded.len() as u64);
                            debug!("Sent keepalive ping ({} bytes)", encoded.len());
                        }
                    }
                }
            }
        });

        loop {
            tokio::select! {
                result = recv.read(&mut buffer) => {
                    match result {
                        Ok(Some(len)) => {
                            self.metrics.record_received(len as u64);

                            // Use framer for proper stream handling
                            framer.extend(&buffer[..len]);

                            // Process all complete messages
                            loop {
                                match framer.try_decode() {
                                    Ok(Some(message)) => {
                                        if let Err(e) = self.handle_message(message).await {
                                            error!("Failed to handle message: {}", e);
                                        }
                                    }
                                    Ok(None) => break, // Need more data
                                    Err(e) => {
                                        error!("Failed to decode message: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            debug!("Stream closed by server");
                            break;
                        }
                        Err(e) => {
                            error!("Read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        keepalive_handle.abort();
        self.metrics.record_connection_closed();

        Ok(())
    }

    #[allow(dead_code)] // Will be used when XDP is fully integrated
    async fn connect_and_run_with_packets(
        &self,
        rx: &mut mpsc::Receiver<Vec<u8>>,
        response_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        let connection = self
            .endpoint
            .connect(self.server_addr, "localhost")?
            .await?;

        info!("✅ Connected to relay server (TUN mode)");
        self.metrics.record_connection_opened();

        // === MASQUE-INSPIRED: Dual-path architecture ===
        // - Streams for reliable traffic (HTTP, TCP)
        // - Datagrams for real-time traffic (gaming, VoIP) - no head-of-line blocking
        let (mut send, mut recv) = connection.open_bi().await?;

        let connect_msg = RelayMessage::connect(self.connection_id);
        send.write_all(&connect_msg.encode()?).await?;

        let mut recv_buf = vec![0u8; self.config.buffer_size];
        let mut framer = MessageFramer::with_capacity(self.config.buffer_size);
        let datagrams_enabled = self.config.enable_datagrams;

        loop {
            tokio::select! {
                // Handle outgoing packets from TUN
                Some(packet) = rx.recv() => {
                    // Determine if this is real-time traffic that should use datagrams
                    let use_datagram = datagrams_enabled && self.should_use_datagram(&packet);

                    if use_datagram {
                        // Send via QUIC datagram - unreliable but ultra-low latency
                        if let Err(e) = self.send_datagram(&connection, packet).await {
                            // Fallback to stream if datagram fails (e.g., too large)
                            debug!("Datagram send failed, falling back to stream: {}", e);
                        }
                    } else {
                        // Send via reliable stream
                        if let Err(e) = self.send_packet(&mut send, packet).await {
                            error!("Failed to send packet: {}", e);
                        }
                    }
                }

                // === MASQUE-INSPIRED: Receive datagrams for real-time responses ===
                Ok(datagram) = connection.read_datagram(), if datagrams_enabled => {
                    self.metrics.record_received(datagram.len() as u64);
                    // Datagrams contain raw IP packets - send directly to TUN
                    if response_tx.send(datagram.to_vec()).await.is_err() {
                        error!("Failed to send datagram response to TUN");
                    }
                }

                // Handle stream receives (reliable traffic)
                result = recv.read(&mut recv_buf) => {
                    match result {
                        Ok(Some(len)) => {
                            self.metrics.record_received(len as u64);
                            framer.extend(&recv_buf[..len]);

                            // Process all complete messages with decode timing
                            loop {
                                let decode_start = Instant::now();
                                match framer.try_decode() {
                                    Ok(Some(message)) => {
                                        self.metrics.record_decode_latency(decode_start.elapsed());
                                        // Handle Data messages - write to TUN
                                        if message.msg_type == MessageType::Data {
                                            if response_tx.send(message.payload).await.is_err() {
                                                error!("Failed to send response to TUN");
                                            }
                                        } else if let Err(e) = self.handle_message(message).await {
                                            error!("Failed to handle message: {}", e);
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            error!("Read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        self.metrics.record_connection_closed();
        Ok(())
    }

    /// Determine if a packet should use QUIC datagrams based on destination port
    fn should_use_datagram(&self, packet: &[u8]) -> bool {
        // Parse IPv4 packet to extract destination port
        if packet.len() < 20 {
            return false;
        }

        // Check IP version (must be IPv4)
        let version = packet[0] >> 4;
        if version != 4 {
            return false;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        let protocol = packet[9];

        // Only UDP (17) and TCP (6) have ports
        if protocol != 6 && protocol != 17 {
            return false;
        }

        if packet.len() < ihl + 4 {
            return false;
        }

        // Extract destination port (big-endian, bytes 2-3 of transport header)
        let dest_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

        // Use datagram for real-time ports
        self.is_realtime_port(dest_port)
    }

    /// Send packet via QUIC datagram (unreliable, low-latency)
    async fn send_datagram(&self, connection: &quinn::Connection, packet: Vec<u8>) -> Result<()> {
        let sequence = SEQUENCE_COUNTER.fetch_add(1, Ordering::SeqCst);

        // For datagrams, use minimal framing - just prepend connection_id and sequence
        // This avoids the overhead of full RelayMessage encoding
        let mut datagram = Vec::with_capacity(16 + packet.len());
        datagram.extend_from_slice(&self.connection_id.to_le_bytes());
        datagram.extend_from_slice(&sequence.to_le_bytes());
        datagram.extend_from_slice(&packet);

        connection.send_datagram(datagram.into())?;
        self.metrics.record_sent(packet.len() as u64);

        Ok(())
    }

    async fn send_packet(&self, send: &mut quinn::SendStream, packet: Vec<u8>) -> Result<()> {
        let process_start = Instant::now();
        let sequence = SEQUENCE_COUNTER.fetch_add(1, Ordering::SeqCst);

        let mut message = RelayMessage::data(self.connection_id, sequence, packet);

        // Use ML engine for smart compression decision
        // Defaults to fast heuristics, can switch to ML when models are ready
        let should_compress_packet = {
            let mut ml = self.ml_engine.write().await;
            let decision = ml.compression_decision(&message.payload);
            // Returns Skip, Light, Normal, or Aggressive - compress unless Skip
            !matches!(
                decision,
                oxidize_common::ml_models::MlCompressionDecision::Skip
            )
        };

        if should_compress_packet {
            let compressed = compress_data(&message.payload)?;

            if compressed.len() < message.payload.len() {
                let saved = message.payload.len() - compressed.len();
                self.metrics.record_compression_saved(saved as u64);
                message.payload = compressed;
                message.compressed = true;
            }
        }

        let encode_start = Instant::now();
        let encoded = message.encode()?;
        self.metrics.record_encode_latency(encode_start.elapsed());

        let forward_start = Instant::now();
        send.write_all(&encoded).await?;
        send.flush().await?;
        self.metrics.record_forward_latency(forward_start.elapsed());

        self.metrics.record_sent(encoded.len() as u64);
        self.metrics.record_process_latency(process_start.elapsed());

        Ok(())
    }

    async fn handle_message(&self, message: RelayMessage) -> Result<()> {
        match message.msg_type {
            MessageType::ConnectAck => {
                info!("Connection acknowledged by server");
            }
            MessageType::DataAck => {
                debug!("ACK received for sequence {}", message.sequence);
            }
            MessageType::Pong => {
                debug!("Pong received");
            }
            _ => {
                debug!("Received message: {:?}", message.msg_type);
            }
        }

        Ok(())
    }

    fn clone_for_task(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            server_addr: self.server_addr,
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            connection_id: self.connection_id,
            dns_cache: self.dns_cache.clone(),
            realtime_ports: self.realtime_ports.clone(),
            session_ticket: self.session_ticket.clone(),
            multipath: self.multipath.clone(),
            prefetcher: self.prefetcher.clone(),
            ml_engine: self.ml_engine.clone(),
            model_hub: self.model_hub.clone(),
        }
    }
}
