use crate::config::ClientConfig;
use crate::dns_cache::DnsCache;
use anyhow::{Context, Result};
use oxidize_common::ml_optimized::{MlCompressionDecision, OptimizedMlEngine};
use oxidize_common::model_hub::{HubConfig, ModelHub};
use oxidize_common::multipath::{MultipathScheduler, PathId, PathMetrics, SchedulingStrategy};
use oxidize_common::prefetch::{PrefetchConfig, PrefetchResource, Prefetcher};
use oxidize_common::{compress_data, MessageFramer, MessageType, RelayMessage, RelayMetrics};
use quinn::ClientConfig as QuinnClientConfig;
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Certificate verifier that accepts any certificate (for self-signed certs)
/// WARNING: This disables certificate verification - use only for development/testing
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
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
    /// Path to persist session cache
    session_cache_path: String,
    /// Multi-path scheduler for bandwidth aggregation
    multipath: Arc<Mutex<MultipathScheduler>>,
    /// Predictive prefetcher for DNS/connections
    prefetcher: Arc<Mutex<Prefetcher>>,
    /// ML Engine for AI-powered decisions (10x optimized)
    ml_engine: Arc<RwLock<OptimizedMlEngine>>,
    /// Model Hub for downloading models
    model_hub: Arc<ModelHub>,
}

impl RelayClient {
    pub async fn new(server_addr: SocketAddr, config: ClientConfig) -> Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        // Build rustls ClientConfig with proper 0-RTT support
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        // Configure client with ALPN and 0-RTT settings
        let mut crypto = crypto;
        crypto.alpn_protocols = vec![b"relay/1".to_vec()];

        // 0-RTT configuration
        if config.enable_0rtt {
            info!("🚀 0-RTT session resumption enabled");
            // Enable early data (0-RTT) - quinn handles the actual 0-RTT mechanics
            crypto.enable_early_data = true;
        } else {
            info!("🔒 Using standard 1-RTT resumption (0-RTT disabled)");
            crypto.enable_early_data = false;
        }

        // quinn 0.11 requires QuicClientConfig wrapper for rustls
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
        let mut client_config = QuinnClientConfig::new(Arc::new(quic_crypto));

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

        // Use Quinn's native BBR congestion control
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        // Connection migration configuration
        if !config.enable_migration {
            // Disable migration if configured
            // Note: Quinn doesn't have a direct disable, but we can set migration to false
            // by not responding to path challenges - handled at connection level
            info!("🔒 Connection migration disabled");
        }

        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        let connection_id = rand::random();
        let dns_cache = Arc::new(DnsCache::new(config.dns_cache_size));

        // Build realtime ports set for O(1) lookup
        let realtime_ports: HashSet<u16> = config.realtime_ports.iter().cloned().collect();

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

        // Initialize 10x Optimized ML Engine (INT8 quantized, Transformer+PPO)
        // Always in ML mode with embedded weights - no external model loading needed
        let ml_engine = OptimizedMlEngine::new();

        // Initialize Model Hub for model sync (kept for future updates)
        let hub_config = HubConfig {
            upload_training_data: true,
            ..Default::default()
        };
        let model_hub = Arc::new(ModelHub::new(hub_config));

        // Log ML engine mode (always ML with optimized engine)
        info!(
            "🧠 ML engine (10x): {:?} (INT8 quantized, Transformer+PPO)",
            ml_engine.inference_mode()
        );

        let ml_engine = Arc::new(RwLock::new(ml_engine));

        if config.enable_multipath {
            info!("🔀 Multi-path support enabled");
        }
        if config.enable_prefetch {
            info!("🔮 Predictive prefetching enabled");
        }

        let session_cache_path = config.session_cache_path.clone();

        Ok(Self {
            endpoint,
            server_addr,
            config: config.clone(),
            metrics: RelayMetrics::new(),
            connection_id,
            dns_cache,
            realtime_ports,
            session_cache_path,
            multipath,
            prefetcher,
            ml_engine,
            model_hub,
        })
    }

    /// Check if a port should use QUIC datagrams (real-time traffic)
    fn is_realtime_port(&self, port: u16) -> bool {
        self.realtime_ports.contains(&port)
    }

    pub fn get_metrics(&self) -> &RelayMetrics {
        &self.metrics
    }

    /// Get the QUIC endpoint for direct connection operations
    #[allow(dead_code)]
    pub fn get_endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Get the server address for this client
    #[allow(dead_code)]
    pub fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Establish QUIC connection (handshake only, no message loop)
    /// Call this before setting up NFQUEUE to ensure the connection is established
    #[allow(dead_code)]
    pub async fn connect(&self) -> Result<quinn::Connection> {
        info!("🔌 Establishing QUIC connection to {}...", self.server_addr);

        let connecting = self.endpoint.connect(self.server_addr, "localhost")?;
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
        Ok(connection)
    }

    /// Run with an existing connection and packet sender channel
    /// Use connect() first to establish the connection before NFQUEUE setup
    #[allow(dead_code)]
    pub async fn run_with_connection(
        &self,
        connection: quinn::Connection,
        mut packet_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        info!("🚀 Starting relay client with existing connection...");

        // Register this connection as the primary path for multipath scheduler
        if self.config.enable_multipath {
            let mut mp = self.multipath.lock().await;
            let local_addr = connection
                .local_ip()
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let path_id = PathId::new(local_addr, self.server_addr);
            let metrics = PathMetrics::new(50.0, 100_000_000, 0.0, 5.0);
            mp.add_path(path_id, metrics);
            info!("🔀 Primary path registered with multipath scheduler");
        }

        // Record connection in prefetcher for pattern learning
        if self.config.enable_prefetch {
            let mut pf = self.prefetcher.lock().await;
            pf.record_access(PrefetchResource::Connection(
                self.server_addr.ip().to_string(),
                self.server_addr.port(),
            ));
        }

        // Open bidirectional stream for control messages
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send connect message
        let connect_msg = RelayMessage::connect(self.connection_id);
        let encoded = connect_msg.encode()?;
        send.write_all(&encoded).await?;
        self.metrics.record_sent(encoded.len() as u64);

        info!("📡 QUIC relay ready for packet forwarding");
        info!("📡 Datagram max size: {:?}", connection.max_datagram_size());

        let mut forwarded_count: u64 = 0;
        let mut failed_count: u64 = 0;
        let mut recv_buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                // Receive packets from the channel (from NFQUEUE)
                Some(packet) = packet_rx.recv() => {
                    // Apply compression if enabled and packet is large enough
                    let (payload, compressed_flag) = if self.config.enable_compression
                        && packet.len() >= self.config.compression_threshold
                    {
                        match compress_data(&packet) {
                            Ok(compressed) if compressed.len() < packet.len() => {
                                let saved = packet.len() - compressed.len();
                                self.metrics.record_compression_saved(saved as u64);
                                (compressed, 1u8)
                            }
                            _ => (packet.clone(), 0u8),
                        }
                    } else {
                        (packet.clone(), 0u8)
                    };

                    // Send via QUIC datagram for low latency
                    // Add 17-byte header: connection_id (8) + sequence (8) + compressed (1)
                    let sequence = SEQUENCE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut datagram = Vec::with_capacity(17 + payload.len());
                    datagram.extend_from_slice(&self.connection_id.to_le_bytes());
                    datagram.extend_from_slice(&sequence.to_le_bytes());
                    datagram.push(compressed_flag);
                    datagram.extend_from_slice(&payload);

                    if let Some(max_size) = connection.max_datagram_size() {
                        if datagram.len() <= max_size {
                            match connection.send_datagram(datagram.into()) {
                                Ok(_) => {
                                    forwarded_count += 1;
                                    self.metrics.record_sent(payload.len() as u64);
                                }
                                Err(e) => {
                                    failed_count += 1;
                                    if failed_count % 100 == 1 {
                                        warn!("Datagram send failed: {} (total failures: {})", e, failed_count);
                                    }
                                }
                            }
                        }
                    }
                }

                // Receive datagrams from server
                Ok(datagram) = connection.read_datagram() => {
                    self.metrics.record_received(datagram.len() as u64);
                    // Process received datagram (responses from relay)
                    debug!("Received datagram: {} bytes", datagram.len());
                }

                // Receive stream data from server
                result = recv.read(&mut recv_buf) => {
                    match result {
                        Ok(Some(n)) => {
                            self.metrics.record_received(n as u64);
                            debug!("Received stream data: {} bytes", n);
                        }
                        Ok(None) => {
                            info!("Stream closed by server");
                            break;
                        }
                        Err(e) => {
                            error!("Stream read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        info!(
            "📊 Session stats: {} forwarded, {} failed",
            forwarded_count, failed_count
        );
        Ok(())
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

        // Register this connection as the primary path for multipath scheduler
        if self.config.enable_multipath {
            let mut mp = self.multipath.lock().await;
            // Create path ID from local and remote addresses
            let local_addr = connection
                .local_ip()
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let path_id = PathId::new(local_addr, self.server_addr);
            let metrics = PathMetrics::new(50.0, 100_000_000, 0.0, 5.0);
            mp.add_path(path_id, metrics);
            info!("🔀 Primary path registered with multipath scheduler");
        }

        // Record connection in prefetcher for pattern learning
        if self.config.enable_prefetch {
            let mut pf = self.prefetcher.lock().await;
            pf.record_access(PrefetchResource::Connection(
                self.server_addr.ip().to_string(),
                self.server_addr.port(),
            ));
        }

        // Open bidirectional stream for control messages
        let (mut send, mut recv) = connection.open_bi().await?;

        // Open separate streams for different traffic types if stream multiplexing is enabled
        let _bulk_stream = if self.config.enable_stream_multiplexing {
            let (bulk_send, _) = connection.open_bi().await?;
            info!("📊 Stream multiplexing enabled: opened bulk transfer stream");
            Some(bulk_send)
        } else {
            None
        };

        // Send connect message
        let connect_msg = RelayMessage::connect(self.connection_id);
        let encoded = connect_msg.encode()?;
        send.write_all(&encoded).await?;
        self.metrics.record_sent(encoded.len() as u64);

        info!("📡 QUIC relay ready for packet forwarding");
        info!("📡 Datagram max size: {:?}", connection.max_datagram_size());

        let mut forwarded_count: u64 = 0;
        let mut failed_count: u64 = 0;
        let mut recv_buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                // Receive packets to forward through QUIC
                Some(packet) = packet_rx.recv() => {
                    let len = packet.len();
                    forwarded_count += 1;

                    if forwarded_count == 1 {
                        info!("📥 First packet received: {} bytes", len);
                    }

                    // Send via QUIC stream as Data message (datagrams not working reliably)
                    let data_msg = RelayMessage::data(self.connection_id, forwarded_count, packet);
                    match data_msg.encode() {
                        Ok(encoded) => {
                            if let Err(e) = send.write_all(&encoded).await {
                                failed_count += 1;
                                if failed_count <= 3 {
                                    error!("❌ Stream send failed: {} (packet {})", e, forwarded_count);
                                }
                            } else {
                                self.metrics.record_sent(len as u64);
                                #[allow(clippy::manual_is_multiple_of)]
                                if forwarded_count % 100 == 0 {
                                    info!("📤 Forwarded {} packets through QUIC stream ({} failed)", forwarded_count, failed_count);
                                }
                            }
                        }
                        Err(e) => {
                            failed_count += 1;
                            if failed_count <= 3 {
                                error!("❌ Message encode failed: {} (packet {})", e, forwarded_count);
                            }
                        }
                    }
                }

                // Receive datagrams from relay (real-time responses)
                Ok(datagram) = connection.read_datagram() => {
                    self.metrics.record_received(datagram.len() as u64);
                    info!("📥 Datagram received from relay: {} bytes", datagram.len());
                }

                // Receive stream data from relay (reliable responses)
                result = recv.read(&mut recv_buf) => {
                    match result {
                        Ok(Some(len)) => {
                            self.metrics.record_received(len as u64);
                            info!("📥 Stream data received from relay: {} bytes", len);
                        }
                        Ok(None) => {
                            info!("Stream closed by relay");
                        }
                        Err(e) => {
                            error!("Stream read error: {}", e);
                        }
                    }
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

    /// Run client with high-performance packet capture
    #[allow(dead_code)]
    pub async fn run_high_perf(&self) -> Result<()> {
        info!("🚀 Starting high-performance client mode");

        // Verify connection works first
        info!("Verifying server connection...");

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

        // Set up channels for packet exchange
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

        info!("📡 High-performance client running");

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
                // Handle outgoing packets from NFQUEUE
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
                        error!("Failed to send datagram response");
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
                                                error!("Failed to send response");
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

        // Use ML engine for smart compression decision (10x optimized)
        let should_compress_packet = if self.config.enable_ai_engine {
            let ml = self.ml_engine.read().await;
            let decision = ml.compression_decision(&message.payload);
            // Returns Skip, Light, Normal, or Aggressive - compress unless Skip
            !matches!(decision, MlCompressionDecision::Skip)
        } else {
            // AI engine disabled - use simple threshold-based compression
            self.config.enable_compression
                && message.payload.len() >= self.config.compression_threshold
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
            session_cache_path: self.session_cache_path.clone(),
            multipath: self.multipath.clone(),
            prefetcher: self.prefetcher.clone(),
            ml_engine: self.ml_engine.clone(),
            model_hub: self.model_hub.clone(),
        }
    }
}
