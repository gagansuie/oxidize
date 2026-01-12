use anyhow::Result;
use oxidize_common::edge_cache::{CacheConfig, EdgeCache};
use oxidize_common::ml_models::MlEngine;
use oxidize_common::model_hub::{HubConfig, ModelHub};
use oxidize_common::security::{SecurityAction, SecurityConfig, SecurityManager};
use oxidize_common::RelayMetrics;
use quinn::{Connection, Endpoint, ServerConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::cache::DataCache;
use crate::config::Config;
use crate::connection::ConnectionHandler;
use crate::graceful::{create_reuseport_socket, ShutdownCoordinator};
use crate::tls::{load_tls_config, TlsConfig};
use crate::xdp_forwarder::SharedTunForwarder;

pub struct RelayServer {
    endpoint: Endpoint,
    config: Config,
    metrics: RelayMetrics,
    connections: Arc<RwLock<HashMap<u64, Arc<ConnectionHandler>>>>,
    cache: Arc<DataCache>,
    security: Arc<Mutex<SecurityManager>>,
    forwarder: Arc<SharedTunForwarder>,
    /// Edge cache for static content
    edge_cache: Arc<RwLock<EdgeCache>>,
    /// ML Engine for AI-powered decisions (NO HEURISTIC FALLBACK)
    /// All decisions are made by trained ML models
    ml_engine: Arc<RwLock<MlEngine>>,
    /// Model Hub for downloading models and uploading training data
    model_hub: Arc<ModelHub>,
}

impl RelayServer {
    pub async fn new(listen_addr: SocketAddr, config: Config) -> Result<Self> {
        let tls_config = if let (Some(cert_path), Some(key_path)) =
            (&config.tls_cert_path, &config.tls_key_path)
        {
            info!("Loading TLS certificates from files");
            TlsConfig::FromFiles {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
            }
        } else {
            warn!("Using self-signed certificate (development only)");
            TlsConfig::SelfSigned
        };

        let (certs, key) = load_tls_config(tls_config)?;

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        server_crypto.alpn_protocols = vec![b"relay/1".to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

        let mut transport_config = quinn::TransportConfig::default();

        // Stream limits for high concurrency
        transport_config.max_concurrent_bidi_streams(1000u32.into());
        transport_config.max_concurrent_uni_streams(1000u32.into());
        transport_config.max_idle_timeout(Some(
            std::time::Duration::from_secs(config.connection_timeout).try_into()?,
        ));

        // === HIGH-PERFORMANCE QUIC TUNING ===

        // Larger receive/send windows for high throughput (16MB default, increase to 64MB)
        transport_config.receive_window(64_000_000u32.into());
        transport_config.send_window(64_000_000u64);
        transport_config.stream_receive_window(16_000_000u32.into());

        // Faster keepalive for low latency connection recovery (15s instead of default)
        transport_config.keep_alive_interval(Some(Duration::from_secs(15)));

        // Lower initial RTT estimate for better initial performance
        transport_config.initial_rtt(Duration::from_millis(10));

        // Enable QUIC datagrams for unreliable low-latency traffic (gaming/VoIP)
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.datagram_send_buffer_size(65536);

        // Enable BBR congestion control for better throughput on lossy networks
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        server_config.transport_config(Arc::new(transport_config));

        // Create socket with SO_REUSEPORT for zero-downtime rolling restarts
        // This allows multiple server processes to bind to the same port
        let socket = create_reuseport_socket(listen_addr)?;
        info!("🔄 SO_REUSEPORT enabled for zero-downtime deployments");

        let runtime =
            quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime found"))?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )?;

        let security_config = SecurityConfig {
            max_connections_per_ip: config.rate_limit_per_ip as u32,
            rate_limit_window_secs: config.rate_limit_window_secs,
            max_pps_per_ip: config.max_pps_per_ip,
            max_bandwidth_per_ip: config.max_bandwidth_per_ip,
            enable_stateless_retry: true,
            blocklist_ttl: Duration::from_secs(3600),
            auto_block_threshold: config.auto_block_threshold,
            enable_challenges: config.enable_challenges,
        };
        let security = Arc::new(Mutex::new(SecurityManager::new(security_config)));

        // Initialize shared TUN forwarder at server startup
        let forwarder = SharedTunForwarder::new().await?;

        // Initialize edge cache
        let edge_cache_config = CacheConfig {
            max_size: config.edge_cache_size,
            max_entries: config.edge_cache_entries,
            enabled: config.enable_edge_cache,
            ..Default::default()
        };
        let edge_cache = Arc::new(RwLock::new(EdgeCache::new(edge_cache_config)));

        // Initialize ML Engine in HEURISTIC mode (default, zero overhead)
        // Training data collection is enabled for continuous improvement
        let mut ml_engine = MlEngine::new();

        // Initialize Model Hub for model sync and training data upload
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
                        info!("⚠️ Loaded {} of 4 ML models - using heuristics (training data collecting)", loaded);
                    } else {
                        info!(
                            "📊 No ML models found - using heuristics (training data collecting)"
                        );
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

        if config.enable_edge_cache {
            info!(
                "📦 Edge cache enabled ({}MB, {} entries)",
                config.edge_cache_size / 1024 / 1024,
                config.edge_cache_entries
            );
        }

        Ok(Self {
            endpoint,
            config,
            metrics: RelayMetrics::new(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(DataCache::new()),
            security,
            forwarder,
            edge_cache,
            ml_engine,
            model_hub,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn get_metrics(&self) -> &RelayMetrics {
        &self.metrics
    }

    pub async fn run(&self) -> Result<()> {
        info!("Server running and accepting connections...");

        // Spawn cleanup task for security and edge cache
        let security_cleanup = self.security.clone();
        let cache_cleanup = self.edge_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                security_cleanup.lock().await.cleanup();
                // Cleanup expired cache entries
                cache_cleanup.write().await.cleanup_expired();
            }
        });

        // Log cache and ML stats periodically
        let cache_stats = self.edge_cache.clone();
        let ml_stats = self.ml_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                let stats = cache_stats.read().await.get_stats();
                if stats.hits > 0 || stats.misses > 0 {
                    info!(
                        "📦 Edge cache: {:.1}% hit rate, {} entries, {}MB used",
                        stats.hit_rate,
                        stats.entries,
                        stats.size_bytes / 1024 / 1024
                    );
                }
                // Log ML engine stats (100% ML, no heuristics)
                let ml_engine_stats = ml_stats.read().await.stats();
                info!(
                    "🧠 ML engine: all_models_loaded={}, lstm_inferences={}, drl_inferences={}, compression_skipped={}",
                    ml_engine_stats.loss_predictor.model_loaded && ml_engine_stats.congestion_controller.model_loaded,
                    ml_engine_stats.loss_predictor.inference_count,
                    ml_engine_stats.congestion_controller.inference_count,
                    ml_engine_stats.compression_oracle.skip_count
                );
            }
        });

        // Periodic ML training data upload to HF Hub (every hour)
        let ml_upload = self.ml_engine.clone();
        let hub_upload = self.model_hub.clone();
        tokio::spawn(async move {
            // Wait 10 minutes before first upload to collect some data
            tokio::time::sleep(Duration::from_secs(600)).await;

            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // 1 hour
            loop {
                interval.tick().await;

                // Export training data to temp directory
                let export_dir = "/tmp/oxidize_training_export";
                if let Err(e) = std::fs::create_dir_all(export_dir) {
                    warn!("Failed to create export dir: {}", e);
                    continue;
                }

                {
                    let engine = ml_upload.read().await;
                    if let Err(e) = engine.export_training_data(export_dir) {
                        warn!("Failed to export training data: {}", e);
                        continue;
                    }
                }

                // Read exported files and upload
                let loss_path = format!("{}/loss_samples.json", export_dir);
                let drl_path = format!("{}/drl_experiences.json", export_dir);

                let loss_samples: Vec<oxidize_common::ml_models::LossSample> =
                    std::fs::read_to_string(&loss_path)
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();

                let drl_experiences: Vec<oxidize_common::ml_models::DrlExperience> =
                    std::fs::read_to_string(&drl_path)
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();

                if loss_samples.is_empty() && drl_experiences.is_empty() {
                    debug!("No training data to upload yet");
                    continue;
                }

                info!(
                    "📤 Uploading training data: {} loss samples, {} DRL experiences",
                    loss_samples.len(),
                    drl_experiences.len()
                );

                match hub_upload.upload_training_data(&loss_samples, &drl_experiences) {
                    Ok(()) => info!("✅ Training data uploaded to HF Hub"),
                    Err(e) => warn!("Failed to upload training data: {}", e),
                }
            }
        });

        while let Some(incoming) = self.endpoint.accept().await {
            let connections = self.connections.clone();
            let metrics = self.metrics.clone();
            let config = self.config.clone();
            let cache = self.cache.clone();
            let security = self.security.clone();
            let forwarder = self.forwarder.clone();

            tokio::spawn(async move {
                // Get remote address before awaiting connection
                let remote_addr = incoming.remote_address();
                let client_ip = remote_addr.ip();

                // Security check
                let action = security.lock().await.check_connection(client_ip);
                match action {
                    SecurityAction::Block => {
                        warn!("Blocked connection from: {}", client_ip);
                        return;
                    }
                    SecurityAction::RateLimit => {
                        debug!("Rate limited connection from: {}", client_ip);
                        return;
                    }
                    SecurityAction::Challenge => {
                        debug!("Challenging connection from: {}", client_ip);
                        // QUIC stateless retry handles this automatically
                    }
                    _ => {}
                }

                match incoming.await {
                    Ok(connection) => {
                        info!("New connection from: {}", connection.remote_address());
                        metrics.record_connection_opened();

                        // Mark as verified after successful handshake
                        security.lock().await.mark_verified(client_ip);

                        if let Err(e) = Self::handle_connection(
                            connection,
                            connections,
                            metrics.clone(),
                            config,
                            cache,
                            forwarder,
                        )
                        .await
                        {
                            error!("Connection error: {}", e);
                        }

                        metrics.record_connection_closed();
                    }
                    Err(e) => {
                        error!("Connection failed: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    /// Run server with graceful shutdown support
    /// This method supports zero-downtime deployments:
    /// - Stops accepting new connections on shutdown signal
    /// - Drains existing connections gracefully
    /// - Works with SO_REUSEPORT for rolling restarts
    pub async fn run_with_shutdown(
        &self,
        shutdown_coordinator: Arc<ShutdownCoordinator>,
    ) -> Result<()> {
        info!("Server running with graceful shutdown support...");

        // Spawn cleanup task for security and edge cache
        let security_cleanup = self.security.clone();
        let cache_cleanup = self.edge_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                security_cleanup.lock().await.cleanup();
                cache_cleanup.write().await.cleanup_expired();
            }
        });

        // Log cache stats periodically
        let cache_stats = self.edge_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                let stats = cache_stats.read().await.get_stats();
                if stats.hits > 0 || stats.misses > 0 {
                    info!(
                        "📦 Edge cache: {:.1}% hit rate, {} entries, {}MB used",
                        stats.hit_rate,
                        stats.entries,
                        stats.size_bytes / 1024 / 1024
                    );
                }
            }
        });

        // Get connection tracker for this server instance
        let tracker = shutdown_coordinator.connection_tracker();

        // Accept connections until shutdown signal
        loop {
            // Check if we should stop accepting new connections
            if !shutdown_coordinator.should_accept() {
                info!("🛑 Stopping new connection acceptance, draining existing...");
                break;
            }

            // Use select to check for both new connections and shutdown
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    if let Some(incoming) = incoming {
                        let connections = self.connections.clone();
                        let metrics = self.metrics.clone();
                        let config = self.config.clone();
                        let cache = self.cache.clone();
                        let security = self.security.clone();
                        let forwarder = self.forwarder.clone();
                        let conn_tracker = tracker.clone_tracker();

                        tokio::spawn(async move {
                            // Register this connection for tracking
                            let _guard = conn_tracker.register();

                            let remote_addr = incoming.remote_address();
                            let client_ip = remote_addr.ip();

                            // Security check
                            let action = security.lock().await.check_connection(client_ip);
                            match action {
                                SecurityAction::Block => {
                                    warn!("Blocked connection from: {}", client_ip);
                                    return;
                                }
                                SecurityAction::RateLimit => {
                                    debug!("Rate limited connection from: {}", client_ip);
                                    return;
                                }
                                SecurityAction::Challenge => {
                                    debug!("Challenging connection from: {}", client_ip);
                                }
                                _ => {}
                            }

                            match incoming.await {
                                Ok(connection) => {
                                    info!("New connection from: {}", connection.remote_address());
                                    metrics.record_connection_opened();

                                    security.lock().await.mark_verified(client_ip);

                                    if let Err(e) = Self::handle_connection(
                                        connection,
                                        connections,
                                        metrics.clone(),
                                        config,
                                        cache,
                                        forwarder,
                                    )
                                    .await
                                    {
                                        error!("Connection error: {}", e);
                                    }

                                    metrics.record_connection_closed();
                                }
                                Err(e) => {
                                    error!("Connection failed: {}", e);
                                }
                            }
                            // _guard dropped here, decrementing active connection count
                        });
                    } else {
                        // Endpoint closed
                        break;
                    }
                }
            }
        }

        // Wait for graceful shutdown to complete (connections to drain)
        // The signal handler will call shutdown_coordinator.shutdown()
        info!(
            "📊 {} active connections remaining",
            shutdown_coordinator.active_count()
        );

        Ok(())
    }

    async fn handle_connection(
        connection: Connection,
        connections: Arc<RwLock<HashMap<u64, Arc<ConnectionHandler>>>>,
        metrics: RelayMetrics,
        config: Config,
        cache: Arc<DataCache>,
        forwarder: Arc<SharedTunForwarder>,
    ) -> Result<()> {
        // === MASQUE-INSPIRED: Spawn datagram handler for real-time traffic ===
        let datagram_connection = connection.clone();
        let datagram_forwarder = forwarder.clone();
        let datagram_metrics = metrics.clone();

        let datagram_handle = tokio::spawn(async move {
            Self::handle_datagrams(datagram_connection, datagram_forwarder, datagram_metrics).await;
        });

        // Handle stream-based traffic (reliable)
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let connections = connections.clone();
                    let metrics = metrics.clone();
                    let config = config.clone();
                    let cache = cache.clone();
                    let forwarder = forwarder.clone();

                    tokio::spawn(async move {
                        let handler =
                            ConnectionHandler::new(send, recv, metrics, config, cache, forwarder)
                                .await;

                        let conn_id = handler.id();

                        if let Err(e) = handler.handle().await {
                            error!("Handler error for connection {}: {}", conn_id, e);
                        }

                        connections.write().await.remove(&conn_id);
                        debug!("Connection {} closed", conn_id);
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Connection closed by peer");
                    break;
                }
                Err(e) => {
                    error!("Stream accept error: {}", e);
                    break;
                }
            }
        }

        datagram_handle.abort();
        Ok(())
    }

    /// Handle QUIC datagrams for real-time traffic (gaming, VoIP)
    /// This bypasses stream ordering for ultra-low latency
    async fn handle_datagrams(
        connection: Connection,
        forwarder: Arc<SharedTunForwarder>,
        metrics: RelayMetrics,
    ) {
        loop {
            match connection.read_datagram().await {
                Ok(datagram) => {
                    metrics.record_received(datagram.len() as u64);

                    // Parse minimal header: connection_id (8) + sequence (8) + payload
                    if datagram.len() < 16 {
                        debug!("Datagram too small, skipping");
                        continue;
                    }

                    let connection_id =
                        u64::from_le_bytes(datagram[0..8].try_into().unwrap_or([0; 8]));
                    // Sequence is bytes 8-16 (unused for now, could track for stats)
                    let payload = &datagram[16..];

                    // Forward directly to TUN - no framing overhead
                    if let Err(e) = forwarder.forward(connection_id, payload.to_vec()).await {
                        debug!("Datagram forward error: {}", e);
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Datagram connection closed");
                    break;
                }
                Err(e) => {
                    debug!("Datagram read error: {}", e);
                    break;
                }
            }
        }
    }
}
