use anyhow::Result;
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
use crate::tls::{load_tls_config, TlsConfig};

pub struct RelayServer {
    endpoint: Endpoint,
    config: Config,
    metrics: RelayMetrics,
    connections: Arc<RwLock<HashMap<u64, Arc<ConnectionHandler>>>>,
    cache: Arc<DataCache>,
    security: Arc<Mutex<SecurityManager>>,
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

        // Allow more data in flight before ACKs (helps throughput on high-latency links)
        transport_config.initial_rtt(Duration::from_millis(50));

        // Enable QUIC datagrams for unreliable low-latency traffic (gaming/VoIP)
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.datagram_send_buffer_size(65536);

        // Enable BBR congestion control for better throughput on lossy networks
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::server(server_config, listen_addr)?;

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

        Ok(Self {
            endpoint,
            config,
            metrics: RelayMetrics::new(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(DataCache::new()),
            security,
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

        // Spawn cleanup task
        let security_cleanup = self.security.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                security_cleanup.lock().await.cleanup();
            }
        });

        while let Some(incoming) = self.endpoint.accept().await {
            let connections = self.connections.clone();
            let metrics = self.metrics.clone();
            let config = self.config.clone();
            let cache = self.cache.clone();
            let security = self.security.clone();

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

    async fn handle_connection(
        connection: Connection,
        connections: Arc<RwLock<HashMap<u64, Arc<ConnectionHandler>>>>,
        metrics: RelayMetrics,
        config: Config,
        cache: Arc<DataCache>,
    ) -> Result<()> {
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let connections = connections.clone();
                    let metrics = metrics.clone();
                    let config = config.clone();
                    let cache = cache.clone();

                    tokio::spawn(async move {
                        let handler = ConnectionHandler::new(send, recv, metrics, config, cache);

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

        Ok(())
    }
}
