use anyhow::Result;
use oxidize_common::RelayMetrics;
use quinn::{Connection, Endpoint, ServerConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::cache::DataCache;
use crate::config::Config;
use crate::connection::ConnectionHandler;
use crate::rate_limiter::RateLimiter;
use crate::tls::{load_tls_config, TlsConfig};

pub struct RelayServer {
    endpoint: Endpoint,
    config: Config,
    metrics: RelayMetrics,
    connections: Arc<RwLock<HashMap<u64, Arc<ConnectionHandler>>>>,
    cache: Arc<DataCache>,
    rate_limiter: RateLimiter,
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
        transport_config.max_concurrent_bidi_streams(1000u32.into());
        transport_config.max_concurrent_uni_streams(1000u32.into());
        transport_config.max_idle_timeout(Some(
            std::time::Duration::from_secs(config.connection_timeout).try_into()?,
        ));

        // Enable BBR congestion control for better throughput on lossy networks
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::server(server_config, listen_addr)?;

        let rate_limiter =
            RateLimiter::new(config.rate_limit_per_ip, config.rate_limit_window_secs);

        Ok(Self {
            endpoint,
            config,
            metrics: RelayMetrics::new(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(DataCache::new()),
            rate_limiter,
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

        loop {
            match self.endpoint.accept().await {
                Some(incoming) => {
                    let connections = self.connections.clone();
                    let metrics = self.metrics.clone();
                    let config = self.config.clone();
                    let cache = self.cache.clone();

                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(connection) => {
                                info!("New connection from: {}", connection.remote_address());
                                metrics.record_connection_opened();

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
                None => {
                    break;
                }
            }
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
                        let handler =
                            Arc::new(ConnectionHandler::new(send, recv, metrics, config, cache));

                        let conn_id = handler.id();
                        connections.write().await.insert(conn_id, handler.clone());

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
