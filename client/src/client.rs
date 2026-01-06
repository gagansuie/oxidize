use crate::config::ClientConfig;
use crate::dns_cache::DnsCache;
use crate::tun_handler::TunHandler;
use anyhow::{Context, Result};
use bytes::Bytes;
use oxidize_common::{compress_data, should_compress, MessageType, RelayMessage, RelayMetrics};
use quinn::ClientConfig as QuinnClientConfig;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

static SEQUENCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct RelayClient {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    config: ClientConfig,
    metrics: RelayMetrics,
    connection_id: u64,
    dns_cache: Arc<DnsCache>,
}

impl RelayClient {
    pub async fn new(server_addr: SocketAddr, config: ClientConfig) -> Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"relay/1".to_vec()];

        let mut client_config = QuinnClientConfig::new(Arc::new(crypto));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(300).try_into()?));

        // Enable BBR congestion control for better throughput
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        let connection_id = rand::random();
        let dns_cache = Arc::new(DnsCache::new(config.dns_cache_size));

        Ok(Self {
            endpoint,
            server_addr,
            config,
            metrics: RelayMetrics::new(),
            connection_id,
            dns_cache,
        })
    }

    pub fn get_metrics(&self) -> &RelayMetrics {
        &self.metrics
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

    pub async fn run_with_tun(&self) -> Result<()> {
        let mut tun_handler =
            TunHandler::new(self.config.clone())?.with_server_ip(self.server_addr.ip());
        let (tx, mut rx) = mpsc::channel(self.config.max_packet_queue);

        let tun_handle = {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = tun_handler.run(tx).await {
                    error!("TUN handler error: {}", e);
                }
            })
        };

        let client_handle = {
            let client = self.clone_for_task();
            tokio::spawn(async move {
                loop {
                    match client.connect_and_run_with_packets(&mut rx).await {
                        Ok(_) => break,
                        Err(e) => {
                            error!("Connection error: {}, reconnecting...", e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                client.config.reconnect_interval,
                            ))
                            .await;
                        }
                    }
                }
            })
        };

        tokio::select! {
            _ = tun_handle => {
                warn!("TUN handler exited");
            }
            _ = client_handle => {
                warn!("Client handler exited");
            }
        }

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

        let mut buffer = vec![0u8; self.config.buffer_size];

        let keepalive_handle = {
            let interval = self.config.keepalive_interval;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                    debug!("Sending keepalive ping");
                }
            })
        };

        loop {
            tokio::select! {
                result = recv.read(&mut buffer) => {
                    match result {
                        Ok(Some(len)) => {
                            self.metrics.record_received(len as u64);

                            let data = Bytes::copy_from_slice(&buffer[..len]);
                            if let Ok(message) = RelayMessage::decode(data) {
                                self.handle_message(message).await?;
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

    async fn connect_and_run_with_packets(&self, rx: &mut mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let connection = self
            .endpoint
            .connect(self.server_addr, "localhost")?
            .await?;

        info!("✅ Connected to relay server (TUN mode)");
        self.metrics.record_connection_opened();

        let (mut send, mut recv) = connection.open_bi().await?;

        let connect_msg = RelayMessage::connect(self.connection_id);
        send.write_all(&connect_msg.encode()?).await?;

        let mut recv_buf = vec![0u8; self.config.buffer_size];

        loop {
            tokio::select! {
                Some(packet) = rx.recv() => {
                    if let Err(e) = self.send_packet(&mut send, packet).await {
                        error!("Failed to send packet: {}", e);
                    }
                }
                result = recv.read(&mut recv_buf) => {
                    match result {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        }

        self.metrics.record_connection_closed();
        Ok(())
    }

    async fn send_packet(&self, send: &mut quinn::SendStream, packet: Vec<u8>) -> Result<()> {
        let sequence = SEQUENCE_COUNTER.fetch_add(1, Ordering::SeqCst);

        let mut message = RelayMessage::data(self.connection_id, sequence, packet);

        if self.config.enable_compression
            && should_compress(&message.payload, self.config.compression_threshold)
        {
            let compressed = compress_data(&message.payload)?;

            if compressed.len() < message.payload.len() {
                let saved = message.payload.len() - compressed.len();
                self.metrics.record_compression_saved(saved as u64);
                message.payload = compressed;
                message.compressed = true;
            }
        }

        let encoded = message.encode()?;
        send.write_all(&encoded).await?;
        self.metrics.record_sent(encoded.len() as u64);

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
        }
    }
}
