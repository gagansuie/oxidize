use crate::config::ClientConfig;
use crate::dns_cache::DnsCache;
use crate::tun_handler::TunHandler;
use anyhow::{Context, Result};
use oxidize_common::{
    compress_data, should_compress, MessageFramer, MessageType, RelayMessage, RelayMetrics,
};
use quinn::ClientConfig as QuinnClientConfig;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
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

        // Initial RTT estimate for better initial performance
        transport_config.initial_rtt(std::time::Duration::from_millis(50));

        // Enable QUIC datagrams for unreliable low-latency traffic (gaming/VoIP)
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.datagram_send_buffer_size(65536);

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
        // CRITICAL: Verify connection works BEFORE setting up TUN routing
        // Otherwise, if connection fails, all system traffic gets black-holed
        info!("Verifying server connection before TUN setup...");

        let test_connection = self.endpoint.connect(self.server_addr, "localhost")?.await;

        match test_connection {
            Ok(conn) => {
                info!("✅ Server connection verified");
                conn.close(0u32.into(), b"test complete");
            }
            Err(e) => {
                error!("❌ Cannot connect to server: {}", e);
                error!("TUN setup aborted to prevent system lockup.");
                error!("Fix the connection issue first, then retry.");
                return Err(anyhow::anyhow!("Server connection failed: {}", e));
            }
        }

        // Connection verified - now safe to set up TUN
        let mut tun_handler =
            TunHandler::new(self.config.clone())?.with_server_ip(self.server_addr.ip());

        // tx: TUN reads -> client sends to server
        // response_tx: client receives from server -> TUN writes
        let (tx, mut rx) = mpsc::channel(self.config.max_packet_queue);
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>(4096);

        let tun_handle = {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = tun_handler.run(tx, response_rx).await {
                    error!("TUN handler error: {}", e);
                }
            })
        };

        let client_handle = {
            let client = self.clone_for_task();
            tokio::spawn(async move {
                loop {
                    match client
                        .connect_and_run_with_packets(&mut rx, response_tx.clone())
                        .await
                    {
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
        let mut framer = MessageFramer::with_capacity(self.config.buffer_size);

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

        let (mut send, mut recv) = connection.open_bi().await?;

        let connect_msg = RelayMessage::connect(self.connection_id);
        send.write_all(&connect_msg.encode()?).await?;

        let mut recv_buf = vec![0u8; self.config.buffer_size];
        let mut framer = MessageFramer::with_capacity(self.config.buffer_size);

        loop {
            tokio::select! {
                Some(packet) = rx.recv() => {
                    if let Err(e) = self.send_packet(&mut send, packet).await {
                        error!("Failed to send packet: {}", e);
                    }
                }
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

    async fn send_packet(&self, send: &mut quinn::SendStream, packet: Vec<u8>) -> Result<()> {
        let process_start = Instant::now();
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
        }
    }
}
