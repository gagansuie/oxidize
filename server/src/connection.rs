use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{RecvStream, SendStream};
use oxidize_common::{decompress_data, MessageType, RelayMessage, RelayMetrics};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::cache::DataCache;
use crate::config::Config;

static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct ConnectionHandler {
    id: u64,
    send_stream: tokio::sync::Mutex<SendStream>,
    recv_stream: tokio::sync::Mutex<RecvStream>,
    metrics: RelayMetrics,
    config: Config,
    cache: Arc<DataCache>,
}

impl ConnectionHandler {
    pub fn new(
        send_stream: SendStream,
        recv_stream: RecvStream,
        metrics: RelayMetrics,
        config: Config,
        cache: Arc<DataCache>,
    ) -> Self {
        let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

        Self {
            id,
            send_stream: tokio::sync::Mutex::new(send_stream),
            recv_stream: tokio::sync::Mutex::new(recv_stream),
            metrics,
            config,
            cache,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn handle(&self) -> Result<()> {
        debug!("Starting connection handler for {}", self.id);

        let mut recv = self.recv_stream.lock().await;
        let mut buffer = vec![0u8; self.config.buffer_size];

        loop {
            match recv.read(&mut buffer).await {
                Ok(Some(len)) => {
                    self.metrics.record_received(len as u64);

                    let data = Bytes::copy_from_slice(&buffer[..len]);

                    match RelayMessage::decode(data) {
                        Ok(message) => {
                            if let Err(e) = self.process_message(message).await {
                                error!("Failed to process message: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode message: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    debug!("Stream closed");
                    break;
                }
                Err(e) => {
                    error!("Read error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_message(&self, message: RelayMessage) -> Result<()> {
        match message.msg_type {
            MessageType::Connect => {
                self.handle_connect(message).await?;
            }
            MessageType::Data => {
                self.handle_data(message).await?;
            }
            MessageType::Ping => {
                self.send_pong(message.connection_id).await?;
            }
            MessageType::Disconnect => {
                debug!(
                    "Disconnect requested for connection {}",
                    message.connection_id
                );
            }
            _ => {
                debug!("Unhandled message type: {:?}", message.msg_type);
            }
        }

        Ok(())
    }

    async fn handle_connect(&self, message: RelayMessage) -> Result<()> {
        info!("Connection request: id={}", message.connection_id);

        let ack = RelayMessage::connect_ack(message.connection_id);
        self.send_message(ack).await?;

        Ok(())
    }

    async fn handle_data(&self, mut message: RelayMessage) -> Result<()> {
        debug!(
            "Data packet: conn={}, seq={}, size={}, compressed={}",
            message.connection_id,
            message.sequence,
            message.payload.len(),
            message.compressed
        );

        if message.compressed {
            message.payload =
                decompress_data(&message.payload).context("Failed to decompress payload")?;

            let original_size = message.payload.len();
            self.metrics
                .record_compression_saved((original_size - message.payload.len()) as u64);
        }

        if self.config.enable_deduplication {
            if let Some(_cached) = self.cache.get(&message.payload).await {
                debug!("Cache hit for {} bytes", message.payload.len());
                return Ok(());
            }
            self.cache.insert(message.payload.clone()).await;
        }

        if self.config.enable_tcp_acceleration {
            let ack = RelayMessage::data_ack(message.connection_id, message.sequence);
            tokio::spawn(async move {
                let _ = Self::send_immediate_ack(ack).await;
            });
        }

        Ok(())
    }

    async fn send_message(&self, message: RelayMessage) -> Result<()> {
        let encoded = message.encode()?;
        let mut send = self.send_stream.lock().await;
        send.write_all(&encoded).await?;

        self.metrics.record_sent(encoded.len() as u64);

        Ok(())
    }

    async fn send_pong(&self, connection_id: u64) -> Result<()> {
        let pong = RelayMessage::pong(connection_id);
        self.send_message(pong).await
    }

    async fn send_immediate_ack(ack: RelayMessage) -> Result<()> {
        debug!("Sending immediate ACK for seq={}", ack.sequence);
        Ok(())
    }

    async fn forward_to_destination(
        &self,
        data: &[u8],
        destination: &str,
        port: u16,
    ) -> Result<()> {
        let addr = format!("{}:{}", destination, port);
        let mut stream = TcpStream::connect(&addr)
            .await
            .context(format!("Failed to connect to {}", addr))?;

        stream.write_all(data).await?;

        let mut response = vec![0u8; self.config.buffer_size];
        let len = stream.read(&mut response).await?;

        if len > 0 {
            debug!("Received {} bytes from destination", len);
        }

        Ok(())
    }
}
