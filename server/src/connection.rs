use anyhow::{Context, Result};
use bytes::BufMut;
use oxidize_common::zero_copy::BufferPool;
use oxidize_common::{decompress_data, MessageType, RelayMessage, RelayMetrics};
use quinn::{RecvStream, SendStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::cache::DataCache;
use crate::config::Config;

static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Shared buffer pool for zero-copy packet handling
static BUFFER_POOL: std::sync::OnceLock<Mutex<BufferPool>> = std::sync::OnceLock::new();

fn get_buffer_pool() -> &'static Mutex<BufferPool> {
    BUFFER_POOL.get_or_init(|| Mutex::new(BufferPool::new(65536, 64, 256)))
}

/// Optimized connection handler with:
/// - Split streams (no mutex on hot path)
/// - Zero-copy buffer pooling
/// - Latency instrumentation
/// - Batched ACKs to reduce round-trips
pub struct ConnectionHandler {
    id: u64,
    send_stream: SendStream,
    recv_stream: RecvStream,
    metrics: RelayMetrics,
    config: Config,
    cache: Arc<DataCache>,
    pending_acks: Vec<(u64, u64)>,
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
            send_stream,
            recv_stream,
            metrics,
            config,
            cache,
            pending_acks: Vec::with_capacity(16),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn handle(mut self) -> Result<()> {
        debug!("Starting optimized connection handler for {}", self.id);

        let mut buffer = {
            let mut pool = get_buffer_pool().lock().await;
            pool.get()
        };

        if buffer.capacity() < self.config.buffer_size {
            buffer.reserve(self.config.buffer_size - buffer.capacity());
        }

        let mut raw_buf = vec![0u8; self.config.buffer_size];

        loop {
            match self.recv_stream.read(&mut raw_buf).await {
                Ok(Some(len)) => {
                    let process_start = Instant::now();
                    self.metrics.record_received(len as u64);

                    buffer.clear();
                    buffer.put_slice(&raw_buf[..len]);
                    let data = buffer.clone().freeze();

                    let decode_start = Instant::now();
                    match RelayMessage::decode(data) {
                        Ok(message) => {
                            self.metrics.record_decode_latency(decode_start.elapsed());

                            if let Err(e) = self.process_message(message).await {
                                error!("Failed to process message: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode message: {}", e);
                        }
                    }

                    self.metrics.record_process_latency(process_start.elapsed());

                    // Always batch ACKs (8 per batch for optimal performance)
                    if self.pending_acks.len() >= 8 {
                        self.flush_acks().await;
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

        {
            let mut pool = get_buffer_pool().lock().await;
            pool.put(buffer);
        }

        Ok(())
    }

    async fn process_message(&mut self, message: RelayMessage) -> Result<()> {
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

    async fn handle_connect(&mut self, message: RelayMessage) -> Result<()> {
        info!("Connection request: id={}", message.connection_id);

        let ack = RelayMessage::connect_ack(message.connection_id);
        self.send_message(ack).await?;

        Ok(())
    }

    async fn handle_data(&mut self, mut message: RelayMessage) -> Result<()> {
        debug!(
            "Data packet: conn={}, seq={}, size={}, compressed={}",
            message.connection_id,
            message.sequence,
            message.payload.len(),
            message.compressed
        );

        if message.compressed {
            let decompress_start = Instant::now();
            message.payload =
                decompress_data(&message.payload).context("Failed to decompress payload")?;
            self.metrics
                .record_decode_latency(decompress_start.elapsed());

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
            self.pending_acks
                .push((message.connection_id, message.sequence));
        }

        Ok(())
    }

    async fn flush_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }

        let acks: Vec<_> = self.pending_acks.drain(..).collect();
        for (conn_id, seq) in acks {
            let ack = RelayMessage::data_ack(conn_id, seq);
            if let Err(e) = self.send_message(ack).await {
                debug!("Failed to send batched ACK: {}", e);
            }
        }
    }

    async fn send_message(&mut self, message: RelayMessage) -> Result<()> {
        let encode_start = Instant::now();
        let encoded = message.encode()?;
        self.metrics.record_encode_latency(encode_start.elapsed());

        self.send_stream.write_all(&encoded).await?;
        self.metrics.record_sent(encoded.len() as u64);

        Ok(())
    }

    async fn send_pong(&mut self, connection_id: u64) -> Result<()> {
        let pong = RelayMessage::pong(connection_id);
        self.send_message(pong).await
    }

    #[allow(dead_code)]
    async fn forward_to_destination(
        &mut self,
        data: &[u8],
        destination: &str,
        port: u16,
    ) -> Result<()> {
        let forward_start = Instant::now();
        let addr = format!("{}:{}", destination, port);
        let mut stream = TcpStream::connect(&addr)
            .await
            .context(format!("Failed to connect to {}", addr))?;

        stream.write_all(data).await?;

        let mut response = vec![0u8; self.config.buffer_size];
        let len = stream.read(&mut response).await?;

        self.metrics.record_forward_latency(forward_start.elapsed());

        if len > 0 {
            debug!("Received {} bytes from destination", len);
        }

        Ok(())
    }
}
