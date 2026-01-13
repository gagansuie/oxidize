//! OxTunnel Client Integration
//!
//! Provides packet batching, optional encryption, and OxTunnel encapsulation
//! for the daemon's NFQUEUE pipeline. Works with both QUIC transport and raw UDP.

use crate::oxtunnel_protocol::{
    encode_packet, flags, generate_id, CryptoEngine, HandshakeInit, PacketBatch, TunnelBufferPool,
    HEADER_SIZE, MAX_PACKET_SIZE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// OxTunnel client configuration
#[derive(Clone, Debug)]
pub struct OxTunnelConfig {
    pub enable_batching: bool,
    pub max_batch_size: usize,
    pub batch_timeout_us: u64,
    pub enable_encryption: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub enable_compression: bool,
    pub server_addr: SocketAddr,
}

impl Default for OxTunnelConfig {
    fn default() -> Self {
        Self {
            enable_batching: true,
            max_batch_size: 64,
            batch_timeout_us: 1000,
            enable_encryption: false,
            encryption_key: None,
            enable_compression: false,
            server_addr: "127.0.0.1:51820".parse().unwrap(),
        }
    }
}

/// Statistics for the OxTunnel client
pub struct ClientStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub batches_sent: AtomicU64,
}

impl ClientStats {
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
        }
    }
}

impl Default for ClientStats {
    fn default() -> Self {
        Self::new()
    }
}

struct PacketBatchState {
    packets: Vec<Vec<u8>>,
    total_size: usize,
    first_packet_time: Option<Instant>,
}

impl PacketBatchState {
    fn new() -> Self {
        Self {
            packets: Vec::with_capacity(64),
            total_size: 0,
            first_packet_time: None,
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.total_size = 0;
        self.first_packet_time = None;
    }
}

/// Encapsulates packets using OxTunnel protocol before sending
pub struct OxTunnelEncapsulator {
    config: OxTunnelConfig,
    client_id: [u8; 32],
    sequence: AtomicU32,
    crypto: Option<CryptoEngine>,
    #[allow(dead_code)]
    buffer_pool: Arc<TunnelBufferPool>,
    stats: Arc<ClientStats>,
    batch: Mutex<PacketBatchState>,
}

impl OxTunnelEncapsulator {
    pub fn new(config: OxTunnelConfig) -> Self {
        let client_id = generate_id();
        let crypto = if config.enable_encryption {
            let key = config
                .encryption_key
                .unwrap_or_else(CryptoEngine::generate_key);
            Some(CryptoEngine::new(Some(&key)))
        } else {
            None
        };

        Self {
            config,
            client_id,
            sequence: AtomicU32::new(0),
            crypto,
            buffer_pool: Arc::new(TunnelBufferPool::new()),
            stats: Arc::new(ClientStats::new()),
            batch: Mutex::new(PacketBatchState::new()),
        }
    }

    #[inline]
    fn next_seq(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub fn encapsulate_single(&self, packet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let seq = self.next_seq();
        let mut flags_byte = 0u8;

        let payload = if self.config.enable_compression && packet.len() > 64 {
            flags_byte |= flags::COMPRESSED;
            lz4_flex::compress_prepend_size(packet)
        } else {
            packet.to_vec()
        };

        let crypto_ref = if self.config.enable_encryption {
            flags_byte |= flags::ENCRYPTED;
            self.crypto.as_ref()
        } else {
            None
        };

        let mut output = vec![0u8; HEADER_SIZE + payload.len() + 32];
        let len = encode_packet(&mut output, &payload, seq, flags_byte, crypto_ref)?;
        output.truncate(len);

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);

        Ok(output)
    }

    pub fn add_to_batch(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut batch = self.batch.lock().unwrap();

        let new_size = batch.total_size + packet.len() + 2;
        let should_flush = new_size > MAX_PACKET_SIZE - HEADER_SIZE - 32
            || batch.packets.len() >= self.config.max_batch_size;

        if should_flush && !batch.packets.is_empty() {
            let result = self.flush_batch_locked(&mut batch);
            batch.packets.push(packet.to_vec());
            batch.total_size = packet.len() + 2;
            batch.first_packet_time = Some(Instant::now());
            return result;
        }

        batch.packets.push(packet.to_vec());
        batch.total_size = new_size;
        if batch.first_packet_time.is_none() {
            batch.first_packet_time = Some(Instant::now());
        }

        None
    }

    pub fn check_batch_timeout(&self) -> Option<Vec<u8>> {
        let mut batch = self.batch.lock().unwrap();
        if batch.packets.is_empty() {
            return None;
        }
        if let Some(first_time) = batch.first_packet_time {
            if first_time.elapsed() > Duration::from_micros(self.config.batch_timeout_us) {
                return self.flush_batch_locked(&mut batch);
            }
        }
        None
    }

    pub fn flush_batch(&self) -> Option<Vec<u8>> {
        let mut batch = self.batch.lock().unwrap();
        self.flush_batch_locked(&mut batch)
    }

    fn flush_batch_locked(&self, batch: &mut PacketBatchState) -> Option<Vec<u8>> {
        if batch.packets.is_empty() {
            return None;
        }

        let packet_count = batch.packets.len();
        let mut batch_obj = PacketBatch::new();
        for pkt in &batch.packets {
            batch_obj.add(pkt);
        }
        batch.clear();

        let mut payload = vec![0u8; MAX_PACKET_SIZE];
        let payload_len = match batch_obj.encode(&mut payload) {
            Ok(len) => len,
            Err(e) => {
                error!("Failed to encode batch: {}", e);
                return None;
            }
        };
        payload.truncate(payload_len);

        let seq = self.next_seq();
        let mut flags_byte = flags::BATCH;

        let crypto_ref = if self.config.enable_encryption {
            flags_byte |= flags::ENCRYPTED;
            self.crypto.as_ref()
        } else {
            None
        };

        let mut output = vec![0u8; HEADER_SIZE + payload.len() + 32];
        match encode_packet(&mut output, &payload, seq, flags_byte, crypto_ref) {
            Ok(len) => {
                output.truncate(len);
                self.stats
                    .packets_sent
                    .fetch_add(packet_count as u64, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                Some(output)
            }
            Err(e) => {
                error!("Failed to encode batch packet: {}", e);
                None
            }
        }
    }

    pub fn create_handshake(&self) -> Vec<u8> {
        let init = HandshakeInit {
            client_id: self.client_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            encryption_supported: self.config.enable_encryption,
        };

        let mut payload = [0u8; 64];
        let payload_len = init.encode(&mut payload);
        let mut output = vec![0u8; HEADER_SIZE + payload_len];
        let len = encode_packet(
            &mut output,
            &payload[..payload_len],
            0,
            flags::CONTROL,
            None,
        )
        .unwrap_or(0);
        output.truncate(len);
        output
    }

    pub fn stats(&self) -> &Arc<ClientStats> {
        &self.stats
    }

    pub fn client_id(&self) -> &[u8; 32] {
        &self.client_id
    }

    pub fn config(&self) -> &OxTunnelConfig {
        &self.config
    }
}

/// High-performance OxTunnel sender that batches packets
pub struct OxTunnelSender {
    encapsulator: Arc<OxTunnelEncapsulator>,
    output_tx: mpsc::Sender<Vec<u8>>,
}

impl OxTunnelSender {
    pub fn new(config: OxTunnelConfig, output_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            encapsulator: Arc::new(OxTunnelEncapsulator::new(config)),
            output_tx,
        }
    }

    pub async fn run(&self, mut input_rx: mpsc::Receiver<Vec<u8>>) {
        info!(
            "📦 OxTunnel sender started (batching: {}, encryption: {})",
            self.encapsulator.config.enable_batching, self.encapsulator.config.enable_encryption
        );

        let mut packet_count: u64 = 0;
        let mut batch_count: u64 = 0;
        let start = Instant::now();

        let encap = self.encapsulator.clone();
        let tx = self.output_tx.clone();
        let timeout_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_micros(500));
            loop {
                interval.tick().await;
                if let Some(batch) = encap.check_batch_timeout() {
                    if tx.send(batch).await.is_err() {
                        break;
                    }
                }
            }
        });

        loop {
            tokio::select! {
                Some(packet) = input_rx.recv() => {
                    packet_count += 1;

                    if self.encapsulator.config.enable_batching {
                        if let Some(batch) = self.encapsulator.add_to_batch(&packet) {
                            batch_count += 1;
                            if self.output_tx.send(batch).await.is_err() {
                                warn!("Output channel closed");
                                break;
                            }
                        }
                    } else {
                        match self.encapsulator.encapsulate_single(&packet) {
                            Ok(encapsulated) => {
                                if self.output_tx.send(encapsulated).await.is_err() {
                                    warn!("Output channel closed");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Encapsulation failed: {}", e);
                            }
                        }
                    }

                    if packet_count.is_multiple_of(10000) {
                        let elapsed = start.elapsed().as_secs_f64();
                        let pps = packet_count as f64 / elapsed;
                        info!("📊 OxTunnel: {} packets, {} batches, {:.0} pps", packet_count, batch_count, pps);
                    }
                }

                else => {
                    if let Some(batch) = self.encapsulator.flush_batch() {
                        let _ = self.output_tx.send(batch).await;
                    }
                    break;
                }
            }
        }

        timeout_task.abort();

        let elapsed = start.elapsed();
        let stats = self.encapsulator.stats();
        info!(
            "📊 OxTunnel sender finished: {} packets, {} batches in {:.2}s ({:.0} pps)",
            stats.packets_sent.load(Ordering::Relaxed),
            stats.batches_sent.load(Ordering::Relaxed),
            elapsed.as_secs_f64(),
            packet_count as f64 / elapsed.as_secs_f64().max(0.001)
        );
    }

    pub fn encapsulator(&self) -> &Arc<OxTunnelEncapsulator> {
        &self.encapsulator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oxtunnel_protocol::PROTOCOL_MAGIC;

    #[test]
    fn test_encapsulate_single() {
        let config = OxTunnelConfig::default();
        let encap = OxTunnelEncapsulator::new(config);
        let packet = vec![0x45, 0x00, 0x00, 0x28];
        let result = encap.encapsulate_single(&packet).unwrap();
        assert_eq!(&result[0..2], &PROTOCOL_MAGIC);
        assert!(result.len() >= HEADER_SIZE + packet.len());
    }

    #[test]
    fn test_batching() {
        let config = OxTunnelConfig {
            enable_batching: true,
            max_batch_size: 3,
            ..Default::default()
        };
        let encap = OxTunnelEncapsulator::new(config);
        let pkt = vec![0x45; 100];
        assert!(encap.add_to_batch(&pkt).is_none());
        assert!(encap.add_to_batch(&pkt).is_none());
        let result = encap.add_to_batch(&pkt);
        let final_batch = encap.flush_batch();
        assert!(result.is_some() || final_batch.is_some());
    }

    #[test]
    fn test_handshake_creation() {
        let config = OxTunnelConfig::default();
        let encap = OxTunnelEncapsulator::new(config);
        let handshake = encap.create_handshake();
        assert_eq!(&handshake[0..2], &PROTOCOL_MAGIC);
        assert!(handshake[2] & flags::CONTROL != 0);
    }
}
