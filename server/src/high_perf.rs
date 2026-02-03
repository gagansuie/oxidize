//! High-Performance Connection Pipeline
//!
//! Integrates all performance optimizations:
//! - Adaptive FEC for packet loss resilience
//! - Zero-copy buffer management
//! - UDP batching (GSO/GRO)
//! - Multi-path support
//! - Kernel bypass ready abstractions

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use oxidize_common::adaptive_fec::{AdaptiveFec, FecLevel};
use oxidize_common::ai_engine::HeuristicEngine;
use oxidize_common::edge_cache::{CacheConfig, EdgeCache};
use oxidize_common::low_latency::LatencyTracker;
use oxidize_common::ml_optimized::{OptimizedMlEngine, TrafficContext};
use oxidize_common::multipath::{MultipathScheduler, PathId, PathMetrics, SchedulingStrategy};
use oxidize_common::parallel_compression::ParallelCompressor;
use oxidize_common::priority_scheduler::PriorityScheduler;
use oxidize_common::simd_compression::SimdCompressor;
use oxidize_common::simd_fec::FecSimdLevel;
use oxidize_common::udp_batch::{GsoBatch, UdpBatcher, UdpCoalescer};
use oxidize_common::zero_copy::{BufferPool, PacketRingBuffer};

// Optimization modules (simplified - legacy modules removed)
use oxidize_common::deep_packet_inspection::DeepPacketInspector;
use oxidize_common::handoff_prediction::HandoffPredictor;
use oxidize_common::mptcp_redundancy::MptcpRedundancyScheduler;
use oxidize_common::optimization_stats::OptimizationStats;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// High-performance packet pipeline statistics
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub fec_recoveries: u64,
    pub batches_sent: u64,
    pub syscalls_saved: u64,
    pub buffer_reuses: u64,
    pub compression_ratio: f64,
    pub avg_latency_us: f64,
}

/// Configuration for high-performance pipeline
#[derive(Debug, Clone)]
pub struct HighPerfConfig {
    /// Enable adaptive FEC
    pub enable_fec: bool,
    /// Enable packet batching
    pub enable_batching: bool,
    /// Enable zero-copy buffers
    pub enable_zero_copy: bool,
    /// Enable multi-path
    pub enable_multipath: bool,
    /// Enable parallel compression
    pub enable_parallel_compression: bool,
    /// Enable priority scheduling
    pub enable_priority_scheduler: bool,
    /// Enable SIMD FEC acceleration
    pub enable_simd_fec: bool,
    /// Enable edge caching for static content
    pub enable_edge_cache: bool,
    /// Maximum edge cache size in bytes
    pub edge_cache_size: usize,
    /// Maximum number of cache entries
    pub edge_cache_entries: usize,
    /// Buffer pool size
    pub buffer_pool_size: usize,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Batch flush interval
    pub batch_flush_us: u64,
}

impl Default for HighPerfConfig {
    fn default() -> Self {
        HighPerfConfig {
            enable_fec: true,
            enable_batching: true,
            enable_zero_copy: true,
            enable_multipath: false, // Requires multiple interfaces
            enable_parallel_compression: true,
            enable_priority_scheduler: true,
            enable_simd_fec: true,
            enable_edge_cache: true,
            edge_cache_size: 64 * 1024 * 1024, // 64MB
            edge_cache_entries: 10000,
            buffer_pool_size: 256,
            max_batch_size: 64,
            batch_flush_us: 100,
        }
    }
}

/// High-performance packet pipeline
pub struct HighPerfPipeline {
    /// Configuration
    config: HighPerfConfig,
    /// Adaptive FEC encoder/decoder
    fec: Mutex<AdaptiveFec>,
    /// Buffer pool for zero-copy
    buffer_pool: Mutex<BufferPool>,
    /// UDP batcher for GSO
    batcher: Mutex<UdpBatcher>,
    /// UDP coalescer for GRO
    coalescer: Mutex<UdpCoalescer>,
    /// Multi-path scheduler
    multipath: Mutex<MultipathScheduler>,
    /// ML path selector engine
    ml_engine: Mutex<OptimizedMlEngine>,
    /// Parallel compressor for multi-threaded compression
    parallel_compressor: ParallelCompressor,
    /// Priority scheduler for traffic prioritization
    priority_scheduler: Mutex<PriorityScheduler>,
    /// SIMD FEC level detected at runtime
    simd_fec_level: FecSimdLevel,
    /// Packet ring buffer for queueing
    #[allow(dead_code)]
    ring_buffer: Mutex<PacketRingBuffer>,
    /// Statistics
    stats: Arc<PipelineStatsAtomic>,
    /// Last batch flush time
    last_flush: Mutex<Instant>,
    /// Latency tracker for µs-precision monitoring
    #[allow(dead_code)]
    latency_tracker: LatencyTracker,
    /// Heuristic AI engine for fallback decisions
    #[allow(dead_code)]
    heuristic_engine: HeuristicEngine,
    /// SIMD-accelerated compressor
    #[allow(dead_code)]
    simd_compressor: SimdCompressor,
    // ===== Optimization Modules =====
    /// MPTCP-style redundancy scheduler
    mptcp_scheduler: MptcpRedundancyScheduler,
    /// ML handoff prediction (WiFi→LTE)
    handoff_predictor: HandoffPredictor,
    /// Deep packet inspection + app fingerprinting
    dpi: DeepPacketInspector,
    /// Edge cache for static content
    edge_cache: Mutex<EdgeCache>,
}

/// Atomic statistics for lock-free updates
struct PipelineStatsAtomic {
    packets_processed: AtomicU64,
    bytes_processed: AtomicU64,
    fec_recoveries: AtomicU64,
    batches_sent: AtomicU64,
    syscalls_saved: AtomicU64,
    buffer_reuses: AtomicU64,
}

impl Default for PipelineStatsAtomic {
    fn default() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            fec_recoveries: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
            syscalls_saved: AtomicU64::new(0),
            buffer_reuses: AtomicU64::new(0),
        }
    }
}

impl HighPerfPipeline {
    pub fn new(config: HighPerfConfig) -> Self {
        // Detect SIMD FEC level at runtime
        let simd_fec_level = FecSimdLevel::detect();
        tracing::info!("SIMD FEC level: {:?}", simd_fec_level);

        HighPerfPipeline {
            fec: Mutex::new(AdaptiveFec::new()),
            buffer_pool: Mutex::new(BufferPool::new(65536, 64, config.buffer_pool_size)),
            batcher: Mutex::new(UdpBatcher::with_config(config.max_batch_size, 1472)),
            coalescer: Mutex::new(UdpCoalescer::default()),
            multipath: Mutex::new(MultipathScheduler::new(SchedulingStrategy::Weighted)),
            ml_engine: Mutex::new(OptimizedMlEngine::new()),
            parallel_compressor: ParallelCompressor::new(100), // Min 100 bytes to compress
            priority_scheduler: Mutex::new(PriorityScheduler::new(1000)),
            simd_fec_level,
            ring_buffer: Mutex::new(PacketRingBuffer::new(1024 * 1024)), // 1MB ring
            stats: Arc::new(PipelineStatsAtomic::default()),
            last_flush: Mutex::new(Instant::now()),
            latency_tracker: LatencyTracker::default(),
            heuristic_engine: HeuristicEngine::new(),
            simd_compressor: SimdCompressor::new(),
            // Optimization modules
            mptcp_scheduler: MptcpRedundancyScheduler::default(),
            handoff_predictor: HandoffPredictor::new(),
            dpi: DeepPacketInspector::new(),
            // Edge cache
            edge_cache: Mutex::new(EdgeCache::new(CacheConfig {
                max_size: config.edge_cache_size,
                max_entries: config.edge_cache_entries,
                enabled: config.enable_edge_cache,
                ..Default::default()
            })),
            config,
        }
    }

    /// Get unified optimization statistics
    pub fn optimization_stats(&self) -> OptimizationStats {
        OptimizationStats::collect(
            Some(&self.mptcp_scheduler),
            Some(&self.handoff_predictor),
            Some(&self.dpi),
        )
    }

    /// Inspect packet and identify application
    pub fn inspect_packet(
        &self,
        src_ip: std::net::IpAddr,
        src_port: u16,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        payload: &[u8],
        packet_size: u16,
    ) -> oxidize_common::deep_packet_inspection::IdentifiedApp {
        self.dpi
            .inspect(src_ip, src_port, dst_ip, dst_port, payload, packet_size)
    }

    /// Process outgoing packet through the pipeline
    pub async fn process_outgoing(&self, data: &[u8], dest: SocketAddr) -> Result<ProcessedPacket> {
        let start = Instant::now();

        // Get buffer from pool
        let _buffer = if self.config.enable_zero_copy {
            let mut pool = self.buffer_pool.lock().await;
            self.stats.buffer_reuses.fetch_add(1, Ordering::Relaxed);
            pool.get()
        } else {
            BytesMut::with_capacity(data.len() + 64)
        };

        // Apply FEC if enabled
        let encoded_data = if self.config.enable_fec {
            let mut fec = self.fec.lock().await;
            let packet = fec.encode(data)?;

            // For now, just use first shard (full integration would send all shards)
            if packet.shards.len() == 1 {
                Bytes::from(packet.shards[0].clone())
            } else {
                // Combine shards for transmission
                let mut combined =
                    BytesMut::with_capacity(packet.shards.iter().map(|s| s.len()).sum());
                for shard in &packet.shards {
                    combined.extend_from_slice(shard);
                }
                combined.freeze()
            }
        } else {
            Bytes::copy_from_slice(data)
        };

        // Queue for batching if enabled
        if self.config.enable_batching {
            let mut batcher = self.batcher.lock().await;
            batcher.queue(dest, encoded_data.clone());

            // Check if we should flush
            let should_flush = batcher.should_flush() || {
                let last = self.last_flush.lock().await;
                last.elapsed().as_micros() as u64 >= self.config.batch_flush_us
            };

            if should_flush {
                let batches = batcher.flush();
                self.stats
                    .batches_sent
                    .fetch_add(batches.len() as u64, Ordering::Relaxed);

                let syscalls_saved: u64 = batches
                    .iter()
                    .map(|b| b.count.saturating_sub(1) as u64)
                    .sum();
                self.stats
                    .syscalls_saved
                    .fetch_add(syscalls_saved, Ordering::Relaxed);

                *self.last_flush.lock().await = Instant::now();

                return Ok(ProcessedPacket {
                    data: encoded_data,
                    dest,
                    batches: Some(batches),
                    latency_us: start.elapsed().as_micros() as u64,
                });
            }
        }

        // Update stats
        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_processed
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(ProcessedPacket {
            data: encoded_data,
            dest,
            batches: None,
            latency_us: start.elapsed().as_micros() as u64,
        })
    }

    /// Process incoming packet through the pipeline
    pub async fn process_incoming(&self, data: &[u8], _src: SocketAddr) -> Result<Vec<Bytes>> {
        let mut results = Vec::new();

        // Process through GRO coalescer if enabled
        let packets = if self.config.enable_batching {
            let mut coalescer = self.coalescer.lock().await;
            coalescer.process_gro(data, 1472)
        } else {
            vec![Bytes::copy_from_slice(data)]
        };

        // Decode FEC if enabled
        for packet in packets {
            let decoded = if self.config.enable_fec {
                // In full implementation, would track and reconstruct FEC groups
                packet
            } else {
                packet
            };

            results.push(decoded);
        }

        // Update stats
        self.stats
            .packets_processed
            .fetch_add(results.len() as u64, Ordering::Relaxed);
        self.stats
            .bytes_processed
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(results)
    }

    /// Add a network path for multi-path support
    pub async fn add_path(&self, local: SocketAddr, remote: SocketAddr, metrics: PathMetrics) {
        if self.config.enable_multipath {
            let mut mp = self.multipath.lock().await;
            mp.add_path(PathId::new(local, remote), metrics);
        }
    }

    /// Get next path for sending (multi-path)
    pub async fn next_path(&self) -> Option<PathId> {
        self.next_path_for_traffic(TrafficContext::Web).await
    }

    /// Get next path for sending using ML selection for a traffic class
    pub async fn next_path_for_traffic(&self, traffic: TrafficContext) -> Option<PathId> {
        if !self.config.enable_multipath {
            return None;
        }

        let mut mp = self.multipath.lock().await;
        let mut ml_engine = self.ml_engine.lock().await;

        if let Some(path) = mp.select_path_ml(&mut ml_engine, traffic) {
            return Some(path);
        }

        mp.next_path()
    }

    /// Record packet acknowledgment (for FEC adaptation)
    pub async fn ack_packet(&self, seq: u64) {
        let mut fec = self.fec.lock().await;
        fec.ack(seq);
    }

    /// Get current FEC level
    pub async fn fec_level(&self) -> FecLevel {
        let fec = self.fec.lock().await;
        fec.level()
    }

    /// Flush all pending batches
    pub async fn flush(&self) -> Vec<GsoBatch> {
        let mut batcher = self.batcher.lock().await;
        batcher.flush_all()
    }

    /// Compress data using parallel compression if enabled
    pub fn compress_parallel(&self, data: &[u8]) -> Vec<u8> {
        if self.config.enable_parallel_compression {
            self.parallel_compressor.compress(data)
        } else {
            data.to_vec()
        }
    }

    /// Get compression statistics
    pub fn compression_stats(&self) -> f64 {
        self.parallel_compressor.stats.compression_ratio()
    }

    /// Get the detected SIMD FEC level
    pub fn simd_level(&self) -> FecSimdLevel {
        self.simd_fec_level
    }

    /// Check if SIMD FEC is available
    pub fn has_simd_fec(&self) -> bool {
        self.config.enable_simd_fec && self.simd_fec_level != FecSimdLevel::Scalar
    }

    /// Get number of streams in priority scheduler
    pub async fn scheduled_streams(&self) -> usize {
        let scheduler = self.priority_scheduler.lock().await;
        scheduler.pending_count()
    }

    /// Get pipeline statistics
    pub fn stats(&self) -> PipelineStats {
        PipelineStats {
            packets_processed: self.stats.packets_processed.load(Ordering::Relaxed),
            bytes_processed: self.stats.bytes_processed.load(Ordering::Relaxed),
            fec_recoveries: self.stats.fec_recoveries.load(Ordering::Relaxed),
            batches_sent: self.stats.batches_sent.load(Ordering::Relaxed),
            syscalls_saved: self.stats.syscalls_saved.load(Ordering::Relaxed),
            buffer_reuses: self.stats.buffer_reuses.load(Ordering::Relaxed),
            compression_ratio: 1.0, // Would calculate from actual data
            avg_latency_us: 0.0,    // Would track moving average
        }
    }

    /// Return buffer to pool
    pub async fn return_buffer(&self, buffer: BytesMut) {
        if self.config.enable_zero_copy {
            let mut pool = self.buffer_pool.lock().await;
            pool.put(buffer);
        }
    }

    // =========================================================================
    // Edge Cache API
    // =========================================================================

    /// Get cached content by key
    pub async fn cache_get(&self, key: &str) -> Option<Bytes> {
        if !self.config.enable_edge_cache {
            return None;
        }
        let mut cache = self.edge_cache.lock().await;
        cache.get(key).map(|entry| entry.data.clone())
    }

    /// Put content into cache
    pub async fn cache_put(&self, key: &str, data: Bytes, content_type: &str) {
        if !self.config.enable_edge_cache {
            return;
        }
        let mut cache = self.edge_cache.lock().await;
        cache.put(
            key.to_string(),
            oxidize_common::edge_cache::CacheEntry::new(
                data,
                content_type,
                std::time::Duration::from_secs(3600),
            ),
        );
    }

    /// Get cache hit rate
    pub async fn cache_hit_rate(&self) -> f64 {
        let cache = self.edge_cache.lock().await;
        cache.stats.hit_rate()
    }

    /// Check if edge cache is enabled
    pub fn is_edge_cache_enabled(&self) -> bool {
        self.config.enable_edge_cache
    }
}

impl Default for HighPerfPipeline {
    fn default() -> Self {
        Self::new(HighPerfConfig::default())
    }
}

/// Processed packet ready for transmission
#[derive(Debug)]
pub struct ProcessedPacket {
    /// Encoded data
    pub data: Bytes,
    /// Destination address
    pub dest: SocketAddr,
    /// Batched packets (if batching triggered flush)
    pub batches: Option<Vec<GsoBatch>>,
    /// Processing latency in microseconds
    pub latency_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820)
    }

    #[tokio::test]
    async fn test_pipeline_basic() {
        let pipeline = HighPerfPipeline::default();
        let data = b"Hello, World!";

        let result = pipeline.process_outgoing(data, test_addr()).await.unwrap();
        assert!(!result.data.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_no_fec() {
        let config = HighPerfConfig {
            enable_fec: false,
            ..Default::default()
        };
        let pipeline = HighPerfPipeline::new(config);
        let data = b"Test data";

        let result = pipeline.process_outgoing(data, test_addr()).await.unwrap();
        assert_eq!(result.data.as_ref(), data);
    }

    #[tokio::test]
    async fn test_pipeline_batching() {
        let config = HighPerfConfig {
            enable_fec: false,
            enable_batching: true,
            max_batch_size: 4,
            ..Default::default()
        };
        let pipeline = HighPerfPipeline::new(config);

        // Queue packets
        for i in 0..5 {
            let _ = pipeline
                .process_outgoing(format!("packet {}", i).as_bytes(), test_addr())
                .await;
        }

        // Should have triggered at least one batch
        let stats = pipeline.stats();
        assert!(stats.batches_sent >= 1);
    }

    #[tokio::test]
    async fn test_incoming_processing() {
        let pipeline = HighPerfPipeline::default();
        let data = b"Incoming data";

        let results = pipeline.process_incoming(data, test_addr()).await.unwrap();
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_stats() {
        let pipeline = HighPerfPipeline::default();

        for _ in 0..10 {
            let _ = pipeline.process_outgoing(b"test", test_addr()).await;
        }

        let stats = pipeline.stats();
        assert!(stats.buffer_reuses > 0);
    }
}
