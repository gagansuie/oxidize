//! Parallel LZ4 Compression
//!
//! Uses rayon for multi-threaded compression to handle high throughput (2+ Gbps).
//! Single-threaded LZ4 tops out at ~82 MB/s, but with parallel processing
//! we can scale linearly with CPU cores.
//!
//! Performance targets:
//! - 4 cores: ~320 MB/s (2.5 Gbps)
//! - 8 cores: ~640 MB/s (5 Gbps)
//! - 16 cores: ~1280 MB/s (10 Gbps)

use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics for parallel compression
#[derive(Debug, Default)]
pub struct ParallelCompressionStats {
    pub packets_compressed: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub batches_processed: AtomicU64,
}

impl ParallelCompressionStats {
    pub fn compression_ratio(&self) -> f64 {
        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);
        if bytes_out == 0 {
            1.0
        } else {
            bytes_in as f64 / bytes_out as f64
        }
    }

    pub fn record(&self, bytes_in: usize, bytes_out: usize) {
        self.packets_compressed.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in as u64, Ordering::Relaxed);
        self.bytes_out
            .fetch_add(bytes_out as u64, Ordering::Relaxed);
    }
}

/// Parallel compression engine using rayon thread pool
pub struct ParallelCompressor {
    /// Minimum size to compress (smaller packets skip compression)
    min_size: usize,
    /// Statistics
    pub stats: ParallelCompressionStats,
}

impl ParallelCompressor {
    /// Create a new parallel compressor
    pub fn new(min_size: usize) -> Self {
        ParallelCompressor {
            min_size,
            stats: ParallelCompressionStats::default(),
        }
    }

    /// Create with custom thread pool size
    pub fn with_threads(min_size: usize, num_threads: usize) -> Self {
        // Configure rayon's global thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()
            .ok(); // Ignore if already initialized

        Self::new(min_size)
    }

    /// Compress a single packet (uses thread pool internally for large data)
    pub fn compress(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < self.min_size || !should_compress_parallel(data) {
            return data.to_vec();
        }

        let compressed = compress_prepend_size(data);

        // Only use compressed if it's actually smaller
        if compressed.len() < data.len() {
            self.stats.record(data.len(), compressed.len());
            compressed
        } else {
            data.to_vec()
        }
    }

    /// Compress multiple packets in parallel
    /// This is the main performance win - batch compression across cores
    pub fn compress_batch(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        self.stats.batches_processed.fetch_add(1, Ordering::Relaxed);

        packets
            .par_iter()
            .map(|packet| self.compress(packet))
            .collect()
    }

    /// Decompress a single packet
    pub fn decompress(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        decompress_size_prepended(data)
            .map_err(|e| anyhow::anyhow!("Decompression failed: {:?}", e))
    }

    /// Decompress multiple packets in parallel
    pub fn decompress_batch(&self, packets: &[Vec<u8>]) -> Vec<anyhow::Result<Vec<u8>>> {
        packets
            .par_iter()
            .map(|packet| self.decompress(packet))
            .collect()
    }
}

impl Default for ParallelCompressor {
    fn default() -> Self {
        Self::new(512)
    }
}

/// Check if data should be compressed (entropy check)
/// High-entropy data (encrypted, already compressed) won't benefit
fn should_compress_parallel(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }

    // Sample-based entropy estimation (fast)
    // Check first 64 bytes for repetition patterns
    let sample = &data[..64.min(data.len())];
    let mut byte_counts = [0u8; 256];

    for &b in sample {
        byte_counts[b as usize] = byte_counts[b as usize].saturating_add(1);
    }

    // Count unique bytes - high uniqueness = high entropy = don't compress
    let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count();

    // If more than 90% unique bytes in sample, probably high entropy
    unique_bytes < (sample.len() * 9 / 10)
}

/// Batch compression helper for channel-based processing
pub struct CompressionBatcher {
    compressor: ParallelCompressor,
    batch: Vec<Vec<u8>>,
    batch_size: usize,
}

impl CompressionBatcher {
    pub fn new(min_compress_size: usize, batch_size: usize) -> Self {
        CompressionBatcher {
            compressor: ParallelCompressor::new(min_compress_size),
            batch: Vec::with_capacity(batch_size),
            batch_size,
        }
    }

    /// Add a packet to the batch
    pub fn push(&mut self, packet: Vec<u8>) {
        self.batch.push(packet);
    }

    /// Check if batch is ready for compression
    pub fn should_flush(&self) -> bool {
        self.batch.len() >= self.batch_size
    }

    /// Compress and drain the batch
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.batch.is_empty() {
            return Vec::new();
        }

        let result = self.compressor.compress_batch(&self.batch);
        self.batch.clear();
        result
    }

    /// Get compression stats
    pub fn stats(&self) -> &ParallelCompressionStats {
        &self.compressor.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_compress() {
        let compressor = ParallelCompressor::new(100);

        // Compressible data
        let data = vec![0xAA; 1000];
        let compressed = compressor.compress(&data);
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_parallel_batch() {
        let compressor = ParallelCompressor::new(100);

        let packets: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 500]).collect();

        let compressed = compressor.compress_batch(&packets);
        assert_eq!(compressed.len(), 100);
    }

    #[test]
    fn test_entropy_check() {
        // Low entropy - should compress
        let repetitive = vec![0xAA; 100];
        assert!(should_compress_parallel(&repetitive));

        // High entropy - should not compress
        let random: Vec<u8> = (0..100).map(|i| i as u8).collect();
        assert!(!should_compress_parallel(&random));
    }

    #[test]
    fn test_roundtrip() {
        let compressor = ParallelCompressor::new(100);

        let original = vec![0x42; 1000];
        let compressed = compressor.compress(&original);
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_batcher() {
        let mut batcher = CompressionBatcher::new(100, 10);

        for i in 0..10 {
            batcher.push(vec![i as u8; 500]);
        }

        assert!(batcher.should_flush());
        let result = batcher.flush();
        assert_eq!(result.len(), 10);
    }
}
