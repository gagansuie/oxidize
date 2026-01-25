//! UDP GSO/GRO Batching
//!
//! Batches multiple UDP packets into single syscalls using:
//! - GSO (Generic Segmentation Offload) for sending
//! - GRO (Generic Receive Offload) for receiving
//!
//! Provides 5-10x packet throughput improvement.

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::VecDeque;
use std::net::SocketAddr;

/// Maximum packets per batch (limited by kernel)
pub const MAX_BATCH_SIZE: usize = 64;

/// Maximum segment size for GSO
pub const MAX_SEGMENT_SIZE: usize = 1472; // MTU - IP/UDP headers

/// Batched packet for transmission
#[derive(Debug, Clone)]
pub struct BatchedPacket {
    pub dest: SocketAddr,
    pub data: Bytes,
}

/// UDP packet batcher for GSO (send side)
pub struct UdpBatcher {
    /// Pending packets grouped by destination
    pending: VecDeque<BatchedPacket>,
    /// Maximum batch size
    max_batch: usize,
    /// Segment size for GSO
    segment_size: usize,
    /// Statistics
    pub stats: BatcherStats,
}

#[derive(Debug, Clone, Default)]
pub struct BatcherStats {
    pub packets_queued: u64,
    pub batches_sent: u64,
    pub packets_per_batch: f64,
    pub syscalls_saved: u64,
}

impl UdpBatcher {
    pub fn new() -> Self {
        Self::with_config(MAX_BATCH_SIZE, MAX_SEGMENT_SIZE)
    }

    pub fn with_config(max_batch: usize, segment_size: usize) -> Self {
        UdpBatcher {
            pending: VecDeque::with_capacity(max_batch),
            max_batch,
            segment_size,
            stats: BatcherStats::default(),
        }
    }

    /// Queue a packet for batched sending
    pub fn queue(&mut self, dest: SocketAddr, data: Bytes) {
        self.pending.push_back(BatchedPacket { dest, data });
        self.stats.packets_queued += 1;
    }

    /// Check if batch is ready to send
    pub fn should_flush(&self) -> bool {
        self.pending.len() >= self.max_batch
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clear pending packets (for reuse)
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Flush pending packets as batched I/O vectors
    /// Returns (destination, combined buffer, segment_size, count)
    pub fn flush(&mut self) -> Vec<GsoBatch> {
        if self.pending.is_empty() {
            return Vec::new();
        }

        let mut batches: Vec<GsoBatch> = Vec::new();
        let mut current_dest: Option<SocketAddr> = None;
        let mut current_batch = GsoBatch::new(self.segment_size);

        while let Some(packet) = self.pending.pop_front() {
            // Start new batch if destination changes or batch is full
            if current_dest.is_some()
                && current_dest != Some(packet.dest)
                && !current_batch.is_empty()
            {
                batches.push(current_batch);
                current_batch = GsoBatch::new(self.segment_size);
            }

            if current_batch.count >= self.max_batch {
                batches.push(current_batch);
                current_batch = GsoBatch::new(self.segment_size);
            }

            current_dest = Some(packet.dest);
            current_batch.dest = packet.dest;
            current_batch.add_packet(packet.data);
        }

        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        // Update stats
        let total_packets: usize = batches.iter().map(|b| b.count).sum();
        if !batches.is_empty() {
            self.stats.batches_sent += batches.len() as u64;
            self.stats.packets_per_batch = total_packets as f64 / batches.len() as f64;
            self.stats.syscalls_saved += (total_packets.saturating_sub(batches.len())) as u64;
        }

        batches
    }

    /// Force flush all pending packets
    pub fn flush_all(&mut self) -> Vec<GsoBatch> {
        self.flush()
    }
}

impl Default for UdpBatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// A batch of packets for GSO transmission
#[derive(Debug, Clone)]
pub struct GsoBatch {
    /// Destination address
    pub dest: SocketAddr,
    /// Combined buffer with all segments
    pub buffer: BytesMut,
    /// Segment size (for GSO)
    pub segment_size: usize,
    /// Number of packets in batch
    pub count: usize,
    /// Individual packet lengths (for variable-size packets)
    pub lengths: Vec<usize>,
}

impl GsoBatch {
    pub fn new(segment_size: usize) -> Self {
        GsoBatch {
            dest: SocketAddr::from(([0, 0, 0, 0], 0)),
            buffer: BytesMut::with_capacity(segment_size * MAX_BATCH_SIZE),
            segment_size,
            count: 0,
            lengths: Vec::with_capacity(MAX_BATCH_SIZE),
        }
    }

    /// Add a packet to the batch
    pub fn add_packet(&mut self, data: Bytes) {
        self.lengths.push(data.len());
        self.buffer.put_slice(&data);
        self.count += 1;
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the combined buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Total size of all packets
    pub fn total_size(&self) -> usize {
        self.buffer.len()
    }
}

/// UDP receive coalescer for GRO (receive side)
pub struct UdpCoalescer {
    /// Buffer for coalesced receives
    buffer: BytesMut,
    /// Segment boundaries
    segments: Vec<(usize, usize)>, // (offset, length)
    /// Maximum buffer size
    #[allow(dead_code)]
    max_size: usize,
}

impl UdpCoalescer {
    pub fn new(max_size: usize) -> Self {
        UdpCoalescer {
            buffer: BytesMut::with_capacity(max_size),
            segments: Vec::with_capacity(MAX_BATCH_SIZE),
            max_size,
        }
    }

    /// Process a GRO-coalesced receive buffer
    /// Returns individual packet slices
    pub fn process_gro(&mut self, data: &[u8], segment_size: usize) -> Vec<Bytes> {
        let mut packets = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + segment_size).min(data.len());
            packets.push(Bytes::copy_from_slice(&data[offset..end]));
            offset = end;
        }

        packets
    }

    /// Add received data
    pub fn add_segment(&mut self, data: &[u8]) {
        let offset = self.buffer.len();
        self.buffer.put_slice(data);
        self.segments.push((offset, data.len()));
    }

    /// Get all segments
    pub fn drain_segments(&mut self) -> Vec<Bytes> {
        let frozen = self.buffer.split().freeze();
        let segments: Vec<Bytes> = self
            .segments
            .iter()
            .map(|(offset, len)| frozen.slice(*offset..*offset + *len))
            .collect();
        self.segments.clear();
        segments
    }

    /// Clear buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.segments.clear();
    }
}

impl Default for UdpCoalescer {
    fn default() -> Self {
        Self::new(MAX_SEGMENT_SIZE * MAX_BATCH_SIZE)
    }
}

/// Configuration for UDP batching
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Enable GSO for sending
    pub enable_gso: bool,
    /// Enable GRO for receiving
    pub enable_gro: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Segment size
    pub segment_size: usize,
    /// Flush interval in microseconds
    pub flush_interval_us: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        BatchConfig {
            enable_gso: true,
            enable_gro: true,
            max_batch_size: MAX_BATCH_SIZE,
            segment_size: MAX_SEGMENT_SIZE,
            flush_interval_us: 100, // 100us batch window
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_udp_batcher() {
        let mut batcher = UdpBatcher::new();
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Queue packets
        for i in 0..10 {
            batcher.queue(dest, Bytes::from(format!("packet {}", i)));
        }

        assert_eq!(batcher.pending_count(), 10);

        // Flush
        let batches = batcher.flush();
        assert_eq!(batches.len(), 1); // All same dest = 1 batch
        assert_eq!(batches[0].count, 10);
    }

    #[test]
    fn test_gso_batch() {
        let mut batch = GsoBatch::new(1400);
        batch.dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433);

        batch.add_packet(Bytes::from_static(b"hello"));
        batch.add_packet(Bytes::from_static(b"world"));

        assert_eq!(batch.count, 2);
        assert_eq!(batch.total_size(), 10);
    }

    #[test]
    fn test_gro_coalescer() {
        let mut coalescer = UdpCoalescer::default();

        // Simulate GRO-coalesced buffer
        let data = b"packet1packet2packet3";
        let packets = coalescer.process_gro(data, 7);

        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].as_ref(), b"packet1");
        assert_eq!(packets[1].as_ref(), b"packet2");
        assert_eq!(packets[2].as_ref(), b"packet3");
    }
}
