//! Windows-specific high-performance TUN implementation
//!
//! Uses:
//! - Overlapped I/O for async operations
//! - Standard WriteFile for compatibility
//!
//! Note: Windows TUN devices (via Wintun) work differently than Unix.
//! This implementation provides the same API surface for cross-platform code.

use super::{TunBatch, TunStats};
use crate::zero_copy::BufferPool;
use bytes::BytesMut;
use std::io;
use std::os::windows::io::RawHandle;
use tracing::debug;

/// Type alias for Windows handle (equivalent to Unix RawFd)
pub type RawFd = RawHandle;

/// High-performance TUN I/O manager (Windows)
pub struct HighPerfTun {
    /// TUN device handle
    handle: RawHandle,
    /// Buffer pool for zero-copy
    buffer_pool: BufferPool,
    /// Outgoing packet batch
    write_batch: TunBatch,
    /// Statistics
    pub stats: TunStats,
}

impl HighPerfTun {
    /// Create a new high-performance TUN handler
    pub fn new(handle: RawHandle) -> io::Result<Self> {
        debug!("Windows TUN handler initialized");

        Ok(HighPerfTun {
            handle,
            buffer_pool: BufferPool::new(65536, 32, 128),
            write_batch: TunBatch::new(64),
            stats: TunStats::default(),
        })
    }

    /// Check if using optimized I/O (always false on Windows for now)
    pub fn using_io_uring(&self) -> bool {
        false
    }

    /// Queue a packet for batched writing
    pub fn queue_write(&mut self, packet: BytesMut) {
        self.write_batch.push(packet);
    }

    /// Flush all queued writes
    pub fn flush_writes(&mut self) -> io::Result<usize> {
        if self.write_batch.is_empty() {
            return Ok(0);
        }

        let packets: Vec<BytesMut> = self.write_batch.drain().collect();
        self.flush_writes_standard(packets)
    }

    /// Standard write implementation for Windows
    fn flush_writes_standard(&mut self, packets: Vec<BytesMut>) -> io::Result<usize> {
        use std::io::Write;
        use std::os::windows::io::FromRawHandle;

        let packet_count = packets.len();

        // SAFETY: We're temporarily borrowing the handle for writes
        let mut file = unsafe { std::fs::File::from_raw_handle(self.handle) };

        for packet in &packets {
            file.write_all(packet)?;
            self.stats.packets_written += 1;
            self.stats.bytes_written += packet.len() as u64;
        }

        // Don't close the handle when file is dropped
        std::mem::forget(file);

        self.stats.batches_written += 1;
        Ok(packet_count)
    }

    /// Get a buffer from the pool
    pub fn get_buffer(&mut self) -> BytesMut {
        self.buffer_pool.get()
    }

    /// Return a buffer to the pool
    pub fn return_buffer(&mut self, buf: BytesMut) {
        self.buffer_pool.put(buf);
    }

    /// Should flush based on batch state
    pub fn should_flush(&self) -> bool {
        self.write_batch.should_flush()
    }
}

/// Vectored write support (Windows implementation)
///
/// Windows doesn't have writev, so this batches writes sequentially.
/// Future optimization: Use WriteFileGather for true scatter-gather.
pub struct VectoredWrite {
    buffers: Vec<Vec<u8>>,
}

impl VectoredWrite {
    pub fn new() -> Self {
        VectoredWrite {
            buffers: Vec::with_capacity(64),
        }
    }

    /// Add a buffer to the vectored write
    pub fn push(&mut self, data: &[u8]) {
        self.buffers.push(data.to_vec());
    }

    /// Execute writes (sequential on Windows)
    pub fn write_to(&self, handle: RawHandle) -> io::Result<usize> {
        use std::io::Write;
        use std::os::windows::io::FromRawHandle;

        if self.buffers.is_empty() {
            return Ok(0);
        }

        let mut total_written = 0usize;

        // SAFETY: Temporarily borrowing handle
        let mut file = unsafe { std::fs::File::from_raw_handle(handle) };

        for buf in &self.buffers {
            file.write_all(buf)?;
            total_written += buf.len();
        }

        // Don't close handle
        std::mem::forget(file);

        Ok(total_written)
    }

    /// Clear all buffers
    pub fn clear(&mut self) {
        self.buffers.clear();
    }

    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }
}

impl Default for VectoredWrite {
    fn default() -> Self {
        Self::new()
    }
}
