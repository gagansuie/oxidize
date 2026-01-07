//! Unix-specific high-performance TUN implementation
//!
//! Uses:
//! - io_uring on Linux for batched I/O
//! - writev for vectored writes on all Unix platforms
//! - readv for vectored reads
//! - Adaptive batch sizing based on throughput
//! - Latency tracking for performance monitoring

use super::{BatchConfig, TunBatch, TunStats};
use crate::zero_copy::BufferPool;
use bytes::BytesMut;
use std::io::{self, Read};
use std::os::unix::io::RawFd;
use std::time::Instant;
use tracing::{debug, trace};

/// High-performance TUN I/O manager (Unix)
pub struct HighPerfTun {
    /// TUN file descriptor
    fd: RawFd,
    /// Buffer pool for zero-copy
    buffer_pool: BufferPool,
    /// Outgoing packet batch
    write_batch: TunBatch,
    /// Incoming packet batch (for read coalescing)
    read_batch: Vec<BytesMut>,
    /// Read buffer size
    read_buf_size: usize,
    /// io_uring instance for Linux
    #[cfg(target_os = "linux")]
    uring: Option<crate::io_uring_impl::UringInstance>,
    /// Statistics
    pub stats: TunStats,
    /// Use vectored writes (writev)
    use_writev: bool,
}

impl HighPerfTun {
    /// Create a new high-performance TUN handler
    pub fn new(fd: RawFd) -> io::Result<Self> {
        Self::with_config(fd, BatchConfig::default())
    }

    /// Create with custom batch configuration
    pub fn with_config(fd: RawFd, config: BatchConfig) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let uring = {
            match crate::io_uring_impl::UringInstance::new(256, 64, 65536) {
                Ok(u) => {
                    debug!("io_uring enabled for TUN operations");
                    Some(u)
                }
                Err(e) => {
                    debug!("io_uring not available, using standard I/O: {}", e);
                    None
                }
            }
        };

        Ok(HighPerfTun {
            fd,
            buffer_pool: BufferPool::new(65536, 64, 256),
            write_batch: TunBatch::with_config(config),
            read_batch: Vec::with_capacity(64),
            read_buf_size: 65536,
            #[cfg(target_os = "linux")]
            uring,
            stats: TunStats::default(),
            use_writev: true,
        })
    }

    /// Create optimized for gaming (low latency)
    pub fn gaming(fd: RawFd) -> io::Result<Self> {
        Self::with_config(fd, BatchConfig::gaming())
    }

    /// Create optimized for throughput
    pub fn high_throughput(fd: RawFd) -> io::Result<Self> {
        Self::with_config(fd, BatchConfig::high_throughput())
    }

    /// Check if io_uring is being used
    pub fn using_io_uring(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.uring.is_some();
        #[cfg(not(target_os = "linux"))]
        return false;
    }

    /// Queue a packet for batched writing
    pub fn queue_write(&mut self, packet: BytesMut) {
        self.write_batch.push(packet);
    }

    /// Read a single packet from TUN (non-blocking friendly)
    pub fn read_packet(&mut self) -> io::Result<Option<BytesMut>> {
        use std::os::unix::io::FromRawFd;

        let mut buf = self.buffer_pool.get();
        buf.resize(self.read_buf_size, 0);

        // SAFETY: Temporarily borrowing fd for read
        let mut file = unsafe { std::fs::File::from_raw_fd(self.fd) };
        let result = file.read(&mut buf);
        std::mem::forget(file);

        match result {
            Ok(0) => Ok(None),
            Ok(n) => {
                buf.truncate(n);
                self.stats.packets_read += 1;
                self.stats.bytes_read += n as u64;
                Ok(Some(buf))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Read multiple packets into batch (for high throughput)
    pub fn read_batch(&mut self, max_packets: usize) -> io::Result<&[BytesMut]> {
        self.read_batch.clear();

        for _ in 0..max_packets {
            match self.read_packet()? {
                Some(packet) => self.read_batch.push(packet),
                None => break,
            }
        }

        if !self.read_batch.is_empty() {
            self.stats.batches_read += 1;
        }

        Ok(&self.read_batch)
    }

    /// Flush all queued writes using best available method
    #[cfg(target_os = "linux")]
    pub fn flush_writes(&mut self) -> io::Result<usize> {
        if self.write_batch.is_empty() {
            return Ok(0);
        }

        let start = Instant::now();
        let packets: Vec<BytesMut> = self.write_batch.drain().collect();
        let packet_count = packets.len();
        let total_bytes: u64 = packets.iter().map(|p| p.len() as u64).sum();

        let result = if let Some(ref mut uring) = self.uring {
            // Use io_uring for batched writes
            let packet_refs: Vec<&[u8]> = packets.iter().map(|p| p.as_ref()).collect();
            uring.queue_tun_writes_batch(self.fd, &packet_refs);
            uring.submit()?;
            self.stats.syscalls_saved += packet_count.saturating_sub(1) as u64;
            Ok(packet_count)
        } else if self.use_writev && packet_count > 1 {
            // Use writev for vectored writes
            self.flush_writev(&packets)
        } else {
            // Standard sequential writes
            self.flush_sequential(&packets)
        };

        // Record stats with latency
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.stats
            .record_write(packet_count as u64, total_bytes, latency_ns);
        self.stats.batches_written += 1;

        // Adapt batch size periodically
        self.write_batch.adapt();

        trace!(
            "Flushed {} packets ({} bytes) in {}ns",
            packet_count,
            total_bytes,
            latency_ns
        );

        result
    }

    /// Flush writes on non-Linux Unix
    #[cfg(not(target_os = "linux"))]
    pub fn flush_writes(&mut self) -> io::Result<usize> {
        if self.write_batch.is_empty() {
            return Ok(0);
        }

        let start = Instant::now();
        let packets: Vec<BytesMut> = self.write_batch.drain().collect();
        let packet_count = packets.len();
        let total_bytes: u64 = packets.iter().map(|p| p.len() as u64).sum();

        let result = if self.use_writev && packet_count > 1 {
            self.flush_writev(&packets)
        } else {
            self.flush_sequential(&packets)
        };

        let latency_ns = start.elapsed().as_nanos() as u64;
        self.stats
            .record_write(packet_count as u64, total_bytes, latency_ns);
        self.stats.batches_written += 1;
        self.write_batch.adapt();

        result
    }

    /// Flush using writev (single syscall for multiple buffers)
    fn flush_writev(&mut self, packets: &[BytesMut]) -> io::Result<usize> {
        let mut vectored = VectoredWrite::new();
        for packet in packets {
            vectored.push(packet);
        }

        let bytes_written = vectored.write_to(self.fd)?;
        self.stats.syscalls_saved += packets.len().saturating_sub(1) as u64;

        trace!("writev: {} packets, {} bytes", packets.len(), bytes_written);
        Ok(packets.len())
    }

    /// Flush using sequential writes (fallback)
    fn flush_sequential(&mut self, packets: &[BytesMut]) -> io::Result<usize> {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let mut file = unsafe { std::fs::File::from_raw_fd(self.fd) };

        for packet in packets {
            file.write_all(packet)?;
        }

        std::mem::forget(file);
        Ok(packets.len())
    }

    /// Should flush based on batch state (size or timeout)
    pub fn should_flush(&self) -> bool {
        self.write_batch.should_flush()
    }

    /// Force flush if timeout exceeded
    pub fn flush_if_timeout(&mut self) -> io::Result<usize> {
        if self.write_batch.should_flush() {
            self.flush_writes()
        } else {
            Ok(0)
        }
    }

    /// Get a buffer from the pool
    pub fn get_buffer(&mut self) -> BytesMut {
        self.buffer_pool.get()
    }

    /// Return a buffer to the pool
    pub fn return_buffer(&mut self, buf: BytesMut) {
        self.buffer_pool.put(buf);
    }

    /// Get current batch size (may change with adaptive sizing)
    pub fn current_batch_size(&self) -> usize {
        self.write_batch.current_size()
    }

    /// Get number of queued packets
    pub fn queued_packets(&self) -> usize {
        self.write_batch.len()
    }

    /// Get statistics summary
    pub fn stats_summary(&self) -> String {
        self.stats.summary()
    }

    /// Get io_uring stats if available (Linux only)
    #[cfg(target_os = "linux")]
    pub fn uring_stats(&self) -> Option<crate::io_uring_impl::UringStats> {
        self.uring.as_ref().map(|u| u.stats.clone())
    }

    /// Enable/disable writev optimization
    pub fn set_use_writev(&mut self, enable: bool) {
        self.use_writev = enable;
    }
}

/// Vectored write support for scatter-gather I/O (Unix)
pub struct VectoredWrite {
    iovecs: Vec<libc::iovec>,
}

impl VectoredWrite {
    pub fn new() -> Self {
        VectoredWrite {
            iovecs: Vec::with_capacity(64),
        }
    }

    /// Add a buffer to the vectored write
    pub fn push(&mut self, data: &[u8]) {
        self.iovecs.push(libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        });
    }

    /// Execute vectored write (writev syscall)
    pub fn write_to(&self, fd: RawFd) -> io::Result<usize> {
        if self.iovecs.is_empty() {
            return Ok(0);
        }

        let result = unsafe { libc::writev(fd, self.iovecs.as_ptr(), self.iovecs.len() as i32) };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    /// Clear all buffers
    pub fn clear(&mut self) {
        self.iovecs.clear();
    }

    pub fn len(&self) -> usize {
        self.iovecs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }
}

impl Default for VectoredWrite {
    fn default() -> Self {
        Self::new()
    }
}
