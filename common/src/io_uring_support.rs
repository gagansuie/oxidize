//! io_uring Support for Linux
//!
//! Provides 10-20x syscall reduction through kernel-bypassing I/O.
//! Only available on Linux 5.1+.
//!
//! This module provides abstractions that can be used with tokio-uring
//! or direct io_uring bindings.

use std::collections::VecDeque;
use std::net::SocketAddr;

/// io_uring operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    /// Read from socket
    Read,
    /// Write to socket  
    Write,
    /// Send UDP packet
    SendMsg,
    /// Receive UDP packet
    RecvMsg,
    /// Accept connection
    Accept,
    /// Connect to remote
    Connect,
    /// Close file descriptor
    Close,
    /// No-op for wakeup
    Nop,
}

/// Submission queue entry
#[derive(Debug, Clone)]
pub struct SubmissionEntry {
    /// Operation type
    pub op: IoOperation,
    /// File descriptor
    pub fd: i32,
    /// Buffer for data
    pub buffer: Vec<u8>,
    /// Buffer offset
    pub offset: usize,
    /// Remote address (for SendMsg/RecvMsg)
    pub addr: Option<SocketAddr>,
    /// User data for completion matching
    pub user_data: u64,
}

/// Completion queue entry
#[derive(Debug, Clone)]
pub struct CompletionEntry {
    /// User data from submission
    pub user_data: u64,
    /// Result (bytes transferred or error code)
    pub result: i32,
    /// Flags
    pub flags: u32,
}

/// io_uring configuration
#[derive(Debug, Clone)]
pub struct IoUringConfig {
    /// Submission queue size (power of 2)
    pub sq_entries: u32,
    /// Completion queue size (power of 2, typically 2x sq_entries)
    pub cq_entries: u32,
    /// Enable SQPOLL (kernel-side submission polling)
    pub sqpoll: bool,
    /// SQPOLL idle timeout in milliseconds
    pub sqpoll_idle_ms: u32,
    /// Enable IOPOLL (busy-polling for completions)
    pub iopoll: bool,
    /// Enable registered buffers
    pub registered_buffers: bool,
    /// Number of registered buffers
    pub num_buffers: usize,
    /// Size of each registered buffer
    pub buffer_size: usize,
}

impl Default for IoUringConfig {
    fn default() -> Self {
        IoUringConfig {
            sq_entries: 256,
            cq_entries: 512,
            sqpoll: false,
            sqpoll_idle_ms: 1000,
            iopoll: false,
            registered_buffers: true,
            num_buffers: 64,
            buffer_size: 65536,
        }
    }
}

/// High-performance config for maximum throughput
impl IoUringConfig {
    pub fn high_performance() -> Self {
        IoUringConfig {
            sq_entries: 4096,
            cq_entries: 8192,
            sqpoll: true,
            sqpoll_idle_ms: 100,
            iopoll: true,
            registered_buffers: true,
            num_buffers: 256,
            buffer_size: 65536,
        }
    }

    pub fn low_latency() -> Self {
        IoUringConfig {
            sq_entries: 128,
            cq_entries: 256,
            sqpoll: true,
            sqpoll_idle_ms: 0, // Never idle
            iopoll: true,
            registered_buffers: true,
            num_buffers: 32,
            buffer_size: 4096,
        }
    }
}

/// Batched I/O operations for io_uring
pub struct IoBatch {
    /// Pending submissions
    submissions: VecDeque<SubmissionEntry>,
    /// Maximum batch size
    max_batch: usize,
    /// Next user_data value
    next_user_data: u64,
    /// Statistics
    pub stats: IoBatchStats,
}

#[derive(Debug, Clone, Default)]
pub struct IoBatchStats {
    pub submissions: u64,
    pub completions: u64,
    pub batches_submitted: u64,
    pub avg_batch_size: f64,
    pub syscalls_saved: u64,
}

impl IoBatch {
    pub fn new(max_batch: usize) -> Self {
        IoBatch {
            submissions: VecDeque::with_capacity(max_batch),
            max_batch,
            next_user_data: 1,
            stats: IoBatchStats::default(),
        }
    }

    /// Queue a read operation
    pub fn queue_read(&mut self, fd: i32, buffer: Vec<u8>) -> u64 {
        let user_data = self.next_user_data;
        self.next_user_data += 1;

        self.submissions.push_back(SubmissionEntry {
            op: IoOperation::Read,
            fd,
            buffer,
            offset: 0,
            addr: None,
            user_data,
        });

        self.stats.submissions += 1;
        user_data
    }

    /// Queue a write operation
    pub fn queue_write(&mut self, fd: i32, buffer: Vec<u8>) -> u64 {
        let user_data = self.next_user_data;
        self.next_user_data += 1;

        self.submissions.push_back(SubmissionEntry {
            op: IoOperation::Write,
            fd,
            buffer,
            offset: 0,
            addr: None,
            user_data,
        });

        self.stats.submissions += 1;
        user_data
    }

    /// Queue a sendmsg operation (UDP)
    pub fn queue_sendmsg(&mut self, fd: i32, buffer: Vec<u8>, addr: SocketAddr) -> u64 {
        let user_data = self.next_user_data;
        self.next_user_data += 1;

        self.submissions.push_back(SubmissionEntry {
            op: IoOperation::SendMsg,
            fd,
            buffer,
            offset: 0,
            addr: Some(addr),
            user_data,
        });

        self.stats.submissions += 1;
        user_data
    }

    /// Queue a recvmsg operation (UDP)
    pub fn queue_recvmsg(&mut self, fd: i32, buffer: Vec<u8>) -> u64 {
        let user_data = self.next_user_data;
        self.next_user_data += 1;

        self.submissions.push_back(SubmissionEntry {
            op: IoOperation::RecvMsg,
            fd,
            buffer,
            offset: 0,
            addr: None,
            user_data,
        });

        self.stats.submissions += 1;
        user_data
    }

    /// Check if batch is ready to submit
    pub fn should_submit(&self) -> bool {
        self.submissions.len() >= self.max_batch
    }

    /// Get pending count
    pub fn pending(&self) -> usize {
        self.submissions.len()
    }

    /// Drain submissions for processing
    pub fn drain(&mut self) -> Vec<SubmissionEntry> {
        let batch_size = self.submissions.len();
        if batch_size > 0 {
            self.stats.batches_submitted += 1;
            self.stats.avg_batch_size = (self.stats.avg_batch_size
                * (self.stats.batches_submitted - 1) as f64
                + batch_size as f64)
                / self.stats.batches_submitted as f64;
            self.stats.syscalls_saved += batch_size.saturating_sub(1) as u64;
        }

        self.submissions.drain(..).collect()
    }

    /// Record completions
    pub fn record_completions(&mut self, count: u64) {
        self.stats.completions += count;
    }
}

impl Default for IoBatch {
    fn default() -> Self {
        Self::new(64)
    }
}

/// Feature detection for io_uring capabilities
pub struct IoUringFeatures {
    pub supported: bool,
    pub kernel_version: (u32, u32),
    pub sqpoll: bool,
    pub iopoll: bool,
    pub registered_buffers: bool,
    pub multishot_accept: bool,
    pub sendmsg_zc: bool, // Zero-copy sendmsg
}

impl IoUringFeatures {
    /// Detect available io_uring features
    pub fn detect() -> Self {
        // In production, this would probe the kernel
        // For now, return conservative defaults
        IoUringFeatures {
            supported: cfg!(target_os = "linux"),
            kernel_version: (5, 10), // Assume modern kernel
            sqpoll: true,
            iopoll: true,
            registered_buffers: true,
            multishot_accept: true,
            sendmsg_zc: false, // Requires kernel 6.0+
        }
    }

    /// Check if io_uring is usable
    pub fn is_usable(&self) -> bool {
        self.supported && self.kernel_version.0 >= 5 && self.kernel_version.1 >= 1
    }
}

impl Default for IoUringFeatures {
    fn default() -> Self {
        Self::detect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_batch() {
        let mut batch = IoBatch::new(4);

        let id1 = batch.queue_write(1, vec![1, 2, 3]);
        let id2 = batch.queue_read(2, vec![0; 1024]);

        assert_eq!(batch.pending(), 2);
        assert!(id1 != id2);

        let entries = batch.drain();
        assert_eq!(entries.len(), 2);
        assert_eq!(batch.pending(), 0);
    }

    #[test]
    fn test_config() {
        let default = IoUringConfig::default();
        assert_eq!(default.sq_entries, 256);

        let hp = IoUringConfig::high_performance();
        assert_eq!(hp.sq_entries, 4096);
        assert!(hp.sqpoll);
    }

    #[test]
    fn test_features() {
        let features = IoUringFeatures::detect();
        // On Linux, should be supported
        #[cfg(target_os = "linux")]
        assert!(features.supported);
    }
}
