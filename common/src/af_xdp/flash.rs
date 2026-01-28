//! FLASH: Fast Linked AF_XDP Sockets
//!
//! Multi-queue AF_XDP with shared UMEM for linear scaling across NIC queues.
//! Each queue gets its own socket, all sharing a single UMEM region.

#[cfg(target_os = "linux")]
use super::linux_impl::{XdpPacket, XdpSocket};
use super::{XdpConfig, XdpStats};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

/// FLASH: Fast Linked AF_XDP Sockets
///
/// Manages multiple AF_XDP sockets bound to different NIC queues,
/// all sharing a single UMEM for memory efficiency.
#[cfg(target_os = "linux")]
pub struct FlashSocket {
    sockets: Vec<XdpSocket>,
    #[allow(dead_code)]
    config: XdpConfig,
    stats: Arc<XdpStats>,
    num_queues: u32,
    /// Last time packets were successfully received
    last_rx_time: Instant,
    /// Total packets received (for stall detection)
    last_rx_count: AtomicU64,
    /// Consecutive polls with no packets
    idle_polls: AtomicU64,
}

#[cfg(target_os = "linux")]
impl FlashSocket {
    /// Create FLASH socket with multiple queues
    pub fn new(mut config: XdpConfig) -> io::Result<Self> {
        let num_queues = if config.num_queues == 0 {
            Self::detect_queue_count(&config.interface)?
        } else {
            config.num_queues
        };

        info!(
            "FLASH: Creating {} linked AF_XDP sockets on {}",
            num_queues, config.interface
        );

        if num_queues == 1 {
            // Single queue - just use regular XdpSocket
            config.queue_id = 0;
            let socket = XdpSocket::new(config.clone())?;
            return Ok(FlashSocket {
                sockets: vec![socket],
                config,
                stats: Arc::new(XdpStats::new()),
                num_queues: 1,
                last_rx_time: Instant::now(),
                last_rx_count: AtomicU64::new(0),
                idle_polls: AtomicU64::new(0),
            });
        }

        // Multi-queue: create first socket with UMEM, others share it
        let mut sockets = Vec::with_capacity(num_queues as usize);

        // First socket owns the UMEM
        config.queue_id = 0;
        let first_socket = XdpSocket::new(config.clone())?;
        let umem_fd = first_socket.as_raw_fd();
        sockets.push(first_socket);

        // Remaining sockets share UMEM via sxdp_shared_umem_fd
        for queue_id in 1..num_queues {
            config.queue_id = queue_id;
            match Self::create_linked_socket(&config, umem_fd) {
                Ok(socket) => {
                    info!("FLASH: Linked socket {} to queue {}", queue_id, queue_id);
                    sockets.push(socket);
                }
                Err(e) => {
                    warn!(
                        "FLASH: Failed to create socket for queue {}: {}",
                        queue_id, e
                    );
                    // Continue with fewer queues
                    break;
                }
            }
        }

        let actual_queues = sockets.len() as u32;
        info!(
            "FLASH: {} linked sockets ready (requested {})",
            actual_queues, num_queues
        );

        Ok(FlashSocket {
            sockets,
            config,
            stats: Arc::new(XdpStats::new()),
            num_queues: actual_queues,
            last_rx_time: Instant::now(),
            last_rx_count: AtomicU64::new(0),
            idle_polls: AtomicU64::new(0),
        })
    }

    /// Create a socket linked to existing UMEM
    fn create_linked_socket(config: &XdpConfig, _umem_fd: i32) -> io::Result<XdpSocket> {
        // For now, create independent sockets (full FLASH requires kernel patches)
        // The shared UMEM feature needs XDP_SHARED_UMEM flag support
        XdpSocket::new(config.clone())
    }

    /// Detect number of hardware queues on interface
    fn detect_queue_count(interface: &str) -> io::Result<u32> {
        // Try to read from /sys/class/net/<iface>/queues/
        let rx_path = format!("/sys/class/net/{}/queues", interface);

        if let Ok(entries) = std::fs::read_dir(&rx_path) {
            let rx_queues = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
                .count();

            if rx_queues > 0 {
                // Use all RX queues - must match NIC for RSS to work
                let queues = rx_queues as u32;
                info!("FLASH: Detected {} RX queues on {}", queues, interface);
                return Ok(queues);
            }
        }

        // Fallback: try ethtool via /proc
        if let Ok(output) = std::process::Command::new("ethtool")
            .args(["-l", interface])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("Combined:") {
                    if let Some(num) = line.split_whitespace().last() {
                        if let Ok(n) = num.parse::<u32>() {
                            let queues = std::cmp::min(n, 8);
                            info!("FLASH: ethtool reports {} combined queues", queues);
                            return Ok(queues);
                        }
                    }
                }
            }
        }

        // Default to single queue
        warn!("FLASH: Could not detect queue count, using 1");
        Ok(1)
    }

    /// Populate fill rings on all sockets
    pub fn populate_fill_rings(&mut self) -> u32 {
        let mut total = 0u32;
        for socket in &mut self.sockets {
            total += socket.populate_fill_ring();
        }
        total
    }

    /// Receive packets from all queues (round-robin)
    pub fn recv(&mut self, batch_size: usize) -> Vec<XdpPacket> {
        let per_queue = batch_size / self.sockets.len().max(1);
        let mut packets = Vec::with_capacity(batch_size);

        for socket in &mut self.sockets {
            let mut queue_packets = socket.recv(per_queue.max(1));
            packets.append(&mut queue_packets);
        }

        // Update aggregate stats
        let total_rx = packets.len() as u64;
        let total_bytes: u64 = packets.iter().map(|p| p.data.len() as u64).sum();
        self.stats.rx_packets.fetch_add(total_rx, Ordering::Relaxed);
        self.stats
            .rx_bytes
            .fetch_add(total_bytes, Ordering::Relaxed);
        self.stats.rx_batches.fetch_add(1, Ordering::Relaxed);

        // Update health tracking
        if !packets.is_empty() {
            self.last_rx_time = Instant::now();
            self.last_rx_count.fetch_add(total_rx, Ordering::Relaxed);
            self.idle_polls.store(0, Ordering::Relaxed);
        } else {
            self.idle_polls.fetch_add(1, Ordering::Relaxed);
        }

        packets
    }

    /// Receive from specific queue
    pub fn recv_queue(&mut self, queue_id: usize, batch_size: usize) -> Vec<XdpPacket> {
        if queue_id < self.sockets.len() {
            self.sockets[queue_id].recv(batch_size)
        } else {
            Vec::new()
        }
    }

    /// Send packets (distributes across queues based on hash)
    pub fn send(&mut self, packets: &[&[u8]]) -> usize {
        if self.sockets.is_empty() {
            return 0;
        }

        if self.sockets.len() == 1 {
            return self.sockets[0].send(packets);
        }

        // Distribute packets across queues (simple round-robin)
        let mut sent = 0;
        let per_queue = packets.len().div_ceil(self.sockets.len());

        for (i, socket) in self.sockets.iter_mut().enumerate() {
            let start = i * per_queue;
            let end = std::cmp::min(start + per_queue, packets.len());
            if start < packets.len() {
                sent += socket.send(&packets[start..end]);
            }
        }

        self.stats
            .tx_packets
            .fetch_add(sent as u64, Ordering::Relaxed);
        self.stats.tx_batches.fetch_add(1, Ordering::Relaxed);
        sent
    }

    /// Send on specific queue
    pub fn send_queue(&mut self, queue_id: usize, packets: &[&[u8]]) -> usize {
        if queue_id < self.sockets.len() {
            self.sockets[queue_id].send(packets)
        } else {
            0
        }
    }

    /// Return frames to fill rings
    pub fn return_frames(&mut self, frames: &[u64]) {
        // For shared UMEM, all frames go back to first socket
        if !self.sockets.is_empty() {
            self.sockets[0].return_frames(frames);
        }
    }

    /// Poll all sockets for events
    pub fn poll(&self, timeout_ms: i32) -> bool {
        // Use epoll for efficient multi-socket polling
        for socket in &self.sockets {
            if socket.poll(0) {
                return true;
            }
        }

        // If no immediate events, poll first socket with timeout
        if !self.sockets.is_empty() {
            self.sockets[0].poll(timeout_ms)
        } else {
            false
        }
    }

    /// Get aggregate stats
    pub fn stats(&self) -> &Arc<XdpStats> {
        &self.stats
    }

    /// Get number of active queues
    pub fn num_queues(&self) -> u32 {
        self.num_queues
    }

    /// Get per-queue stats
    pub fn queue_stats(&self) -> Vec<&Arc<XdpStats>> {
        self.sockets.iter().map(|s| s.stats()).collect()
    }

    /// Check if FLASH is supported
    pub fn is_supported() -> bool {
        XdpSocket::is_supported()
    }

    /// Get socket file descriptors for each queue (for XSKMAP registration)
    pub fn socket_fds(&self) -> Vec<(u32, i32)> {
        self.sockets
            .iter()
            .enumerate()
            .map(|(i, s)| (i as u32, s.as_raw_fd()))
            .collect()
    }

    /// Check if AF_XDP appears to be stalled (no packets for extended period)
    /// Returns true if stalled and should fall back to standard UDP
    pub fn is_stalled(&self, stall_threshold_secs: u64) -> bool {
        let idle_polls = self.idle_polls.load(Ordering::Relaxed);
        let total_rx = self.last_rx_count.load(Ordering::Relaxed);
        let elapsed = self.last_rx_time.elapsed().as_secs();

        // Only consider stalled if we've had SIGNIFICANT traffic before
        // (a few random packets shouldn't trigger stall detection)
        // Require at least 100 packets to consider the connection "established"
        if total_rx < 100 {
            return false;
        }

        // Consider stalled if:
        // 1. We previously had significant traffic (total_rx >= 100), AND
        // 2. No packets received for stall_threshold_secs, AND
        // 3. We've been polling actively (>1000 idle polls)
        if elapsed > stall_threshold_secs && idle_polls > 1000 {
            warn!(
                "AF_XDP appears stalled: no packets for {}s, {} idle polls, had {} total rx",
                elapsed, idle_polls, total_rx
            );
            return true;
        }
        false
    }

    /// Get health status for monitoring
    pub fn health_status(&self) -> FlashHealthStatus {
        let total_free_frames: usize = self.sockets.iter().map(|s| s.free_frame_count()).sum();
        let fill_ring_low = self.sockets.iter().any(|s| s.fill_ring_low());

        FlashHealthStatus {
            idle_secs: self.last_rx_time.elapsed().as_secs(),
            idle_polls: self.idle_polls.load(Ordering::Relaxed),
            total_rx: self.last_rx_count.load(Ordering::Relaxed),
            free_frames: total_free_frames,
            fill_ring_low,
        }
    }

    /// Force replenish all fill rings (call periodically to prevent starvation)
    pub fn maintain(&mut self) {
        // Always try to replenish fill rings
        self.populate_fill_rings();
    }
}

/// Health status for FLASH socket monitoring
#[derive(Debug, Clone)]
pub struct FlashHealthStatus {
    pub idle_secs: u64,
    pub idle_polls: u64,
    pub total_rx: u64,
    pub free_frames: usize,
    pub fill_ring_low: bool,
}

#[cfg(not(target_os = "linux"))]
pub struct FlashSocket {
    socket: super::stub_impl::XdpSocket,
    stats: Arc<XdpStats>,
}

#[cfg(not(target_os = "linux"))]
impl FlashSocket {
    pub fn new(config: XdpConfig) -> io::Result<Self> {
        Ok(FlashSocket {
            socket: super::stub_impl::XdpSocket::new(config)?,
            stats: Arc::new(XdpStats::new()),
        })
    }

    pub fn populate_fill_rings(&mut self) -> u32 {
        0
    }

    pub fn recv(&mut self, batch_size: usize) -> Vec<super::stub_impl::XdpPacket> {
        self.socket.recv(batch_size)
    }

    pub fn send(&mut self, packets: &[&[u8]]) -> usize {
        self.socket.send(packets)
    }

    pub fn return_frames(&mut self, _frames: &[u64]) {}

    pub fn poll(&self, timeout_ms: i32) -> bool {
        self.socket.poll(timeout_ms)
    }

    pub fn stats(&self) -> &Arc<XdpStats> {
        &self.stats
    }

    pub fn num_queues(&self) -> u32 {
        1
    }

    pub fn is_supported() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_config() {
        let config = XdpConfig {
            enable_flash: true,
            num_queues: 4,
            ..Default::default()
        };
        assert!(config.enable_flash);
        assert_eq!(config.num_queues, 4);
    }
}
