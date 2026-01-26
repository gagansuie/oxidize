//! Low-Latency Optimizations for Gaming/VoIP
//!
//! Target: <1ms end-to-end latency with AF_XDP/FLASH.
//!
//! Optimizations:
//! - AF_XDP kernel bypass (zero-copy, no syscall per packet)
//! - UDP datagrams (no ordering overhead)
//! - Skip compression for tiny packets
//! - Microsecond-level instrumentation
//! - Hot path optimizations

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Latency budget components (microseconds)
#[derive(Debug, Clone, Copy)]
pub struct LatencyBudget {
    /// Target total latency
    pub target_us: u64,
    /// Network RTT (physical distance)
    pub network_us: u64,
    /// Server processing time
    pub processing_us: u64,
    /// Serialization overhead
    pub serialization_us: u64,
    /// Compression time (if enabled)
    pub compression_us: u64,
}

impl LatencyBudget {
    /// 5ms target for gaming
    pub fn gaming() -> Self {
        Self {
            target_us: 5000,
            network_us: 2000,      // ~200km to edge
            processing_us: 500,    // Hot path
            serialization_us: 100, // UDP datagrams
            compression_us: 50,    // LZ4 is fast
        }
    }

    /// 20ms target for VoIP (more forgiving)
    pub fn voip() -> Self {
        Self {
            target_us: 20000,
            network_us: 10000,
            processing_us: 2000,
            serialization_us: 500,
            compression_us: 500,
        }
    }

    /// Check if we're within budget
    pub fn within_budget(&self) -> bool {
        self.total() <= self.target_us
    }

    /// Total estimated latency
    pub fn total(&self) -> u64 {
        self.network_us + self.processing_us + self.serialization_us + self.compression_us
    }

    /// Remaining budget
    pub fn remaining(&self) -> i64 {
        self.target_us as i64 - self.total() as i64
    }
}

/// Microsecond-precision latency tracker
#[derive(Debug, Default)]
pub struct LatencyTracker {
    /// Total packets measured
    pub packets: AtomicU64,
    /// Sum of latencies (for average)
    pub total_us: AtomicU64,
    /// Minimum latency seen
    pub min_us: AtomicU64,
    /// Maximum latency seen
    pub max_us: AtomicU64,
    /// Packets under 5ms
    pub under_5ms: AtomicU64,
    /// Packets under 10ms
    pub under_10ms: AtomicU64,
    /// Packets under 20ms
    pub under_20ms: AtomicU64,
}

impl LatencyTracker {
    pub fn new() -> Self {
        Self {
            min_us: AtomicU64::new(u64::MAX),
            ..Default::default()
        }
    }

    /// Record a latency measurement
    pub fn record(&self, latency: Duration) {
        let us = latency.as_micros() as u64;

        self.packets.fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(us, Ordering::Relaxed);

        // Update min (compare-and-swap loop)
        let mut current_min = self.min_us.load(Ordering::Relaxed);
        while us < current_min {
            match self.min_us.compare_exchange_weak(
                current_min,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }

        // Update max
        let mut current_max = self.max_us.load(Ordering::Relaxed);
        while us > current_max {
            match self.max_us.compare_exchange_weak(
                current_max,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }

        // Bucket counters
        if us < 5000 {
            self.under_5ms.fetch_add(1, Ordering::Relaxed);
        }
        if us < 10000 {
            self.under_10ms.fetch_add(1, Ordering::Relaxed);
        }
        if us < 20000 {
            self.under_20ms.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get average latency in microseconds
    pub fn avg_us(&self) -> u64 {
        let packets = self.packets.load(Ordering::Relaxed);
        if packets == 0 {
            return 0;
        }
        self.total_us.load(Ordering::Relaxed) / packets
    }

    /// Get percentage of packets under 5ms
    pub fn percent_under_5ms(&self) -> f64 {
        let packets = self.packets.load(Ordering::Relaxed);
        if packets == 0 {
            return 0.0;
        }
        (self.under_5ms.load(Ordering::Relaxed) as f64 / packets as f64) * 100.0
    }

    /// Summary string
    pub fn summary(&self) -> String {
        let packets = self.packets.load(Ordering::Relaxed);
        if packets == 0 {
            return "No packets measured".to_string();
        }

        let min = self.min_us.load(Ordering::Relaxed);
        let max = self.max_us.load(Ordering::Relaxed);
        let avg = self.avg_us();
        let p5 = self.percent_under_5ms();

        format!(
            "Latency: avg={:.2}ms, min={:.2}ms, max={:.2}ms, <5ms={:.1}% ({} packets)",
            avg as f64 / 1000.0,
            min as f64 / 1000.0,
            max as f64 / 1000.0,
            p5,
            packets
        )
    }
}

/// Timer for measuring code section latency
pub struct LatencyTimer {
    start: Instant,
    tracker: Option<&'static LatencyTracker>,
}

impl LatencyTimer {
    /// Start a new timer
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
            tracker: None,
        }
    }

    /// Start with auto-recording to a tracker
    pub fn start_with_tracker(tracker: &'static LatencyTracker) -> Self {
        Self {
            start: Instant::now(),
            tracker: Some(tracker),
        }
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get elapsed microseconds
    pub fn elapsed_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    /// Stop and record (if tracker attached)
    pub fn stop(self) -> Duration {
        let elapsed = self.start.elapsed();
        if let Some(tracker) = self.tracker {
            tracker.record(elapsed);
        }
        elapsed
    }
}

/// Gaming packet optimization settings
#[derive(Debug, Clone)]
pub struct GamingOptimizations {
    /// Use UDP datagrams for real-time traffic
    pub use_datagrams: bool,
    /// Skip compression for packets under this size
    pub compression_threshold: usize,
    /// Enable LZ4 (fast enough for gaming)
    pub enable_lz4: bool,
    /// Disable ROHC (header compression) for lowest latency
    pub enable_rohc: bool,
    /// Target latency in microseconds
    pub target_latency_us: u64,
}

impl Default for GamingOptimizations {
    fn default() -> Self {
        Self {
            use_datagrams: true,
            compression_threshold: 256, // Skip compression for small packets
            enable_lz4: true,           // LZ4 is fast enough
            enable_rohc: false,         // Skip for gaming, enable for VoIP
            target_latency_us: 5000,    // 5ms target
        }
    }
}

impl GamingOptimizations {
    /// Strict low-latency mode
    pub fn ultra_low_latency() -> Self {
        Self {
            use_datagrams: true,
            compression_threshold: 1500, // Skip all compression
            enable_lz4: false,
            enable_rohc: false,
            target_latency_us: 3000, // 3ms target
        }
    }

    /// Balanced gaming mode
    pub fn balanced() -> Self {
        Self::default()
    }

    /// VoIP optimized (compression helps bandwidth)
    pub fn voip() -> Self {
        Self {
            use_datagrams: true,
            compression_threshold: 64,
            enable_lz4: true,
            enable_rohc: true, // 97% header reduction for RTP
            target_latency_us: 20000,
        }
    }

    /// Should we compress this packet?
    pub fn should_compress(&self, packet_size: usize) -> bool {
        self.enable_lz4 && packet_size >= self.compression_threshold
    }
}

/// Detect if a port is gaming-related
pub fn is_gaming_port(port: u16) -> bool {
    matches!(
        port,
        // Valve/Steam
        27000..=27050 |
        // Riot Games (LoL, Valorant)
        5000..=5500 |
        // Epic Games / Fortnite
        5795..=5847 |
        // Xbox Live
        3074 |
        // PlayStation
        3478..=3480 |
        // Common game server ports
        7777..=7800 |
        25565 | // Minecraft
        19132 | // Minecraft Bedrock
        9987 | // TeamSpeak
        // High dynamic range (Nintendo, etc)
        45000..=65535
    )
}

/// Detect if a port is VoIP-related
pub fn is_voip_port(port: u16) -> bool {
    matches!(
        port,
        // SIP
        5060 | 5061 |
        // RTP range
        16384..=32767 |
        // Discord
        50000..=65535 |
        // Zoom
        8801..=8810 |
        // Teams
        3478..=3481 |
        // Generic VoIP
        10000..=20000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_budget_gaming() {
        let budget = LatencyBudget::gaming();
        assert!(budget.target_us == 5000);
        assert!(budget.total() < budget.target_us);
    }

    #[test]
    fn test_latency_tracker() {
        let tracker = LatencyTracker::new();

        tracker.record(Duration::from_micros(3000)); // 3ms
        tracker.record(Duration::from_micros(4000)); // 4ms
        tracker.record(Duration::from_micros(6000)); // 6ms

        assert_eq!(tracker.packets.load(Ordering::Relaxed), 3);
        assert_eq!(tracker.under_5ms.load(Ordering::Relaxed), 2);
        assert!(tracker.percent_under_5ms() > 60.0);
    }

    #[test]
    fn test_gaming_optimizations() {
        let opts = GamingOptimizations::default();

        // Small packets skip compression
        assert!(!opts.should_compress(100));
        // Large packets get compressed
        assert!(opts.should_compress(500));
    }

    #[test]
    fn test_port_detection() {
        assert!(is_gaming_port(27015)); // CS2
        assert!(is_gaming_port(25565)); // Minecraft
        assert!(is_voip_port(5060)); // SIP
        assert!(is_voip_port(16384)); // RTP
    }
}
