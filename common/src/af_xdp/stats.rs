//! AF_XDP Performance Statistics

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// AF_XDP performance statistics
#[derive(Debug, Default)]
pub struct XdpStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_batches: AtomicU64,
    pub tx_batches: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
    pub poll_cycles: AtomicU64,
    pub zero_copy_hits: AtomicU64,
}

impl XdpStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rx_pps(&self, elapsed: Duration) -> f64 {
        self.rx_packets.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64()
    }

    pub fn tx_pps(&self, elapsed: Duration) -> f64 {
        self.tx_packets.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64()
    }

    pub fn rx_gbps(&self, elapsed: Duration) -> f64 {
        let bytes = self.rx_bytes.load(Ordering::Relaxed);
        (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000_000.0
    }

    pub fn tx_gbps(&self, elapsed: Duration) -> f64 {
        let bytes = self.tx_bytes.load(Ordering::Relaxed);
        (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000_000.0
    }

    pub fn avg_batch_size(&self) -> f64 {
        let packets = self.rx_packets.load(Ordering::Relaxed);
        let batches = self.rx_batches.load(Ordering::Relaxed);
        if batches == 0 {
            0.0
        } else {
            packets as f64 / batches as f64
        }
    }

    pub fn summary(&self, elapsed: Duration) -> String {
        format!(
            "RX: {:.2} Gbps ({:.2}M pps) | TX: {:.2} Gbps ({:.2}M pps) | Batch: {:.1}",
            self.rx_gbps(elapsed),
            self.rx_pps(elapsed) / 1_000_000.0,
            self.tx_gbps(elapsed),
            self.tx_pps(elapsed) / 1_000_000.0,
            self.avg_batch_size()
        )
    }
}
