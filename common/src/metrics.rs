use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RelayMetrics {
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub packets_sent: Arc<AtomicU64>,
    pub packets_received: Arc<AtomicU64>,
    pub connections_active: Arc<AtomicU64>,
    pub connections_total: Arc<AtomicU64>,
    pub compression_saved: Arc<AtomicU64>,
    pub start_time: Instant,
    // Latency instrumentation
    pub total_process_time_us: Arc<AtomicU64>,
    pub total_forward_time_us: Arc<AtomicU64>,
    pub total_encode_time_us: Arc<AtomicU64>,
    pub total_decode_time_us: Arc<AtomicU64>,
    pub latency_samples: Arc<AtomicU64>,
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayMetrics {
    pub fn new() -> Self {
        Self {
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            connections_active: Arc::new(AtomicU64::new(0)),
            connections_total: Arc::new(AtomicU64::new(0)),
            compression_saved: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            total_process_time_us: Arc::new(AtomicU64::new(0)),
            total_forward_time_us: Arc::new(AtomicU64::new(0)),
            total_encode_time_us: Arc::new(AtomicU64::new(0)),
            total_decode_time_us: Arc::new(AtomicU64::new(0)),
            latency_samples: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_opened(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_compression_saved(&self, bytes: u64) {
        self.compression_saved.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record processing latency for a single packet
    pub fn record_process_latency(&self, duration: Duration) {
        self.total_process_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    /// Record forwarding latency
    pub fn record_forward_latency(&self, duration: Duration) {
        self.total_forward_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record encode latency
    pub fn record_encode_latency(&self, duration: Duration) {
        self.total_encode_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record decode latency
    pub fn record_decode_latency(&self, duration: Duration) {
        self.total_decode_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Get average processing latency in microseconds
    pub fn avg_process_latency_us(&self) -> f64 {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return 0.0;
        }
        self.total_process_time_us.load(Ordering::Relaxed) as f64 / samples as f64
    }

    pub fn get_stats(&self) -> Stats {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        Stats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            compression_saved: self.compression_saved.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
            avg_process_latency_us: self.avg_process_latency_us(),
            avg_forward_latency_us: if samples > 0 {
                self.total_forward_time_us.load(Ordering::Relaxed) as f64 / samples as f64
            } else {
                0.0
            },
            avg_encode_latency_us: if samples > 0 {
                self.total_encode_time_us.load(Ordering::Relaxed) as f64 / samples as f64
            } else {
                0.0
            },
            avg_decode_latency_us: if samples > 0 {
                self.total_decode_time_us.load(Ordering::Relaxed) as f64 / samples as f64
            } else {
                0.0
            },
            latency_samples: samples,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Stats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connections_active: u64,
    pub connections_total: u64,
    pub compression_saved: u64,
    pub uptime_secs: u64,
    // Latency metrics
    pub avg_process_latency_us: f64,
    pub avg_forward_latency_us: f64,
    pub avg_encode_latency_us: f64,
    pub avg_decode_latency_us: f64,
    pub latency_samples: u64,
}

impl Stats {
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;

        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }

        format!("{:.2} {}", size, UNITS[unit_idx])
    }

    pub fn print_summary(&self) {
        println!("╔════════════════════════════════════════════════╗");
        println!("║           Oxidize Statistics                   ║");
        println!("╠════════════════════════════════════════════════╣");
        println!("║ Uptime: {} seconds", self.uptime_secs);
        println!("║ Active Connections: {}", self.connections_active);
        println!("║ Total Connections: {}", self.connections_total);
        println!("║ Bytes Sent: {}", Self::format_bytes(self.bytes_sent));
        println!(
            "║ Bytes Received: {}",
            Self::format_bytes(self.bytes_received)
        );
        println!("║ Packets Sent: {}", self.packets_sent);
        println!("║ Packets Received: {}", self.packets_received);
        println!(
            "║ Compression Saved: {}",
            Self::format_bytes(self.compression_saved)
        );
        println!("╠════════════════════════════════════════════════╣");
        println!(
            "║ Avg Process Latency: {:.2}µs",
            self.avg_process_latency_us
        );
        println!(
            "║ Avg Forward Latency: {:.2}µs",
            self.avg_forward_latency_us
        );
        println!("║ Avg Encode Latency:  {:.2}µs", self.avg_encode_latency_us);
        println!("║ Avg Decode Latency:  {:.2}µs", self.avg_decode_latency_us);
        println!("║ Latency Samples: {}", self.latency_samples);
        println!("╚════════════════════════════════════════════════╝");
    }
}
