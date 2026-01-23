//! OxTunnel Speed Test
//!
//! Benchmarks connection latency and throughput using the OxTunnel protocol.

use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::info;

/// Speed test configuration
pub struct SpeedTestConfig {
    pub server_addr: SocketAddr,
    pub packet_size: usize,
    pub packet_count: usize,
    pub warmup_packets: usize,
}

impl Default for SpeedTestConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:4433".parse().unwrap(),
            packet_size: 1400,
            packet_count: 1000,
            warmup_packets: 10,
        }
    }
}

/// Speed test results
#[derive(Debug, Clone)]
pub struct SpeedTestResults {
    pub latency_min_us: u64,
    pub latency_max_us: u64,
    pub latency_avg_us: u64,
    pub latency_p50_us: u64,
    pub latency_p99_us: u64,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub throughput_mbps: f64,
    pub duration_ms: u64,
}

impl SpeedTestResults {
    /// Print results in human-readable format
    pub fn print_human(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║              OxTunnel Speed Test Results                   ║");
        println!("╠═══════════════════════════════════════════════════════════╣");
        println!("║ Latency:                                                   ║");
        println!(
            "║   Min: {:>8} µs                                         ║",
            self.latency_min_us
        );
        println!(
            "║   Max: {:>8} µs                                         ║",
            self.latency_max_us
        );
        println!(
            "║   Avg: {:>8} µs                                         ║",
            self.latency_avg_us
        );
        println!(
            "║   P50: {:>8} µs                                         ║",
            self.latency_p50_us
        );
        println!(
            "║   P99: {:>8} µs                                         ║",
            self.latency_p99_us
        );
        println!("╠═══════════════════════════════════════════════════════════╣");
        println!("║ Throughput:                                                ║");
        println!(
            "║   Packets: {}/{} ({:.1}% loss)                    ║",
            self.packets_received, self.packets_sent, self.packet_loss_percent
        );
        println!(
            "║   Speed: {:>8.2} Mbps                                    ║",
            self.throughput_mbps
        );
        println!(
            "║   Duration: {} ms                                      ║",
            self.duration_ms
        );
        println!("╚═══════════════════════════════════════════════════════════╝");
    }

    /// Print results as JSON
    pub fn print_json(&self) -> Result<()> {
        let json = serde_json::json!({
            "latency": {
                "min_us": self.latency_min_us,
                "max_us": self.latency_max_us,
                "avg_us": self.latency_avg_us,
                "p50_us": self.latency_p50_us,
                "p99_us": self.latency_p99_us,
            },
            "throughput": {
                "packets_sent": self.packets_sent,
                "packets_received": self.packets_received,
                "packet_loss_percent": self.packet_loss_percent,
                "mbps": self.throughput_mbps,
            },
            "duration_ms": self.duration_ms,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        Ok(())
    }
}

/// OxTunnel speed test
pub struct SpeedTest {
    config: SpeedTestConfig,
}

impl SpeedTest {
    /// Create a new speed test with server address
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            config: SpeedTestConfig {
                server_addr,
                ..Default::default()
            },
        }
    }

    /// Create with custom config
    pub fn with_config(config: SpeedTestConfig) -> Self {
        Self { config }
    }

    /// Run the speed test
    pub async fn run(&self) -> Result<SpeedTestResults> {
        info!(
            "Starting OxTunnel speed test to {}",
            self.config.server_addr
        );

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.config.server_addr).await?;

        // Warmup
        info!("Warming up ({} packets)...", self.config.warmup_packets);
        for _ in 0..self.config.warmup_packets {
            let packet = vec![0u8; self.config.packet_size];
            let _ = socket.send(&packet).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Latency test (ping-pong)
        info!("Testing latency...");
        let mut latencies = Vec::with_capacity(100);
        let _ping_packet = [0x01u8; 64]; // Small ping packet

        for _ in 0..100 {
            let start = Instant::now();
            socket.send(&[0x01; 64]).await?;

            let mut buf = [0u8; 128];
            if let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buf)).await
            {
                let elapsed = start.elapsed().as_micros() as u64;
                latencies.push(elapsed);
            }
        }

        // Calculate latency stats
        latencies.sort();
        let (latency_min, latency_max, latency_avg, latency_p50, latency_p99) =
            if !latencies.is_empty() {
                let sum: u64 = latencies.iter().sum();
                let len = latencies.len();
                (
                    latencies[0],
                    latencies[len - 1],
                    sum / len as u64,
                    latencies[len / 2],
                    latencies[(len as f64 * 0.99) as usize],
                )
            } else {
                (0, 0, 0, 0, 0)
            };

        // Throughput test
        info!(
            "Testing throughput ({} packets of {} bytes)...",
            self.config.packet_count, self.config.packet_size
        );

        let packet = vec![0xAAu8; self.config.packet_size];
        let start = Instant::now();
        let mut sent = 0;
        let mut received = 0;

        for i in 0..self.config.packet_count {
            // Include sequence number in packet
            let mut pkt = packet.clone();
            pkt[0..4].copy_from_slice(&(i as u32).to_le_bytes());

            if socket.send(&pkt).await.is_ok() {
                sent += 1;
            }

            // Non-blocking receive check
            let mut buf = [0u8; 2048];
            if let Ok(result) =
                tokio::time::timeout(Duration::from_micros(100), socket.recv(&mut buf)).await
            {
                if result.is_ok() {
                    received += 1;
                }
            }
        }

        // Drain remaining responses
        let drain_start = Instant::now();
        while drain_start.elapsed() < Duration::from_millis(500) {
            let mut buf = [0u8; 2048];
            match tokio::time::timeout(Duration::from_millis(50), socket.recv(&mut buf)).await {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }

        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;
        let bytes_sent = sent * self.config.packet_size;
        let throughput_mbps = (bytes_sent as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0);
        let packet_loss = if sent > 0 {
            ((sent - received) as f64 / sent as f64) * 100.0
        } else {
            100.0
        };

        info!("Speed test complete");

        Ok(SpeedTestResults {
            latency_min_us: latency_min,
            latency_max_us: latency_max,
            latency_avg_us: latency_avg,
            latency_p50_us: latency_p50,
            latency_p99_us: latency_p99,
            packets_sent: sent,
            packets_received: received,
            packet_loss_percent: packet_loss,
            throughput_mbps,
            duration_ms,
        })
    }
}
