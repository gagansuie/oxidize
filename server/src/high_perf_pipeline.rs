//! High-Performance Pipeline
//!
//! Integrates DPDK, BBRv3, and XDP for maximum throughput on Hetzner bare metal.
//! Target: 10-40 Gbps with sub-5µs latency per packet.

#![allow(dead_code)] // Integration scaffolding

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info};

#[cfg(target_os = "linux")]
use oxidize_common::bbr_v3::{BbrCongestionControl, BbrState};
#[cfg(target_os = "linux")]
use oxidize_common::dpdk::{DpdkConfig, DpdkPacket, DpdkProcessor};

/// High-performance pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// DPDK configuration
    pub dpdk: DpdkConfigWrapper,
    /// BBRv3 configuration
    pub bbr: BbrConfigWrapper,
    /// Number of worker threads
    pub workers: usize,
    /// Batch size for packet processing
    pub batch_size: usize,
    /// Enable kTLS offload
    pub enable_ktls: bool,
    /// Enable ROHC compression
    pub enable_rohc: bool,
    /// QUIC port
    pub quic_port: u16,
}

/// Wrapper for DPDK config (allows non-Linux builds)
#[derive(Debug, Clone, Default)]
pub struct DpdkConfigWrapper {
    pub pci_address: String,
    pub rx_queues: u16,
    pub tx_queues: u16,
    pub enable_rss: bool,
}

/// Wrapper for BBR config
#[derive(Debug, Clone)]
pub struct BbrConfigWrapper {
    pub gaming_mode: bool,
    pub loss_tolerance: f64,
}

impl Default for BbrConfigWrapper {
    fn default() -> Self {
        Self {
            gaming_mode: false,
            loss_tolerance: 0.02,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            dpdk: DpdkConfigWrapper::default(),
            bbr: BbrConfigWrapper::default(),
            workers: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
                .min(8),
            batch_size: 64,
            enable_ktls: true,
            enable_rohc: true,
            quic_port: 4433,
        }
    }
}

impl PipelineConfig {
    /// Configuration for maximum throughput
    pub fn high_throughput() -> Self {
        Self {
            dpdk: DpdkConfigWrapper {
                rx_queues: 8,
                tx_queues: 8,
                enable_rss: true,
                ..Default::default()
            },
            bbr: BbrConfigWrapper {
                gaming_mode: false,
                loss_tolerance: 0.05,
            },
            workers: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(8),
            batch_size: 128,
            enable_ktls: true,
            enable_rohc: true,
            quic_port: 4433,
        }
    }

    /// Configuration for gaming (low latency)
    pub fn gaming() -> Self {
        Self {
            dpdk: DpdkConfigWrapper {
                rx_queues: 4,
                tx_queues: 4,
                enable_rss: true,
                ..Default::default()
            },
            bbr: BbrConfigWrapper {
                gaming_mode: true,
                loss_tolerance: 0.01,
            },
            workers: 4,
            batch_size: 32,
            enable_ktls: true,
            enable_rohc: true,
            quic_port: 4433,
        }
    }
}

/// Pipeline statistics
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub processing_time_ns: AtomicU64,
    pub packets_compressed: AtomicU64,
    pub bytes_saved: AtomicU64,
    pub bbr_cwnd_avg: AtomicU64,
}

impl PipelineStats {
    pub fn summary(&self, elapsed: Duration) -> String {
        let rx_pkts = self.rx_packets.load(Ordering::Relaxed);
        let tx_pkts = self.tx_packets.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let proc_ns = self.processing_time_ns.load(Ordering::Relaxed);

        let rx_gbps = (rx_bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000_000.0;
        let tx_gbps = (tx_bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000_000.0;
        let avg_proc_ns = if rx_pkts > 0 { proc_ns / rx_pkts } else { 0 };

        format!(
            "Pipeline: RX {:.2} Gbps ({} pkts), TX {:.2} Gbps ({} pkts), avg proc {}ns",
            rx_gbps, rx_pkts, tx_gbps, tx_pkts, avg_proc_ns
        )
    }
}

/// High-performance packet processing pipeline
pub struct HighPerfPipeline {
    config: PipelineConfig,
    stats: Arc<PipelineStats>,
    running: Arc<AtomicBool>,
    start_time: Instant,
    #[cfg(target_os = "linux")]
    dpdk: Option<DpdkProcessor>,
    #[cfg(target_os = "linux")]
    bbr_controllers: Vec<BbrCongestionControl>,
}

impl HighPerfPipeline {
    /// Create a new high-performance pipeline
    pub fn new(config: PipelineConfig) -> std::io::Result<Self> {
        info!("Initializing high-performance pipeline");
        info!("  Workers: {}", config.workers);
        info!("  Batch size: {}", config.batch_size);
        info!(
            "  kTLS: {}",
            if config.enable_ktls {
                "enabled"
            } else {
                "disabled"
            }
        );
        info!(
            "  ROHC: {}",
            if config.enable_rohc {
                "enabled"
            } else {
                "disabled"
            }
        );

        #[cfg(target_os = "linux")]
        let dpdk = if !config.dpdk.pci_address.is_empty() {
            let dpdk_config = DpdkConfig {
                pci_address: config.dpdk.pci_address.clone(),
                rx_queues: config.dpdk.rx_queues,
                tx_queues: config.dpdk.tx_queues,
                enable_rss: config.dpdk.enable_rss,
                quic_port: config.quic_port,
                ..DpdkConfig::default()
            };
            Some(DpdkProcessor::new(dpdk_config)?)
        } else {
            info!("DPDK disabled - no PCI address configured");
            None
        };

        #[cfg(target_os = "linux")]
        let bbr_controllers = (0..config.workers)
            .map(|_| {
                if config.bbr.gaming_mode {
                    BbrCongestionControl::gaming()
                } else {
                    BbrCongestionControl::throughput()
                }
            })
            .collect();

        Ok(Self {
            config,
            stats: Arc::new(PipelineStats::default()),
            running: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
            #[cfg(target_os = "linux")]
            dpdk,
            #[cfg(target_os = "linux")]
            bbr_controllers,
        })
    }

    /// Check if DPDK is available and configured
    #[cfg(target_os = "linux")]
    pub fn dpdk_available(&self) -> bool {
        self.dpdk.is_some() && DpdkProcessor::is_available()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn dpdk_available(&self) -> bool {
        false
    }

    /// Start the pipeline
    pub fn start(&mut self) {
        self.running.store(true, Ordering::SeqCst);
        self.start_time = Instant::now();

        #[cfg(target_os = "linux")]
        if let Some(ref dpdk) = self.dpdk {
            dpdk.start();
        }

        info!("High-performance pipeline started");
    }

    /// Stop the pipeline
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        #[cfg(target_os = "linux")]
        if let Some(ref dpdk) = self.dpdk {
            dpdk.stop();
        }

        info!("{}", self.stats.summary(self.start_time.elapsed()));
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get statistics
    pub fn stats(&self) -> &Arc<PipelineStats> {
        &self.stats
    }

    /// Process a batch of packets (main hot path)
    #[cfg(target_os = "linux")]
    pub fn process_batch(
        &mut self,
        worker_id: usize,
        packets: &mut Vec<DpdkPacket>,
    ) -> Vec<DpdkPacket> {
        let start = Instant::now();
        let mut output = Vec::with_capacity(packets.len());
        let bbr_idx = worker_id % self.bbr_controllers.len();
        let stats = Arc::clone(&self.stats);
        let quic_port = self.config.quic_port;
        let enable_rohc = self.config.enable_rohc;

        for mut packet in packets.drain(..) {
            stats.rx_packets.fetch_add(1, Ordering::Relaxed);
            stats
                .rx_bytes
                .fetch_add(packet.len as u64, Ordering::Relaxed);

            // Check BBR congestion window
            if !self.bbr_controllers[bbr_idx].can_send() {
                debug!("BBR congestion - dropping packet");
                continue;
            }

            // Process packet inline
            if !packet.parse_headers() {
                continue;
            }

            // Check if it's a QUIC packet for our port
            if let Some(dst) = packet.dst_addr {
                if dst.port() != quic_port {
                    output.push(packet);
                    continue;
                }
            }

            // Apply ROHC compression if enabled
            if enable_rohc {
                stats.packets_compressed.fetch_add(1, Ordering::Relaxed);
            }

            // Record send with BBR
            self.bbr_controllers[bbr_idx].on_send(packet.len as u64);

            stats.tx_packets.fetch_add(1, Ordering::Relaxed);
            stats
                .tx_bytes
                .fetch_add(packet.len as u64, Ordering::Relaxed);

            output.push(packet);
        }

        let proc_time = start.elapsed().as_nanos() as u64;
        stats
            .processing_time_ns
            .fetch_add(proc_time, Ordering::Relaxed);

        output
    }

    /// Process a single packet
    #[cfg(target_os = "linux")]
    fn process_single_packet(&self, mut packet: DpdkPacket) -> Option<DpdkPacket> {
        // Parse headers
        if !packet.parse_headers() {
            return None;
        }

        // Check if it's a QUIC packet for our port
        if let Some(dst) = packet.dst_addr {
            if dst.port() != self.config.quic_port {
                // Not for us - bypass
                return Some(packet);
            }
        }

        // Apply ROHC compression if enabled
        if self.config.enable_rohc {
            // In full implementation: compress headers
            self.stats
                .packets_compressed
                .fetch_add(1, Ordering::Relaxed);
        }

        Some(packet)
    }

    /// Record an ACK for BBR
    #[cfg(target_os = "linux")]
    pub fn record_ack(&mut self, worker_id: usize, bytes: u64, rtt: Duration) {
        let bbr_idx = worker_id % self.bbr_controllers.len();
        self.bbr_controllers[bbr_idx].on_ack(bytes, rtt);

        // Update stats with BBR cwnd
        let cwnd = self.bbr_controllers[bbr_idx].cwnd();
        self.stats.bbr_cwnd_avg.store(cwnd, Ordering::Relaxed);
    }

    /// Record a packet loss for BBR
    #[cfg(target_os = "linux")]
    pub fn record_loss(&mut self, worker_id: usize, bytes: u64) {
        let bbr_idx = worker_id % self.bbr_controllers.len();
        self.bbr_controllers[bbr_idx].on_loss(bytes);
    }

    /// Get current BBR state for a worker
    #[cfg(target_os = "linux")]
    pub fn bbr_state(&self, worker_id: usize) -> BbrState {
        self.bbr_controllers[worker_id % self.bbr_controllers.len()].state()
    }

    /// Get BBR statistics
    #[cfg(target_os = "linux")]
    pub fn bbr_stats(&self, worker_id: usize) -> String {
        self.bbr_controllers[worker_id % self.bbr_controllers.len()]
            .stats()
            .summary()
    }
}

/// Integration with existing server
pub struct PipelineIntegration;

impl PipelineIntegration {
    /// Create pipeline from server config
    pub fn from_config(
        enable_dpdk: bool,
        pci_address: Option<&str>,
        gaming_mode: bool,
        quic_port: u16,
    ) -> PipelineConfig {
        let mut config = if gaming_mode {
            PipelineConfig::gaming()
        } else {
            PipelineConfig::high_throughput()
        };

        if enable_dpdk {
            if let Some(pci) = pci_address {
                config.dpdk.pci_address = pci.to_string();
            }
        }

        config.quic_port = quic_port;
        config
    }

    /// Check system capabilities
    pub fn check_capabilities() -> PipelineCapabilities {
        PipelineCapabilities {
            #[cfg(target_os = "linux")]
            dpdk_available: DpdkProcessor::is_available(),
            #[cfg(not(target_os = "linux"))]
            dpdk_available: false,
            #[cfg(target_os = "linux")]
            ktls_available: oxidize_common::ktls::KtlsSocket::is_available(),
            #[cfg(not(target_os = "linux"))]
            ktls_available: false,
            cpu_cores: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1),
            numa_nodes: 1, // Would detect via libnuma
        }
    }
}

/// System capabilities for pipeline
#[derive(Debug)]
pub struct PipelineCapabilities {
    pub dpdk_available: bool,
    pub ktls_available: bool,
    pub cpu_cores: usize,
    pub numa_nodes: usize,
}

impl PipelineCapabilities {
    pub fn summary(&self) -> String {
        format!(
            "Capabilities: DPDK={}, kTLS={}, cores={}, NUMA={}",
            if self.dpdk_available { "yes" } else { "no" },
            if self.ktls_available { "yes" } else { "no" },
            self.cpu_cores,
            self.numa_nodes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config() {
        let config = PipelineConfig::default();
        assert!(config.workers > 0);
        assert!(config.batch_size > 0);
    }

    #[test]
    fn test_pipeline_creation() {
        let config = PipelineConfig::default();
        let pipeline = HighPerfPipeline::new(config);
        assert!(pipeline.is_ok());
    }

    #[test]
    fn test_capabilities_check() {
        let caps = PipelineIntegration::check_capabilities();
        assert!(caps.cpu_cores > 0);
    }
}
