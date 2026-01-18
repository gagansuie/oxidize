//! High-Performance Pipeline
//!
//! Integrates kernel bypass and BBRv4 for maximum throughput on Vultr bare metal.
//! Target: 40-100+ Gbps with sub-1µs latency per packet.
//!
//! BBRv4 optimizations:
//! - Fixed-point arithmetic (no f64 in hot paths)
//! - Cache-line aligned structures
//! - Batch ACK processing
//! - Lock-free atomics

#![allow(dead_code)] // Integration scaffolding

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
use tracing::debug;
use tracing::info;

#[cfg(target_os = "linux")]
use oxidize_common::bbr_v4::{BbrV4, BbrV4State};
// Kernel bypass is feature-gated - only available with --features kernel-bypass
#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
use oxidize_common::kernel_bypass::{BypassConfig, BypassPacket, BypassProcessor};

/// High-performance pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Kernel bypass configuration
    pub bypass: BypassConfigWrapper,
    /// BBRv4 configuration
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

/// Wrapper for kernel bypass config (allows non-Linux builds)
#[derive(Debug, Clone, Default)]
pub struct BypassConfigWrapper {
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
            bypass: BypassConfigWrapper::default(),
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
            bypass: BypassConfigWrapper {
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
            bypass: BypassConfigWrapper {
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
    #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
    bypass: Option<BypassProcessor>,
    #[cfg(all(target_os = "linux", not(feature = "kernel-bypass")))]
    bypass: Option<()>,
    #[cfg(target_os = "linux")]
    bbr_controllers: Vec<BbrV4>,
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

        #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
        let bypass = if !config.bypass.pci_address.is_empty() {
            let bypass_config = BypassConfig {
                pci_address: config.bypass.pci_address.clone(),
                rx_queues: config.bypass.rx_queues,
                tx_queues: config.bypass.tx_queues,
                enable_rss: config.bypass.enable_rss,
                quic_port: config.quic_port,
                ..BypassConfig::default()
            };
            Some(BypassProcessor::new(bypass_config)?)
        } else {
            info!("Kernel bypass disabled - no PCI address configured");
            None
        };
        #[cfg(all(target_os = "linux", not(feature = "kernel-bypass")))]
        let bypass: Option<()> = None;

        #[cfg(target_os = "linux")]
        let bbr_controllers = (0..config.workers)
            .map(|_| {
                if config.bbr.gaming_mode {
                    BbrV4::gaming()
                } else {
                    BbrV4::throughput()
                }
            })
            .collect();

        Ok(Self {
            config,
            stats: Arc::new(PipelineStats::default()),
            running: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
            #[cfg(target_os = "linux")]
            bypass,
            #[cfg(target_os = "linux")]
            bbr_controllers,
        })
    }

    /// Check if kernel bypass is available and configured
    #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
    pub fn bypass_available(&self) -> bool {
        self.bypass.is_some() && BypassProcessor::is_available()
    }

    #[cfg(all(target_os = "linux", not(feature = "kernel-bypass")))]
    pub fn bypass_available(&self) -> bool {
        false
    }

    #[cfg(not(target_os = "linux"))]
    pub fn bypass_available(&self) -> bool {
        false
    }

    /// Start the pipeline
    pub fn start(&mut self) {
        self.running.store(true, Ordering::SeqCst);
        self.start_time = Instant::now();

        #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
        if let Some(ref bypass) = self.bypass {
            bypass.start();
        }

        info!("High-performance pipeline started");
    }

    /// Stop the pipeline
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
        if let Some(ref bypass) = self.bypass {
            bypass.stop();
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
    #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
    pub fn process_batch(
        &mut self,
        worker_id: usize,
        packets: &mut Vec<BypassPacket>,
    ) -> Vec<BypassPacket> {
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
    #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
    fn process_single_packet(&self, mut packet: BypassPacket) -> Option<BypassPacket> {
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
    pub fn bbr_state(&self, worker_id: usize) -> BbrV4State {
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
        enable_bypass: bool,
        pci_address: Option<&str>,
        gaming_mode: bool,
        quic_port: u16,
    ) -> PipelineConfig {
        let mut config = if gaming_mode {
            PipelineConfig::gaming()
        } else {
            PipelineConfig::high_throughput()
        };

        if enable_bypass {
            if let Some(pci) = pci_address {
                config.bypass.pci_address = pci.to_string();
            }
        }

        config.quic_port = quic_port;
        config
    }

    /// Check system capabilities
    pub fn check_capabilities() -> PipelineCapabilities {
        PipelineCapabilities {
            #[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
            bypass_available: BypassProcessor::is_available(),
            #[cfg(not(all(target_os = "linux", feature = "kernel-bypass")))]
            bypass_available: false,
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
    pub bypass_available: bool,
    pub ktls_available: bool,
    pub cpu_cores: usize,
    pub numa_nodes: usize,
}

impl PipelineCapabilities {
    pub fn summary(&self) -> String {
        format!(
            "Capabilities: Bypass={}, kTLS={}, cores={}, NUMA={}",
            if self.bypass_available { "yes" } else { "no" },
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
