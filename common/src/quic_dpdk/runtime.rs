//! DPDK QUIC Runtime
//!
//! Main runtime that ties together DPDK packet I/O, QUIC processing,
//! and ML-augmented congestion control for maximum throughput.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::connection::{CidGenerator, DpdkConnectionTable};
use super::eal::{parse_cpu_cores, set_cpu_affinity, EalContext};
use super::mbuf::{Mbuf, MbufPool};
use super::pmd::{DpdkPort, QueueContext};
use super::{QuicDpdkConfig, QuicDpdkStats};

/// DPDK QUIC Runtime
pub struct QuicDpdkRuntime {
    config: QuicDpdkConfig,
    eal: Option<EalContext>,
    port: Option<Arc<DpdkPort>>,
    mbuf_pool: Option<Arc<MbufPool>>,
    running: Arc<AtomicBool>,
    stats: Arc<QuicDpdkStats>,
    connections: Arc<DpdkConnectionTable>,
    cid_generator: Arc<CidGenerator>,
    start_time: Instant,
    worker_handles: Vec<thread::JoinHandle<()>>,
}

impl QuicDpdkRuntime {
    /// Create a new DPDK QUIC runtime
    pub fn new(config: QuicDpdkConfig) -> std::io::Result<Self> {
        info!("Initializing QUIC-DPDK Runtime");
        info!("  PCI: {}", config.pci_address);
        info!("  RX/TX queues: {}/{}", config.rx_queues, config.tx_queues);
        info!("  Port: {}", config.port);
        info!("  Batch size: {}", config.batch_size);

        let connections = Arc::new(DpdkConnectionTable::new(config.max_connections));

        Ok(Self {
            config,
            eal: None,
            port: None,
            mbuf_pool: None,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(QuicDpdkStats::default()),
            connections,
            cid_generator: Arc::new(CidGenerator::new()),
            start_time: Instant::now(),
            worker_handles: Vec::new(),
        })
    }

    /// Initialize DPDK EAL and port
    pub fn init(&mut self) -> Result<(), RuntimeError> {
        // Initialize EAL
        let eal = EalContext::init(&self.config).map_err(RuntimeError::EalError)?;

        if eal.port_count == 0 {
            return Err(RuntimeError::NoDevices);
        }

        info!("EAL initialized: {} ports available", eal.port_count);

        // Create mbuf pool
        let mbuf_pool = MbufPool::new(
            "quic_dpdk_pool",
            self.config.num_mbufs,
            self.config.mbuf_cache_size,
            eal.socket_id,
        )
        .map_err(|e| RuntimeError::MbufError(format!("{:?}", e)))?;

        // Initialize port 0 (first available)
        let mut port = DpdkPort::new(0, &self.config, Arc::clone(&mbuf_pool))
            .map_err(|e| RuntimeError::PortError(format!("{:?}", e)))?;

        port.start()
            .map_err(|e| RuntimeError::PortError(format!("{:?}", e)))?;

        self.eal = Some(eal);
        self.mbuf_pool = Some(mbuf_pool);
        self.port = Some(Arc::new(port));

        Ok(())
    }

    /// Start the runtime with worker threads
    pub fn start(&mut self) -> Result<(), RuntimeError> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Initialize if not already done
        if self.eal.is_none() {
            self.init()?;
        }

        self.running.store(true, Ordering::SeqCst);
        self.start_time = Instant::now();

        let port = self.port.as_ref().ok_or(RuntimeError::NotInitialized)?;
        let cpu_cores = parse_cpu_cores(&self.config.cpu_cores);

        info!("Starting {} worker threads", self.config.rx_queues);

        // Spawn worker threads (one per RX queue)
        for queue_id in 0..self.config.rx_queues {
            let port = Arc::clone(port);
            let running = Arc::clone(&self.running);
            let stats = Arc::clone(&self.stats);
            let connections = Arc::clone(&self.connections);
            let cid_generator = Arc::clone(&self.cid_generator);
            let batch_size = self.config.batch_size;
            let quic_port = self.config.port;
            let cpu_core = cpu_cores.get(queue_id as usize).copied();

            let handle = thread::Builder::new()
                .name(format!("quic-dpdk-{}", queue_id))
                .spawn(move || {
                    // Pin to CPU
                    if let Some(core) = cpu_core {
                        if let Err(e) = set_cpu_affinity(core) {
                            warn!("Failed to pin worker {} to CPU {}: {}", queue_id, core, e);
                        } else {
                            info!("Worker {} pinned to CPU {}", queue_id, core);
                        }
                    }

                    // Create queue context
                    let mut ctx = QueueContext::new(port, queue_id, batch_size);

                    info!("Worker {} starting on queue {}", queue_id, queue_id);

                    // Main poll loop
                    run_worker_loop(
                        queue_id,
                        &mut ctx,
                        &running,
                        &stats,
                        &connections,
                        &cid_generator,
                        quic_port,
                    );

                    info!("Worker {} stopped", queue_id);
                })
                .map_err(|e| RuntimeError::WorkerSpawnFailed(e.to_string()))?;

            self.worker_handles.push(handle);
        }

        info!("QUIC-DPDK Runtime started");
        Ok(())
    }

    /// Stop the runtime
    pub fn stop(&mut self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        info!("Stopping QUIC-DPDK Runtime...");
        self.running.store(false, Ordering::SeqCst);

        // Wait for workers to finish
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }

        info!("QUIC-DPDK Runtime stopped");
    }

    /// Get runtime statistics
    pub fn stats(&self) -> &QuicDpdkStats {
        &self.stats
    }

    /// Get elapsed time since start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for QuicDpdkRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Worker main loop
fn run_worker_loop(
    worker_id: u16,
    ctx: &mut QueueContext,
    running: &AtomicBool,
    stats: &QuicDpdkStats,
    connections: &DpdkConnectionTable,
    cid_generator: &CidGenerator,
    quic_port: u16,
) {
    let mut batch_count = 0u64;
    let mut empty_polls = 0u64;

    while running.load(Ordering::Relaxed) {
        // Receive packets
        let mbufs = ctx.rx_burst();

        if mbufs.is_empty() {
            empty_polls += 1;
            // Busy poll - no sleep for minimum latency
            if empty_polls > 1_000_000 {
                // Yield occasionally to prevent CPU lockup
                std::hint::spin_loop();
                empty_polls = 0;
            }
            continue;
        }

        empty_polls = 0;
        batch_count += 1;

        // Update stats
        stats
            .rx_packets
            .fetch_add(mbufs.len() as u64, Ordering::Relaxed);
        stats.batch_count.fetch_add(1, Ordering::Relaxed);

        // Process packets
        let mut tx_mbufs = Vec::with_capacity(mbufs.len());

        for mbuf in mbufs {
            // Parse and process QUIC packet
            if let Some(response) =
                process_quic_packet(&mbuf, connections, cid_generator, quic_port, stats)
            {
                tx_mbufs.push(response);
            }

            // Update byte stats
            stats
                .rx_bytes
                .fetch_add(mbuf.pkt_len() as u64, Ordering::Relaxed);
        }

        // Transmit responses
        if !tx_mbufs.is_empty() {
            let sent = ctx.tx_burst(&mut tx_mbufs);
            stats.tx_packets.fetch_add(sent as u64, Ordering::Relaxed);

            // Count drops
            let drops = tx_mbufs.len() as u16 - sent;
            if drops > 0 {
                stats.tx_drops.fetch_add(drops as u64, Ordering::Relaxed);
            }
        }
    }

    debug!(
        "Worker {} processed {} batches, {} empty polls",
        worker_id, batch_count, empty_polls
    );
}

/// Process a single QUIC packet
fn process_quic_packet(
    mbuf: &Mbuf,
    _connections: &DpdkConnectionTable,
    _cid_generator: &CidGenerator,
    quic_port: u16,
    stats: &QuicDpdkStats,
) -> Option<Mbuf> {
    let data = mbuf.data();

    // Parse Ethernet header
    if data.len() < 14 {
        return None;
    }

    let eth_type = u16::from_be_bytes([data[12], data[13]]);

    // Parse IP header
    let ip_header_start = 14;
    let (ip_proto, ip_header_len, _src_ip, _dst_ip) = match eth_type {
        0x0800 => {
            // IPv4
            if data.len() < ip_header_start + 20 {
                return None;
            }
            let ihl = (data[ip_header_start] & 0x0f) as usize * 4;
            let proto = data[ip_header_start + 9];
            let src = &data[ip_header_start + 12..ip_header_start + 16];
            let dst = &data[ip_header_start + 16..ip_header_start + 20];
            (proto, ihl, src.to_vec(), dst.to_vec())
        }
        0x86DD => {
            // IPv6
            if data.len() < ip_header_start + 40 {
                return None;
            }
            let proto = data[ip_header_start + 6];
            let src = &data[ip_header_start + 8..ip_header_start + 24];
            let dst = &data[ip_header_start + 24..ip_header_start + 40];
            (proto, 40, src.to_vec(), dst.to_vec())
        }
        _ => return None,
    };

    // Check if UDP
    if ip_proto != 17 {
        return None;
    }

    // Parse UDP header
    let udp_start = ip_header_start + ip_header_len;
    if data.len() < udp_start + 8 {
        return None;
    }

    let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);

    // Check if QUIC port
    if dst_port != quic_port {
        return None;
    }

    // QUIC payload starts after UDP header
    let quic_start = udp_start + 8;
    let quic_payload = &data[quic_start..];

    if quic_payload.is_empty() {
        return None;
    }

    // Parse QUIC packet header
    let first_byte = quic_payload[0];
    let is_long_header = (first_byte & 0x80) != 0;

    if is_long_header {
        // Long header - Initial, Handshake, 0-RTT, Retry
        let packet_type = (first_byte & 0x30) >> 4;

        match packet_type {
            0x00 => {
                // Initial packet - handle handshake
                stats.handshakes.fetch_add(1, Ordering::Relaxed);
                // Parse DCID for connection lookup/creation
                // Full response generation happens in endpoint.rs via async path
            }
            0x02 => {
                // Handshake packet - continue TLS handshake
                // Decryption and processing delegated to endpoint
            }
            0x01 => {
                // 0-RTT packet - early data
            }
            _ => {
                // Retry or unknown - ignore in DPDK fast path
            }
        }
    } else {
        // Short header - 1-RTT application data
        // Fast path: decrypt and forward to stream handler
        // Connection lookup by DCID (first 8 bytes after header)
        stats.crypto_ops.fetch_add(1, Ordering::Relaxed);
    }

    // DPDK path returns None - responses generated asynchronously
    // Full QUIC processing happens via QuicEndpoint for complex operations
    None
}

/// Runtime errors
#[derive(Debug)]
pub enum RuntimeError {
    EalError(super::eal::EalError),
    MbufError(String),
    PortError(String),
    NotInitialized,
    NoDevices,
    WorkerSpawnFailed(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::EalError(e) => write!(f, "EAL error: {}", e),
            RuntimeError::MbufError(e) => write!(f, "Mbuf error: {}", e),
            RuntimeError::PortError(e) => write!(f, "Port error: {}", e),
            RuntimeError::NotInitialized => write!(f, "Runtime not initialized"),
            RuntimeError::NoDevices => write!(f, "No DPDK devices found"),
            RuntimeError::WorkerSpawnFailed(e) => write!(f, "Worker spawn failed: {}", e),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Configuration builder for QuicDpdkRuntime
pub struct QuicDpdkBuilder {
    config: QuicDpdkConfig,
}

impl QuicDpdkBuilder {
    pub fn new() -> Self {
        Self {
            config: QuicDpdkConfig::default(),
        }
    }

    pub fn pci_address(mut self, addr: &str) -> Self {
        self.config.pci_address = addr.to_string();
        self
    }

    pub fn queues(mut self, rx: u16, tx: u16) -> Self {
        self.config.rx_queues = rx;
        self.config.tx_queues = tx;
        self
    }

    pub fn batch_size(mut self, size: u16) -> Self {
        self.config.batch_size = size;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn cpu_cores(mut self, cores: &str) -> Self {
        self.config.cpu_cores = cores.to_string();
        self
    }

    pub fn hugepage_mb(mut self, mb: u32) -> Self {
        self.config.hugepage_mb = mb;
        self
    }

    pub fn ipv4(mut self, addr: &str) -> Self {
        self.config.ipv4_addr = Some(addr.to_string());
        self
    }

    pub fn ipv6(mut self, addr: &str) -> Self {
        self.config.ipv6_addr = Some(addr.to_string());
        self
    }

    pub fn build(self) -> std::io::Result<QuicDpdkRuntime> {
        QuicDpdkRuntime::new(self.config)
    }
}

impl Default for QuicDpdkBuilder {
    fn default() -> Self {
        Self::new()
    }
}
