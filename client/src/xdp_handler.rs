//! XDP Handler for Client
//!
//! High-performance packet processing using AF_XDP for 10+ Gbps throughput.
//! Replaces TUN interface for maximum performance on Linux.

#![allow(dead_code)] // Scaffolding for XDP feature - methods will be used when fully integrated

#[cfg(target_os = "linux")]
use oxidize_common::af_xdp::{XdpConfig, XdpSocket};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info};

/// XDP-accelerated client handler
/// Replaces TUN for higher throughput on supported systems
#[cfg(target_os = "linux")]
pub struct XdpClientHandler {
    config: XdpConfig,
    /// Server address
    server_addr: SocketAddr,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Statistics
    pub stats: Arc<ClientXdpStats>,
    /// Original gateway for bypass routing
    original_gateway: Option<String>,
}

/// Client-specific XDP statistics
#[derive(Debug, Default)]
pub struct ClientXdpStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tunneled_packets: AtomicU64,
    pub bypassed_packets: AtomicU64,
    pub dropped_packets: AtomicU64,
}

impl ClientXdpStats {
    pub fn summary(&self, elapsed: Duration) -> String {
        let rx = self.rx_packets.load(Ordering::Relaxed);
        let tx = self.tx_packets.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tunneled = self.tunneled_packets.load(Ordering::Relaxed);
        let bypassed = self.bypassed_packets.load(Ordering::Relaxed);

        let rx_gbps = (rx_bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000_000.0;
        let pps = rx as f64 / elapsed.as_secs_f64() / 1_000_000.0;

        format!(
            "XDP Client: {:.2} Gbps, {:.2}M pps, {} tunneled, {} bypassed, {} TX",
            rx_gbps, pps, tunneled, bypassed, tx
        )
    }
}

#[cfg(target_os = "linux")]
impl XdpClientHandler {
    /// Create a new XDP client handler
    pub fn new(interface: &str, server_addr: SocketAddr) -> std::io::Result<Self> {
        let mut config = XdpConfig::high_throughput();
        config.interface = interface.to_string();

        info!(
            "Creating XDP client handler on {} for server {}",
            interface, server_addr
        );

        Ok(XdpClientHandler {
            config,
            server_addr,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(ClientXdpStats::default()),
            original_gateway: None,
        })
    }

    /// Create with custom config
    pub fn with_config(config: XdpConfig, server_addr: SocketAddr) -> std::io::Result<Self> {
        Ok(XdpClientHandler {
            config,
            server_addr,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(ClientXdpStats::default()),
            original_gateway: None,
        })
    }

    /// Create optimized for gaming (low latency)
    pub fn gaming(interface: &str, server_addr: SocketAddr) -> std::io::Result<Self> {
        let mut config = XdpConfig::low_latency();
        config.interface = interface.to_string();

        Ok(XdpClientHandler {
            config,
            server_addr,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(ClientXdpStats::default()),
            original_gateway: None,
        })
    }

    /// Check if XDP is available
    pub fn is_available() -> bool {
        XdpSocket::is_supported()
    }

    /// Get the default network interface
    pub fn get_default_interface() -> Option<String> {
        // Read default route to find interface
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "00000000" {
                    return Some(parts[0].to_string());
                }
            }
        }
        None
    }

    /// Save original network configuration
    fn save_original_config(&mut self) -> std::io::Result<()> {
        // Get default gateway
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            let route_output = String::from_utf8_lossy(&output.stdout);
            if let Some(gateway) = route_output.split_whitespace().nth(2) {
                self.original_gateway = Some(gateway.to_string());
                info!("Original gateway: {}", gateway);
            }
        }
        Ok(())
    }

    /// Setup routing for XDP mode
    fn setup_routing(&self) -> std::io::Result<()> {
        // Add route for server to bypass XDP (use original gateway)
        if let Some(ref gateway) = self.original_gateway {
            let server_ip = match self.server_addr.ip() {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => ip.to_string(),
            };

            std::process::Command::new("ip")
                .args(["route", "add", &server_ip, "via", gateway])
                .output()
                .ok();

            info!(
                "Added bypass route for server {} via {}",
                server_ip, gateway
            );
        }
        Ok(())
    }

    /// Cleanup routing
    fn cleanup_routing(&self) -> std::io::Result<()> {
        if let Some(ref _gateway) = self.original_gateway {
            let server_ip = match self.server_addr.ip() {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => ip.to_string(),
            };

            std::process::Command::new("ip")
                .args(["route", "del", &server_ip])
                .output()
                .ok();

            info!("Removed bypass route for server {}", server_ip);
        }
        Ok(())
    }

    /// Start the XDP handler
    pub fn start(&mut self) -> std::io::Result<()> {
        self.save_original_config()?;
        self.setup_routing()?;
        self.running.store(true, Ordering::SeqCst);
        info!("XDP client handler started");
        Ok(())
    }

    /// Stop the XDP handler
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.cleanup_routing().ok();
        info!("XDP client handler stopped");
    }

    /// Check if packet should be tunneled or bypassed
    fn should_tunnel(&self, _packet: &[u8]) -> bool {
        // In production, implement traffic classification here
        // For now, tunnel everything except server traffic
        true
    }

    /// Check if packet is destined for our server (should bypass)
    fn is_server_traffic(&self, packet: &[u8]) -> bool {
        if packet.len() < 34 {
            return false;
        }

        // Check if IPv4
        if packet[12] != 0x08 || packet[13] != 0x00 {
            return false;
        }

        // Get destination IP
        let dst_ip = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);

        match self.server_addr.ip() {
            IpAddr::V4(server_ip) => dst_ip == server_ip,
            _ => false,
        }
    }

    /// Run the XDP processing loop
    pub async fn run(
        &mut self,
        _quic_tx: mpsc::Sender<Vec<u8>>, // Packets to send through tunnel
        mut quic_rx: mpsc::Receiver<Vec<u8>>, // Packets received from tunnel
    ) -> std::io::Result<()> {
        info!("Starting XDP client processing loop");
        self.start()?;

        let start_time = Instant::now();

        // In a real implementation, this would:
        // 1. Create AF_XDP socket on the network interface
        // 2. Load eBPF program to redirect packets
        // 3. Process packets in a tight loop:
        //    - RX: Capture packets, classify, tunnel or bypass
        //    - TX: Inject tunnel responses back to applications

        while self.running.load(Ordering::Relaxed) {
            tokio::select! {
                // Handle packets from tunnel (responses)
                Some(packet) = quic_rx.recv() => {
                    self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.stats.rx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    // In real impl: inject packet to local network stack via AF_XDP TX
                }

                // Periodic stats logging
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    debug!("{}", self.stats.summary(start_time.elapsed()));
                }
            }
        }

        self.stop();
        info!(
            "XDP client stopped. Stats: {}",
            self.stats.summary(start_time.elapsed())
        );

        Ok(())
    }
}

/// Fallback for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub struct XdpClientHandler;

#[cfg(not(target_os = "linux"))]
impl XdpClientHandler {
    pub fn new(_interface: &str, _server_addr: SocketAddr) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "XDP is only supported on Linux",
        ))
    }

    pub fn is_available() -> bool {
        false
    }

    pub fn get_default_interface() -> Option<String> {
        None
    }
}

/// Determine whether to use XDP or TUN based on system capabilities
pub fn select_capture_mode() -> CaptureMode {
    #[cfg(target_os = "linux")]
    {
        if XdpClientHandler::is_available() {
            if let Some(iface) = XdpClientHandler::get_default_interface() {
                if oxidize_common::af_xdp::XdpSocket::interface_supports_xdp(&iface) {
                    return CaptureMode::Xdp(iface);
                }
            }
        }
    }

    CaptureMode::Tun
}

/// Packet capture mode
#[derive(Debug, Clone)]
pub enum CaptureMode {
    /// AF_XDP (Linux, high performance)
    Xdp(String), // interface name
    /// TUN device (cross-platform)
    Tun,
    /// No capture (proxy mode only)
    None,
}

impl CaptureMode {
    pub fn description(&self) -> &'static str {
        match self {
            CaptureMode::Xdp(_) => "AF_XDP (10+ Gbps, Linux)",
            CaptureMode::Tun => "TUN device (cross-platform, ~2 Gbps)",
            CaptureMode::None => "No capture (proxy mode)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats() {
        let stats = ClientXdpStats::default();
        stats.rx_packets.fetch_add(1000, Ordering::Relaxed);
        stats.rx_bytes.fetch_add(64000, Ordering::Relaxed);
        stats.tunneled_packets.fetch_add(900, Ordering::Relaxed);
        stats.bypassed_packets.fetch_add(100, Ordering::Relaxed);

        let summary = stats.summary(Duration::from_secs(1));
        assert!(summary.contains("tunneled"));
        assert!(summary.contains("bypassed"));
    }

    #[test]
    fn test_capture_mode_description() {
        let mode = CaptureMode::Tun;
        assert!(mode.description().contains("TUN"));

        let mode = CaptureMode::Xdp("eth0".to_string());
        assert!(mode.description().contains("XDP"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_default_interface() {
        // This might return None in CI environments
        let iface = XdpClientHandler::get_default_interface();
        println!("Default interface: {:?}", iface);
    }
}
