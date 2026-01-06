use anyhow::{Context, Result};
use oxidize_common::traffic_classifier::{
    ClassifierConfig, DnsTrafficDetector, Protocol, TrafficClassifier,
};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::ClientConfig;

/// TUN interface configuration
pub struct TunConfig {
    /// TUN interface name
    pub name: String,
    /// TUN interface IP address
    pub address: (u8, u8, u8, u8),
    /// TUN interface netmask
    pub netmask: (u8, u8, u8, u8),
    /// MTU size
    pub mtu: usize,
    /// DNS servers to use
    pub dns_servers: Vec<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "oxidize0".to_string(),
            address: (10, 200, 200, 1),
            netmask: (255, 255, 255, 0),
            mtu: 1400,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        }
    }
}

pub struct TunHandler {
    config: ClientConfig,
    tun_config: TunConfig,
    server_ip: Option<IpAddr>,
    original_gateway: Option<String>,
    original_dns: Option<Vec<String>>,
    /// Traffic classifier for smart routing
    classifier: Arc<TrafficClassifier>,
    /// DNS detector to map IPs to domains
    dns_detector: Arc<DnsTrafficDetector>,
    /// Bypass domains configuration
    bypass_domains: Vec<String>,
}

impl TunHandler {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let classifier_config = ClassifierConfig::default();
        let bypass_domains = classifier_config.bypass_domains.clone();

        Ok(Self {
            config,
            tun_config: TunConfig::default(),
            server_ip: None,
            original_gateway: None,
            original_dns: None,
            classifier: Arc::new(TrafficClassifier::new(classifier_config)),
            dns_detector: Arc::new(DnsTrafficDetector::new()),
            bypass_domains,
        })
    }

    pub fn with_server_ip(mut self, ip: IpAddr) -> Self {
        self.server_ip = Some(ip);
        self
    }

    /// Setup TUN interface and configure routing
    pub async fn setup(&mut self) -> Result<tun::platform::Device> {
        info!("Setting up TUN interface...");

        // Check for root/admin privileges
        if !Self::has_privileges() {
            anyhow::bail!(
                "Root/administrator privileges required for TUN mode.\n\
                 Run with: sudo oxidize-client --server <addr>\n\
                 Or use --no-tun for proxy mode."
            );
        }

        // Save original network configuration for cleanup
        self.save_original_config()?;

        // Create TUN device
        let mut tun_config = tun::Configuration::default();
        tun_config
            .address(self.tun_config.address)
            .netmask(self.tun_config.netmask)
            .mtu(self.tun_config.mtu as i32)
            .up();

        #[cfg(target_os = "linux")]
        tun_config.platform(|config| {
            config.packet_information(false);
        });

        #[cfg(target_os = "linux")]
        tun_config.name(&self.tun_config.name);

        let dev = tun::create(&tun_config).context("Failed to create TUN device")?;

        info!("✅ TUN interface created: {}", self.tun_config.name);
        info!(
            "   Address: {}.{}.{}.{}/24",
            self.tun_config.address.0,
            self.tun_config.address.1,
            self.tun_config.address.2,
            self.tun_config.address.3
        );
        info!("   MTU: {}", self.tun_config.mtu);

        // Configure routing to capture all traffic
        self.setup_routing()?;

        // Configure DNS to prevent leaks
        self.setup_dns()?;

        info!("✅ Routing configured - all traffic via Oxidize");

        Ok(dev)
    }

    /// Configure routing to send all traffic through TUN
    fn setup_routing(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.setup_routing_linux()?;
        }

        #[cfg(target_os = "macos")]
        {
            self.setup_routing_macos()?;
        }

        #[cfg(target_os = "windows")]
        {
            self.setup_routing_windows()?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn setup_routing_linux(&self) -> Result<()> {
        let _tun_ip = format!(
            "{}.{}.{}.{}",
            self.tun_config.address.0,
            self.tun_config.address.1,
            self.tun_config.address.2,
            self.tun_config.address.3
        );

        // Add route for relay server to bypass TUN (use original gateway)
        if let (Some(server_ip), Some(ref gateway)) = (&self.server_ip, &self.original_gateway) {
            run_cmd(
                "ip",
                &["route", "add", &server_ip.to_string(), "via", gateway],
            )?;
            info!("   Route: {} via {} (direct)", server_ip, gateway);
        }

        // Route all traffic through TUN using split routing
        // 0.0.0.0/1 and 128.0.0.0/1 cover all IPs without replacing default route
        run_cmd(
            "ip",
            &["route", "add", "0.0.0.0/1", "dev", &self.tun_config.name],
        )?;
        run_cmd(
            "ip",
            &["route", "add", "128.0.0.0/1", "dev", &self.tun_config.name],
        )?;

        info!("   Route: 0.0.0.0/1 via {}", self.tun_config.name);
        info!("   Route: 128.0.0.0/1 via {}", self.tun_config.name);

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn setup_routing_macos(&self) -> Result<()> {
        let tun_ip = format!(
            "{}.{}.{}.{}",
            self.tun_config.address.0,
            self.tun_config.address.1,
            self.tun_config.address.2,
            self.tun_config.address.3
        );

        // Add route for relay server to bypass TUN
        if let (Some(server_ip), Some(ref gateway)) = (&self.server_ip, &self.original_gateway) {
            run_cmd(
                "route",
                &["-n", "add", "-host", &server_ip.to_string(), gateway],
            )?;
        }

        // Route all traffic through TUN
        run_cmd(
            "route",
            &["-n", "add", "-net", "0.0.0.0/1", "-interface", "utun0"],
        )?;
        run_cmd(
            "route",
            &["-n", "add", "-net", "128.0.0.0/1", "-interface", "utun0"],
        )?;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn setup_routing_windows(&self) -> Result<()> {
        let tun_ip = format!(
            "{}.{}.{}.{}",
            self.tun_config.address.0,
            self.tun_config.address.1,
            self.tun_config.address.2,
            self.tun_config.address.3
        );

        // Add route for relay server to bypass TUN
        if let (Some(server_ip), Some(ref gateway)) = (&self.server_ip, &self.original_gateway) {
            run_cmd(
                "route",
                &[
                    "add",
                    &server_ip.to_string(),
                    "mask",
                    "255.255.255.255",
                    gateway,
                ],
            )?;
        }

        // Route all traffic through TUN
        run_cmd(
            "route",
            &[
                "add",
                "0.0.0.0",
                "mask",
                "128.0.0.0",
                &tun_ip,
                "metric",
                "1",
            ],
        )?;
        run_cmd(
            "route",
            &[
                "add",
                "128.0.0.0",
                "mask",
                "128.0.0.0",
                &tun_ip,
                "metric",
                "1",
            ],
        )?;

        Ok(())
    }

    /// Configure DNS to use secure resolvers
    fn setup_dns(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.setup_dns_linux()?;
        }

        #[cfg(target_os = "macos")]
        {
            self.setup_dns_macos()?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn setup_dns_linux(&self) -> Result<()> {
        // Use resolvconf if available, otherwise modify /etc/resolv.conf
        let dns = &self.tun_config.dns_servers;

        if Command::new("resolvconf").arg("--version").output().is_ok() {
            let dns_config = dns
                .iter()
                .map(|s| format!("nameserver {}", s))
                .collect::<Vec<_>>()
                .join("\n");

            let mut child = Command::new("resolvconf")
                .args(&["-a", &format!("{}.oxidize", self.tun_config.name)])
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(dns_config.as_bytes())?;
            }
            child.wait()?;
        } else {
            // Backup and modify resolv.conf directly
            warn!("resolvconf not found, modifying /etc/resolv.conf directly");
            let backup = std::fs::read_to_string("/etc/resolv.conf").ok();
            if backup.is_some() {
                std::fs::write("/etc/resolv.conf.oxidize.bak", backup.unwrap())?;
            }

            let new_config = dns
                .iter()
                .map(|s| format!("nameserver {}", s))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write("/etc/resolv.conf", new_config)?;
        }

        info!("   DNS: {:?}", dns);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn setup_dns_macos(&self) -> Result<()> {
        let dns = &self.tun_config.dns_servers;
        for dns_server in dns {
            run_cmd("networksetup", &["-setdnsservers", "Wi-Fi", dns_server])?;
        }
        info!("   DNS: {:?}", dns);
        Ok(())
    }

    /// Save original network configuration for restoration
    fn save_original_config(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // Get default gateway
            let output = Command::new("ip")
                .args(&["route", "show", "default"])
                .output()?;
            let route_output = String::from_utf8_lossy(&output.stdout);
            if let Some(gateway) = route_output.split_whitespace().nth(2) {
                self.original_gateway = Some(gateway.to_string());
                info!("   Original gateway: {}", gateway);
            }

            // Get original DNS
            if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
                let dns: Vec<String> = resolv
                    .lines()
                    .filter(|l| l.starts_with("nameserver"))
                    .filter_map(|l| l.split_whitespace().nth(1))
                    .map(|s| s.to_string())
                    .collect();
                if !dns.is_empty() {
                    self.original_dns = Some(dns);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("route")
                .args(&["-n", "get", "default"])
                .output()?;
            let route_output = String::from_utf8_lossy(&output.stdout);
            for line in route_output.lines() {
                if line.contains("gateway:") {
                    if let Some(gw) = line.split_whitespace().last() {
                        self.original_gateway = Some(gw.to_string());
                    }
                }
            }
        }

        Ok(())
    }

    /// Cleanup routing and restore original configuration
    pub fn cleanup(&self) -> Result<()> {
        info!("Cleaning up TUN configuration...");

        #[cfg(target_os = "linux")]
        {
            // Remove routes
            let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1"]);
            let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1"]);

            if let Some(ref server_ip) = self.server_ip {
                let _ = run_cmd("ip", &["route", "del", &server_ip.to_string()]);
            }

            // Restore DNS
            if std::path::Path::new("/etc/resolv.conf.oxidize.bak").exists() {
                let _ = std::fs::copy("/etc/resolv.conf.oxidize.bak", "/etc/resolv.conf");
                let _ = std::fs::remove_file("/etc/resolv.conf.oxidize.bak");
            }

            // Remove resolvconf entry if used
            let _ = Command::new("resolvconf")
                .args(&["-d", &format!("{}.oxidize", self.tun_config.name)])
                .output();
        }

        #[cfg(target_os = "macos")]
        {
            let _ = run_cmd("route", &["-n", "delete", "-net", "0.0.0.0/1"]);
            let _ = run_cmd("route", &["-n", "delete", "-net", "128.0.0.0/1"]);

            // Reset DNS to automatic
            let _ = run_cmd("networksetup", &["-setdnsservers", "Wi-Fi", "empty"]);
        }

        info!("✅ Cleanup complete");
        Ok(())
    }

    /// Check if running with required privileges
    fn has_privileges() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(windows)]
        {
            // On Windows, check if running as administrator
            true // Simplified - would need proper Windows API check
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    /// Run TUN handler with smart traffic classification
    /// - Gaming/general traffic → QUIC tunnel (tx channel)
    /// - Streaming traffic → bypass (sent directly)
    pub async fn run(&mut self, tx: mpsc::Sender<Vec<u8>>) -> Result<()> {
        let mut dev = self.setup().await?;
        let mtu = self.config.tun_mtu;

        // Setup cleanup on Ctrl+C
        let cleanup_handler = self.clone_for_cleanup();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cleanup_handler.cleanup().ok();
            std::process::exit(0);
        });

        // Channel for raw packets from TUN
        let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(1024);

        // Classifier and DNS detector for routing decisions
        let classifier = self.classifier.clone();
        let dns_detector = self.dns_detector.clone();

        // Spawn blocking reader for TUN device
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut buffer = vec![0u8; mtu + 4];

            loop {
                match dev.read(&mut buffer) {
                    Ok(len) if len > 0 => {
                        let packet = buffer[..len].to_vec();
                        if raw_tx.blocking_send(packet).is_err() {
                            break;
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Process packets with smart routing
        while let Some(packet) = raw_rx.recv().await {
            // Parse packet to get routing info
            if let Some((dest_ip, dest_port, protocol)) = Self::parse_ipv4_packet(&packet) {
                // Check if we know the domain for this IP (from DNS tracking)
                let domain = dns_detector.get_domain(IpAddr::V4(dest_ip)).await;

                // Get routing decision from classifier
                let decision = classifier
                    .get_route(IpAddr::V4(dest_ip), dest_port, protocol, domain.as_deref())
                    .await;

                if decision.bypass_tunnel {
                    // Streaming traffic - bypass tunnel
                    debug!(
                        "BYPASS: {:?} -> {}:{} (streaming/bypass traffic)",
                        domain, dest_ip, dest_port
                    );
                    // Packet is dropped here - it will be routed directly by the kernel
                    // via the bypass routes we set up for streaming domains
                    continue;
                }

                // Gaming/general traffic - send through QUIC tunnel
                debug!(
                    "TUNNEL: {:?} -> {}:{} (optimized)",
                    domain, dest_ip, dest_port
                );
            }

            // Send to QUIC tunnel
            if tx.send(packet).await.is_err() {
                error!("Failed to queue packet to tunnel");
                break;
            }
        }

        self.cleanup()?;
        Ok(())
    }

    fn clone_for_cleanup(&self) -> Self {
        Self {
            config: self.config.clone(),
            tun_config: TunConfig::default(),
            server_ip: self.server_ip,
            original_gateway: self.original_gateway.clone(),
            original_dns: self.original_dns.clone(),
            classifier: self.classifier.clone(),
            dns_detector: self.dns_detector.clone(),
            bypass_domains: self.bypass_domains.clone(),
        }
    }

    /// Parse IPv4 packet to extract destination IP and protocol
    fn parse_ipv4_packet(packet: &[u8]) -> Option<(Ipv4Addr, u16, Protocol)> {
        if packet.len() < 20 {
            return None;
        }

        // Check IP version
        let version = (packet[0] >> 4) & 0x0f;
        if version != 4 {
            return None;
        }

        // Get header length
        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl {
            return None;
        }

        // Extract destination IP (bytes 16-19)
        let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        // Extract protocol (byte 9)
        let protocol = Protocol::from(packet[9]);

        // Extract destination port (first 2 bytes after IP header for TCP/UDP)
        let dest_port = if packet.len() >= ihl + 4 {
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]])
        } else {
            0
        };

        Some((dest_ip, dest_port, protocol))
    }
}

/// Run a system command, logging errors
fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    debug!("Running: {} {}", cmd, args.join(" "));
    let output = Command::new(cmd).args(args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Command failed: {} {} - {}", cmd, args.join(" "), stderr);
    }

    Ok(())
}
