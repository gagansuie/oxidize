//! Cross-Platform TUN Device Management
//!
//! Provides unified TUN device creation, configuration, and I/O for all platforms.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use tracing::{info, warn};

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "oxtun0" on Linux, "utun3" on macOS)
    pub name: String,
    /// TUN IP address
    pub address: IpAddr,
    /// Network prefix length (e.g., 24 for /24)
    pub netmask: u8,
    /// MTU size (default 1500)
    pub mtu: u16,
    /// Enable packet info header (4 bytes: flags + proto)
    pub packet_info: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "oxtun0".to_string(),
            address: IpAddr::V4(Ipv4Addr::new(10, 200, 200, 1)),
            netmask: 24,
            mtu: 1500,
            packet_info: true,
        }
    }
}

/// Cross-platform TUN device
pub struct TunDevice {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    device: tun_tap::Iface,
    #[cfg(target_os = "windows")]
    session: wintun::Session,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    fd: RawFd,
    #[allow(dead_code)]
    config: TunConfig,
}

// SAFETY: TunDevice is Send-safe because:
// 1. tun_tap::Iface is thread-safe for I/O operations
// 2. All access to TunDevice is protected by Mutex in the daemon/client
#[cfg(target_os = "linux")]
unsafe impl Send for TunDevice {}

// SAFETY: Same as Send - all mutable access is synchronized via Mutex
#[cfg(target_os = "linux")]
unsafe impl Sync for TunDevice {}

impl TunDevice {
    /// Create and configure a new TUN device
    pub fn new(config: TunConfig) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::new_linux(config)
        }
        #[cfg(target_os = "macos")]
        {
            Self::new_macos(config)
        }
        #[cfg(target_os = "windows")]
        {
            Self::new_windows(config)
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // Mobile platforms: TUN fd provided by VpnService/NetworkExtension
            Err(anyhow::anyhow!(
                "Mobile TUN devices must be created by the OS VPN API"
            ))
        }
    }

    /// Create TUN device from existing file descriptor (Android/iOS)
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn from_fd(fd: RawFd, config: TunConfig) -> Result<Self> {
        info!("Using TUN fd {} from VPN service", fd);
        Ok(Self { fd, config })
    }

    // ============================================================================
    // Linux Implementation
    // ============================================================================
    #[cfg(target_os = "linux")]
    fn new_linux(config: TunConfig) -> Result<Self> {
        use std::process::Command;

        info!("Creating Linux TUN device: {}", config.name);

        // Create TUN device
        let device = tun_tap::Iface::without_packet_info(&config.name, tun_tap::Mode::Tun)
            .context("Failed to create TUN device (requires CAP_NET_ADMIN)")?;

        info!("✅ TUN device {} created", config.name);

        // Configure IP address
        let addr_str = format!("{}/{}", config.address, config.netmask);
        let output = Command::new("ip")
            .args(["addr", "add", &addr_str, "dev", &config.name])
            .output()
            .context("Failed to set TUN IP address")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("ip addr add warning: {}", stderr);
            }
        }

        // Set MTU
        let output = Command::new("ip")
            .args([
                "link",
                "set",
                "dev",
                &config.name,
                "mtu",
                &config.mtu.to_string(),
            ])
            .output()
            .context("Failed to set MTU")?;

        if !output.status.success() {
            warn!(
                "Failed to set MTU: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Bring interface up
        let output = Command::new("ip")
            .args(["link", "set", "dev", &config.name, "up"])
            .output()
            .context("Failed to bring TUN interface up")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to bring interface up: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        info!("✅ TUN device {} configured: {}", config.name, addr_str);

        Ok(Self { device, config })
    }

    // ============================================================================
    // macOS Implementation - utun
    // ============================================================================
    #[cfg(target_os = "macos")]
    fn new_macos(config: TunConfig) -> Result<Self> {
        use std::process::Command;

        info!("Creating macOS TUN device");

        // macOS uses utun devices (kernel automatically assigns number)
        let device = tun_tap::Iface::without_packet_info("utun", tun_tap::Mode::Tun)
            .context("Failed to create utun device (requires root)")?;

        let actual_name = device.name();
        info!("✅ TUN device {} created", actual_name);

        // Configure IP address
        let addr_str = format!("{}", config.address);
        let netmask_str = Self::netmask_to_string(config.netmask);

        let output = Command::new("ifconfig")
            .args([
                &*actual_name,
                &*addr_str,
                &*addr_str,
                "netmask",
                &*netmask_str,
                "up",
            ])
            .output()
            .context("Failed to configure utun device")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to configure utun: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Set MTU
        let output = Command::new("ifconfig")
            .args([&actual_name, "mtu", &config.mtu.to_string()])
            .output()
            .context("Failed to set MTU")?;

        if !output.status.success() {
            warn!(
                "Failed to set MTU: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        info!("✅ TUN device {} configured: {}", actual_name, addr_str);

        Ok(Self { device, config })
    }

    #[cfg(target_os = "macos")]
    fn netmask_to_string(prefix: u8) -> String {
        let mask = !0u32 << (32 - prefix);
        format!(
            "{}.{}.{}.{}",
            (mask >> 24) & 0xff,
            (mask >> 16) & 0xff,
            (mask >> 8) & 0xff,
            mask & 0xff
        )
    }

    // ============================================================================
    // Windows Implementation - Wintun
    // ============================================================================
    #[cfg(target_os = "windows")]
    fn new_windows(config: TunConfig) -> Result<Self> {
        info!("Creating Windows Wintun adapter: {}", config.name);

        // Load Wintun DLL
        let wintun = unsafe { wintun::load()? };

        // Create adapter
        let adapter = wintun::Adapter::create(&wintun, &config.name, "OxTunnel", None)
            .context("Failed to create Wintun adapter (requires admin)")?;

        info!("✅ Wintun adapter {} created", config.name);

        // Start session
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("Failed to start Wintun session")?;

        // Configure IP address using netsh
        use std::process::Command;
        let addr_str = format!("{}", config.address);
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &config.name,
                "static",
                &addr_str,
                "255.255.255.0",
            ])
            .output()
            .context("Failed to set IP address")?;

        if !output.status.success() {
            warn!("netsh warning: {}", String::from_utf8_lossy(&output.stderr));
        }

        info!("✅ Wintun adapter {} configured: {}", config.name, addr_str);

        Ok(Self { session, config })
    }

    // ============================================================================
    // I/O Operations
    // ============================================================================

    /// Read a packet from the TUN device
    /// Uses standard TUN I/O
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.device
                .recv(buf)
                .context("Failed to read from TUN device")
        }

        #[cfg(target_os = "macos")]
        {
            self.device
                .recv(buf)
                .context("Failed to read from TUN device")
        }

        #[cfg(target_os = "windows")]
        {
            match self.session.receive_blocking() {
                Ok(packet) => {
                    let len = packet.bytes().len().min(buf.len());
                    buf[..len].copy_from_slice(&packet.bytes()[..len]);
                    Ok(len)
                }
                Err(e) => Err(anyhow::anyhow!("Wintun receive error: {}", e)),
            }
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            use std::io::Read;
            let mut file = unsafe { std::fs::File::from_raw_fd(self.fd) };
            let result = file.read(buf).context("Failed to read from TUN fd");
            std::mem::forget(file); // Don't close fd
            result
        }
    }

    /// Write a packet to the TUN device
    /// Uses standard TUN I/O
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.device
                .send(buf)
                .context("Failed to write to TUN device")
        }

        #[cfg(target_os = "macos")]
        {
            self.device
                .send(buf)
                .context("Failed to write to TUN device")
        }

        #[cfg(target_os = "windows")]
        {
            let packet = self
                .session
                .allocate_send_packet(buf.len() as u16)
                .context("Failed to allocate Wintun packet")?;
            packet.bytes_mut()[..buf.len()].copy_from_slice(buf);
            self.session.send_packet(packet);
            Ok(buf.len())
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            use std::io::Write;
            let mut file = unsafe { std::fs::File::from_raw_fd(self.fd) };
            let result = file.write(buf).context("Failed to write to TUN fd");
            std::mem::forget(file); // Don't close fd
            result
        }
    }

    /// Get the TUN device name
    pub fn name(&self) -> &str {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.device.name()
        }
        #[cfg(target_os = "windows")]
        {
            &self.config.name
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            &self.config.name
        }
    }

    /// Get the raw file descriptor (Unix only)
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "android",
        target_os = "ios"
    ))]
    pub fn as_raw_fd(&self) -> RawFd {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.device.as_raw_fd()
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            self.fd
        }
    }

    /// Add a route through this TUN device
    pub fn add_route(&self, destination: &str, gateway: Option<&str>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let mut args = vec!["route", "add", destination, "dev", self.name()];
            if let Some(gw) = gateway {
                args.extend_from_slice(&["via", gw]);
            }
            let output = Command::new("ip").args(&args).output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    return Err(anyhow::anyhow!("Failed to add route: {}", stderr));
                }
            }
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let mut args = vec!["add", "-net", destination];
            if let Some(gw) = gateway {
                args.extend_from_slice(&[gw]);
            } else {
                args.push("-interface");
                args.push(self.name());
            }
            let output = Command::new("route").args(&args).output()?;
            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to add route: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(())
        }

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("route")
                .args(["ADD", destination, "MASK", "255.255.255.0", self.name()])
                .output()?;
            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to add route: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(())
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // Routes managed by VpnService/NetworkExtension
            Ok(())
        }
    }

    /// Set default route through this TUN device
    pub fn set_default_route(&self, relay_server_ip: IpAddr) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            // Add default route through TUN
            let output = Command::new("ip")
                .args([
                    "route",
                    "add",
                    "default",
                    "dev",
                    self.name(),
                    "metric",
                    "100",
                ])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    warn!("Failed to add default route: {}", stderr);
                }
            }

            // Ensure relay server is reachable via original gateway
            let output = Command::new("ip")
                .args([
                    "route",
                    "add",
                    &relay_server_ip.to_string(),
                    "via",
                    "$(ip route | grep default | awk '{print $3}')",
                ])
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to add relay server route: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let output = Command::new("route")
                .args(["add", "default", "-interface", self.name()])
                .output()?;
            if !output.status.success() {
                warn!(
                    "Failed to add default route: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(())
        }

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("route")
                .args(["ADD", "0.0.0.0", "MASK", "0.0.0.0", self.name()])
                .output()?;
            if !output.status.success() {
                warn!(
                    "Failed to add default route: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(())
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // Routes managed by VpnService/NetworkExtension
            Ok(())
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        info!("Closing TUN device: {}", self.name());
        // Device cleanup is automatic via Drop implementations
    }
}
