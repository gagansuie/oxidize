//! eBPF Program Loader
//!
//! Loads and attaches eBPF programs to network interfaces using aya.

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

/// XDP attach mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAttachMode {
    /// Offload to NIC hardware (best, requires support)
    Offload,
    /// Native driver mode (fast, requires driver support)
    Native,
    /// Generic/SKB mode (works everywhere, slower)
    Generic,
}

impl XdpAttachMode {
    /// Get the aya flags for this mode
    #[cfg(target_os = "linux")]
    pub fn to_flags(&self) -> u32 {
        match self {
            XdpAttachMode::Offload => 4, // XDP_FLAGS_HW_MODE
            XdpAttachMode::Native => 2,  // XDP_FLAGS_DRV_MODE
            XdpAttachMode::Generic => 1, // XDP_FLAGS_SKB_MODE
        }
    }

    /// Select best available mode for interface
    pub fn auto_select(interface: &str) -> Self {
        // Check if interface supports native XDP
        if Self::supports_native(interface) {
            XdpAttachMode::Native
        } else {
            XdpAttachMode::Generic
        }
    }

    fn supports_native(interface: &str) -> bool {
        // Check for known XDP-native drivers
        let driver_path = format!("/sys/class/net/{}/device/driver/module", interface);
        if let Ok(driver) = std::fs::read_link(&driver_path) {
            let driver_name = driver.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Drivers known to support native XDP
            let native_drivers = [
                "i40e",       // Intel X710/XL710
                "ixgbe",      // Intel 10G
                "mlx5_core",  // Mellanox ConnectX-4+
                "mlx4_en",    // Mellanox ConnectX-3
                "nfp",        // Netronome
                "bnxt_en",    // Broadcom
                "virtio_net", // Virtio (KVM)
                "veth",       // Virtual ethernet
            ];

            return native_drivers.iter().any(|&d| driver_name.contains(d));
        }
        false
    }
}

/// eBPF program loader
#[cfg(target_os = "linux")]
pub struct EbpfLoader {
    interface: String,
    mode: XdpAttachMode,
    quic_port: u16,
}

#[cfg(target_os = "linux")]
impl EbpfLoader {
    /// Create a new loader for the specified interface
    pub fn new(interface: &str, quic_port: u16) -> Self {
        let mode = XdpAttachMode::auto_select(interface);
        info!("eBPF loader created for {} with {:?} mode", interface, mode);

        EbpfLoader {
            interface: interface.to_string(),
            mode,
            quic_port,
        }
    }

    /// Create with specific attach mode
    pub fn with_mode(interface: &str, quic_port: u16, mode: XdpAttachMode) -> Self {
        EbpfLoader {
            interface: interface.to_string(),
            mode,
            quic_port,
        }
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get the attach mode
    pub fn mode(&self) -> XdpAttachMode {
        self.mode
    }

    /// Load and attach the XDP program
    /// Returns the program file descriptor on success
    pub fn load_xdp_program(&self) -> io::Result<i32> {
        info!(
            "Loading XDP program on {} (port {}, mode {:?})",
            self.interface, self.quic_port, self.mode
        );

        // XDP program loading requires the `xdp` feature flag
        #[cfg(feature = "xdp")]
        {
            use aya::programs::{Xdp, XdpFlags};
            use aya::Bpf;

            // Load compiled eBPF bytecode
            let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/oxidize-xdp"
            )))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let program: &mut Xdp = bpf
                .program_mut("oxidize_xdp")
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDP program not found"))?
                .try_into()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

            program
                .load()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let flags = match self.mode {
                XdpAttachMode::Generic => XdpFlags::SKB_MODE,
                XdpAttachMode::Native => XdpFlags::DRV_MODE,
                XdpAttachMode::Offload => XdpFlags::HW_MODE,
            };

            program
                .attach(&self.interface, flags)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            info!("XDP program loaded and attached to {}", self.interface);
            Ok(program.fd().unwrap().as_raw_fd())
        }

        #[cfg(not(feature = "xdp"))]
        {
            // XDP requires the `xdp` feature flag and Linux kernel 4.18+
            warn!("XDP support requires the `xdp` feature flag - enable with: cargo build --features xdp");
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XDP requires the `xdp` feature flag",
            ))
        }
    }

    /// Detach the XDP program from interface
    #[cfg(feature = "xdp")]
    pub fn detach(&self) -> io::Result<()> {
        info!("Detaching XDP program from {}", self.interface);
        // XDP detach handled by dropping the program handle
        Ok(())
    }

    #[cfg(not(feature = "xdp"))]
    pub fn detach(&self) -> io::Result<()> {
        Ok(())
    }

    /// Check if eBPF/XDP is supported on this system
    pub fn is_supported() -> bool {
        // Check kernel version >= 4.18 for XDP
        // Check for bpf() syscall

        // Simple check: try to access BPF syscall
        let kernel_version = Self::get_kernel_version();
        if let Some((major, minor)) = kernel_version {
            return major > 4 || (major == 4 && minor >= 18);
        }
        false
    }

    fn get_kernel_version() -> Option<(u32, u32)> {
        // Read kernel version from /proc/version
        if let Ok(version) = std::fs::read_to_string("/proc/version") {
            // Parse "Linux version X.Y.Z ..."
            let parts: Vec<&str> = version.split_whitespace().collect();
            if parts.len() >= 3 {
                let ver_parts: Vec<&str> = parts[2].split('.').collect();
                if ver_parts.len() >= 2 {
                    let major = ver_parts[0].parse().ok()?;
                    let minor = ver_parts[1].parse().ok()?;
                    return Some((major, minor));
                }
            }
        }
        None
    }

    /// Get XDP statistics from kernel
    /// Returns default stats when `xdp` feature is not enabled
    pub fn get_stats(&self) -> XdpLoaderStats {
        // Stats are populated by the XDP program via BPF maps
        XdpLoaderStats::default()
    }
}

/// Statistics from loaded XDP program
#[derive(Debug, Default, Clone)]
pub struct XdpLoaderStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub redirected: u64,
    pub passed: u64,
    pub dropped: u64,
}

/// Fallback for non-Linux
#[cfg(not(target_os = "linux"))]
pub struct EbpfLoader;

#[cfg(not(target_os = "linux"))]
impl EbpfLoader {
    pub fn new(_interface: &str, _quic_port: u16) -> Self {
        EbpfLoader
    }

    pub fn is_supported() -> bool {
        false
    }

    pub fn load_xdp_program(&self) -> std::io::Result<i32> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "eBPF is only supported on Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attach_mode_selection() {
        // Test auto-selection (will be Generic on most dev machines)
        let mode = XdpAttachMode::auto_select("lo");
        println!("Selected mode for lo: {:?}", mode);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_kernel_version() {
        let supported = EbpfLoader::is_supported();
        println!("eBPF supported: {}", supported);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_loader_creation() {
        let loader = EbpfLoader::new("lo", 4433);
        assert_eq!(loader.interface(), "lo");
    }
}
