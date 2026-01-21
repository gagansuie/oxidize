//! DPDK Environment Abstraction Layer (EAL) wrapper
//!
//! Safe Rust wrapper around DPDK EAL initialization and management.

#[cfg(feature = "dpdk")]
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use tracing::{error, info};

use super::QuicDpdkConfig;

static EAL_INIT: Once = Once::new();
static EAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// DPDK EAL initialization result
#[derive(Debug)]
pub struct EalContext {
    /// Number of available lcores
    pub lcore_count: u32,
    /// Main lcore ID
    pub main_lcore: u32,
    /// NUMA socket ID
    pub socket_id: i32,
    /// Available Ethernet ports
    pub port_count: u16,
}

impl EalContext {
    /// Initialize DPDK EAL with the given configuration
    pub fn init(config: &QuicDpdkConfig) -> Result<Self, EalError> {
        let mut initialized = false;

        EAL_INIT.call_once(|| match Self::do_init(config) {
            Ok(_) => {
                EAL_INITIALIZED.store(true, Ordering::SeqCst);
                initialized = true;
            }
            Err(e) => {
                error!("EAL initialization failed: {:?}", e);
            }
        });

        if !EAL_INITIALIZED.load(Ordering::SeqCst) {
            return Err(EalError::InitFailed("EAL initialization failed".into()));
        }

        // Get EAL state
        #[cfg(feature = "dpdk")]
        let (lcore_count, main_lcore, socket_id, port_count) = unsafe {
            use super::dpdk_bindings::*;
            (
                rte_lcore_count(),
                rte_get_main_lcore(),
                rte_socket_id(),
                rte_eth_dev_count_avail(),
            )
        };

        #[cfg(not(feature = "dpdk"))]
        let (lcore_count, main_lcore, socket_id, port_count) = {
            let cores: Vec<usize> = config
                .cpu_cores
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            (cores.len() as u32, 0, 0, 1)
        };

        info!(
            "EAL initialized: {} lcores, {} ports",
            lcore_count, port_count
        );

        Ok(Self {
            lcore_count,
            main_lcore,
            socket_id,
            port_count,
        })
    }

    #[cfg(feature = "dpdk")]
    fn do_init(config: &QuicDpdkConfig) -> Result<(), EalError> {
        use super::dpdk_bindings::*;

        // Build EAL arguments
        let mut args = vec![
            CString::new("oxidize-dpdk").unwrap(),
            CString::new("-l").unwrap(),
            CString::new(config.cpu_cores.clone()).unwrap(),
            CString::new("-n").unwrap(),
            CString::new("4").unwrap(), // Memory channels
            CString::new("--socket-mem").unwrap(),
            CString::new(format!("{}", config.hugepage_mb)).unwrap(),
            CString::new("-a").unwrap(),
            CString::new(config.pci_address.clone()).unwrap(),
            CString::new("--proc-type").unwrap(),
            CString::new("primary").unwrap(),
            CString::new("--file-prefix").unwrap(),
            CString::new("oxidize").unwrap(),
        ];

        let mut argv: Vec<*mut i8> = args.iter_mut().map(|s| s.as_ptr() as *mut i8).collect();
        let argc = argv.len() as i32;

        info!("Initializing DPDK EAL...");
        info!("  PCI: {}", config.pci_address);
        info!("  Cores: {}", config.cpu_cores);
        info!("  Hugepages: {} MB", config.hugepage_mb);

        let ret = unsafe { rte_eal_init(argc, argv.as_mut_ptr()) };

        if ret < 0 {
            return Err(EalError::InitFailed(format!(
                "rte_eal_init returned {}",
                ret
            )));
        }

        info!("EAL initialized with {} lcores", unsafe {
            rte_lcore_count()
        });
        Ok(())
    }

    #[cfg(not(feature = "dpdk"))]
    fn do_init(config: &QuicDpdkConfig) -> Result<(), EalError> {
        info!("DPDK simulation mode (no libdpdk linked)");
        info!("  Configured cores: {}", config.cpu_cores);
        info!("  PCI address: {}", config.pci_address);
        Ok(())
    }

    /// Check if EAL is initialized
    pub fn is_initialized() -> bool {
        EAL_INITIALIZED.load(Ordering::SeqCst)
    }

    /// Get current lcore ID
    #[cfg(feature = "dpdk")]
    pub fn current_lcore() -> u32 {
        unsafe { super::dpdk_bindings::rte_lcore_id() }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn current_lcore() -> u32 {
        0
    }
}

impl Drop for EalContext {
    fn drop(&mut self) {
        #[cfg(feature = "dpdk")]
        unsafe {
            super::dpdk_bindings::rte_eal_cleanup();
        }
        info!("EAL cleanup complete");
    }
}

/// EAL initialization errors
#[derive(Debug)]
pub enum EalError {
    InitFailed(String),
    AlreadyInitialized,
    NoDevices,
    InvalidConfig(String),
}

impl std::fmt::Display for EalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EalError::InitFailed(msg) => write!(f, "EAL init failed: {}", msg),
            EalError::AlreadyInitialized => write!(f, "EAL already initialized"),
            EalError::NoDevices => write!(f, "No DPDK devices found"),
            EalError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
        }
    }
}

impl std::error::Error for EalError {}

/// CPU affinity helper
pub fn set_cpu_affinity(core: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(core, &mut cpuset);
            let ret = libc::sched_setaffinity(0, std::mem::size_of_val(&cpuset), &cpuset);
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Parse CPU core list (e.g., "2,3,4,5" or "2-5")
pub fn parse_cpu_cores(cores: &str) -> Vec<usize> {
    let mut result = Vec::new();

    for part in cores.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<usize>(), range[1].parse::<usize>())
                {
                    result.extend(start..=end);
                }
            }
        } else if let Ok(core) = part.parse::<usize>() {
            result.push(core);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_cores() {
        assert_eq!(parse_cpu_cores("2,3,4,5"), vec![2, 3, 4, 5]);
        assert_eq!(parse_cpu_cores("2-5"), vec![2, 3, 4, 5]);
        assert_eq!(parse_cpu_cores("2,4-6,8"), vec![2, 4, 5, 6, 8]);
    }
}
