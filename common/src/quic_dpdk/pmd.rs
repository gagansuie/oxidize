//! DPDK Poll Mode Driver (PMD) interface
//!
//! High-performance Ethernet device driver abstraction for DPDK.

use std::sync::Arc;

#[cfg(not(feature = "dpdk"))]
use tracing::info;
#[cfg(feature = "dpdk")]
use tracing::{debug, info, warn};

use super::dpdk_bindings::*;
use super::mbuf::{Mbuf, MbufPool};
use super::QuicDpdkConfig;

/// Ethernet port managed by DPDK PMD
pub struct DpdkPort {
    /// Port ID
    pub port_id: PortId,
    /// Number of RX queues
    pub rx_queues: u16,
    /// Number of TX queues
    pub tx_queues: u16,
    /// MAC address
    pub mac_addr: [u8; 6],
    /// Mbuf pool for this port
    pub mbuf_pool: Arc<MbufPool>,
    /// Is port started
    started: bool,
}

impl DpdkPort {
    /// Initialize a DPDK port
    pub fn new(
        port_id: PortId,
        config: &QuicDpdkConfig,
        mbuf_pool: Arc<MbufPool>,
    ) -> Result<Self, PortError> {
        info!("Configuring DPDK port {}", port_id);

        #[cfg(feature = "dpdk")]
        {
            // Get device info
            let mut dev_info: rte_eth_dev_info = unsafe { std::mem::zeroed() };
            let ret = unsafe { rte_eth_dev_info_get(port_id, &mut dev_info) };
            if ret != 0 {
                return Err(PortError::DeviceInfoFailed);
            }

            info!(
                "  Max RX queues: {}, Max TX queues: {}",
                dev_info.max_rx_queues, dev_info.max_tx_queues
            );

            // Validate queue counts
            let rx_queues = config.rx_queues.min(dev_info.max_rx_queues);
            let tx_queues = config.tx_queues.min(dev_info.max_tx_queues);

            // Build port configuration
            let mut port_conf: rte_eth_conf = unsafe { std::mem::zeroed() };

            // Enable RSS for multi-queue
            if rx_queues > 1 {
                port_conf.rxmode.mq_mode = 1; // RTE_ETH_MQ_RX_RSS
                port_conf.rx_adv_conf.rss_conf.rss_hf =
                    RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_NONFRAG_IPV4_UDP;
            }

            // Enable offloads
            port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
            port_conf.txmode.offloads =
                RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

            // Configure the device
            let ret = unsafe { rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf) };
            if ret != 0 {
                return Err(PortError::ConfigureFailed(ret));
            }

            // Setup RX queues
            for queue_id in 0..rx_queues {
                let ret = unsafe {
                    rte_eth_rx_queue_setup(
                        port_id,
                        queue_id,
                        config.rx_ring_size,
                        0, // socket_id (auto)
                        std::ptr::null(),
                        mbuf_pool.as_ptr(),
                    )
                };
                if ret != 0 {
                    return Err(PortError::RxQueueSetupFailed(queue_id, ret));
                }
                debug!("  RX queue {} configured", queue_id);
            }

            // Setup TX queues
            for queue_id in 0..tx_queues {
                let ret = unsafe {
                    rte_eth_tx_queue_setup(
                        port_id,
                        queue_id,
                        config.tx_ring_size,
                        0, // socket_id (auto)
                        std::ptr::null(),
                    )
                };
                if ret != 0 {
                    return Err(PortError::TxQueueSetupFailed(queue_id, ret));
                }
                debug!("  TX queue {} configured", queue_id);
            }

            // Get MAC address
            let mut mac_addr: rte_ether_addr = unsafe { std::mem::zeroed() };
            unsafe { rte_eth_macaddr_get(port_id, &mut mac_addr) };

            info!(
                "Port {} configured: {} RX, {} TX queues, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                port_id,
                rx_queues,
                tx_queues,
                mac_addr.addr_bytes[0],
                mac_addr.addr_bytes[1],
                mac_addr.addr_bytes[2],
                mac_addr.addr_bytes[3],
                mac_addr.addr_bytes[4],
                mac_addr.addr_bytes[5]
            );

            Ok(Self {
                port_id,
                rx_queues,
                tx_queues,
                mac_addr: mac_addr.addr_bytes,
                mbuf_pool,
                started: false,
            })
        }

        #[cfg(not(feature = "dpdk"))]
        {
            info!(
                "Port {} (simulated): {} RX, {} TX queues",
                port_id, config.rx_queues, config.tx_queues
            );

            Ok(Self {
                port_id,
                rx_queues: config.rx_queues,
                tx_queues: config.tx_queues,
                mac_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                mbuf_pool,
                started: false,
            })
        }
    }

    /// Start the port
    pub fn start(&mut self) -> Result<(), PortError> {
        if self.started {
            return Ok(());
        }

        #[cfg(feature = "dpdk")]
        {
            let ret = unsafe { rte_eth_dev_start(self.port_id) };
            if ret != 0 {
                return Err(PortError::StartFailed(ret));
            }

            // Enable promiscuous mode for testing
            unsafe { rte_eth_promiscuous_enable(self.port_id) };
        }

        self.started = true;
        info!("Port {} started", self.port_id);
        Ok(())
    }

    /// Stop the port
    pub fn stop(&mut self) -> Result<(), PortError> {
        if !self.started {
            return Ok(());
        }

        #[cfg(feature = "dpdk")]
        {
            let ret = unsafe { rte_eth_dev_stop(self.port_id) };
            if ret != 0 {
                warn!("Port {} stop returned {}", self.port_id, ret);
            }
        }

        self.started = false;
        info!("Port {} stopped", self.port_id);
        Ok(())
    }

    /// Receive packets from a queue
    #[cfg(feature = "dpdk")]
    pub fn rx_burst(&self, queue_id: QueueId, max_pkts: u16) -> Vec<Mbuf> {
        let mut ptrs: Vec<*mut rte_mbuf> = vec![std::ptr::null_mut(); max_pkts as usize];

        let nb_rx =
            unsafe { rte_eth_rx_burst(self.port_id, queue_id, ptrs.as_mut_ptr(), max_pkts) };

        ptrs.truncate(nb_rx as usize);
        ptrs.into_iter()
            .filter_map(|p| std::ptr::NonNull::new(p).map(Mbuf::from_raw))
            .collect()
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn rx_burst(&self, _queue_id: QueueId, _max_pkts: u16) -> Vec<Mbuf> {
        Vec::new() // No packets in simulation mode
    }

    /// Transmit packets on a queue
    #[cfg(feature = "dpdk")]
    pub fn tx_burst(&self, queue_id: QueueId, mbufs: &mut [Mbuf]) -> u16 {
        if mbufs.is_empty() {
            return 0;
        }

        let mut ptrs: Vec<*mut rte_mbuf> = mbufs.iter().map(|m| m.as_ptr()).collect();

        let nb_tx = unsafe {
            rte_eth_tx_burst(
                self.port_id,
                queue_id,
                ptrs.as_mut_ptr(),
                mbufs.len() as u16,
            )
        };

        nb_tx
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn tx_burst(&self, _queue_id: QueueId, mbufs: &mut [Mbuf]) -> u16 {
        mbufs.len() as u16 // Pretend all packets were sent
    }

    /// Check if port is started
    pub fn is_started(&self) -> bool {
        self.started
    }
}

impl Drop for DpdkPort {
    fn drop(&mut self) {
        if self.started {
            let _ = self.stop();
        }

        #[cfg(feature = "dpdk")]
        {
            unsafe { rte_eth_dev_close(self.port_id) };
        }

        info!("Port {} closed", self.port_id);
    }
}

/// Port initialization errors
#[derive(Debug)]
pub enum PortError {
    DeviceInfoFailed,
    ConfigureFailed(i32),
    RxQueueSetupFailed(u16, i32),
    TxQueueSetupFailed(u16, i32),
    StartFailed(i32),
    StopFailed(i32),
    NotStarted,
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortError::DeviceInfoFailed => write!(f, "Failed to get device info"),
            PortError::ConfigureFailed(e) => write!(f, "Configure failed: {}", e),
            PortError::RxQueueSetupFailed(q, e) => write!(f, "RX queue {} setup failed: {}", q, e),
            PortError::TxQueueSetupFailed(q, e) => write!(f, "TX queue {} setup failed: {}", q, e),
            PortError::StartFailed(e) => write!(f, "Start failed: {}", e),
            PortError::StopFailed(e) => write!(f, "Stop failed: {}", e),
            PortError::NotStarted => write!(f, "Port not started"),
        }
    }
}

impl std::error::Error for PortError {}

/// Per-queue RX/TX context for a worker thread
pub struct QueueContext {
    pub port: Arc<DpdkPort>,
    pub queue_id: QueueId,
    pub batch_size: u16,
    pub rx_count: u64,
    pub tx_count: u64,
}

impl QueueContext {
    pub fn new(port: Arc<DpdkPort>, queue_id: QueueId, batch_size: u16) -> Self {
        Self {
            port,
            queue_id,
            batch_size,
            rx_count: 0,
            tx_count: 0,
        }
    }

    /// Receive a batch of packets
    pub fn rx_burst(&mut self) -> Vec<Mbuf> {
        let mbufs = self.port.rx_burst(self.queue_id, self.batch_size);
        self.rx_count += mbufs.len() as u64;
        mbufs
    }

    /// Transmit a batch of packets
    pub fn tx_burst(&mut self, mbufs: &mut [Mbuf]) -> u16 {
        let sent = self.port.tx_burst(self.queue_id, mbufs);
        self.tx_count += sent as u64;
        sent
    }
}

/// Bind a NIC to DPDK-compatible driver
pub fn bind_nic_to_dpdk(pci_address: &str) -> std::io::Result<()> {
    info!("Binding {} to vfio-pci driver", pci_address);

    // Unbind from current driver
    let unbind_path = format!("/sys/bus/pci/devices/{}/driver/unbind", pci_address);
    if std::path::Path::new(&unbind_path).exists() {
        std::fs::write(&unbind_path, pci_address)?;
        info!("Unbound {} from kernel driver", pci_address);
    }

    // Bind to vfio-pci
    let driver_override = format!("/sys/bus/pci/devices/{}/driver_override", pci_address);
    std::fs::write(&driver_override, "vfio-pci")?;

    let probe_path = "/sys/bus/pci/drivers_probe";
    std::fs::write(probe_path, pci_address)?;

    info!("Bound {} to vfio-pci", pci_address);
    Ok(())
}

/// Get PCI device info
pub fn get_pci_info(pci_address: &str) -> Option<(u16, u16)> {
    let vendor_path = format!("/sys/bus/pci/devices/{}/vendor", pci_address);
    let device_path = format!("/sys/bus/pci/devices/{}/device", pci_address);

    let vendor = std::fs::read_to_string(&vendor_path).ok()?;
    let device = std::fs::read_to_string(&device_path).ok()?;

    let vendor = u16::from_str_radix(vendor.trim().trim_start_matches("0x"), 16).ok()?;
    let device = u16::from_str_radix(device.trim().trim_start_matches("0x"), 16).ok()?;

    Some((vendor, device))
}
