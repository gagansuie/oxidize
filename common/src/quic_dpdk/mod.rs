//! DPDK-Native QUIC Implementation
//!
//! Maximum performance QUIC implementation using DPDK for complete kernel bypass.
//! Uses dedicated poll-mode drivers for maximum throughput.
//!
//! # Performance Targets
//! - **Throughput**: 800+ Gbps (multi-queue, 1024 batch)
//! - **Latency**: <300ns per packet (P99)
//! - **PPS**: 400+ Mpps with batching
//! - **Zero syscalls**: Entire data path in userspace
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    DPDK Native QUIC Stack                               │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────────────────────────────────────────────────────────┐   │
//! │  │   DPDK EAL (Environment Abstraction Layer)                       │   │
//! │  │   - Hugepage memory management                                   │   │
//! │  │   - CPU core affinity                                            │   │
//! │  │   - PCI device binding                                           │   │
//! │  └──────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌──────────────────────────────────────────────────────────────────┐   │
//! │  │   Poll Mode Driver (PMD)                                         │   │
//! │  │   - Intel ixgbe/i40e/ice                                         │   │
//! │  │   - Mellanox mlx5                                                │   │
//! │  │   - Zero-copy DMA                                                │   │
//! │  └──────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌──────────────────────────────────────────────────────────────────┐   │
//! │  │   Mbuf Pool (Packet Buffers)                                     │   │
//! │  │   - Pre-allocated from hugepages                                 │   │
//! │  │   - Per-core cache for lock-free alloc                           │   │
//! │  │   - 1024 packet batch processing                                 │   │
//! │  └──────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌──────────────────────────────────────────────────────────────────┐   │
//! │  │   QUIC Packet Processor                                          │   │
//! │  │   - SIMD header parsing (AVX-512)                                │   │
//! │  │   - Vectorized crypto (AES-NI batch)                             │   │
//! │  │   - Lock-free connection lookup                                  │   │
//! │  └──────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌──────────────────────────────────────────────────────────────────┐   │
//! │  │   ML Congestion Control                                          │   │
//! │  │   - INT8 quantized inference                                     │   │
//! │  │   - Lookup tables for common cases                               │   │
//! │  │   - ECN-aware rate adaptation                                    │   │
//! │  └──────────────────────────────────────────────────────────────────┘   │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

pub mod connection;
pub mod crypto;
pub mod dpdk_bindings;
pub mod eal;
pub mod endpoint;
pub mod mbuf;
pub mod packet;
pub mod pmd;
pub mod runtime;
pub mod socket;
pub mod stream;
pub mod tls;

pub use connection::{
    CidGenerator as DpdkCidGenerator, ConnectionState, DpdkConnection, DpdkConnectionTable,
};
pub use crypto::{CryptoError, HeaderProtection, InitialSecrets as DpdkInitialSecrets, QuicAead};
pub use eal::{parse_cpu_cores, set_cpu_affinity, EalContext, EalError};
pub use endpoint::{EndpointConfig, EndpointStats, QuicEndpoint};
pub use mbuf::{Mbuf, MbufBatch, MbufError, MbufPool};
pub use packet::{
    IpAddr as QuicIpAddr, NetworkHeaders, QuicHeader, QuicPacketBuilder, QuicPacketType,
};
pub use pmd::{DpdkPort, PortError, QueueContext};
pub use runtime::{QuicDpdkBuilder, QuicDpdkRuntime, RuntimeError};
pub use socket::{AsyncQuicSocket, PacketBatch, QuicSocket, SocketStats};
pub use stream::{QuicStream, StreamFrame, StreamId, StreamManager, StreamState, StreamType};
pub use tls::{QuicTlsClientConfig, QuicTlsServerConfig, QuicTlsSession};

use std::sync::atomic::{AtomicU64, Ordering};

/// DPDK QUIC configuration
#[derive(Debug, Clone)]
pub struct QuicDpdkConfig {
    /// PCI address of the NIC (e.g., "0000:01:00.1")
    pub pci_address: String,
    /// Number of RX queues
    pub rx_queues: u16,
    /// Number of TX queues
    pub tx_queues: u16,
    /// RX ring size (must be power of 2)
    pub rx_ring_size: u16,
    /// TX ring size (must be power of 2)
    pub tx_ring_size: u16,
    /// Number of mbufs in the pool
    pub num_mbufs: u32,
    /// Mbuf cache size per core
    pub mbuf_cache_size: u32,
    /// Batch size for RX/TX
    pub batch_size: u16,
    /// QUIC listen port
    pub port: u16,
    /// Maximum connections
    pub max_connections: usize,
    /// CPU cores for workers (comma-separated)
    pub cpu_cores: String,
    /// Hugepage memory in MB
    pub hugepage_mb: u32,
    /// Enable hardware crypto offload
    pub hw_crypto: bool,
    /// Enable ML congestion control
    pub ml_congestion: bool,
    /// IPv4 address to bind
    pub ipv4_addr: Option<String>,
    /// IPv6 address to bind
    pub ipv6_addr: Option<String>,
}

impl Default for QuicDpdkConfig {
    fn default() -> Self {
        Self {
            pci_address: "0000:01:00.1".to_string(),
            rx_queues: 4,
            tx_queues: 4,
            rx_ring_size: 4096,
            tx_ring_size: 4096,
            num_mbufs: 65536,
            mbuf_cache_size: 512,
            batch_size: 64,
            port: 4433,
            max_connections: 100_000,
            cpu_cores: "2,3,4,5".to_string(),
            hugepage_mb: 4096,
            hw_crypto: true,
            ml_congestion: true,
            ipv4_addr: None,
            ipv6_addr: None,
        }
    }
}

impl QuicDpdkConfig {
    /// Maximum throughput configuration
    pub fn max_throughput() -> Self {
        Self {
            rx_queues: 16,
            tx_queues: 16,
            rx_ring_size: 8192,
            tx_ring_size: 8192,
            num_mbufs: 262144,
            batch_size: 256,
            cpu_cores: "2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17".to_string(),
            hugepage_mb: 16384,
            ..Default::default()
        }
    }

    /// Low latency gaming configuration
    pub fn low_latency() -> Self {
        Self {
            rx_queues: 2,
            tx_queues: 2,
            batch_size: 16,
            cpu_cores: "2,3".to_string(),
            ..Default::default()
        }
    }
}

/// DPDK runtime statistics
#[derive(Default)]
pub struct QuicDpdkStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_drops: AtomicU64,
    pub tx_drops: AtomicU64,
    pub connections: AtomicU64,
    pub handshakes: AtomicU64,
    pub crypto_ops: AtomicU64,
    pub batch_count: AtomicU64,
    pub avg_batch_fill: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub ml_predictions: AtomicU64,
}

impl QuicDpdkStats {
    pub fn summary(&self, elapsed_secs: f64) -> String {
        let rx_pkts = self.rx_packets.load(Ordering::Relaxed);
        let tx_pkts = self.tx_packets.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let rx_drops = self.rx_drops.load(Ordering::Relaxed);

        let rx_gbps = (rx_bytes as f64 * 8.0) / elapsed_secs / 1_000_000_000.0;
        let tx_gbps = (tx_bytes as f64 * 8.0) / elapsed_secs / 1_000_000_000.0;
        let rx_mpps = rx_pkts as f64 / elapsed_secs / 1_000_000.0;
        let tx_mpps = tx_pkts as f64 / elapsed_secs / 1_000_000.0;

        format!(
            "QUIC-DPDK: RX {:.2} Gbps ({:.2}M pps), TX {:.2} Gbps ({:.2}M pps), drops: {}",
            rx_gbps, rx_mpps, tx_gbps, tx_mpps, rx_drops
        )
    }
}

/// DPDK driver type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkDriver {
    /// Intel ixgbe (10GbE)
    Ixgbe,
    /// Intel i40e (40GbE)
    I40e,
    /// Intel ice (100GbE)
    Ice,
    /// Mellanox mlx5 (ConnectX-4/5/6)
    Mlx5,
    /// VFIO-PCI (generic)
    VfioPci,
}

impl DpdkDriver {
    pub fn from_pci_id(vendor: u16, device: u16) -> Option<Self> {
        match (vendor, device) {
            // Intel 10GbE
            (0x8086, 0x10fb) => Some(DpdkDriver::Ixgbe), // X520
            (0x8086, 0x1528) => Some(DpdkDriver::Ixgbe), // X540
            (0x8086, 0x154d) => Some(DpdkDriver::Ixgbe), // X550
            // Intel 40GbE
            (0x8086, 0x1583) => Some(DpdkDriver::I40e), // XL710
            (0x8086, 0x1584) => Some(DpdkDriver::I40e), // XL710
            // Intel 100GbE
            (0x8086, 0x1592) => Some(DpdkDriver::Ice), // E810
            (0x8086, 0x1593) => Some(DpdkDriver::Ice), // E810
            // Mellanox
            (0x15b3, 0x1013) => Some(DpdkDriver::Mlx5), // ConnectX-4
            (0x15b3, 0x1015) => Some(DpdkDriver::Mlx5), // ConnectX-4 Lx
            (0x15b3, 0x1017) => Some(DpdkDriver::Mlx5), // ConnectX-5
            (0x15b3, 0x101b) => Some(DpdkDriver::Mlx5), // ConnectX-6
            _ => None,
        }
    }

    pub fn kernel_driver(&self) -> &'static str {
        match self {
            DpdkDriver::Ixgbe => "ixgbe",
            DpdkDriver::I40e => "i40e",
            DpdkDriver::Ice => "ice",
            DpdkDriver::Mlx5 => "mlx5_core",
            DpdkDriver::VfioPci => "vfio-pci",
        }
    }

    pub fn dpdk_driver(&self) -> &'static str {
        match self {
            DpdkDriver::Ixgbe => "net_ixgbe",
            DpdkDriver::I40e => "net_i40e",
            DpdkDriver::Ice => "net_ice",
            DpdkDriver::Mlx5 => "net_mlx5",
            DpdkDriver::VfioPci => "net_virtio",
        }
    }
}
