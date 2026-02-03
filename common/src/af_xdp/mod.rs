//! AF_XDP High-Performance Networking - Zero-copy packet I/O for 10-25 Gbps
//!
//! Bypasses kernel network stack. Requires Linux 5.4+, root, XDP-capable NIC.
//!
//! ## FLASH: Fast Linked AF_XDP Sockets
//! Multi-queue support with shared UMEM for linear scaling across NIC queues.

#[cfg(target_os = "linux")]
mod linux_impl;

#[cfg(target_os = "linux")]
mod xdp_loader;

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(target_os = "linux")]
pub use xdp_loader::XdpProgram;

#[cfg(not(target_os = "linux"))]
mod stub_impl;

#[cfg(not(target_os = "linux"))]
pub use stub_impl::*;

mod config;
pub use config::*;

mod stats;
pub use stats::*;

mod flash;
pub use flash::FlashSocket;

// High-performance utilities (consolidated from kernel_bypass.rs)
pub mod utils;
pub use utils::{
    packet_flags,
    security,
    AlignedCounter,
    // Backward compatibility types
    BypassConfig,
    BypassMode,
    BypassPacket,
    BypassProcessor,
    PacketBuffer,
    PacketParser,
    ParsedPacket,
    SpscRing,
    UnifiedBypass,
    CACHE_LINE_SIZE,
    MAX_BURST_SIZE,
    PACKET_BUFFER_SIZE,
};
