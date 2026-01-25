//! AF_XDP High-Performance Networking - Zero-copy packet I/O for 10-25 Gbps
//!
//! Bypasses kernel network stack. Requires Linux 5.4+, root, XDP-capable NIC.

#[cfg(target_os = "linux")]
mod linux_impl;

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(not(target_os = "linux"))]
mod stub_impl;

#[cfg(not(target_os = "linux"))]
pub use stub_impl::*;

mod config;
pub use config::*;

mod stats;
pub use stats::*;
