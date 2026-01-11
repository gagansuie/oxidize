//! eBPF Programs for High-Performance Networking
//!
//! This module contains eBPF programs that run in the kernel for:
//! - XDP packet filtering and redirection
//! - Traffic classification
//! - Rate limiting
//!
//! These programs are loaded using the aya crate and provide
//! the fast path for 10+ Gbps packet processing.

#[cfg(target_os = "linux")]
pub mod xdp_redirect;

#[cfg(target_os = "linux")]
pub mod loader;

/// eBPF program types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfProgram {
    /// XDP redirect program for QUIC packets
    XdpQuicRedirect,
    /// XDP rate limiter
    XdpRateLimiter,
    /// Traffic classifier
    TrafficClassifier,
}

impl EbpfProgram {
    /// Get the program name
    pub fn name(&self) -> &'static str {
        match self {
            EbpfProgram::XdpQuicRedirect => "xdp_quic_redirect",
            EbpfProgram::XdpRateLimiter => "xdp_rate_limiter",
            EbpfProgram::TrafficClassifier => "traffic_classifier",
        }
    }
}
