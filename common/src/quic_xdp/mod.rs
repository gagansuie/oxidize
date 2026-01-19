//! AF_XDP-Native QUIC Implementation
//!
//! A complete userspace QUIC implementation designed for kernel bypass.
//! Runs entirely on AF_XDP with zero syscalls in the hot path.
//!
//! # Performance Targets (10x Optimized)
//! - **Throughput**: 400+ Gbps (multi-queue, 512 batch)
//! - **Latency**: <500ns per packet (P99)
//! - **PPS**: 200+ Mpps with batching
//! - **ML Inference**: <1µs (ONNX + lookup tables)
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    AF_XDP Native QUIC Stack                              │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │
//! │  │   AF_XDP     │   │   io_uring   │   │    DPDK      │                │
//! │  │   Socket     │   │   Async I/O  │   │   (future)   │                │
//! │  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                │
//! │         │                  │                  │                         │
//! │         └──────────────────┼──────────────────┘                         │
//! │                            ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    PacketRxTx (Zero-Copy)                        │   │
//! │  │  - Batch receive (64 packets)                                    │   │
//! │  │  - UMEM direct access                                            │   │
//! │  │  - No memcpy in hot path                                         │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    QUIC Packet Parser (SIMD)                     │   │
//! │  │  - AVX-512/AVX2 header parsing                                   │   │
//! │  │  - Connection ID lookup (hash table)                             │   │
//! │  │  - Packet number decoding                                        │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Crypto Engine (AES-NI/Intel QAT)              │   │
//! │  │  - Intel QAT hardware offload (if available)                     │   │
//! │  │  - AES-NI fallback with batch processing                         │   │
//! │  │  - Zero-copy decrypt-in-place                                    │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Stream/Datagram Handler                       │   │
//! │  │  - Lock-free stream state                                        │   │
//! │  │  - Datagram direct forwarding                                    │   │
//! │  │  - ML-augmented flow control                                     │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Congestion Control (ML+ECN)                   │   │
//! │  │  - ONNX Runtime inference (<1µs)                                 │   │
//! │  │  - Lookup tables for common cases (skip ML 90%)                  │   │
//! │  │  - ECN-aware congestion response                                 │   │
//! │  │  - Multipath QUIC support                                        │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![allow(dead_code)] // QUIC-XDP implementation scaffolding
#![allow(ambiguous_glob_reexports)] // Intentional - prefer local types over re-exports
#![allow(clippy::manual_clamp)] // Performance: explicit min/max faster than clamp in hot paths
#![allow(clippy::needless_range_loop)] // Performance: explicit indexing preferred in SIMD-friendly loops
#![allow(clippy::manual_c_str_literals)] // Compatibility with older Rust versions

// Core QUIC modules
pub mod connection;
pub mod crypto;
pub mod frame;
pub mod packet;
pub mod runtime;
pub mod stream;

// 10x Optimization modules
pub mod adaptive_ml; // Adaptive ML with online learning
pub mod ecn; // ECN (Explicit Congestion Notification)
pub mod ml_lookup; // ML lookup tables (generated from model)
pub mod multipath; // Multipath QUIC support
pub mod onnx_ml; // ONNX Runtime ML inference
pub mod qat_crypto; // Intel QAT hardware crypto offload

pub use adaptive_ml::*;
pub use connection::*;
pub use crypto::*;
pub use ecn::*;
pub use frame::*;
pub use ml_lookup::*;
pub use multipath::*;
pub use onnx_ml::*;
pub use packet::*;
pub use qat_crypto::*;
pub use runtime::*;
pub use stream::*;

use std::sync::atomic::{AtomicU64, Ordering};

/// QUIC XDP configuration
#[derive(Debug, Clone)]
pub struct QuicXdpConfig {
    /// Network interface (e.g., "eth0")
    pub interface: String,
    /// Number of RX/TX queues
    pub num_queues: u32,
    /// Enable zero-copy mode
    pub zero_copy: bool,
    /// QUIC port to listen on
    pub port: u16,
    /// Maximum connections
    pub max_connections: usize,
    /// Batch size for packet processing
    pub batch_size: usize,
    /// Enable busy polling (no interrupts)
    pub busy_poll: bool,
    /// Enable hardware crypto offload
    pub hw_crypto: bool,
    /// CPU cores to pin (comma-separated)
    pub cpu_cores: String,
    /// Enable ML-augmented congestion control
    pub ml_congestion: bool,
    /// Enable speculative caching
    pub speculative_cache: bool,
}

impl Default for QuicXdpConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            num_queues: 4,
            zero_copy: true,
            port: 4433,
            max_connections: 100_000,
            batch_size: 512, // 8x larger batches for throughput
            busy_poll: true,
            hw_crypto: true,
            cpu_cores: "2,3,4,5".to_string(),
            ml_congestion: true,
            speculative_cache: true,
        }
    }
}

impl QuicXdpConfig {
    /// Configuration for maximum throughput (400+ Gbps)
    pub fn max_throughput() -> Self {
        Self {
            num_queues: 16,
            batch_size: 512,
            cpu_cores: "2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17".to_string(),
            ..Default::default()
        }
    }

    /// Configuration for gaming (ultra-low latency)
    pub fn gaming() -> Self {
        Self {
            num_queues: 2,
            batch_size: 16,
            busy_poll: true,
            cpu_cores: "2,3".to_string(),
            ..Default::default()
        }
    }
}

/// Global statistics for QUIC XDP runtime
#[derive(Default)]
pub struct QuicXdpStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub connections: AtomicU64,
    pub handshakes: AtomicU64,
    pub datagrams: AtomicU64,
    pub streams: AtomicU64,
    pub crypto_ops: AtomicU64,
    pub batch_count: AtomicU64,
    pub avg_batch_size: AtomicU64,
    pub ml_predictions: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

impl QuicXdpStats {
    pub fn summary(&self, elapsed_secs: f64) -> String {
        let rx_pkts = self.rx_packets.load(Ordering::Relaxed);
        let tx_pkts = self.tx_packets.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);

        let rx_gbps = (rx_bytes as f64 * 8.0) / elapsed_secs / 1_000_000_000.0;
        let tx_gbps = (tx_bytes as f64 * 8.0) / elapsed_secs / 1_000_000_000.0;
        let rx_mpps = rx_pkts as f64 / elapsed_secs / 1_000_000.0;
        let tx_mpps = tx_pkts as f64 / elapsed_secs / 1_000_000.0;

        let conns = self.connections.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_total = cache_hits + self.cache_misses.load(Ordering::Relaxed);
        let cache_rate = if cache_total > 0 {
            (cache_hits as f64 / cache_total as f64) * 100.0
        } else {
            0.0
        };

        format!(
            "QUIC-XDP: RX {:.2} Gbps ({:.2}M pps), TX {:.2} Gbps ({:.2}M pps), {} conns, {:.1}% cache",
            rx_gbps, rx_mpps, tx_gbps, tx_mpps, conns, cache_rate
        )
    }
}
