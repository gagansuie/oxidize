// ============================================================================
// BARE METAL AF_XDP OPTIMIZED - Maximum Throughput, Minimum Latency
// ============================================================================

// Core performance modules
pub mod adaptive_dict;
pub mod adaptive_fec;
pub mod compression;
pub mod fec;
pub mod metrics;
pub mod packet;
pub mod packet_processor;
pub mod protocol;
pub mod security;
pub mod simd_compression;
pub mod udp_batch;
pub mod zero_copy;

// ML Engine (INT8 quantized for inline processing)
pub mod advanced_ml;
pub mod ai_engine;
pub mod ml_optimized;
pub mod ml_training;
pub mod model_hub;

// High-performance networking
pub mod multipath;
pub mod prefetch;
pub mod priority_scheduler;
pub mod traffic_classifier;

// OxTunnel protocol (runs over QUIC-XDP)
pub mod oxtunnel_client;
pub mod oxtunnel_protocol;
pub mod rohc;
pub mod varint_header;

// Mesh and caching
pub mod edge_cache;
pub mod relay_mesh;

// Benchmark utilities
pub mod benchmark;

// Kernel Bypass - 100x optimized with custom implementations (100+ Gbps)
// Provides: BypassConfig, BypassPacket, BypassProcessor
// Plus: UltraConfig, KernelBypassRuntime, PacketBuffer, SpscRing (100x optimized)
#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
pub mod kernel_bypass;

// AF_XDP - Real NIC integration for 10-40 Gbps (Linux only, kernel-bypass feature)
// Provides: AfXdpSocket, AfXdpRuntime, AfXdpConfig
#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
pub mod af_xdp;

// DPDK - Full kernel bypass for 100+ Gbps (Linux only, kernel-bypass feature)
// Provides: DpdkRuntime, DpdkConfig, DpdkStats
#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
pub mod dpdk;

// QUIC-XDP - Native AF_XDP QUIC implementation for 100x performance (Linux only, kernel-bypass feature)
// Provides: QuicXdpRuntime, QuicXdpConfig, QuicXdpStats, Connection, Stream
// Complete userspace QUIC stack running on kernel bypass with:
// - Zero-copy packet processing via UMEM (no syscalls in hot path)
// - SIMD-accelerated parsing
// - Hardware crypto (AES-NI)
// - ML-augmented congestion control
// - Batch processing (64+ packets)
#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
pub mod quic_xdp;

// Core optimizations
pub mod low_latency;
pub mod parallel_compression;
pub mod simd_fec;

// Advanced Optimizations
pub mod deep_packet_inspection;
pub mod handoff_prediction; // ML handoff prediction (WiFi→LTE)
pub mod mptcp_redundancy; // MPTCP-style redundancy for multipath

// Unified optimization stats for analytics
pub mod optimization_stats;

pub use compression::*;
pub use metrics::*;
pub use packet::*;
pub use packet_processor::*;
pub use protocol::*;
