// ============================================================================
// OXIDIZE - High Performance Relay with AF_XDP/FLASH Zero-Copy I/O
// ============================================================================

// Authentication
pub mod auth;

// Core performance modules
pub mod adaptive_dict;
pub mod adaptive_fec;
pub mod compression;
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
pub mod ml_data_quality;
pub mod ml_optimized;
pub mod ml_training;
pub mod model_hub;

// High-performance networking
pub mod multipath;
pub mod prefetch;
pub mod priority_scheduler;
pub mod traffic_classifier;

// OxTunnel protocol (runs over UDP; AF_XDP/FLASH on Linux servers)
pub mod oxtunnel_client;
pub mod oxtunnel_protocol;
pub mod rohc;
pub mod varint_header;

// TUN/VPN device management (cross-platform)
pub mod tun_device;

// QUIC/MASQUE transport (fallback for restrictive networks)
pub mod quic_transport;

// OXIDE Engine - server-side AF_XDP/FLASH (client path is TUN-only)
// Non-Linux backends are legacy prototypes
pub mod oxide_engine;

// OXIDE SIMD - AVX-512/NEON parallel packet processing
pub mod oxide_simd;

// OXIDE Memory - Huge Pages, CPU Pinning, NUMA-aware allocation
pub mod oxide_memory;

// Mesh and caching
pub mod edge_cache;
pub mod relay_mesh;

// Benchmark utilities
pub mod benchmark;

// AF_XDP - High-performance zero-copy networking (Linux only)
// Includes kernel bypass utilities (SpscRing, PacketBuffer, etc.)
// Uses XDP (eXpress Data Path) for kernel-integrated acceleration
// Benefits:
// - Event-driven (no dedicated CPU cores)
// - Low power consumption
// - Full kernel integration
// - 10-25 Gbps throughput
#[cfg(target_os = "linux")]
pub mod af_xdp;

// eBPF/XDP programs for packet filtering and redirection
#[cfg(target_os = "linux")]
pub mod ebpf;

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
