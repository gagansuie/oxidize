pub mod adaptive_dict;
pub mod adaptive_fec;

pub mod advanced_ml;
pub mod ai_engine;
pub mod benchmark;
pub mod compression;
pub mod connection_migration;
pub mod connection_pool;
pub mod edge_cache;
pub mod fec;
pub mod metrics;
pub mod ml_optimized;
pub mod ml_training;
pub mod model_hub;
pub mod multipath;
pub mod packet;
pub mod packet_processor;
pub mod prefetch;
pub mod priority_scheduler;
pub mod protocol;
pub mod relay_mesh;
pub mod security;
pub mod simd_compression;
pub mod traffic_classifier;
pub mod udp_batch;
pub mod zero_copy;

pub mod oxtunnel_client;
pub mod oxtunnel_protocol;
pub mod packet_capture;
pub mod rohc;
pub mod unified_transport;
pub mod varint_header;

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

pub mod bbr_v4;
pub mod crypto_accel;
#[cfg(target_os = "linux")]
pub mod ktls;
pub mod low_latency;
pub mod parallel_compression;
pub mod simd_fec;

// Advanced Optimizations (High Impact)
pub mod deep_packet_inspection;
pub mod handoff_prediction; // ML handoff prediction (WiFi→LTE)
pub mod ml_pacing; // ML-augmented pacing for BBRv4
pub mod mptcp_redundancy; // MPTCP-style redundancy for multipath // DPI + application fingerprinting

// Protocol Optimizations (Medium Impact)
pub mod protocol_optimizations; // Varint encoding, trusted networks, buffer pool, NUMA
pub mod simd_avx512; // AVX-512 SIMD packet parsing

// Unified optimization stats for analytics
pub mod optimization_stats;

pub use compression::*;
pub use metrics::*;
pub use packet::*;
pub use packet_processor::*;
pub use protocol::*;
