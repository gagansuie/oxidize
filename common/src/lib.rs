pub mod adaptive_fec;

pub mod ai_engine;
pub mod benchmark;
pub mod compression;
pub mod congestion_control;
pub mod connection_migration;
pub mod connection_pool;
pub mod edge_cache;
pub mod fec;
pub mod metrics;
pub mod ml_integration;
pub mod ml_models;
pub mod ml_training;
pub mod model_hub;
pub mod multipath;
pub mod packet;
pub mod packet_processor;
pub mod prefetch;
pub mod priority_scheduler;
pub mod protocol;
pub mod protocol_detect;
pub mod relay_mesh;
pub mod security;
pub mod simd_compression;
pub mod traffic_classifier;
pub mod udp_batch;
pub mod zero_copy;

pub mod rohc;

#[cfg(target_os = "linux")]
pub mod io_uring_support;

#[cfg(target_os = "linux")]
pub mod io_uring_impl;

// High-performance networking (pick ONE - DPDK is preferred for bare metal)
#[cfg(target_os = "linux")]
pub mod dpdk; // DPDK: 40+ Gbps, requires hugepages + VFIO (Hetzner)

#[cfg(target_os = "linux")]
pub mod af_xdp; // AF_XDP: 20 Gbps, fallback for non-bare-metal

#[cfg(target_os = "linux")]
pub mod ebpf;

pub mod bbr_v3;
pub mod crypto_accel;
#[cfg(target_os = "linux")]
pub mod ktls;
pub mod low_latency;
pub mod parallel_compression;
pub mod simd_fec; // Kernel TLS offload for 30% CPU reduction

pub use compression::*;
pub use metrics::*;
pub use packet::*;
pub use packet_processor::*;
pub use protocol::*;
