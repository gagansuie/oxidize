pub mod adaptive_fec;

pub mod advanced_ml;
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

#[cfg(target_os = "linux")]
pub mod io_uring_support;

#[cfg(target_os = "linux")]
pub mod io_uring_impl;

// Kernel Bypass - 100x optimized with custom implementations (100+ Gbps)
// Provides: BypassConfig, BypassPacket, BypassProcessor
// Plus: UltraConfig, KernelBypassRuntime, PacketBuffer, SpscRing (100x optimized)
#[cfg(all(target_os = "linux", feature = "kernel-bypass"))]
pub mod kernel_bypass;

pub mod bbr_v4;
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
