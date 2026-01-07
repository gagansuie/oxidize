pub mod adaptive_fec;
pub mod benchmark;
pub mod compression;
pub mod congestion_control;
pub mod connection_migration;
pub mod connection_pool;
pub mod edge_cache;
pub mod fec;
pub mod metrics;
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

#[cfg(feature = "rohc")]
pub mod rohc;

#[cfg(target_os = "linux")]
pub mod io_uring_support;

#[cfg(target_os = "linux")]
pub mod io_uring_impl;

pub mod high_perf_tun;
pub mod parallel_compression;

pub use compression::*;
pub use metrics::*;
pub use packet::*;
pub use packet_processor::*;
pub use protocol::*;
