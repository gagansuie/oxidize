pub mod cache;
pub mod config;
pub mod connection;
pub mod forwarder;
pub mod graceful;
pub mod high_perf;
pub mod high_perf_pipeline; // DPDK + BBRv3 integration
pub mod mesh_manager;
pub mod mobile_server;
pub mod prometheus;
pub mod quic_xdp_server; // AF_XDP-native QUIC (100x performance)
pub mod server;
pub mod tls;

pub use config::Config;
pub use forwarder::SharedForwarder;
pub use high_perf::{HighPerfConfig, HighPerfPipeline, PipelineStats};
pub use high_perf_pipeline::{PipelineCapabilities, PipelineConfig, PipelineIntegration};
pub use quic_xdp_server::{QuicCapabilities, QuicMode, QuicServerConfig, QuicXdpServer};
