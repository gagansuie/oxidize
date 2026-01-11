pub mod cache;
pub mod config;
pub mod connection;
pub mod graceful;
pub mod high_perf;
pub mod high_perf_pipeline; // DPDK + BBRv3 + XDP integration
pub mod mesh_manager;
pub mod prometheus;
pub mod server;
pub mod tls;
pub mod wireguard;
pub mod xdp_forwarder;
pub mod xdp_handler;

pub use config::Config;
pub use high_perf::{HighPerfConfig, HighPerfPipeline, PipelineStats};
pub use high_perf_pipeline::{PipelineCapabilities, PipelineConfig, PipelineIntegration};
pub use xdp_forwarder::SharedTunForwarder;
pub use xdp_handler::{ServerXdpStats, XdpServerHandler};
