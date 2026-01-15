use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub max_connections: usize,
    pub enable_compression: bool,
    pub compression_threshold: usize,
    pub buffer_size: usize,
    pub keepalive_interval: u64,
    pub connection_timeout: u64,
    pub enable_tcp_acceleration: bool,
    pub enable_deduplication: bool,

    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_ip: usize,
    #[serde(default = "default_rate_window")]
    pub rate_limit_window_secs: u64,

    // Security settings
    #[serde(default = "default_max_pps")]
    pub max_pps_per_ip: u32,
    #[serde(default = "default_max_bandwidth")]
    pub max_bandwidth_per_ip: u64,
    #[serde(default = "default_auto_block_threshold")]
    pub auto_block_threshold: u32,
    #[serde(default = "default_enable_challenges")]
    pub enable_challenges: bool,

    // Oxtunnel settings
    #[serde(default = "default_enable_oxtunnel")]
    pub enable_oxtunnel: bool,
    pub oxtunnel_port: Option<u16>,

    /// Enable ROHC (Robust Header Compression) for IP/UDP/TCP headers
    #[serde(default = "default_enable_rohc")]
    pub enable_rohc: bool,
    /// Maximum packet size for ROHC compression
    #[serde(default = "default_rohc_max_size")]
    pub rohc_max_size: usize,

    /// ACK batch size - number of ACKs to accumulate before sending
    /// Lower values = lower latency, higher values = higher throughput
    #[serde(default = "default_ack_batch_size")]
    pub ack_batch_size: usize,

    // === Edge Caching ===
    /// Enable edge caching for static content
    #[serde(default = "default_enable_edge_cache")]
    pub enable_edge_cache: bool,
    /// Maximum edge cache size in bytes (default 64MB)
    #[serde(default = "default_edge_cache_size")]
    pub edge_cache_size: usize,
    /// Maximum number of cache entries
    #[serde(default = "default_edge_cache_entries")]
    pub edge_cache_entries: usize,

    // === AI/Heuristic Engine ===
    /// Enable AI-powered heuristic engine for smart compression/FEC
    #[serde(default = "default_enable_ai_engine")]
    pub enable_ai_engine: bool,

    // === 0-RTT Session Resumption ===
    /// Enable 0-RTT session resumption for faster reconnects
    /// WARNING: 0-RTT is vulnerable to replay attacks. Only enable if you understand the risks.
    /// For VPN tunnels, this is generally safe as inner protocols handle replay protection.
    #[serde(default = "default_enable_0rtt")]
    pub enable_0rtt: bool,

    /// Maximum early data size in bytes for 0-RTT (default 16KB)
    #[serde(default = "default_max_early_data_size")]
    pub max_early_data_size: u32,
}

fn default_enable_oxtunnel() -> bool {
    false
}

fn default_enable_rohc() -> bool {
    true
}

fn default_rohc_max_size() -> usize {
    1500
}

fn default_ack_batch_size() -> usize {
    1 // Immediate ACKs for lowest latency
}

fn default_rate_limit() -> usize {
    100
}

fn default_rate_window() -> u64 {
    60
}

fn default_max_pps() -> u32 {
    1000
}

fn default_max_bandwidth() -> u64 {
    10 * 1024 * 1024 // 10 MB/s
}

fn default_auto_block_threshold() -> u32 {
    10
}

fn default_enable_challenges() -> bool {
    true
}

fn default_enable_edge_cache() -> bool {
    true
}

fn default_edge_cache_size() -> usize {
    64 * 1024 * 1024 // 64MB
}

fn default_edge_cache_entries() -> usize {
    10000
}

fn default_enable_ai_engine() -> bool {
    true
}

fn default_enable_0rtt() -> bool {
    true // Enabled - requires max_early_data_size = 0 or u32::MAX
}

fn default_max_early_data_size() -> u32 {
    u32::MAX // QUIC requires 0 or u32::MAX for early data
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            enable_compression: true,
            compression_threshold: 512,
            buffer_size: 65536,
            keepalive_interval: 30,
            connection_timeout: 300,
            enable_tcp_acceleration: true,
            enable_deduplication: true,
            tls_cert_path: None,
            tls_key_path: None,
            rate_limit_per_ip: 100,
            rate_limit_window_secs: 60,
            enable_oxtunnel: false,
            oxtunnel_port: None,
            enable_rohc: true,
            rohc_max_size: 1500,
            ack_batch_size: 8,
            max_pps_per_ip: 1000,
            max_bandwidth_per_ip: 10 * 1024 * 1024,
            auto_block_threshold: 10,
            enable_challenges: true,
            enable_edge_cache: true,
            edge_cache_size: 64 * 1024 * 1024,
            edge_cache_entries: 10000,
            enable_ai_engine: true,
            enable_0rtt: true,
            max_early_data_size: u32::MAX, // QUIC requires 0 or u32::MAX
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
