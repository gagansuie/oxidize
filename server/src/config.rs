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

    // WireGuard settings
    #[serde(default = "default_enable_wireguard")]
    pub enable_wireguard: bool,
    #[serde(default)]
    pub wireguard_port: Option<u16>,
    #[serde(default)]
    pub wireguard_private_key: Option<String>,
}

fn default_enable_wireguard() -> bool {
    false
}

fn default_rate_limit() -> usize {
    100
}

fn default_rate_window() -> u64 {
    60
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
            enable_wireguard: false,
            wireguard_port: None,
            wireguard_private_key: None,
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
