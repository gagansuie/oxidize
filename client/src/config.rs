use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub enable_compression: bool,
    pub compression_threshold: usize,
    pub buffer_size: usize,
    pub keepalive_interval: u64,
    pub reconnect_interval: u64,
    pub enable_dns_prefetch: bool,
    pub dns_cache_size: usize,
    pub max_packet_queue: usize,
    pub tun_mtu: usize,
    pub enable_header_compression: bool,

    /// Enable ROHC (Robust Header Compression) for IP/UDP/TCP headers
    #[serde(default = "default_enable_rohc")]
    pub enable_rohc: bool,
    /// Maximum packet size for ROHC compression (larger packets use LZ4 only)
    #[serde(default = "default_rohc_max_size")]
    pub rohc_max_size: usize,
}

fn default_enable_rohc() -> bool {
    true
}

fn default_rohc_max_size() -> usize {
    1500
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            enable_compression: true,
            compression_threshold: 512,
            buffer_size: 65536,
            keepalive_interval: 30,
            reconnect_interval: 5,
            enable_dns_prefetch: true,
            dns_cache_size: 1000,
            max_packet_queue: 10000,
            tun_mtu: 1500,
            enable_header_compression: true,
            enable_rohc: true,
            rohc_max_size: 1500,
        }
    }
}

impl ClientConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: ClientConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
