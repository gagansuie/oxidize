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
    #[serde(default = "default_enable_header_compression")]
    pub enable_header_compression: bool,

    /// Enable ROHC (Robust Header Compression) for IP/UDP/TCP headers
    #[serde(default = "default_enable_rohc")]
    pub enable_rohc: bool,
    /// Maximum packet size for ROHC compression (larger packets use LZ4 only)
    #[serde(default = "default_rohc_max_size")]
    pub rohc_max_size: usize,

    /// Additional domains to bypass (not routed through tunnel)
    #[serde(default)]
    pub bypass_domains: Vec<String>,

    // === MASQUE-INSPIRED PERFORMANCE OPTIONS ===
    /// Enable 0-RTT session resumption for instant reconnects
    #[serde(default = "default_enable_0rtt")]
    pub enable_0rtt: bool,

    /// Path to session ticket cache file
    #[serde(default = "default_session_cache_path")]
    pub session_cache_path: String,

    /// Enable QUIC datagrams for real-time traffic (gaming/VoIP)
    #[serde(default = "default_enable_datagrams")]
    pub enable_datagrams: bool,

    /// Latency threshold (ms) below which to use datagrams instead of streams
    #[serde(default = "default_datagram_latency_threshold_ms")]
    pub datagram_latency_threshold_ms: u64,

    /// Enable connection migration for seamless IP changes
    #[serde(default = "default_enable_migration")]
    pub enable_migration: bool,

    /// Enable multiplexed streams by traffic type
    #[serde(default = "default_enable_stream_multiplexing")]
    pub enable_stream_multiplexing: bool,

    /// Ports considered real-time/gaming traffic (use datagrams)
    #[serde(default = "default_realtime_ports")]
    pub realtime_ports: Vec<u16>,

    // === Multi-path Support ===
    /// Enable multi-path for bandwidth aggregation and failover
    #[serde(default = "default_enable_multipath")]
    pub enable_multipath: bool,

    // === Predictive Prefetching ===
    /// Enable predictive DNS/connection prefetching
    #[serde(default = "default_enable_prefetch")]
    pub enable_prefetch: bool,

    // === AI/Heuristic Engine ===
    /// Enable AI-powered heuristic engine for smart compression decisions
    #[serde(default = "default_enable_ai_engine")]
    pub enable_ai_engine: bool,
}

fn default_enable_rohc() -> bool {
    true
}

fn default_rohc_max_size() -> usize {
    1500
}

fn default_enable_header_compression() -> bool {
    true
}

fn default_enable_0rtt() -> bool {
    true
}

fn default_session_cache_path() -> String {
    "/tmp/oxidize-session-cache".to_string()
}

fn default_enable_datagrams() -> bool {
    true
}

fn default_datagram_latency_threshold_ms() -> u64 {
    50 // Use datagrams for traffic needing <50ms latency
}

fn default_enable_migration() -> bool {
    true
}

fn default_enable_stream_multiplexing() -> bool {
    true
}

fn default_realtime_ports() -> Vec<u16> {
    // Gaming, VoIP, and real-time application ports
    vec![
        // Gaming
        3074, 3478, 3479, 3480, // Xbox Live
        3658, 3659, // PlayStation
        27015, 27016, 27017, // Steam/Valve
        7777, 7778, 7779, // Unreal Engine
        // VoIP
        5060, 5061, // SIP
        16384, 16482, // RTP range start
        3478, 3479, // STUN/TURN
        19302, 19305, // Google STUN
        // Streaming
        1935, // RTMP
    ]
}

fn default_enable_multipath() -> bool {
    true
}

fn default_enable_prefetch() -> bool {
    true
}

fn default_enable_ai_engine() -> bool {
    true
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
            bypass_domains: vec![],
            enable_0rtt: default_enable_0rtt(),
            session_cache_path: default_session_cache_path(),
            enable_datagrams: default_enable_datagrams(),
            datagram_latency_threshold_ms: default_datagram_latency_threshold_ms(),
            enable_migration: default_enable_migration(),
            enable_stream_multiplexing: default_enable_stream_multiplexing(),
            realtime_ports: default_realtime_ports(),
            enable_multipath: default_enable_multipath(),
            enable_prefetch: default_enable_prefetch(),
            enable_ai_engine: default_enable_ai_engine(),
        }
    }
}

impl ClientConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: ClientConfig = toml::from_str(&content)?;
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
