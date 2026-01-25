//! AF_XDP Configuration

/// AF_XDP socket configuration
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// Network interface name (e.g., "eth0")
    pub interface: String,
    /// Queue ID to bind to (use 0 for single-queue NICs)
    pub queue_id: u32,
    /// Number of frames in UMEM (power of 2)
    pub frame_count: u32,
    /// Size of each frame (typically 4096)
    pub frame_size: u32,
    /// Headroom before packet data
    pub headroom: u32,
    /// Number of RX ring entries
    pub rx_ring_size: u32,
    /// Number of TX ring entries
    pub tx_ring_size: u32,
    /// Number of fill ring entries
    pub fill_ring_size: u32,
    /// Number of completion ring entries
    pub comp_ring_size: u32,
    /// Use zero-copy mode (requires driver support)
    pub zero_copy: bool,
    /// Use busy polling for lowest latency
    pub busy_poll: bool,
    /// Busy poll budget (packets per poll)
    pub busy_poll_budget: u32,
    /// QUIC port to filter (0 = all UDP)
    pub quic_port: u16,
    /// Batch size for processing
    pub batch_size: usize,
}

impl Default for XdpConfig {
    fn default() -> Self {
        XdpConfig {
            interface: "eth0".to_string(),
            queue_id: 0,
            frame_count: 4096,
            frame_size: 4096,
            headroom: 256,
            rx_ring_size: 4096,
            tx_ring_size: 4096,
            fill_ring_size: 4096,
            comp_ring_size: 4096,
            zero_copy: true,
            busy_poll: true,
            busy_poll_budget: 64,
            quic_port: 4433,
            batch_size: 64,
        }
    }
}

impl XdpConfig {
    /// High-throughput configuration for 10+ Gbps
    pub fn high_throughput(interface: &str) -> Self {
        XdpConfig {
            interface: interface.to_string(),
            frame_count: 16384,
            rx_ring_size: 8192,
            tx_ring_size: 8192,
            fill_ring_size: 8192,
            comp_ring_size: 8192,
            batch_size: 128,
            busy_poll_budget: 128,
            ..Default::default()
        }
    }

    /// Low-latency configuration for gaming/VoIP
    pub fn low_latency(interface: &str) -> Self {
        XdpConfig {
            interface: interface.to_string(),
            frame_count: 2048,
            frame_size: 2048,
            rx_ring_size: 2048,
            tx_ring_size: 2048,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            batch_size: 16,
            busy_poll_budget: 16,
            ..Default::default()
        }
    }
}
