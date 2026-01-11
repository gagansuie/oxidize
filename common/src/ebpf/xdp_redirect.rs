//! XDP Redirect Program for QUIC Packets
//!
//! This eBPF program runs at the XDP hook (earliest point in packet processing)
//! and redirects QUIC packets to AF_XDP sockets for zero-copy processing.
//!
//! Performance: <1µs per packet decision

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

/// XDP action codes (match kernel definitions)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAction {
    /// Packet processing error, drop
    Aborted = 0,
    /// Drop the packet silently
    Drop = 1,
    /// Pass to normal kernel network stack
    Pass = 2,
    /// Transmit packet back out same interface
    Tx = 3,
    /// Redirect to another interface or AF_XDP socket
    Redirect = 4,
}

/// Ethernet header (14 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthHeader {
    pub const SIZE: usize = 14;

    /// Check if IPv4 packet
    pub fn is_ipv4(&self) -> bool {
        u16::from_be(self.ethertype) == 0x0800
    }

    /// Check if IPv6 packet
    pub fn is_ipv6(&self) -> bool {
        u16::from_be(self.ethertype) == 0x86DD
    }
}

/// IPv4 header (20 bytes minimum)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
}

impl Ipv4Header {
    pub const SIZE: usize = 20;

    /// Get IP header length in bytes
    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) * 4) as usize
    }

    /// Check if UDP protocol
    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    /// Check if TCP protocol
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    /// Get source IP as Ipv4Addr
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.src_ip))
    }

    /// Get destination IP as Ipv4Addr
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.dst_ip))
    }
}

/// UDP header (8 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub const SIZE: usize = 8;

    pub fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }
}

/// XDP program configuration
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// QUIC port to redirect
    pub quic_port: u16,
    /// AF_XDP socket map file descriptor
    pub xsk_map_fd: Option<i32>,
    /// Enable rate limiting
    pub rate_limit: bool,
    /// Packets per second limit
    pub pps_limit: u64,
}

impl Default for XdpConfig {
    fn default() -> Self {
        XdpConfig {
            quic_port: 4433,
            xsk_map_fd: None,
            rate_limit: false,
            pps_limit: 1_000_000, // 1M pps default
        }
    }
}

/// Parse packet and determine XDP action
/// This is the core logic that would run in the eBPF program
pub fn classify_packet(packet: &[u8], config: &XdpConfig) -> XdpAction {
    // Minimum packet size: Eth (14) + IP (20) + UDP (8) = 42 bytes
    if packet.len() < 42 {
        return XdpAction::Pass;
    }

    // Parse Ethernet header
    let eth = unsafe { &*(packet.as_ptr() as *const EthHeader) };

    // Only handle IPv4 for now
    if !eth.is_ipv4() {
        return XdpAction::Pass;
    }

    // Parse IP header
    let ip_offset = EthHeader::SIZE;
    if packet.len() < ip_offset + Ipv4Header::SIZE {
        return XdpAction::Pass;
    }

    let ip = unsafe { &*(packet[ip_offset..].as_ptr() as *const Ipv4Header) };

    // Only handle UDP (QUIC runs over UDP)
    if !ip.is_udp() {
        return XdpAction::Pass;
    }

    // Parse UDP header
    let udp_offset = ip_offset + ip.header_len();
    if packet.len() < udp_offset + UdpHeader::SIZE {
        return XdpAction::Pass;
    }

    let udp = unsafe { &*(packet[udp_offset..].as_ptr() as *const UdpHeader) };

    // Check if this is QUIC traffic (destination port matches)
    if udp.dst_port() == config.quic_port {
        // Redirect to AF_XDP socket for zero-copy processing
        return XdpAction::Redirect;
    }

    // Check source port too (for response packets)
    if udp.src_port() == config.quic_port {
        return XdpAction::Redirect;
    }

    // Pass all other traffic to normal stack
    XdpAction::Pass
}

/// Statistics for XDP program
#[derive(Debug, Default, Clone)]
pub struct XdpStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub redirected: u64,
    pub passed: u64,
    pub dropped: u64,
    pub errors: u64,
}

impl XdpStats {
    pub fn redirect_ratio(&self) -> f64 {
        if self.rx_packets == 0 {
            0.0
        } else {
            self.redirected as f64 / self.rx_packets as f64
        }
    }
}

/// eBPF program source code template
/// This would be compiled with aya-bpf for actual deployment
pub const XDP_PROGRAM_TEMPLATE: &str = r#"
// XDP program for QUIC packet redirection
// Compile with: cargo build-bpf

#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

const QUIC_PORT: u16 = 4433;

#[xdp]
pub fn oxidize_xdp(ctx: XdpContext) -> u32 {
    match try_oxidize_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_oxidize_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Check minimum packet size
    if data + 42 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse Ethernet header
    let eth = unsafe { &*(data as *const EthHdr) };
    if eth.ether_type != ETH_P_IP.to_be() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IP header
    let ip = unsafe { &*((data + 14) as *const IpHdr) };
    if ip.protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse UDP header
    let ihl = (ip.ihl_version & 0x0F) as usize * 4;
    let udp = unsafe { &*((data + 14 + ihl) as *const UdpHdr) };

    // Check for QUIC port
    let dst_port = u16::from_be(udp.dest);
    let src_port = u16::from_be(udp.source);

    if dst_port == QUIC_PORT || src_port == QUIC_PORT {
        // Redirect to AF_XDP socket
        return XSKS_MAP
            .redirect(ctx.rx_queue_index(), 0)
            .map(|_| xdp_action::XDP_REDIRECT)
            .map_err(|_| ());
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_quic_packet() {
        let config = XdpConfig::default();

        // Create a mock QUIC packet
        let mut packet = vec![0u8; 100];

        // Ethernet header
        packet[12] = 0x08; // IPv4 ethertype
        packet[13] = 0x00;

        // IP header
        packet[14] = 0x45; // Version 4, IHL 5
        packet[23] = 17; // UDP protocol

        // UDP header (offset 34)
        packet[36] = (4433 >> 8) as u8; // dst port high
        packet[37] = (4433 & 0xFF) as u8; // dst port low

        let action = classify_packet(&packet, &config);
        assert_eq!(action, XdpAction::Redirect);
    }

    #[test]
    fn test_classify_non_quic_packet() {
        let config = XdpConfig::default();

        // Create a mock HTTP packet
        let mut packet = vec![0u8; 100];

        // Ethernet header
        packet[12] = 0x08;
        packet[13] = 0x00;

        // IP header
        packet[14] = 0x45;
        packet[23] = 6; // TCP protocol

        let action = classify_packet(&packet, &config);
        assert_eq!(action, XdpAction::Pass);
    }

    #[test]
    fn test_xdp_stats() {
        let mut stats = XdpStats::default();
        stats.rx_packets = 1000;
        stats.redirected = 800;
        stats.passed = 200;

        assert!((stats.redirect_ratio() - 0.8).abs() < 0.001);
    }
}
