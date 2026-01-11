//! Pure Rust ROHC (Robust Header Compression) implementation
//!
//! Implements a subset of RFC 3095 for IP/UDP header compression.
//! This is a simplified implementation optimized for the common case
//! of compressing IP/UDP headers in gaming and VoIP traffic.

mod compressor;
mod decompressor;
mod encoding;
mod profiles;
pub mod rtp; // RTP profile for VoIP/gaming (97% header reduction)

pub use compressor::RohcCompressor;
pub use decompressor::RohcDecompressor;
pub use encoding::{RohcCrc, Sdvl, WlsbEncoder};
pub use profiles::Profile;
pub use rtp::{RtpCodec, RtpContext};

use anyhow::Result;

/// ROHC compression context configuration
#[derive(Debug, Clone)]
pub struct RohcConfig {
    /// Maximum number of compression contexts (flows)
    pub max_contexts: usize,
}

impl Default for RohcConfig {
    fn default() -> Self {
        RohcConfig { max_contexts: 16 }
    }
}

/// Combined ROHC context for bidirectional compression
pub struct RohcContext {
    pub compressor: RohcCompressor,
    pub decompressor: RohcDecompressor,
}

impl RohcContext {
    /// Create a new ROHC context with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&RohcConfig::default())
    }

    /// Create a new ROHC context with custom configuration
    pub fn with_config(config: &RohcConfig) -> Result<Self> {
        Ok(RohcContext {
            compressor: RohcCompressor::new(config.max_contexts),
            decompressor: RohcDecompressor::new(config.max_contexts),
        })
    }

    /// Compress a packet
    pub fn compress(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.compressor.compress(packet)
    }

    /// Decompress a packet
    pub fn decompress(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        self.decompressor.decompress(compressed)
    }
}

impl Default for RohcContext {
    fn default() -> Self {
        Self::new().expect("Failed to create default RohcContext")
    }
}

/// Flow identifier for context lookup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FlowId {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowId {
    /// Extract flow ID from an IPv4 packet
    pub fn from_ipv4_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }

        let version = (packet[0] >> 4) & 0xF;
        if version != 4 {
            return None;
        }

        let ihl = (packet[0] & 0xF) as usize * 4;
        if packet.len() < ihl {
            return None;
        }

        let protocol = packet[9];
        let src_addr = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
        let dst_addr = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);

        // Extract ports for UDP/TCP
        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && packet.len() >= ihl + 4 {
            let src = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            (src, dst)
        } else {
            (0, 0)
        };

        Some(FlowId {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_id_extraction() {
        // Minimal IPv4/UDP packet
        let packet = [
            0x45, 0x00, 0x00, 0x1c, // IPv4, IHL=5, total len=28
            0x00, 0x00, 0x00, 0x00, // ID, flags, frag
            0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP, checksum
            0x0a, 0x00, 0x00, 0x01, // src IP: 10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // dst IP: 10.0.0.2
            0x00, 0x50, 0x00, 0x51, // src port: 80, dst port: 81
            0x00, 0x08, 0x00, 0x00, // UDP len, checksum
        ];

        let flow = FlowId::from_ipv4_packet(&packet).unwrap();
        assert_eq!(flow.src_addr, 0x0a000001);
        assert_eq!(flow.dst_addr, 0x0a000002);
        assert_eq!(flow.src_port, 80);
        assert_eq!(flow.dst_port, 81);
        assert_eq!(flow.protocol, 17); // UDP
    }

    #[test]
    fn test_roundtrip() {
        let mut ctx = RohcContext::new().unwrap();

        // IPv4/UDP packet with payload
        let packet = vec![
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x50, 0x00, 0x51, 0x00, 0x0c, 0x00, 0x00,
            0xDE, 0xAD, 0xBE, 0xEF,
        ];

        let compressed = ctx.compress(&packet).unwrap();
        let decompressed = ctx.decompress(&compressed).unwrap();

        // ROHC preserves: addresses, ports, protocol, payload
        // May recalculate: checksum, and some flags
        assert_eq!(decompressed.len(), packet.len());
        // Check IP addresses (bytes 12-19)
        assert_eq!(&decompressed[12..20], &packet[12..20]);
        // Check ports (bytes 20-23)
        assert_eq!(&decompressed[20..24], &packet[20..24]);
        // Check payload (bytes 28-31)
        assert_eq!(&decompressed[28..32], &packet[28..32]);
        // Check protocol (byte 9)
        assert_eq!(decompressed[9], packet[9]);
    }
}
