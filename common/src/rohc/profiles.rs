//! ROHC compression profiles
//!
//! Supports: Uncompressed, IP, UDP, TCP, and IPv6 variants

/// ROHC Profile identifiers (RFC 3095 + extensions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Profile {
    /// Uncompressed profile - sends packet as-is with minimal header
    Uncompressed = 0x00,
    /// RTP profile (IP/UDP/RTP)
    Rtp = 0x01,
    /// UDP profile - compresses IP + UDP headers
    Udp = 0x02,
    /// ESP profile
    Esp = 0x03,
    /// IP profile - compresses IP header only
    Ip = 0x04,
    /// TCP profile (RFC 6846) - compresses IP + TCP headers
    Tcp = 0x06,
    /// UDP-Lite profile
    UdpLite = 0x08,
    /// IPv6 + UDP
    Ipv6Udp = 0x12,
    /// IPv6 + TCP
    Ipv6Tcp = 0x16,
}

impl Profile {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Profile::Uncompressed),
            0x01 => Some(Profile::Rtp),
            0x02 => Some(Profile::Udp),
            0x03 => Some(Profile::Esp),
            0x04 => Some(Profile::Ip),
            0x06 => Some(Profile::Tcp),
            0x08 => Some(Profile::UdpLite),
            0x12 => Some(Profile::Ipv6Udp),
            0x16 => Some(Profile::Ipv6Tcp),
            _ => None,
        }
    }

    /// Determine the best profile for a packet
    pub fn detect(packet: &[u8]) -> Self {
        if packet.len() < 20 {
            return Profile::Uncompressed;
        }

        let version = (packet[0] >> 4) & 0xF;

        match version {
            4 => Self::detect_ipv4(packet),
            6 => Self::detect_ipv6(packet),
            _ => Profile::Uncompressed,
        }
    }

    fn detect_ipv4(packet: &[u8]) -> Self {
        if packet.len() < 20 {
            return Profile::Uncompressed;
        }

        let ihl = (packet[0] & 0xF) as usize * 4;
        let protocol = packet[9];

        match protocol {
            6 if packet.len() >= ihl + 20 => Profile::Tcp, // TCP
            17 if packet.len() >= ihl + 8 => Profile::Udp, // UDP
            136 if packet.len() >= ihl + 8 => Profile::UdpLite, // UDP-Lite
            50 => Profile::Esp,                            // ESP
            _ => Profile::Ip,
        }
    }

    fn detect_ipv6(packet: &[u8]) -> Self {
        if packet.len() < 40 {
            return Profile::Uncompressed;
        }

        let next_header = packet[6];

        match next_header {
            6 if packet.len() >= 60 => Profile::Ipv6Tcp,  // TCP
            17 if packet.len() >= 48 => Profile::Ipv6Udp, // UDP
            _ => Profile::Ip,
        }
    }

    /// Returns true if this is an IPv6 profile
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Profile::Ipv6Udp | Profile::Ipv6Tcp)
    }

    /// Returns true if this profile compresses TCP
    pub fn is_tcp(&self) -> bool {
        matches!(self, Profile::Tcp | Profile::Ipv6Tcp)
    }

    /// Returns true if this profile compresses UDP
    pub fn is_udp(&self) -> bool {
        matches!(
            self,
            Profile::Udp | Profile::Ipv6Udp | Profile::Rtp | Profile::UdpLite
        )
    }
}
