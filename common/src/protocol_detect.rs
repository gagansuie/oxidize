use std::net::IpAddr;

/// Detected protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    HTTP,
    HTTPS,
    DNS,
    Gaming,
    Video,
    VoIP,
    Unknown,
}

/// Protocol detection based on packet inspection
pub struct ProtocolDetector;

impl ProtocolDetector {
    /// Detect protocol from packet data and destination
    pub fn detect(data: &[u8], dest_port: u16, _dest_ip: IpAddr) -> Protocol {
        // Port-based detection (fast path)
        match dest_port {
            80 => return Protocol::HTTP,
            443 => return Protocol::HTTPS,
            53 => return Protocol::DNS,
            // Gaming ports
            27015..=27030 | 3074 | 3478..=3479 => return Protocol::Gaming,
            // VoIP
            5060..=5061 | 5004..=5005 => return Protocol::VoIP,
            // Streaming
            1935 | 8554 => return Protocol::Video,
            _ => {}
        }

        // Deep packet inspection for ambiguous cases
        if data.len() < 4 {
            return Protocol::Unknown;
        }

        // HTTP detection
        if data.starts_with(b"GET ") || data.starts_with(b"POST") || data.starts_with(b"HEAD") {
            return Protocol::HTTP;
        }

        // TLS/HTTPS detection (ClientHello)
        if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 {
            return Protocol::HTTPS;
        }

        // DNS query detection
        if data.len() > 12 && is_dns_query(data) {
            return Protocol::DNS;
        }

        // Small packets with high frequency = likely gaming
        if data.len() < 512 {
            return Protocol::Gaming;
        }

        Protocol::Unknown
    }

    /// Get optimization strategy for protocol
    pub fn get_strategy(protocol: Protocol) -> OptimizationStrategy {
        match protocol {
            Protocol::HTTP | Protocol::HTTPS => OptimizationStrategy {
                priority: Priority::Medium,
                compress: true,
                coalesce: true,
                max_delay_ms: 50,
            },
            Protocol::Gaming => OptimizationStrategy {
                priority: Priority::High,
                compress: false, // Latency > size
                coalesce: false, // Send immediately
                max_delay_ms: 5,
            },
            Protocol::VoIP => OptimizationStrategy {
                priority: Priority::High,
                compress: false,
                coalesce: false,
                max_delay_ms: 10,
            },
            Protocol::Video => OptimizationStrategy {
                priority: Priority::Low,
                compress: false, // Already compressed
                coalesce: true,
                max_delay_ms: 100,
            },
            Protocol::DNS => OptimizationStrategy {
                priority: Priority::High,
                compress: false,
                coalesce: false,
                max_delay_ms: 10,
            },
            Protocol::Unknown => OptimizationStrategy {
                priority: Priority::Medium,
                compress: true,
                coalesce: true,
                max_delay_ms: 50,
            },
        }
    }
}

/// Packet priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Medium = 1,
    High = 2,
}

/// Optimization strategy for a protocol
#[derive(Debug, Clone)]
pub struct OptimizationStrategy {
    pub priority: Priority,
    pub compress: bool,
    pub coalesce: bool,    // Can batch multiple packets
    pub max_delay_ms: u64, // Maximum acceptable delay
}

fn is_dns_query(data: &[u8]) -> bool {
    // Basic DNS query validation
    if data.len() < 12 {
        return false;
    }
    // Check if QR bit is 0 (query) and opcode is 0 (standard query)
    let flags = u16::from_be_bytes([data[2], data[3]]);
    (flags & 0x8000) == 0 && ((flags >> 11) & 0x0F) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_http_detection() {
        let data = b"GET / HTTP/1.1\r\n";
        let proto = ProtocolDetector::detect(data, 8080, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(proto, Protocol::HTTP);
    }

    #[test]
    fn test_gaming_port_detection() {
        let data = b"some game data";
        let proto = ProtocolDetector::detect(data, 27015, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(proto, Protocol::Gaming);
    }

    #[test]
    fn test_gaming_strategy() {
        let strategy = ProtocolDetector::get_strategy(Protocol::Gaming);
        assert_eq!(strategy.priority, Priority::High);
        assert!(!strategy.compress); // Low latency > compression
        assert!(strategy.max_delay_ms < 10);
    }
}
