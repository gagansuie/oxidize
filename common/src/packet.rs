//! Packet Analysis and Classification
//!
//! Analyzes network packets for protocol detection, port classification,
//! and compression suitability.
//!
//! Note: For traffic priority/classification, prefer using `TrafficClass` from
//! `traffic_classifier.rs` which provides a more comprehensive classification system.

use crate::traffic_classifier::TrafficClass;
use etherparse::*;

/// Packet priority level for scheduling
///
/// **Deprecated**: Consider using `TrafficClass` from `traffic_classifier` module
/// for new code, which provides richer classification (Gaming, Streaming, RealTime, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[deprecated(
    since = "0.2.0",
    note = "Use TrafficClass from traffic_classifier module instead"
)]
pub enum PacketPriority {
    Critical,
    High,
    Normal,
    Low,
}

#[allow(deprecated)]
impl PacketPriority {
    /// Convert to TrafficClass for interoperability
    pub fn to_traffic_class(self) -> TrafficClass {
        match self {
            PacketPriority::Critical => TrafficClass::Gaming,
            PacketPriority::High => TrafficClass::RealTime,
            PacketPriority::Normal => TrafficClass::Web,
            PacketPriority::Low => TrafficClass::Bulk,
        }
    }
}

#[derive(Debug)]
#[allow(deprecated)]
pub struct PacketInfo {
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub priority: PacketPriority,
    /// Traffic class (preferred over priority)
    pub traffic_class: TrafficClass,
    pub size: usize,
}

#[allow(deprecated)]
impl PacketInfo {
    pub fn analyze(data: &[u8]) -> anyhow::Result<Self> {
        let mut protocol = 0;
        let mut src_port = None;
        let mut dst_port = None;
        let mut priority = PacketPriority::Normal;
        let mut traffic_class = TrafficClass::General;

        match SlicedPacket::from_ip(data) {
            Ok(packet) => {
                if let Some(net_headers) = packet.net {
                    protocol = match net_headers {
                        NetSlice::Ipv4(ipv4) => ipv4.header().protocol().into(),
                        NetSlice::Ipv6(ipv6) => ipv6.header().next_header().into(),
                    };
                }

                if let Some(transport) = packet.transport {
                    match transport {
                        TransportSlice::Udp(udp) => {
                            src_port = Some(udp.source_port());
                            dst_port = Some(udp.destination_port());
                            let port = udp.destination_port();
                            priority = Self::classify_udp_priority(port);
                            traffic_class = Self::classify_udp_traffic(port);
                        }
                        TransportSlice::Tcp(tcp) => {
                            src_port = Some(tcp.source_port());
                            dst_port = Some(tcp.destination_port());
                            let port = tcp.destination_port();
                            priority = Self::classify_tcp_priority(port);
                            traffic_class = Self::classify_tcp_traffic(port);
                        }
                        TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                            priority = PacketPriority::High;
                            traffic_class = TrafficClass::RealTime;
                        }
                    }
                }
            }
            Err(_) => {
                priority = PacketPriority::Low;
                traffic_class = TrafficClass::Bulk;
            }
        }

        Ok(PacketInfo {
            protocol,
            src_port,
            dst_port,
            priority,
            traffic_class,
            size: data.len(),
        })
    }

    fn classify_udp_priority(port: u16) -> PacketPriority {
        match port {
            53 => PacketPriority::Critical,
            3478 | 3479 => PacketPriority::High,
            5060..=5061 => PacketPriority::High,
            10000..=20000 => PacketPriority::High,
            _ => PacketPriority::Normal,
        }
    }

    fn classify_tcp_priority(port: u16) -> PacketPriority {
        match port {
            22 => PacketPriority::High,
            80 | 443 => PacketPriority::High,
            25 | 587 | 465 => PacketPriority::Normal,
            _ => PacketPriority::Normal,
        }
    }

    /// Classify UDP traffic using TrafficClass (preferred)
    fn classify_udp_traffic(port: u16) -> TrafficClass {
        use crate::low_latency::{is_gaming_port, is_voip_port};

        if is_gaming_port(port) {
            TrafficClass::Gaming
        } else if is_voip_port(port) {
            TrafficClass::RealTime
        } else if port == 53 {
            TrafficClass::Web // DNS is interactive
        } else if port > 10000 {
            TrafficClass::Gaming // High UDP ports often gaming
        } else {
            TrafficClass::General
        }
    }

    /// Classify TCP traffic using TrafficClass (preferred)
    fn classify_tcp_traffic(port: u16) -> TrafficClass {
        match port {
            22 => TrafficClass::RealTime, // SSH is interactive
            80 | 443 => TrafficClass::Web,
            25 | 587 | 465 | 993 | 995 => TrafficClass::Bulk, // Email
            21 | 20 => TrafficClass::Bulk,                    // FTP
            _ => TrafficClass::General,
        }
    }
}

pub fn is_compressible(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }

    match SlicedPacket::from_ip(data) {
        Ok(packet) => {
            if let Some(TransportSlice::Tcp(tcp)) = packet.transport {
                !matches!(tcp.destination_port(), 443 | 22 | 993 | 995)
            } else {
                true
            }
        }
        Err(_) => true,
    }
}
