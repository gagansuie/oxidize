use etherparse::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketPriority {
    Critical,
    High,
    Normal,
    Low,
}

#[derive(Debug)]
pub struct PacketInfo {
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub priority: PacketPriority,
    pub size: usize,
}

impl PacketInfo {
    pub fn analyze(data: &[u8]) -> anyhow::Result<Self> {
        let mut protocol = 0;
        let mut src_port = None;
        let mut dst_port = None;
        let mut priority = PacketPriority::Normal;

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

                            priority = Self::classify_udp_priority(udp.destination_port());
                        }
                        TransportSlice::Tcp(tcp) => {
                            src_port = Some(tcp.source_port());
                            dst_port = Some(tcp.destination_port());

                            priority = Self::classify_tcp_priority(tcp.destination_port());
                        }
                        TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                            priority = PacketPriority::High;
                        }
                    }
                }
            }
            Err(_) => {
                priority = PacketPriority::Low;
            }
        }

        Ok(PacketInfo {
            protocol,
            src_port,
            dst_port,
            priority,
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
