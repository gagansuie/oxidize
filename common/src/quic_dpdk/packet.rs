//! DPDK QUIC Packet Processing
//!
//! High-performance QUIC packet parsing and building using DPDK mbufs.
//! Optimized for zero-copy operations and SIMD where possible.

use std::net::{Ipv4Addr, Ipv6Addr};

/// QUIC packet types (long header)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QuicPacketType {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    Short = 0xFF, // 1-RTT (short header)
}

/// Parsed QUIC packet header
#[derive(Debug, Clone)]
pub struct QuicHeader {
    pub packet_type: QuicPacketType,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub packet_number: u64,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub token: Option<Vec<u8>>,
}

/// Parsed network headers (Ethernet + IP + UDP)
#[derive(Debug, Clone)]
pub struct NetworkHeaders {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_header_len: usize,
    pub total_header_len: usize,
}

/// IP address (v4 or v6)
#[derive(Debug, Clone, Copy)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl NetworkHeaders {
    /// Parse network headers from mbuf
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        // Ethernet header
        let dst_mac = [data[0], data[1], data[2], data[3], data[4], data[5]];
        let src_mac = [data[6], data[7], data[8], data[9], data[10], data[11]];
        let ether_type = u16::from_be_bytes([data[12], data[13]]);

        let ip_start = 14;

        match ether_type {
            0x0800 => {
                // IPv4
                if data.len() < ip_start + 20 {
                    return None;
                }
                let ihl = (data[ip_start] & 0x0f) as usize * 4;
                let proto = data[ip_start + 9];
                if proto != 17 {
                    // Not UDP
                    return None;
                }

                let src_ip = Ipv4Addr::new(
                    data[ip_start + 12],
                    data[ip_start + 13],
                    data[ip_start + 14],
                    data[ip_start + 15],
                );
                let dst_ip = Ipv4Addr::new(
                    data[ip_start + 16],
                    data[ip_start + 17],
                    data[ip_start + 18],
                    data[ip_start + 19],
                );

                let udp_start = ip_start + ihl;
                if data.len() < udp_start + 8 {
                    return None;
                }

                let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
                let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);

                Some(Self {
                    src_mac,
                    dst_mac,
                    src_ip: IpAddr::V4(src_ip),
                    dst_ip: IpAddr::V4(dst_ip),
                    src_port,
                    dst_port,
                    ip_header_len: ihl,
                    total_header_len: udp_start + 8,
                })
            }
            0x86DD => {
                // IPv6
                if data.len() < ip_start + 40 {
                    return None;
                }
                let proto = data[ip_start + 6];
                if proto != 17 {
                    return None;
                }

                let mut src_bytes = [0u8; 16];
                let mut dst_bytes = [0u8; 16];
                src_bytes.copy_from_slice(&data[ip_start + 8..ip_start + 24]);
                dst_bytes.copy_from_slice(&data[ip_start + 24..ip_start + 40]);

                let src_ip = Ipv6Addr::from(src_bytes);
                let dst_ip = Ipv6Addr::from(dst_bytes);

                let udp_start = ip_start + 40;
                if data.len() < udp_start + 8 {
                    return None;
                }

                let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
                let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);

                Some(Self {
                    src_mac,
                    dst_mac,
                    src_ip: IpAddr::V6(src_ip),
                    dst_ip: IpAddr::V6(dst_ip),
                    src_port,
                    dst_port,
                    ip_header_len: 40,
                    total_header_len: udp_start + 8,
                })
            }
            _ => None,
        }
    }
}

impl QuicHeader {
    /// Parse QUIC header from payload (after UDP header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let first_byte = data[0];
        let is_long_header = (first_byte & 0x80) != 0;

        if is_long_header {
            Self::parse_long_header(data)
        } else {
            Self::parse_short_header(data)
        }
    }

    fn parse_long_header(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }

        let first_byte = data[0];
        let packet_type = match (first_byte & 0x30) >> 4 {
            0x00 => QuicPacketType::Initial,
            0x01 => QuicPacketType::ZeroRtt,
            0x02 => QuicPacketType::Handshake,
            0x03 => QuicPacketType::Retry,
            _ => return None,
        };

        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len + 1 {
            return None;
        }
        let dcid = data[6..6 + dcid_len].to_vec();

        let scid_len = data[6 + dcid_len] as usize;
        let scid_start = 7 + dcid_len;
        if data.len() < scid_start + scid_len {
            return None;
        }
        let scid = data[scid_start..scid_start + scid_len].to_vec();

        let mut offset = scid_start + scid_len;

        // Token (only for Initial packets)
        let token = if packet_type == QuicPacketType::Initial {
            let (token_len, token_len_size) = decode_varint(&data[offset..])?;
            offset += token_len_size;
            if data.len() < offset + token_len as usize {
                return None;
            }
            let t = data[offset..offset + token_len as usize].to_vec();
            offset += token_len as usize;
            Some(t)
        } else {
            None
        };

        // Length
        let (length, length_size) = decode_varint(&data[offset..])?;
        offset += length_size;

        // Packet number (1-4 bytes based on first_byte)
        let pn_len = ((first_byte & 0x03) + 1) as usize;
        if data.len() < offset + pn_len {
            return None;
        }
        let packet_number = decode_packet_number(&data[offset..offset + pn_len]);
        offset += pn_len;

        Some(Self {
            packet_type,
            version,
            dcid,
            scid,
            packet_number,
            payload_offset: offset,
            payload_len: length as usize - pn_len,
            token,
        })
    }

    fn parse_short_header(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let first_byte = data[0];

        // For short header, we need to know the DCID length from connection state
        // Default to 8 bytes (common case)
        let dcid_len = 8;
        if data.len() < 1 + dcid_len {
            return None;
        }

        let dcid = data[1..1 + dcid_len].to_vec();

        let pn_len = ((first_byte & 0x03) + 1) as usize;
        let pn_offset = 1 + dcid_len;
        if data.len() < pn_offset + pn_len {
            return None;
        }

        let packet_number = decode_packet_number(&data[pn_offset..pn_offset + pn_len]);

        Some(Self {
            packet_type: QuicPacketType::Short,
            version: 0,
            dcid,
            scid: Vec::new(),
            packet_number,
            payload_offset: pn_offset + pn_len,
            payload_len: data.len() - pn_offset - pn_len,
            token: None,
        })
    }
}

/// Decode QUIC variable-length integer
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    let len = 1 << (first >> 6);

    if data.len() < len {
        return None;
    }

    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let v = u16::from_be_bytes([data[0], data[1]]);
            (v & 0x3fff) as u64
        }
        4 => {
            let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            (v & 0x3fffffff) as u64
        }
        8 => {
            let v = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            v & 0x3fffffffffffffff
        }
        _ => return None,
    };

    Some((value, len))
}

/// Decode packet number
fn decode_packet_number(data: &[u8]) -> u64 {
    match data.len() {
        1 => data[0] as u64,
        2 => u16::from_be_bytes([data[0], data[1]]) as u64,
        3 => ((data[0] as u64) << 16) | ((data[1] as u64) << 8) | (data[2] as u64),
        4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
        _ => 0,
    }
}

/// Encode QUIC variable-length integer
pub fn encode_varint(value: u64, buf: &mut [u8]) -> usize {
    if value < 0x40 {
        buf[0] = value as u8;
        1
    } else if value < 0x4000 {
        let v = (value as u16) | 0x4000;
        buf[0..2].copy_from_slice(&v.to_be_bytes());
        2
    } else if value < 0x40000000 {
        let v = (value as u32) | 0x80000000;
        buf[0..4].copy_from_slice(&v.to_be_bytes());
        4
    } else {
        let v = value | 0xc000000000000000;
        buf[0..8].copy_from_slice(&v.to_be_bytes());
        8
    }
}

/// QUIC packet builder for DPDK mbufs
pub struct QuicPacketBuilder {
    version: u32,
    dcid: Vec<u8>,
    scid: Vec<u8>,
}

impl QuicPacketBuilder {
    pub fn new(version: u32, dcid: Vec<u8>, scid: Vec<u8>) -> Self {
        Self {
            version,
            dcid,
            scid,
        }
    }

    /// Build Initial packet
    pub fn build_initial(
        &self,
        packet_number: u64,
        payload: &[u8],
        token: &[u8],
        buf: &mut [u8],
    ) -> usize {
        let mut offset = 0;

        // First byte: Long header + Initial type
        let pn_len = Self::packet_number_len(packet_number);
        buf[offset] = 0xc0 | ((pn_len - 1) as u8);
        offset += 1;

        // Version
        buf[offset..offset + 4].copy_from_slice(&self.version.to_be_bytes());
        offset += 4;

        // DCID length + DCID
        buf[offset] = self.dcid.len() as u8;
        offset += 1;
        buf[offset..offset + self.dcid.len()].copy_from_slice(&self.dcid);
        offset += self.dcid.len();

        // SCID length + SCID
        buf[offset] = self.scid.len() as u8;
        offset += 1;
        buf[offset..offset + self.scid.len()].copy_from_slice(&self.scid);
        offset += self.scid.len();

        // Token length + token
        offset += encode_varint(token.len() as u64, &mut buf[offset..]);
        buf[offset..offset + token.len()].copy_from_slice(token);
        offset += token.len();

        // Length (packet number + payload + auth tag)
        let length = pn_len + payload.len() + 16; // 16 = AEAD tag
        offset += encode_varint(length as u64, &mut buf[offset..]);

        // Packet number
        Self::encode_packet_number(packet_number, pn_len, &mut buf[offset..]);
        offset += pn_len;

        // Payload (would be encrypted)
        buf[offset..offset + payload.len()].copy_from_slice(payload);
        offset += payload.len();

        // Auth tag placeholder (16 bytes)
        for i in 0..16 {
            buf[offset + i] = 0;
        }
        offset += 16;

        offset
    }

    /// Build Handshake packet
    pub fn build_handshake(&self, packet_number: u64, payload: &[u8], buf: &mut [u8]) -> usize {
        let mut offset = 0;

        let pn_len = Self::packet_number_len(packet_number);
        buf[offset] = 0xe0 | ((pn_len - 1) as u8); // Handshake type
        offset += 1;

        // Version
        buf[offset..offset + 4].copy_from_slice(&self.version.to_be_bytes());
        offset += 4;

        // DCID length + DCID
        buf[offset] = self.dcid.len() as u8;
        offset += 1;
        buf[offset..offset + self.dcid.len()].copy_from_slice(&self.dcid);
        offset += self.dcid.len();

        // SCID length + SCID
        buf[offset] = self.scid.len() as u8;
        offset += 1;
        buf[offset..offset + self.scid.len()].copy_from_slice(&self.scid);
        offset += self.scid.len();

        // Length
        let length = pn_len + payload.len() + 16;
        offset += encode_varint(length as u64, &mut buf[offset..]);

        // Packet number
        Self::encode_packet_number(packet_number, pn_len, &mut buf[offset..]);
        offset += pn_len;

        // Payload
        buf[offset..offset + payload.len()].copy_from_slice(payload);
        offset += payload.len();

        // Auth tag
        for i in 0..16 {
            buf[offset + i] = 0;
        }
        offset += 16;

        offset
    }

    /// Build 1-RTT (short header) packet
    pub fn build_short(&self, packet_number: u64, payload: &[u8], buf: &mut [u8]) -> usize {
        let mut offset = 0;

        let pn_len = Self::packet_number_len(packet_number);
        buf[offset] = 0x40 | ((pn_len - 1) as u8); // Short header, spin=0, key_phase=0
        offset += 1;

        // DCID only (no length prefix)
        buf[offset..offset + self.dcid.len()].copy_from_slice(&self.dcid);
        offset += self.dcid.len();

        // Packet number
        Self::encode_packet_number(packet_number, pn_len, &mut buf[offset..]);
        offset += pn_len;

        // Payload
        buf[offset..offset + payload.len()].copy_from_slice(payload);
        offset += payload.len();

        // Auth tag
        for i in 0..16 {
            buf[offset + i] = 0;
        }
        offset += 16;

        offset
    }

    fn packet_number_len(pn: u64) -> usize {
        if pn < 0x100 {
            1
        } else if pn < 0x10000 {
            2
        } else if pn < 0x1000000 {
            3
        } else {
            4
        }
    }

    fn encode_packet_number(pn: u64, len: usize, buf: &mut [u8]) {
        match len {
            1 => buf[0] = pn as u8,
            2 => buf[0..2].copy_from_slice(&(pn as u16).to_be_bytes()),
            3 => {
                buf[0] = (pn >> 16) as u8;
                buf[1] = (pn >> 8) as u8;
                buf[2] = pn as u8;
            }
            4 => buf[0..4].copy_from_slice(&(pn as u32).to_be_bytes()),
            _ => {}
        }
    }
}

/// Build Ethernet + IP + UDP headers
pub fn build_network_headers(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    buf: &mut [u8],
) -> usize {
    // Ethernet header
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    let mut offset = 12;

    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // EtherType IPv4
            buf[offset..offset + 2].copy_from_slice(&0x0800u16.to_be_bytes());
            offset += 2;

            // IPv4 header (20 bytes)
            let total_len = 20 + 8 + payload_len; // IP + UDP + payload
            buf[offset] = 0x45; // Version + IHL
            buf[offset + 1] = 0x00; // DSCP + ECN
            buf[offset + 2..offset + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[offset + 4..offset + 6].copy_from_slice(&0u16.to_be_bytes()); // ID
            buf[offset + 6..offset + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags + Fragment
            buf[offset + 8] = 64; // TTL
            buf[offset + 9] = 17; // Protocol (UDP)
            buf[offset + 10..offset + 12].copy_from_slice(&0u16.to_be_bytes()); // Checksum (0 for now)
            buf[offset + 12..offset + 16].copy_from_slice(&src.octets());
            buf[offset + 16..offset + 20].copy_from_slice(&dst.octets());
            offset += 20;

            // UDP header (8 bytes)
            let udp_len = 8 + payload_len;
            buf[offset..offset + 2].copy_from_slice(&src_port.to_be_bytes());
            buf[offset + 2..offset + 4].copy_from_slice(&dst_port.to_be_bytes());
            buf[offset + 4..offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            buf[offset + 6..offset + 8].copy_from_slice(&0u16.to_be_bytes()); // Checksum
            offset += 8;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            // EtherType IPv6
            buf[offset..offset + 2].copy_from_slice(&0x86DDu16.to_be_bytes());
            offset += 2;

            // IPv6 header (40 bytes)
            let payload_len_ipv6 = 8 + payload_len; // UDP + payload
            buf[offset] = 0x60; // Version
            buf[offset + 1] = 0x00;
            buf[offset + 2] = 0x00;
            buf[offset + 3] = 0x00; // Traffic class + Flow label
            buf[offset + 4..offset + 6].copy_from_slice(&(payload_len_ipv6 as u16).to_be_bytes());
            buf[offset + 6] = 17; // Next header (UDP)
            buf[offset + 7] = 64; // Hop limit
            buf[offset + 8..offset + 24].copy_from_slice(&src.octets());
            buf[offset + 24..offset + 40].copy_from_slice(&dst.octets());
            offset += 40;

            // UDP header
            let udp_len = 8 + payload_len;
            buf[offset..offset + 2].copy_from_slice(&src_port.to_be_bytes());
            buf[offset + 2..offset + 4].copy_from_slice(&dst_port.to_be_bytes());
            buf[offset + 4..offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            buf[offset + 6..offset + 8].copy_from_slice(&0u16.to_be_bytes());
            offset += 8;
        }
        _ => {} // Mismatched IP versions
    }

    offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_decode() {
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x3f]), Some((63, 1)));
        assert_eq!(decode_varint(&[0x40, 0x40]), Some((64, 2)));
    }

    #[test]
    fn test_varint_encode() {
        let mut buf = [0u8; 8];
        assert_eq!(encode_varint(0, &mut buf), 1);
        assert_eq!(buf[0], 0x00);

        assert_eq!(encode_varint(63, &mut buf), 1);
        assert_eq!(buf[0], 0x3f);
    }
}
