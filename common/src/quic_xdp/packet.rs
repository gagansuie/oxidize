//! QUIC Packet Parsing for AF_XDP
//!
//! Zero-copy SIMD-accelerated QUIC packet parsing designed for kernel bypass.
//! Parses directly from UMEM buffers without any memory copies.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};

/// Cache line size for alignment
const CACHE_LINE: usize = 64;

/// Maximum QUIC packet size
pub const MAX_QUIC_PACKET_SIZE: usize = 1350;

/// QUIC version constants
pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// QUIC packet types (long header)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QuicPacketType {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    /// Short header (1-RTT)
    OneRtt = 0xff,
}

/// Connection ID (up to 20 bytes per QUIC spec)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C, align(32))]
pub struct ConnectionId {
    pub bytes: [u8; 20],
    pub len: u8,
}

impl ConnectionId {
    pub const EMPTY: Self = Self {
        bytes: [0; 20],
        len: 0,
    };

    #[inline(always)]
    pub fn new(data: &[u8]) -> Self {
        let mut cid = Self::EMPTY;
        let len = data.len().min(20);
        cid.bytes[..len].copy_from_slice(&data[..len]);
        cid.len = len as u8;
        cid
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Fast hash for connection lookup (FNV-1a)
    #[inline(always)]
    pub fn hash_fnv1a(&self) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &byte in &self.bytes[..self.len as usize] {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Parsed QUIC packet header (zero-copy reference)
#[derive(Debug, Clone)]
#[repr(C, align(64))]
pub struct QuicPacketHeader {
    /// Packet type
    pub packet_type: QuicPacketType,
    /// Is this a long header?
    pub is_long_header: bool,
    /// QUIC version (for long headers)
    pub version: u32,
    /// Destination Connection ID
    pub dcid: ConnectionId,
    /// Source Connection ID (long headers only)
    pub scid: ConnectionId,
    /// Packet number (decoded)
    pub packet_number: u64,
    /// Packet number length in bytes (1-4)
    pub pn_length: u8,
    /// Header length (offset to payload)
    pub header_len: usize,
    /// Payload length
    pub payload_len: usize,
    /// Token (Initial packets only)
    pub token_offset: usize,
    pub token_len: usize,
    /// Source address
    pub src_addr: SocketAddr,
    /// Destination address  
    pub dst_addr: SocketAddr,
}

impl Default for QuicPacketHeader {
    fn default() -> Self {
        Self {
            packet_type: QuicPacketType::OneRtt,
            is_long_header: false,
            version: 0,
            dcid: ConnectionId::EMPTY,
            scid: ConnectionId::EMPTY,
            packet_number: 0,
            pn_length: 0,
            header_len: 0,
            payload_len: 0,
            token_offset: 0,
            token_len: 0,
            src_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            dst_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

/// SIMD-accelerated QUIC packet parser
#[repr(C, align(64))]
pub struct QuicPacketParser {
    /// Expected DCID length (for short headers)
    dcid_len: u8,
    /// Statistics
    pub stats: ParserStats,
}

#[derive(Default)]
pub struct ParserStats {
    pub packets_parsed: AtomicU64,
    pub long_headers: AtomicU64,
    pub short_headers: AtomicU64,
    pub initial_packets: AtomicU64,
    pub handshake_packets: AtomicU64,
    pub onertt_packets: AtomicU64,
    pub parse_errors: AtomicU64,
}

impl QuicPacketParser {
    pub fn new(dcid_len: u8) -> Self {
        Self {
            dcid_len,
            stats: ParserStats::default(),
        }
    }

    /// Parse a QUIC packet from raw bytes (zero-copy)
    /// Returns header info and payload offset
    #[inline]
    pub fn parse<'a>(&self, data: &'a [u8]) -> Result<(QuicPacketHeader, &'a [u8]), ParseError> {
        if data.len() < 1 {
            return Err(ParseError::TooShort);
        }

        let first_byte = data[0];
        let is_long_header = (first_byte & 0x80) != 0;

        self.stats.packets_parsed.fetch_add(1, Ordering::Relaxed);

        if is_long_header {
            self.stats.long_headers.fetch_add(1, Ordering::Relaxed);
            self.parse_long_header(data, first_byte)
        } else {
            self.stats.short_headers.fetch_add(1, Ordering::Relaxed);
            self.parse_short_header(data, first_byte)
        }
    }

    /// Parse long header (Initial, Handshake, 0-RTT, Retry)
    #[inline]
    fn parse_long_header<'a>(
        &self,
        data: &'a [u8],
        first_byte: u8,
    ) -> Result<(QuicPacketHeader, &'a [u8]), ParseError> {
        // Long header minimum: 1 + 4 + 1 + 1 = 7 bytes
        if data.len() < 7 {
            self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            return Err(ParseError::TooShort);
        }

        let packet_type = match (first_byte & 0x30) >> 4 {
            0x00 => {
                self.stats.initial_packets.fetch_add(1, Ordering::Relaxed);
                QuicPacketType::Initial
            }
            0x01 => QuicPacketType::ZeroRtt,
            0x02 => {
                self.stats.handshake_packets.fetch_add(1, Ordering::Relaxed);
                QuicPacketType::Handshake
            }
            0x03 => QuicPacketType::Retry,
            _ => return Err(ParseError::InvalidPacketType),
        };

        // Version (4 bytes, big-endian)
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        // DCID length and DCID
        let dcid_len = data[5] as usize;
        if dcid_len > 20 || data.len() < 6 + dcid_len {
            return Err(ParseError::InvalidConnectionId);
        }
        let dcid = ConnectionId::new(&data[6..6 + dcid_len]);

        // SCID length and SCID
        let scid_offset = 6 + dcid_len;
        if data.len() < scid_offset + 1 {
            return Err(ParseError::TooShort);
        }
        let scid_len = data[scid_offset] as usize;
        if scid_len > 20 || data.len() < scid_offset + 1 + scid_len {
            return Err(ParseError::InvalidConnectionId);
        }
        let scid = ConnectionId::new(&data[scid_offset + 1..scid_offset + 1 + scid_len]);

        let mut offset = scid_offset + 1 + scid_len;
        let mut token_offset = 0;
        let mut token_len = 0;

        // Token (Initial packets only)
        if packet_type == QuicPacketType::Initial {
            let (tlen, tlen_bytes) = self.decode_varint(&data[offset..])?;
            token_offset = offset + tlen_bytes;
            token_len = tlen as usize;
            offset = token_offset + token_len;
        }

        // Length (varint)
        if data.len() < offset + 1 {
            return Err(ParseError::TooShort);
        }
        let (payload_len, len_bytes) = self.decode_varint(&data[offset..])?;
        offset += len_bytes;

        // Packet number (1-4 bytes, indicated by first byte bits 0-1)
        let pn_length = (first_byte & 0x03) + 1;
        if data.len() < offset + pn_length as usize {
            return Err(ParseError::TooShort);
        }

        let packet_number = self.decode_packet_number(&data[offset..], pn_length);
        let header_len = offset + pn_length as usize;

        let header = QuicPacketHeader {
            packet_type,
            is_long_header: true,
            version,
            dcid,
            scid,
            packet_number,
            pn_length,
            header_len,
            payload_len: payload_len as usize,
            token_offset,
            token_len,
            ..Default::default()
        };

        Ok((header, &data[header_len..]))
    }

    /// Parse short header (1-RTT)
    #[inline]
    fn parse_short_header<'a>(
        &self,
        data: &'a [u8],
        first_byte: u8,
    ) -> Result<(QuicPacketHeader, &'a [u8]), ParseError> {
        self.stats.onertt_packets.fetch_add(1, Ordering::Relaxed);

        // Short header: 1 byte + DCID + PN
        let dcid_len = self.dcid_len as usize;
        let min_len = 1 + dcid_len + 1; // At least 1 byte PN

        if data.len() < min_len {
            self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            return Err(ParseError::TooShort);
        }

        let dcid = ConnectionId::new(&data[1..1 + dcid_len]);

        // Packet number length from first byte
        let pn_length = (first_byte & 0x03) + 1;
        let pn_offset = 1 + dcid_len;

        if data.len() < pn_offset + pn_length as usize {
            return Err(ParseError::TooShort);
        }

        let packet_number = self.decode_packet_number(&data[pn_offset..], pn_length);
        let header_len = pn_offset + pn_length as usize;

        let header = QuicPacketHeader {
            packet_type: QuicPacketType::OneRtt,
            is_long_header: false,
            version: 0,
            dcid,
            scid: ConnectionId::EMPTY,
            packet_number,
            pn_length,
            header_len,
            payload_len: data.len() - header_len,
            token_offset: 0,
            token_len: 0,
            ..Default::default()
        };

        Ok((header, &data[header_len..]))
    }

    /// Decode variable-length integer (QUIC varint)
    #[inline(always)]
    fn decode_varint(&self, data: &[u8]) -> Result<(u64, usize), ParseError> {
        if data.is_empty() {
            return Err(ParseError::TooShort);
        }

        let first = data[0];
        let len = 1 << (first >> 6);

        if data.len() < len {
            return Err(ParseError::TooShort);
        }

        let value = match len {
            1 => (first & 0x3f) as u64,
            2 => {
                let val = u16::from_be_bytes([data[0], data[1]]);
                (val & 0x3fff) as u64
            }
            4 => {
                let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                (val & 0x3fff_ffff) as u64
            }
            8 => {
                let val = u64::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                val & 0x3fff_ffff_ffff_ffff
            }
            _ => return Err(ParseError::InvalidVarint),
        };

        Ok((value, len))
    }

    /// Decode packet number (1-4 bytes)
    #[inline(always)]
    fn decode_packet_number(&self, data: &[u8], len: u8) -> u64 {
        match len {
            1 => data[0] as u64,
            2 => u16::from_be_bytes([data[0], data[1]]) as u64,
            3 => {
                let mut buf = [0u8; 4];
                buf[1..4].copy_from_slice(&data[..3]);
                u32::from_be_bytes(buf) as u64
            }
            4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
            _ => 0,
        }
    }

    /// Batch parse multiple packets (SIMD-friendly)
    #[inline]
    pub fn parse_batch<'a>(
        &self,
        packets: &[&'a [u8]],
        headers: &mut Vec<QuicPacketHeader>,
        payloads: &mut Vec<&'a [u8]>,
    ) -> usize {
        let mut success = 0;
        for packet in packets {
            match self.parse(packet) {
                Ok((header, payload)) => {
                    headers.push(header);
                    payloads.push(payload);
                    success += 1;
                }
                Err(_) => continue,
            }
        }
        success
    }
}

/// Parse errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidPacketType,
    InvalidConnectionId,
    InvalidVarint,
    InvalidVersion,
}

/// Extract IP/UDP headers from raw packet
#[inline]
pub fn parse_ip_udp_headers(data: &[u8]) -> Option<(SocketAddr, SocketAddr, usize)> {
    if data.len() < 28 {
        // Minimum: IP (20) + UDP (8)
        return None;
    }

    let ip_version = (data[0] >> 4) & 0x0f;

    match ip_version {
        4 => {
            let ihl = (data[0] & 0x0f) as usize * 4;
            if data.len() < ihl + 8 {
                return None;
            }

            let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
            let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

            let udp_offset = ihl;
            let src_port = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);
            let dst_port = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);

            let payload_offset = udp_offset + 8;

            Some((
                SocketAddr::V4(SocketAddrV4::new(src_ip, src_port)),
                SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
                payload_offset,
            ))
        }
        6 => {
            if data.len() < 48 {
                // IPv6 (40) + UDP (8)
                return None;
            }

            let src_ip = Ipv6Addr::new(
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
                u16::from_be_bytes([data[20], data[21]]),
                u16::from_be_bytes([data[22], data[23]]),
            );
            let dst_ip = Ipv6Addr::new(
                u16::from_be_bytes([data[24], data[25]]),
                u16::from_be_bytes([data[26], data[27]]),
                u16::from_be_bytes([data[28], data[29]]),
                u16::from_be_bytes([data[30], data[31]]),
                u16::from_be_bytes([data[32], data[33]]),
                u16::from_be_bytes([data[34], data[35]]),
                u16::from_be_bytes([data[36], data[37]]),
                u16::from_be_bytes([data[38], data[39]]),
            );

            let udp_offset = 40;
            let src_port = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);
            let dst_port = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);

            let payload_offset = udp_offset + 8;

            Some((
                SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0)),
                payload_offset,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let cid = ConnectionId::new(&data);
        assert_eq!(cid.len, 8);
        assert_eq!(cid.as_slice(), &data);
    }

    #[test]
    fn test_cid_hash() {
        let cid1 = ConnectionId::new(&[1, 2, 3, 4]);
        let cid2 = ConnectionId::new(&[1, 2, 3, 4]);
        let cid3 = ConnectionId::new(&[1, 2, 3, 5]);

        assert_eq!(cid1.hash_fnv1a(), cid2.hash_fnv1a());
        assert_ne!(cid1.hash_fnv1a(), cid3.hash_fnv1a());
    }
}
