//! Variable-Length Header Encoding for OxTunnel Protocol
//!
//! Reduces average header size from 9 bytes to ~4 bytes using:
//! - Varint encoding for sequence numbers (1-5 bytes vs fixed 4)
//! - Combined type+flags byte
//! - Optional length field (omitted for fixed-size packets)
//!
//! ## Header Format (V2 - Variable Length)
//!
//! ```text
//! Minimal header (2-3 bytes for small seq nums):
//! +----------+------------+
//! | TypeFlags| SeqNum     |
//! | 1B       | 1-5B varint|
//! +----------+------------+
//!
//! With length (add 1-2 bytes when payload size varies):
//! +----------+------------+--------+
//! | TypeFlags| SeqNum     | Length |
//! | 1B       | 1-5B varint| 1-2B   |
//! +----------+------------+--------+
//! ```
//!
//! ## TypeFlags byte layout:
//! - Bits 0-3: Packet type (0=data, 1=ack, 2=control, etc.)
//! - Bit 4: Has length field
//! - Bit 5: Encrypted
//! - Bit 6: Compressed
//! - Bit 7: IPv6

use std::io::{self, Error, ErrorKind};

// ============================================================================
// Varint Encoding (LEB128-style, but optimized for network)
// ============================================================================

/// Encode a u32 as a varint (1-5 bytes)
/// Uses continuation bit encoding: MSB=1 means more bytes follow
#[inline]
pub fn encode_varint32(value: u32, buf: &mut [u8]) -> usize {
    let mut v = value;
    let mut i = 0;

    while v >= 0x80 {
        buf[i] = (v as u8) | 0x80;
        v >>= 7;
        i += 1;
    }
    buf[i] = v as u8;
    i + 1
}

/// Decode a varint from buffer, returns (value, bytes_consumed)
#[inline]
pub fn decode_varint32(buf: &[u8]) -> io::Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift = 0;

    for (i, &byte) in buf.iter().enumerate() {
        if i >= 5 {
            return Err(Error::new(ErrorKind::InvalidData, "varint too long"));
        }

        value |= ((byte & 0x7F) as u32) << shift;

        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }

        shift += 7;
    }

    Err(Error::new(ErrorKind::UnexpectedEof, "incomplete varint"))
}

/// Encode a u16 as 1-2 bytes (for length field)
/// Values 0-127 use 1 byte, 128-32767 use 2 bytes
#[inline]
pub fn encode_length(value: u16, buf: &mut [u8]) -> usize {
    if value < 128 {
        buf[0] = value as u8;
        1
    } else {
        buf[0] = ((value >> 8) as u8) | 0x80;
        buf[1] = value as u8;
        2
    }
}

/// Decode length field
#[inline]
pub fn decode_length(buf: &[u8]) -> io::Result<(u16, usize)> {
    if buf.is_empty() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "empty length field"));
    }

    if buf[0] & 0x80 == 0 {
        Ok((buf[0] as u16, 1))
    } else if buf.len() >= 2 {
        let value = (((buf[0] & 0x7F) as u16) << 8) | (buf[1] as u16);
        Ok((value, 2))
    } else {
        Err(Error::new(ErrorKind::UnexpectedEof, "incomplete length"))
    }
}

// ============================================================================
// V2 Header Types
// ============================================================================

/// Packet type (4 bits, 0-15)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0,
    Ack = 1,
    Control = 2,
    Batch = 3,
    Keepalive = 4,
    Handshake = 5,
    KeyRotation = 6,
    Disconnect = 7,
}

impl PacketType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PacketType::Data),
            1 => Some(PacketType::Ack),
            2 => Some(PacketType::Control),
            3 => Some(PacketType::Batch),
            4 => Some(PacketType::Keepalive),
            5 => Some(PacketType::Handshake),
            6 => Some(PacketType::KeyRotation),
            7 => Some(PacketType::Disconnect),
            _ => None,
        }
    }
}

/// TypeFlags byte layout
pub mod type_flags {
    pub const TYPE_MASK: u8 = 0x0F; // Bits 0-3: packet type
    pub const HAS_LENGTH: u8 = 0x10; // Bit 4: length field present
    pub const ENCRYPTED: u8 = 0x20; // Bit 5: encrypted
    pub const COMPRESSED: u8 = 0x40; // Bit 6: compressed
    pub const IPV6: u8 = 0x80; // Bit 7: IPv6 payload
}

/// V2 Variable-length header
#[derive(Debug, Clone)]
pub struct V2Header {
    pub packet_type: PacketType,
    pub has_length: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub ipv6: bool,
    pub seq_num: u32,
    pub length: Option<u16>,
}

impl V2Header {
    /// Create a new data header
    pub fn data(seq_num: u32, encrypted: bool, compressed: bool) -> Self {
        Self {
            packet_type: PacketType::Data,
            has_length: false,
            encrypted,
            compressed,
            ipv6: false,
            seq_num,
            length: None,
        }
    }

    /// Create with explicit length
    pub fn with_length(mut self, len: u16) -> Self {
        self.has_length = true;
        self.length = Some(len);
        self
    }

    /// Encode header to buffer, returns bytes written
    pub fn encode(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Err(Error::new(ErrorKind::WriteZero, "buffer too small"));
        }

        // Build type+flags byte
        let mut type_flags = self.packet_type as u8;
        if self.has_length {
            type_flags |= type_flags::HAS_LENGTH;
        }
        if self.encrypted {
            type_flags |= type_flags::ENCRYPTED;
        }
        if self.compressed {
            type_flags |= type_flags::COMPRESSED;
        }
        if self.ipv6 {
            type_flags |= type_flags::IPV6;
        }

        buf[0] = type_flags;
        let mut offset = 1;

        // Encode sequence number as varint
        if buf.len() < offset + 5 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "buffer too small for seqnum",
            ));
        }
        offset += encode_varint32(self.seq_num, &mut buf[offset..]);

        // Encode length if present
        if self.has_length {
            if let Some(len) = self.length {
                if buf.len() < offset + 2 {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "buffer too small for length",
                    ));
                }
                offset += encode_length(len, &mut buf[offset..]);
            }
        }

        Ok(offset)
    }

    /// Decode header from buffer, returns (header, bytes_consumed)
    pub fn decode(buf: &[u8]) -> io::Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "empty buffer"));
        }

        let type_flags = buf[0];
        let packet_type = PacketType::from_u8(type_flags & type_flags::TYPE_MASK)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid packet type"))?;

        let has_length = type_flags & type_flags::HAS_LENGTH != 0;
        let encrypted = type_flags & type_flags::ENCRYPTED != 0;
        let compressed = type_flags & type_flags::COMPRESSED != 0;
        let ipv6 = type_flags & type_flags::IPV6 != 0;

        let mut offset = 1;

        // Decode sequence number
        let (seq_num, seq_len) = decode_varint32(&buf[offset..])?;
        offset += seq_len;

        // Decode length if present
        let length = if has_length {
            let (len, len_bytes) = decode_length(&buf[offset..])?;
            offset += len_bytes;
            Some(len)
        } else {
            None
        };

        Ok((
            Self {
                packet_type,
                has_length,
                encrypted,
                compressed,
                ipv6,
                seq_num,
                length,
            },
            offset,
        ))
    }

    /// Calculate encoded size without actually encoding
    #[inline]
    pub fn encoded_size(&self) -> usize {
        let mut size = 1; // type+flags byte

        // Varint size for seq_num
        size += varint_size(self.seq_num);

        // Length field size
        if self.has_length {
            if let Some(len) = self.length {
                size += if len < 128 { 1 } else { 2 };
            }
        }

        size
    }
}

/// Calculate varint encoded size for a u32
#[inline]
pub fn varint_size(value: u32) -> usize {
    match value {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1FFFFF => 3,
        0x200000..=0x0FFFFFFF => 4,
        _ => 5,
    }
}

// ============================================================================
// Batch Encoding (multiple packets in one)
// ============================================================================

/// Batch header for multiple small packets
#[derive(Debug, Clone)]
pub struct BatchHeader {
    pub encrypted: bool,
    pub compressed: bool,
    pub packet_count: u8,
    pub seq_base: u32,
}

impl BatchHeader {
    pub fn new(seq_base: u32, count: u8) -> Self {
        Self {
            encrypted: false,
            compressed: false,
            packet_count: count,
            seq_base,
        }
    }

    /// Encode batch header
    pub fn encode(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() < 3 {
            return Err(Error::new(ErrorKind::WriteZero, "buffer too small"));
        }

        let mut type_flags = PacketType::Batch as u8;
        if self.encrypted {
            type_flags |= type_flags::ENCRYPTED;
        }
        if self.compressed {
            type_flags |= type_flags::COMPRESSED;
        }

        buf[0] = type_flags;
        buf[1] = self.packet_count;
        let mut offset = 2;

        offset += encode_varint32(self.seq_base, &mut buf[offset..]);

        Ok(offset)
    }

    /// Decode batch header
    pub fn decode(buf: &[u8]) -> io::Result<(Self, usize)> {
        if buf.len() < 3 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "buffer too small"));
        }

        let type_flags = buf[0];
        let encrypted = type_flags & type_flags::ENCRYPTED != 0;
        let compressed = type_flags & type_flags::COMPRESSED != 0;
        let packet_count = buf[1];

        let (seq_base, seq_len) = decode_varint32(&buf[2..])?;

        Ok((
            Self {
                encrypted,
                compressed,
                packet_count,
                seq_base,
            },
            2 + seq_len,
        ))
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Header encoding statistics
#[derive(Debug, Default)]
pub struct HeaderStats {
    pub total_headers: u64,
    pub total_bytes_v1: u64, // What V1 (9-byte) would use
    pub total_bytes_v2: u64, // What V2 (variable) actually uses
}

impl HeaderStats {
    pub fn record(&mut self, v2_size: usize) {
        self.total_headers += 1;
        self.total_bytes_v1 += 9; // V1 fixed size
        self.total_bytes_v2 += v2_size as u64;
    }

    pub fn savings_percent(&self) -> f64 {
        if self.total_bytes_v1 == 0 {
            return 0.0;
        }
        let saved = self.total_bytes_v1.saturating_sub(self.total_bytes_v2);
        (saved as f64 / self.total_bytes_v1 as f64) * 100.0
    }

    pub fn avg_header_size(&self) -> f64 {
        if self.total_headers == 0 {
            return 0.0;
        }
        self.total_bytes_v2 as f64 / self.total_headers as f64
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        let mut buf = [0u8; 5];

        // Small values
        assert_eq!(encode_varint32(0, &mut buf), 1);
        assert_eq!(buf[0], 0);

        assert_eq!(encode_varint32(127, &mut buf), 1);
        assert_eq!(buf[0], 127);

        // Medium values
        assert_eq!(encode_varint32(128, &mut buf), 2);
        let (val, len) = decode_varint32(&buf).unwrap();
        assert_eq!(val, 128);
        assert_eq!(len, 2);

        // Large values
        assert_eq!(encode_varint32(16384, &mut buf), 3);
        let (val, len) = decode_varint32(&buf).unwrap();
        assert_eq!(val, 16384);
        assert_eq!(len, 3);

        // Max u32
        assert_eq!(encode_varint32(u32::MAX, &mut buf), 5);
        let (val, len) = decode_varint32(&buf).unwrap();
        assert_eq!(val, u32::MAX);
        assert_eq!(len, 5);
    }

    #[test]
    fn test_v2_header_small_seq() {
        let header = V2Header::data(100, true, false);
        let mut buf = [0u8; 16];

        let encoded_len = header.encode(&mut buf).unwrap();
        assert_eq!(encoded_len, 2); // 1 byte flags + 1 byte seq

        let (decoded, consumed) = V2Header::decode(&buf).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(decoded.seq_num, 100);
        assert!(decoded.encrypted);
        assert!(!decoded.compressed);
    }

    #[test]
    fn test_v2_header_large_seq() {
        let header = V2Header::data(1_000_000, false, true);
        let mut buf = [0u8; 16];

        let encoded_len = header.encode(&mut buf).unwrap();
        assert_eq!(encoded_len, 4); // 1 byte flags + 3 bytes seq

        let (decoded, _) = V2Header::decode(&buf).unwrap();
        assert_eq!(decoded.seq_num, 1_000_000);
        assert!(!decoded.encrypted);
        assert!(decoded.compressed);
    }

    #[test]
    fn test_v2_header_with_length() {
        let header = V2Header::data(50, true, true).with_length(1000);
        let mut buf = [0u8; 16];

        let encoded_len = header.encode(&mut buf).unwrap();
        assert_eq!(encoded_len, 4); // 1 + 1 + 2 (flags + seq + length)

        let (decoded, consumed) = V2Header::decode(&buf).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded.length, Some(1000));
    }

    #[test]
    fn test_header_savings() {
        let mut stats = HeaderStats::default();

        // Typical gaming traffic: small seq nums, no length needed
        for seq in 0..1000u32 {
            let header = V2Header::data(seq, true, false);
            stats.record(header.encoded_size());
        }

        // Should save ~55% (avg 4 bytes vs 9 bytes)
        println!("Avg header size: {:.2} bytes", stats.avg_header_size());
        println!("Savings: {:.1}%", stats.savings_percent());
        assert!(stats.savings_percent() > 50.0);
    }
}
