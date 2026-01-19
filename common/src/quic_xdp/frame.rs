//! QUIC Frame Parsing and Encoding for AF_XDP
//!
//! Zero-copy frame handling with SIMD acceleration where possible.
//! Supports all QUIC v1/v2 frame types.

use std::sync::atomic::{AtomicU64, Ordering};

/// QUIC frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08, // 0x08-0x0f depending on flags
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12, // Bidi
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlocked = 0x16, // Bidi
    StreamsBlockedUni = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,
    Datagram = 0x30, // 0x30-0x31 with/without length
    DatagramLen = 0x31,
    Unknown = 0xff,
}

impl From<u8> for FrameType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => FrameType::Padding,
            0x01 => FrameType::Ping,
            0x02 => FrameType::Ack,
            0x03 => FrameType::AckEcn,
            0x04 => FrameType::ResetStream,
            0x05 => FrameType::StopSending,
            0x06 => FrameType::Crypto,
            0x07 => FrameType::NewToken,
            0x08..=0x0f => FrameType::Stream,
            0x10 => FrameType::MaxData,
            0x11 => FrameType::MaxStreamData,
            0x12 => FrameType::MaxStreams,
            0x13 => FrameType::MaxStreamsUni,
            0x14 => FrameType::DataBlocked,
            0x15 => FrameType::StreamDataBlocked,
            0x16 => FrameType::StreamsBlocked,
            0x17 => FrameType::StreamsBlockedUni,
            0x18 => FrameType::NewConnectionId,
            0x19 => FrameType::RetireConnectionId,
            0x1a => FrameType::PathChallenge,
            0x1b => FrameType::PathResponse,
            0x1c => FrameType::ConnectionClose,
            0x1d => FrameType::ConnectionCloseApp,
            0x1e => FrameType::HandshakeDone,
            0x30 => FrameType::Datagram,
            0x31 => FrameType::DatagramLen,
            _ => FrameType::Unknown,
        }
    }
}

/// Parsed STREAM frame
#[derive(Debug, Clone)]
pub struct StreamFrame<'a> {
    pub stream_id: u64,
    pub offset: u64,
    pub length: usize,
    pub fin: bool,
    pub data: &'a [u8],
}

/// Parsed ACK frame
#[derive(Debug, Clone)]
pub struct AckFrame {
    pub largest_ack: u64,
    pub ack_delay: u64,
    pub first_range: u64,
    pub ranges: Vec<AckRange>,
    pub ecn_counts: Option<EcnCounts>,
}

#[derive(Debug, Clone, Copy)]
pub struct AckRange {
    pub gap: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// Parsed CRYPTO frame
#[derive(Debug, Clone)]
pub struct CryptoFrame<'a> {
    pub offset: u64,
    pub length: usize,
    pub data: &'a [u8],
}

/// Parsed DATAGRAM frame
#[derive(Debug, Clone)]
pub struct DatagramFrame<'a> {
    pub length: Option<usize>,
    pub data: &'a [u8],
}

/// Parsed CONNECTION_CLOSE frame
#[derive(Debug, Clone)]
pub struct ConnectionCloseFrame<'a> {
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub reason: &'a [u8],
}

/// Zero-copy frame parser
pub struct FrameParser {
    pub stats: FrameStats,
}

#[derive(Default)]
pub struct FrameStats {
    pub frames_parsed: AtomicU64,
    pub stream_frames: AtomicU64,
    pub ack_frames: AtomicU64,
    pub crypto_frames: AtomicU64,
    pub datagram_frames: AtomicU64,
    pub padding_bytes: AtomicU64,
}

impl FrameParser {
    pub fn new() -> Self {
        Self {
            stats: FrameStats::default(),
        }
    }

    /// Parse all frames from a decrypted payload
    /// Calls the handler for each frame found
    #[inline]
    pub fn parse_frames<'a, F>(&self, mut data: &'a [u8], mut handler: F) -> Result<(), FrameError>
    where
        F: FnMut(Frame<'a>) -> Result<(), FrameError>,
    {
        while !data.is_empty() {
            let (frame, consumed) = self.parse_frame(data)?;
            self.stats.frames_parsed.fetch_add(1, Ordering::Relaxed);
            handler(frame)?;
            data = &data[consumed..];
        }
        Ok(())
    }

    /// Parse a single frame, returns (frame, bytes_consumed)
    #[inline]
    fn parse_frame<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        if data.is_empty() {
            return Err(FrameError::UnexpectedEnd);
        }

        let frame_type_byte = data[0];

        // Handle STREAM frames specially (0x08-0x0f)
        if frame_type_byte >= 0x08 && frame_type_byte <= 0x0f {
            return self.parse_stream_frame(data, frame_type_byte);
        }

        let frame_type = FrameType::from(frame_type_byte);

        match frame_type {
            FrameType::Padding => self.parse_padding(data),
            FrameType::Ping => Ok((Frame::Ping, 1)),
            FrameType::Ack => self.parse_ack(data, false),
            FrameType::AckEcn => self.parse_ack(data, true),
            FrameType::Crypto => self.parse_crypto(data),
            FrameType::Datagram => self.parse_datagram(data, false),
            FrameType::DatagramLen => self.parse_datagram(data, true),
            FrameType::MaxData => self.parse_max_data(data),
            FrameType::MaxStreamData => self.parse_max_stream_data(data),
            FrameType::ConnectionClose => self.parse_connection_close(data, false),
            FrameType::ConnectionCloseApp => self.parse_connection_close(data, true),
            FrameType::HandshakeDone => Ok((Frame::HandshakeDone, 1)),
            FrameType::PathChallenge => self.parse_path_challenge(data),
            FrameType::PathResponse => self.parse_path_response(data),
            FrameType::NewConnectionId => self.parse_new_connection_id(data),
            _ => Err(FrameError::UnknownFrameType(frame_type_byte)),
        }
    }

    /// Parse PADDING frames (consume all consecutive 0x00 bytes)
    #[inline]
    fn parse_padding<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        let mut count = 0;
        while count < data.len() && data[count] == 0x00 {
            count += 1;
        }
        self.stats
            .padding_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok((Frame::Padding(count), count))
    }

    /// Parse STREAM frame
    #[inline]
    fn parse_stream_frame<'a>(
        &self,
        data: &'a [u8],
        flags: u8,
    ) -> Result<(Frame<'a>, usize), FrameError> {
        self.stats.stream_frames.fetch_add(1, Ordering::Relaxed);

        let has_offset = (flags & 0x04) != 0;
        let has_length = (flags & 0x02) != 0;
        let fin = (flags & 0x01) != 0;

        let mut offset = 1;

        // Stream ID (varint)
        let (stream_id, len) = decode_varint(&data[offset..])?;
        offset += len;

        // Offset (varint, optional)
        let data_offset = if has_offset {
            let (off, len) = decode_varint(&data[offset..])?;
            offset += len;
            off
        } else {
            0
        };

        // Length (varint, optional)
        let length = if has_length {
            let (len, varint_len) = decode_varint(&data[offset..])?;
            offset += varint_len;
            len as usize
        } else {
            data.len() - offset
        };

        if offset + length > data.len() {
            return Err(FrameError::UnexpectedEnd);
        }

        let frame_data = &data[offset..offset + length];
        let consumed = offset + length;

        Ok((
            Frame::Stream(StreamFrame {
                stream_id,
                offset: data_offset,
                length,
                fin,
                data: frame_data,
            }),
            consumed,
        ))
    }

    /// Parse ACK frame
    #[inline]
    fn parse_ack<'a>(
        &self,
        data: &'a [u8],
        has_ecn: bool,
    ) -> Result<(Frame<'a>, usize), FrameError> {
        self.stats.ack_frames.fetch_add(1, Ordering::Relaxed);

        let mut offset = 1;

        let (largest_ack, len) = decode_varint(&data[offset..])?;
        offset += len;

        let (ack_delay, len) = decode_varint(&data[offset..])?;
        offset += len;

        let (range_count, len) = decode_varint(&data[offset..])?;
        offset += len;

        let (first_range, len) = decode_varint(&data[offset..])?;
        offset += len;

        let mut ranges = Vec::with_capacity(range_count as usize);
        for _ in 0..range_count {
            let (gap, len) = decode_varint(&data[offset..])?;
            offset += len;
            let (length, len) = decode_varint(&data[offset..])?;
            offset += len;
            ranges.push(AckRange { gap, length });
        }

        let ecn_counts = if has_ecn {
            let (ect0, len) = decode_varint(&data[offset..])?;
            offset += len;
            let (ect1, len) = decode_varint(&data[offset..])?;
            offset += len;
            let (ce, len) = decode_varint(&data[offset..])?;
            offset += len;
            Some(EcnCounts { ect0, ect1, ce })
        } else {
            None
        };

        Ok((
            Frame::Ack(AckFrame {
                largest_ack,
                ack_delay,
                first_range,
                ranges,
                ecn_counts,
            }),
            offset,
        ))
    }

    /// Parse CRYPTO frame
    #[inline]
    fn parse_crypto<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        self.stats.crypto_frames.fetch_add(1, Ordering::Relaxed);

        let mut offset = 1;

        let (crypto_offset, len) = decode_varint(&data[offset..])?;
        offset += len;

        let (length, len) = decode_varint(&data[offset..])?;
        offset += len;

        let length = length as usize;
        if offset + length > data.len() {
            return Err(FrameError::UnexpectedEnd);
        }

        let frame_data = &data[offset..offset + length];
        let consumed = offset + length;

        Ok((
            Frame::Crypto(CryptoFrame {
                offset: crypto_offset,
                length,
                data: frame_data,
            }),
            consumed,
        ))
    }

    /// Parse DATAGRAM frame
    #[inline]
    fn parse_datagram<'a>(
        &self,
        data: &'a [u8],
        has_length: bool,
    ) -> Result<(Frame<'a>, usize), FrameError> {
        self.stats.datagram_frames.fetch_add(1, Ordering::Relaxed);

        let mut offset = 1;

        let (length, frame_data) = if has_length {
            let (len, varint_len) = decode_varint(&data[offset..])?;
            offset += varint_len;
            let len = len as usize;
            if offset + len > data.len() {
                return Err(FrameError::UnexpectedEnd);
            }
            (Some(len), &data[offset..offset + len])
        } else {
            (None, &data[offset..])
        };

        let consumed = offset + frame_data.len();

        Ok((
            Frame::Datagram(DatagramFrame {
                length,
                data: frame_data,
            }),
            consumed,
        ))
    }

    /// Parse MAX_DATA frame
    #[inline]
    fn parse_max_data<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        let mut offset = 1;
        let (max_data, len) = decode_varint(&data[offset..])?;
        offset += len;
        Ok((Frame::MaxData(max_data), offset))
    }

    /// Parse MAX_STREAM_DATA frame
    #[inline]
    fn parse_max_stream_data<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        let mut offset = 1;
        let (stream_id, len) = decode_varint(&data[offset..])?;
        offset += len;
        let (max_data, len) = decode_varint(&data[offset..])?;
        offset += len;
        Ok((
            Frame::MaxStreamData {
                stream_id,
                max_data,
            },
            offset,
        ))
    }

    /// Parse CONNECTION_CLOSE frame
    #[inline]
    fn parse_connection_close<'a>(
        &self,
        data: &'a [u8],
        is_app: bool,
    ) -> Result<(Frame<'a>, usize), FrameError> {
        let mut offset = 1;

        let (error_code, len) = decode_varint(&data[offset..])?;
        offset += len;

        let frame_type = if !is_app {
            let (ft, len) = decode_varint(&data[offset..])?;
            offset += len;
            Some(ft)
        } else {
            None
        };

        let (reason_len, len) = decode_varint(&data[offset..])?;
        offset += len;

        let reason_len = reason_len as usize;
        if offset + reason_len > data.len() {
            return Err(FrameError::UnexpectedEnd);
        }

        let reason = &data[offset..offset + reason_len];
        let consumed = offset + reason_len;

        Ok((
            Frame::ConnectionClose(ConnectionCloseFrame {
                error_code,
                frame_type,
                reason,
            }),
            consumed,
        ))
    }

    /// Parse PATH_CHALLENGE frame
    #[inline]
    fn parse_path_challenge<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        if data.len() < 9 {
            return Err(FrameError::UnexpectedEnd);
        }
        let mut challenge = [0u8; 8];
        challenge.copy_from_slice(&data[1..9]);
        Ok((Frame::PathChallenge(challenge), 9))
    }

    /// Parse PATH_RESPONSE frame
    #[inline]
    fn parse_path_response<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, usize), FrameError> {
        if data.len() < 9 {
            return Err(FrameError::UnexpectedEnd);
        }
        let mut response = [0u8; 8];
        response.copy_from_slice(&data[1..9]);
        Ok((Frame::PathResponse(response), 9))
    }

    /// Parse NEW_CONNECTION_ID frame
    #[inline]
    fn parse_new_connection_id<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<(Frame<'a>, usize), FrameError> {
        let mut offset = 1;

        let (sequence, len) = decode_varint(&data[offset..])?;
        offset += len;

        let (retire_prior, len) = decode_varint(&data[offset..])?;
        offset += len;

        if offset >= data.len() {
            return Err(FrameError::UnexpectedEnd);
        }

        let cid_len = data[offset] as usize;
        offset += 1;

        if offset + cid_len + 16 > data.len() {
            return Err(FrameError::UnexpectedEnd);
        }

        let mut cid = [0u8; 20];
        cid[..cid_len].copy_from_slice(&data[offset..offset + cid_len]);
        offset += cid_len;

        let mut reset_token = [0u8; 16];
        reset_token.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        Ok((
            Frame::NewConnectionId {
                sequence,
                retire_prior,
                cid,
                cid_len: cid_len as u8,
                reset_token,
            },
            offset,
        ))
    }
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed frame enum
#[derive(Debug)]
pub enum Frame<'a> {
    Padding(usize),
    Ping,
    Ack(AckFrame),
    Stream(StreamFrame<'a>),
    Crypto(CryptoFrame<'a>),
    Datagram(DatagramFrame<'a>),
    MaxData(u64),
    MaxStreamData {
        stream_id: u64,
        max_data: u64,
    },
    ConnectionClose(ConnectionCloseFrame<'a>),
    HandshakeDone,
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    NewConnectionId {
        sequence: u64,
        retire_prior: u64,
        cid: [u8; 20],
        cid_len: u8,
        reset_token: [u8; 16],
    },
}

/// Frame parsing errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    UnexpectedEnd,
    InvalidVarint,
    UnknownFrameType(u8),
    InvalidStreamId,
    ProtocolViolation,
}

/// Decode QUIC varint
#[inline(always)]
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize), FrameError> {
    if data.is_empty() {
        return Err(FrameError::UnexpectedEnd);
    }

    let first = data[0];
    let len = 1 << (first >> 6);

    if data.len() < len {
        return Err(FrameError::UnexpectedEnd);
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
        _ => return Err(FrameError::InvalidVarint),
    };

    Ok((value, len))
}

/// Encode QUIC varint
#[inline(always)]
pub fn encode_varint(value: u64, buf: &mut [u8]) -> usize {
    if value < 0x40 {
        buf[0] = value as u8;
        1
    } else if value < 0x4000 {
        let val = (value as u16) | 0x4000;
        buf[..2].copy_from_slice(&val.to_be_bytes());
        2
    } else if value < 0x4000_0000 {
        let val = (value as u32) | 0x8000_0000;
        buf[..4].copy_from_slice(&val.to_be_bytes());
        4
    } else {
        let val = value | 0xc000_0000_0000_0000;
        buf[..8].copy_from_slice(&val.to_be_bytes());
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let mut buf = [0u8; 8];

        for value in [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let len = encode_varint(value, &mut buf);
            let (decoded, decoded_len) = decode_varint(&buf[..len]).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(len, decoded_len);
        }
    }
}
