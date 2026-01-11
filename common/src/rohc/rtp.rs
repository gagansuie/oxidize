//! RTP Profile for ROHC (RFC 3095)
//!
//! Provides maximum compression for VoIP/gaming traffic:
//! - 40-byte IP/UDP/RTP header → 1-3 bytes (97% reduction)
//! - Optimized for periodic traffic patterns
//! - Timestamp stride detection for predictable codecs

use super::encoding::WlsbEncoder;

/// RTP header fields for compression context
#[derive(Debug, Clone)]
pub struct RtpContext {
    /// SSRC (Synchronization Source) - static field
    pub ssrc: u32,
    /// Payload type - usually static
    pub payload_type: u8,
    /// Last sequence number
    pub last_seq: u16,
    /// Last timestamp
    pub last_timestamp: u32,
    /// Timestamp stride (delta between packets, e.g., 160 for G.711 @ 20ms)
    pub ts_stride: u32,
    /// Whether ts_stride is established
    pub ts_stride_established: bool,
    /// Marker bit from last packet
    pub last_marker: bool,
    /// W-LSB encoder for sequence number
    pub seq_encoder: WlsbEncoder,
    /// W-LSB encoder for timestamp
    pub ts_encoder: WlsbEncoder,
    /// Packets processed
    pub packet_count: u32,
}

impl Default for RtpContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpContext {
    pub fn new() -> Self {
        Self {
            ssrc: 0,
            payload_type: 0,
            last_seq: 0,
            last_timestamp: 0,
            ts_stride: 0,
            ts_stride_established: false,
            last_marker: false,
            seq_encoder: WlsbEncoder::new(0),
            ts_encoder: WlsbEncoder::new(-1),
            packet_count: 0,
        }
    }

    /// Initialize context from first RTP packet
    pub fn init_from_packet(&mut self, rtp_header: &[u8]) -> bool {
        if rtp_header.len() < 12 {
            return false;
        }

        // RTP header: V(2) P(1) X(1) CC(4) M(1) PT(7) SEQ(16) TS(32) SSRC(32)
        let version = (rtp_header[0] >> 6) & 0x03;
        if version != 2 {
            return false;
        }

        self.payload_type = rtp_header[1] & 0x7F;
        self.last_marker = (rtp_header[1] & 0x80) != 0;
        self.last_seq = u16::from_be_bytes([rtp_header[2], rtp_header[3]]);
        self.last_timestamp =
            u32::from_be_bytes([rtp_header[4], rtp_header[5], rtp_header[6], rtp_header[7]]);
        self.ssrc =
            u32::from_be_bytes([rtp_header[8], rtp_header[9], rtp_header[10], rtp_header[11]]);

        self.seq_encoder = WlsbEncoder::new(0);
        self.seq_encoder.encode(self.last_seq as u32);

        self.ts_encoder = WlsbEncoder::new(-1);
        self.ts_encoder.encode(self.last_timestamp);

        self.packet_count = 1;
        true
    }

    /// Update context with new packet, returns compression info
    pub fn update(&mut self, rtp_header: &[u8]) -> Option<RtpDelta> {
        if rtp_header.len() < 12 {
            return None;
        }

        let marker = (rtp_header[1] & 0x80) != 0;
        let seq = u16::from_be_bytes([rtp_header[2], rtp_header[3]]);
        let timestamp =
            u32::from_be_bytes([rtp_header[4], rtp_header[5], rtp_header[6], rtp_header[7]]);

        // Calculate deltas
        let seq_delta = seq.wrapping_sub(self.last_seq);
        let ts_delta = timestamp.wrapping_sub(self.last_timestamp);

        // Detect timestamp stride
        if !self.ts_stride_established && self.packet_count > 0 {
            if self.ts_stride == 0 {
                self.ts_stride = ts_delta;
            } else if self.ts_stride == ts_delta {
                // Consistent stride - establish it
                self.ts_stride_established = true;
            } else {
                // Reset stride detection
                self.ts_stride = ts_delta;
            }
        }

        // Check if we can use scaled timestamp mode
        let ts_scaled = if self.ts_stride_established && self.ts_stride > 0 {
            Some((ts_delta / self.ts_stride) as u8)
        } else {
            None
        };

        let delta = RtpDelta {
            seq_delta,
            ts_delta,
            ts_scaled,
            marker_changed: marker != self.last_marker,
            marker,
        };

        // Update context
        self.last_seq = seq;
        self.last_timestamp = timestamp;
        self.last_marker = marker;
        self.seq_encoder.encode(seq as u32);
        self.ts_encoder.encode(timestamp);
        self.packet_count += 1;

        Some(delta)
    }

    /// Get compressed header size estimate
    pub fn compressed_size(&self, delta: &RtpDelta) -> usize {
        if delta.seq_delta == 1 && delta.ts_scaled == Some(1) && !delta.marker_changed {
            // UO-0: 1 byte (most common case)
            1
        } else if delta.seq_delta <= 15 && delta.ts_scaled.is_some() {
            // UO-1: 2 bytes
            2
        } else {
            // UO-2 or IR-DYN: 3+ bytes
            3
        }
    }
}

/// Delta information between RTP packets
#[derive(Debug, Clone)]
pub struct RtpDelta {
    /// Sequence number delta (usually 1)
    pub seq_delta: u16,
    /// Timestamp delta (raw)
    pub ts_delta: u32,
    /// Scaled timestamp (if stride is established)
    pub ts_scaled: Option<u8>,
    /// Whether marker bit changed
    pub marker_changed: bool,
    /// Current marker bit value
    pub marker: bool,
}

/// Common RTP payload types and their timestamp strides
#[derive(Debug, Clone, Copy)]
pub enum RtpCodec {
    /// G.711 μ-law (8kHz, 20ms frames → stride 160)
    Pcmu,
    /// G.711 A-law
    Pcma,
    /// G.729 (8kHz, 10ms frames → stride 80)
    G729,
    /// Opus (48kHz, 20ms frames → stride 960)
    Opus,
    /// Unknown codec
    Unknown,
}

impl RtpCodec {
    /// Detect codec from payload type
    pub fn from_payload_type(pt: u8) -> Self {
        match pt {
            0 => RtpCodec::Pcmu,
            8 => RtpCodec::Pcma,
            18 => RtpCodec::G729,
            111 => RtpCodec::Opus, // Common dynamic PT for Opus
            _ => RtpCodec::Unknown,
        }
    }

    /// Get expected timestamp stride
    pub fn expected_stride(&self) -> Option<u32> {
        match self {
            RtpCodec::Pcmu | RtpCodec::Pcma => Some(160), // 20ms @ 8kHz
            RtpCodec::G729 => Some(80),                   // 10ms @ 8kHz
            RtpCodec::Opus => Some(960),                  // 20ms @ 48kHz
            RtpCodec::Unknown => None,
        }
    }
}

/// RTP packet type identifiers for compressed packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpPacketType {
    /// IR packet - full header + profile info
    Ir,
    /// IR-DYN - dynamic chain only
    IrDyn,
    /// UO-0 - 1 byte, SN only
    Uo0,
    /// UO-1 - 2 bytes, SN + TS
    Uo1,
    /// UO-2 - 3+ bytes, extension
    Uo2,
}

impl RtpPacketType {
    /// Encode packet type discriminator
    pub fn discriminator(&self) -> u8 {
        match self {
            RtpPacketType::Ir => 0xFC,    // 1111110x
            RtpPacketType::IrDyn => 0xF8, // 11111000
            RtpPacketType::Uo0 => 0x00,   // 0xxxxxxx
            RtpPacketType::Uo1 => 0x80,   // 10xxxxxx
            RtpPacketType::Uo2 => 0xC0,   // 110xxxxx
        }
    }
}

/// Compress an RTP header using established context
pub fn compress_rtp(
    ctx: &mut RtpContext,
    ip_udp_rtp: &[u8],
    output: &mut Vec<u8>,
) -> Option<usize> {
    // Minimum: IP(20) + UDP(8) + RTP(12) = 40 bytes
    if ip_udp_rtp.len() < 40 {
        return None;
    }

    let ip_header_len = ((ip_udp_rtp[0] & 0x0F) * 4) as usize;
    let rtp_offset = ip_header_len + 8; // IP + UDP

    if ip_udp_rtp.len() < rtp_offset + 12 {
        return None;
    }

    let rtp_header = &ip_udp_rtp[rtp_offset..rtp_offset + 12];

    // First packet - initialize and send IR
    if ctx.packet_count == 0 {
        ctx.init_from_packet(rtp_header);
        // Send IR packet (simplified - just send original for now)
        output.push(RtpPacketType::Ir.discriminator());
        output.push(ctx.ssrc as u8); // CID
        output.extend_from_slice(ip_udp_rtp);
        return Some(output.len());
    }

    // Get delta
    let delta = ctx.update(rtp_header)?;

    // Choose packet type based on delta
    let original_len = output.len();

    if delta.seq_delta == 1 && delta.ts_scaled == Some(1) && !delta.marker_changed {
        // UO-0: Most efficient (1 byte)
        // Format: 0 + SN(4 bits) + CRC(3 bits)
        let sn_4 = (ctx.last_seq & 0x0F) as u8;
        output.push(sn_4); // CRC would be computed here
    } else if delta.seq_delta <= 15 && delta.ts_scaled.is_some() {
        // UO-1: 2 bytes
        // Format: 10 + TS(5) + M + SN(4) + CRC(3)
        let ts_5 = (delta.ts_scaled.unwrap_or(0) & 0x1F) as u8;
        let m = if delta.marker { 1 } else { 0 };
        let sn_4 = (ctx.last_seq & 0x0F) as u8;
        output.push(0x80 | ts_5);
        output.push((m << 7) | (sn_4 << 3)); // + CRC
    } else {
        // UO-2: 3+ bytes for larger deltas
        output.push(0xC0); // UO-2 discriminator
        output.extend_from_slice(&(ctx.last_seq).to_be_bytes());
        // More fields would go here
    }

    // Append RTP payload (after RTP header)
    let payload_start = rtp_offset + 12;
    if ip_udp_rtp.len() > payload_start {
        output.extend_from_slice(&ip_udp_rtp[payload_start..]);
    }

    Some(output.len() - original_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_context_init() {
        let mut ctx = RtpContext::new();

        // Minimal RTP header: V=2, PT=0, Seq=1, TS=160, SSRC=12345
        let rtp = [
            0x80, 0x00, // V=2, P=0, X=0, CC=0, M=0, PT=0
            0x00, 0x01, // Seq=1
            0x00, 0x00, 0x00, 0xA0, // TS=160
            0x00, 0x00, 0x30, 0x39, // SSRC=12345
        ];

        assert!(ctx.init_from_packet(&rtp));
        assert_eq!(ctx.last_seq, 1);
        assert_eq!(ctx.last_timestamp, 160);
        assert_eq!(ctx.ssrc, 12345);
    }

    #[test]
    fn test_stride_detection() {
        let mut ctx = RtpContext::new();

        // First packet
        let rtp1 = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, // TS=160
            0x00, 0x00, 0x30, 0x39,
        ];
        ctx.init_from_packet(&rtp1);

        // Second packet with stride 160
        let rtp2 = [
            0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x40, // TS=320
            0x00, 0x00, 0x30, 0x39,
        ];
        ctx.update(&rtp2);

        // Third packet confirms stride
        let rtp3 = [
            0x80, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01, 0xE0, // TS=480
            0x00, 0x00, 0x30, 0x39,
        ];
        ctx.update(&rtp3);

        assert!(ctx.ts_stride_established);
        assert_eq!(ctx.ts_stride, 160);
    }

    #[test]
    fn test_codec_detection() {
        assert!(matches!(RtpCodec::from_payload_type(0), RtpCodec::Pcmu));
        assert_eq!(RtpCodec::Pcmu.expected_stride(), Some(160));
    }
}
