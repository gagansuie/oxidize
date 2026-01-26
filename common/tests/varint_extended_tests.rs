//! Extended tests for varint_header module

use oxidize_common::varint_header::{
    decode_length, decode_varint32, encode_length, encode_varint32, varint_size, BatchHeader,
    HeaderStats, PacketType, V2Header,
};

// ============================================================================
// Varint Encoding Tests
// ============================================================================

#[test]
fn test_encode_varint32_zero() {
    let mut buf = [0u8; 5];
    let len = encode_varint32(0, &mut buf);
    assert_eq!(len, 1);
    assert_eq!(buf[0], 0);
}

#[test]
fn test_encode_varint32_one_byte_max() {
    let mut buf = [0u8; 5];
    let len = encode_varint32(127, &mut buf);
    assert_eq!(len, 1);
    assert_eq!(buf[0], 127);
}

#[test]
fn test_encode_varint32_two_bytes() {
    let mut buf = [0u8; 5];
    let len = encode_varint32(128, &mut buf);
    assert_eq!(len, 2);

    let (val, consumed) = decode_varint32(&buf).unwrap();
    assert_eq!(val, 128);
    assert_eq!(consumed, 2);
}

#[test]
fn test_encode_varint32_three_bytes() {
    let mut buf = [0u8; 5];
    let len = encode_varint32(16384, &mut buf);
    assert_eq!(len, 3);

    let (val, consumed) = decode_varint32(&buf).unwrap();
    assert_eq!(val, 16384);
    assert_eq!(consumed, 3);
}

#[test]
fn test_encode_varint32_max() {
    let mut buf = [0u8; 5];
    let len = encode_varint32(u32::MAX, &mut buf);
    assert_eq!(len, 5);

    let (val, consumed) = decode_varint32(&buf).unwrap();
    assert_eq!(val, u32::MAX);
    assert_eq!(consumed, 5);
}

#[test]
fn test_decode_varint32_empty() {
    let buf: [u8; 0] = [];
    let result = decode_varint32(&buf);
    assert!(result.is_err());
}

#[test]
fn test_decode_varint32_incomplete() {
    // Byte with continuation bit set but no more bytes
    let buf = [0x80];
    let result = decode_varint32(&buf);
    assert!(result.is_err());
}

#[test]
fn test_varint_roundtrip() {
    let values = [0u32, 1, 127, 128, 255, 16383, 16384, 2097151, 2097152, u32::MAX];

    for &val in &values {
        let mut buf = [0u8; 5];
        let encoded_len = encode_varint32(val, &mut buf);
        let (decoded, decoded_len) = decode_varint32(&buf).unwrap();
        assert_eq!(val, decoded);
        assert_eq!(encoded_len, decoded_len);
    }
}

// ============================================================================
// Length Encoding Tests
// ============================================================================

#[test]
fn test_encode_length_small() {
    let mut buf = [0u8; 2];
    let len = encode_length(100, &mut buf);
    assert_eq!(len, 1);
    assert_eq!(buf[0], 100);
}

#[test]
fn test_encode_length_boundary() {
    let mut buf = [0u8; 2];
    let len = encode_length(127, &mut buf);
    assert_eq!(len, 1);
    assert_eq!(buf[0], 127);
}

#[test]
fn test_encode_length_large() {
    let mut buf = [0u8; 2];
    let len = encode_length(1000, &mut buf);
    assert_eq!(len, 2);

    let (val, decoded_len) = decode_length(&buf).unwrap();
    assert_eq!(val, 1000);
    assert_eq!(decoded_len, 2);
}

#[test]
fn test_decode_length_empty() {
    let buf: [u8; 0] = [];
    let result = decode_length(&buf);
    assert!(result.is_err());
}

#[test]
fn test_decode_length_incomplete_two_byte() {
    // MSB set but only one byte
    let buf = [0x80];
    let result = decode_length(&buf);
    assert!(result.is_err());
}

#[test]
fn test_length_roundtrip() {
    let values = [0u16, 1, 100, 127, 128, 1000, 10000, 32767];

    for &val in &values {
        let mut buf = [0u8; 2];
        let encoded_len = encode_length(val, &mut buf);
        let (decoded, decoded_len) = decode_length(&buf).unwrap();
        assert_eq!(val, decoded);
        assert_eq!(encoded_len, decoded_len);
    }
}

// ============================================================================
// varint_size Tests
// ============================================================================

#[test]
fn test_varint_size_one_byte() {
    assert_eq!(varint_size(0), 1);
    assert_eq!(varint_size(1), 1);
    assert_eq!(varint_size(127), 1);
}

#[test]
fn test_varint_size_two_bytes() {
    assert_eq!(varint_size(128), 2);
    assert_eq!(varint_size(16383), 2);
}

#[test]
fn test_varint_size_three_bytes() {
    assert_eq!(varint_size(16384), 3);
    assert_eq!(varint_size(2097151), 3);
}

#[test]
fn test_varint_size_four_bytes() {
    assert_eq!(varint_size(2097152), 4);
    assert_eq!(varint_size(268435455), 4);
}

#[test]
fn test_varint_size_five_bytes() {
    assert_eq!(varint_size(268435456), 5);
    assert_eq!(varint_size(u32::MAX), 5);
}

// ============================================================================
// PacketType Tests
// ============================================================================

#[test]
fn test_packet_type_values() {
    assert_eq!(PacketType::Data as u8, 0);
    assert_eq!(PacketType::Ack as u8, 1);
    assert_eq!(PacketType::Control as u8, 2);
    assert_eq!(PacketType::Batch as u8, 3);
    assert_eq!(PacketType::Keepalive as u8, 4);
    assert_eq!(PacketType::Handshake as u8, 5);
    assert_eq!(PacketType::KeyRotation as u8, 6);
    assert_eq!(PacketType::Disconnect as u8, 7);
}

// ============================================================================
// V2Header Tests
// ============================================================================

#[test]
fn test_v2_header_data() {
    let header = V2Header::data(100, true, false);
    assert_eq!(header.packet_type, PacketType::Data);
    assert_eq!(header.seq_num, 100);
    assert!(header.encrypted);
    assert!(!header.compressed);
    assert!(!header.has_length);
    assert!(!header.ipv6);
}

#[test]
fn test_v2_header_with_length() {
    let header = V2Header::data(50, false, true).with_length(1000);
    assert!(header.has_length);
    assert_eq!(header.length, Some(1000));
}

#[test]
fn test_v2_header_encode_decode_minimal() {
    let header = V2Header::data(10, false, false);
    let mut buf = [0u8; 16];

    let encoded_len = header.encode(&mut buf).unwrap();
    let (decoded, decoded_len) = V2Header::decode(&buf).unwrap();

    assert_eq!(encoded_len, decoded_len);
    assert_eq!(decoded.packet_type, PacketType::Data);
    assert_eq!(decoded.seq_num, 10);
    assert!(!decoded.encrypted);
    assert!(!decoded.compressed);
}

#[test]
fn test_v2_header_encode_decode_full() {
    let header = V2Header {
        packet_type: PacketType::Data,
        has_length: true,
        encrypted: true,
        compressed: true,
        ipv6: true,
        seq_num: 1000,
        length: Some(500),
    };

    let mut buf = [0u8; 16];
    let encoded_len = header.encode(&mut buf).unwrap();
    let (decoded, decoded_len) = V2Header::decode(&buf).unwrap();

    assert_eq!(encoded_len, decoded_len);
    assert_eq!(decoded.packet_type, PacketType::Data);
    assert!(decoded.has_length);
    assert!(decoded.encrypted);
    assert!(decoded.compressed);
    assert!(decoded.ipv6);
    assert_eq!(decoded.seq_num, 1000);
    assert_eq!(decoded.length, Some(500));
}

#[test]
fn test_v2_header_encode_buffer_too_small() {
    let header = V2Header::data(100, false, false);
    let mut buf = [0u8; 0];

    let result = header.encode(&mut buf);
    assert!(result.is_err());
}

#[test]
fn test_v2_header_decode_empty() {
    let buf: [u8; 0] = [];
    let result = V2Header::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn test_v2_header_encoded_size() {
    let header_small = V2Header::data(10, false, false);
    assert_eq!(header_small.encoded_size(), 2); // 1 + 1

    let header_large = V2Header::data(1_000_000, false, false);
    assert_eq!(header_large.encoded_size(), 4); // 1 + 3

    let header_with_length = V2Header::data(10, false, false).with_length(1000);
    assert_eq!(header_with_length.encoded_size(), 4); // 1 + 1 + 2
}

// ============================================================================
// BatchHeader Tests
// ============================================================================

#[test]
fn test_batch_header_new() {
    let header = BatchHeader::new(100, 5);
    assert_eq!(header.seq_base, 100);
    assert_eq!(header.packet_count, 5);
    assert!(!header.encrypted);
    assert!(!header.compressed);
}

#[test]
fn test_batch_header_encode_decode() {
    let mut header = BatchHeader::new(500, 10);
    header.encrypted = true;

    let mut buf = [0u8; 16];
    let encoded_len = header.encode(&mut buf).unwrap();
    let (decoded, decoded_len) = BatchHeader::decode(&buf).unwrap();

    assert_eq!(encoded_len, decoded_len);
    assert_eq!(decoded.seq_base, 500);
    assert_eq!(decoded.packet_count, 10);
    assert!(decoded.encrypted);
    assert!(!decoded.compressed);
}

#[test]
fn test_batch_header_encode_buffer_too_small() {
    let header = BatchHeader::new(100, 5);
    let mut buf = [0u8; 2];

    let result = header.encode(&mut buf);
    assert!(result.is_err());
}

#[test]
fn test_batch_header_decode_buffer_too_small() {
    let buf = [0u8; 2];
    let result = BatchHeader::decode(&buf);
    assert!(result.is_err());
}

// ============================================================================
// HeaderStats Tests
// ============================================================================

#[test]
fn test_header_stats_default() {
    let stats = HeaderStats::default();
    assert_eq!(stats.total_headers, 0);
    assert_eq!(stats.total_bytes_v1, 0);
    assert_eq!(stats.total_bytes_v2, 0);
}

#[test]
fn test_header_stats_record() {
    let mut stats = HeaderStats::default();

    stats.record(3);
    stats.record(4);

    assert_eq!(stats.total_headers, 2);
    assert_eq!(stats.total_bytes_v1, 18); // 2 * 9
    assert_eq!(stats.total_bytes_v2, 7); // 3 + 4
}

#[test]
fn test_header_stats_savings_percent() {
    let mut stats = HeaderStats::default();

    // Record 10 headers with V2 size of 4 bytes each
    for _ in 0..10 {
        stats.record(4);
    }

    // V1: 90 bytes, V2: 40 bytes = ~55.5% savings
    let savings = stats.savings_percent();
    assert!((savings - 55.5).abs() < 1.0);
}

#[test]
fn test_header_stats_savings_percent_empty() {
    let stats = HeaderStats::default();
    assert_eq!(stats.savings_percent(), 0.0);
}

#[test]
fn test_header_stats_avg_header_size() {
    let mut stats = HeaderStats::default();

    stats.record(2);
    stats.record(4);
    stats.record(6);

    assert_eq!(stats.avg_header_size(), 4.0);
}

#[test]
fn test_header_stats_avg_header_size_empty() {
    let stats = HeaderStats::default();
    assert_eq!(stats.avg_header_size(), 0.0);
}
