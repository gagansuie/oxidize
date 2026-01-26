//! Tests for packet module: PacketInfo, PacketPriority, is_compressible

use oxidize_common::packet::{is_compressible, PacketInfo};
use oxidize_common::traffic_classifier::TrafficClass;

// ============================================================================
// PacketPriority Tests
// ============================================================================

#[test]
#[allow(deprecated)]
fn test_packet_priority_to_traffic_class() {
    use oxidize_common::packet::PacketPriority;

    assert_eq!(
        PacketPriority::Critical.to_traffic_class(),
        TrafficClass::Gaming
    );
    assert_eq!(
        PacketPriority::High.to_traffic_class(),
        TrafficClass::RealTime
    );
    assert_eq!(PacketPriority::Normal.to_traffic_class(), TrafficClass::Web);
    assert_eq!(PacketPriority::Low.to_traffic_class(), TrafficClass::Bulk);
}

// ============================================================================
// PacketInfo Tests
// ============================================================================

/// Create a valid IPv4 UDP packet
fn create_udp_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 64];
    let total_len: u16 = 64;
    let udp_len: u16 = 44; // 64 - 20

    // IPv4 header (20 bytes)
    packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&total_len.to_be_bytes()); // Total length
    packet[4..6].copy_from_slice(&[0x00, 0x01]); // ID
    packet[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment, no offset
    packet[8] = 64; // TTL
    packet[9] = 17; // Protocol = UDP
    packet[10..12].copy_from_slice(&[0x00, 0x00]); // Checksum (can be 0 for testing)
    packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]); // Dest IP

    // UDP header (8 bytes)
    packet[20..22].copy_from_slice(&src_port.to_be_bytes()); // Source port
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes()); // Dest port
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes()); // UDP length
    packet[26..28].copy_from_slice(&[0x00, 0x00]); // Checksum

    packet
}

/// Create a valid IPv4 TCP packet
fn create_tcp_packet(src_port: u16, dst_port: u16, size: usize) -> Vec<u8> {
    let mut packet = vec![0u8; size];
    let total_len = size as u16;

    // IPv4 header (20 bytes)
    packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&total_len.to_be_bytes()); // Total length
    packet[4..6].copy_from_slice(&[0x00, 0x01]); // ID
    packet[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment, no offset
    packet[8] = 64; // TTL
    packet[9] = 6; // Protocol = TCP
    packet[10..12].copy_from_slice(&[0x00, 0x00]); // Checksum
    packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]); // Dest IP

    // TCP header (20 bytes minimum)
    packet[20..22].copy_from_slice(&src_port.to_be_bytes()); // Source port
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes()); // Dest port
    packet[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Sequence number
    packet[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack number
    packet[32] = 0x50; // Data offset (5 words = 20 bytes), reserved
    packet[33] = 0x02; // Flags (SYN)
    packet[34..36].copy_from_slice(&[0xFF, 0xFF]); // Window size
    packet[36..38].copy_from_slice(&[0x00, 0x00]); // Checksum
    packet[38..40].copy_from_slice(&[0x00, 0x00]); // Urgent pointer

    packet
}

#[test]
fn test_packet_info_analyze_udp() {
    let packet = create_udp_packet(12345, 53);

    let info = PacketInfo::analyze(&packet).unwrap();
    assert_eq!(info.protocol, 17); // UDP
    assert_eq!(info.src_port, Some(12345));
    assert_eq!(info.dst_port, Some(53));
    assert_eq!(info.size, 64);
}

#[test]
fn test_packet_info_analyze_tcp() {
    let packet = create_tcp_packet(54321, 443, 64);

    let info = PacketInfo::analyze(&packet).unwrap();
    assert_eq!(info.protocol, 6); // TCP
    assert_eq!(info.src_port, Some(54321));
    assert_eq!(info.dst_port, Some(443));
}

#[test]
fn test_packet_info_analyze_gaming_port() {
    let packet = create_udp_packet(12345, 27015); // Source engine port

    let info = PacketInfo::analyze(&packet).unwrap();
    assert_eq!(info.traffic_class, TrafficClass::Gaming);
}

#[test]
fn test_packet_info_analyze_voip_port() {
    // Use RTP port which is clearly in VoIP range and not gaming
    let packet = create_udp_packet(12345, 16384); // RTP range start

    let info = PacketInfo::analyze(&packet).unwrap();
    assert_eq!(info.traffic_class, TrafficClass::RealTime);
}

#[test]
fn test_packet_info_analyze_invalid() {
    // Too short packet
    let packet = vec![0u8; 10];
    let info = PacketInfo::analyze(&packet).unwrap();
    assert_eq!(info.traffic_class, TrafficClass::Bulk);
}

// ============================================================================
// is_compressible Tests
// ============================================================================

#[test]
fn test_is_compressible_small_packet() {
    let small_packet = vec![0u8; 32];
    assert!(!is_compressible(&small_packet)); // Too small
}

#[test]
fn test_is_compressible_tcp_https() {
    // HTTPS packet should not be compressed (already encrypted)
    let packet = create_tcp_packet(12345, 443, 128);
    assert!(!is_compressible(&packet));
}

#[test]
fn test_is_compressible_tcp_ssh() {
    // SSH packet should not be compressed (already encrypted)
    let packet = create_tcp_packet(12345, 22, 128);
    assert!(!is_compressible(&packet));
}

#[test]
fn test_is_compressible_tcp_http() {
    // HTTP packet should be compressed
    let packet = create_tcp_packet(12345, 80, 128);
    assert!(is_compressible(&packet));
}

#[test]
fn test_is_compressible_udp() {
    // UDP packets are generally compressible
    let mut packet = create_udp_packet(12345, 8080);
    // Extend to 128 bytes for size threshold
    packet.resize(128, 0);
    // Update total length in header
    packet[2..4].copy_from_slice(&128u16.to_be_bytes());

    assert!(is_compressible(&packet));
}

#[test]
fn test_is_compressible_invalid_packet() {
    // Invalid packet data should return true (fail-safe)
    let garbage = vec![0xFF; 128];
    assert!(is_compressible(&garbage));
}
