//! Tests for deep_packet_inspection module

use oxidize_common::deep_packet_inspection::{DeepPacketInspector, IdentifiedApp, TrafficClass};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;

// ============================================================================
// IdentifiedApp Tests
// ============================================================================

#[test]
fn test_identified_app_traffic_class_gaming() {
    assert_eq!(IdentifiedApp::Valorant.traffic_class(), TrafficClass::Gaming);
    assert_eq!(IdentifiedApp::CSGO.traffic_class(), TrafficClass::Gaming);
    assert_eq!(
        IdentifiedApp::ApexLegends.traffic_class(),
        TrafficClass::Gaming
    );
    assert_eq!(IdentifiedApp::Fortnite.traffic_class(), TrafficClass::Gaming);
    assert_eq!(
        IdentifiedApp::LeagueOfLegends.traffic_class(),
        TrafficClass::Gaming
    );
    assert_eq!(
        IdentifiedApp::Minecraft.traffic_class(),
        TrafficClass::Gaming
    );
    assert_eq!(IdentifiedApp::Roblox.traffic_class(), TrafficClass::Gaming);
    assert_eq!(
        IdentifiedApp::GenericGame.traffic_class(),
        TrafficClass::Gaming
    );
}

#[test]
fn test_identified_app_traffic_class_voip() {
    assert_eq!(IdentifiedApp::Discord.traffic_class(), TrafficClass::VoIP);
    assert_eq!(IdentifiedApp::Zoom.traffic_class(), TrafficClass::VoIP);
    assert_eq!(IdentifiedApp::Teams.traffic_class(), TrafficClass::VoIP);
    assert_eq!(IdentifiedApp::Slack.traffic_class(), TrafficClass::VoIP);
    assert_eq!(IdentifiedApp::Telegram.traffic_class(), TrafficClass::VoIP);
    assert_eq!(IdentifiedApp::WhatsApp.traffic_class(), TrafficClass::VoIP);
    assert_eq!(
        IdentifiedApp::GenericVoIP.traffic_class(),
        TrafficClass::VoIP
    );
}

#[test]
fn test_identified_app_traffic_class_streaming() {
    assert_eq!(
        IdentifiedApp::YouTube.traffic_class(),
        TrafficClass::Streaming
    );
    assert_eq!(
        IdentifiedApp::Netflix.traffic_class(),
        TrafficClass::Streaming
    );
    assert_eq!(
        IdentifiedApp::Twitch.traffic_class(),
        TrafficClass::Streaming
    );
    assert_eq!(
        IdentifiedApp::Spotify.traffic_class(),
        TrafficClass::Streaming
    );
    assert_eq!(
        IdentifiedApp::GenericStreaming.traffic_class(),
        TrafficClass::Streaming
    );
}

#[test]
fn test_identified_app_traffic_class_other() {
    assert_eq!(
        IdentifiedApp::WebBrowsing.traffic_class(),
        TrafficClass::Interactive
    );
    assert_eq!(
        IdentifiedApp::FileTransfer.traffic_class(),
        TrafficClass::Bulk
    );
    assert_eq!(
        IdentifiedApp::Unknown.traffic_class(),
        TrafficClass::Normal
    );
}

// ============================================================================
// DeepPacketInspector Tests
// ============================================================================

fn test_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
}

fn dest_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

#[test]
fn test_dpi_new() {
    let dpi = DeepPacketInspector::new();
    assert_eq!(dpi.stats.packets_inspected.load(Ordering::Relaxed), 0);
    assert_eq!(dpi.stats.flows_identified.load(Ordering::Relaxed), 0);
}

#[test]
fn test_dpi_default() {
    let dpi = DeepPacketInspector::default();
    assert_eq!(dpi.stats.packets_inspected.load(Ordering::Relaxed), 0);
}

#[test]
fn test_dpi_inspect_discord() {
    let dpi = DeepPacketInspector::new();

    // Discord uses ports 50000-50005 with DTLS prefix
    let payload = vec![0x16, 0xfe, 0x00, 0x00, 0x00]; // DTLS prefix
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 50000, &payload, 100);

    assert_eq!(app, IdentifiedApp::Discord);
    assert_eq!(dpi.stats.packets_inspected.load(Ordering::Relaxed), 1);
    assert_eq!(dpi.stats.flows_identified.load(Ordering::Relaxed), 1);
}

#[test]
fn test_dpi_inspect_zoom() {
    let dpi = DeepPacketInspector::new();

    // Zoom uses ports 8801-8805 with DTLS prefix
    let payload = vec![0x16, 0xfe, 0x01, 0x00, 0x00];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 8801, &payload, 200);

    assert_eq!(app, IdentifiedApp::Zoom);
}

#[test]
fn test_dpi_inspect_teams() {
    let dpi = DeepPacketInspector::new();

    // Teams uses ports 3478-3481
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 3478, &payload, 100);

    assert_eq!(app, IdentifiedApp::Teams);
}

#[test]
fn test_dpi_inspect_valorant() {
    let dpi = DeepPacketInspector::new();

    // Valorant uses ports 7000-7010
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 7005, &payload, 100);

    assert_eq!(app, IdentifiedApp::Valorant);
}

#[test]
fn test_dpi_inspect_fortnite() {
    let dpi = DeepPacketInspector::new();

    // Fortnite ports
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 9000, &payload, 100);

    assert_eq!(app, IdentifiedApp::Fortnite);
}

#[test]
fn test_dpi_inspect_csgo() {
    let dpi = DeepPacketInspector::new();

    // CS:GO/CS2 uses Source engine ports
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 27015, &payload, 100);

    assert_eq!(app, IdentifiedApp::CSGO);
}

#[test]
fn test_dpi_inspect_league() {
    let dpi = DeepPacketInspector::new();

    // League uses ports 5000-5009
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 5005, &payload, 100);

    assert_eq!(app, IdentifiedApp::LeagueOfLegends);
}

#[test]
fn test_dpi_inspect_minecraft() {
    let dpi = DeepPacketInspector::new();

    // Minecraft default port
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 25565, &payload, 100);

    assert_eq!(app, IdentifiedApp::Minecraft);
}

#[test]
fn test_dpi_inspect_generic_game_heuristic() {
    let dpi = DeepPacketInspector::new();

    // Xbox Live port should match heuristic
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 3074, &payload, 100);

    assert_eq!(app, IdentifiedApp::GenericGame);
}

#[test]
fn test_dpi_inspect_generic_voip_heuristic() {
    let dpi = DeepPacketInspector::new();

    // SIP port should match heuristic
    let payload = vec![0x00; 50];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 5060, &payload, 100);

    assert_eq!(app, IdentifiedApp::GenericVoIP);
}

#[test]
fn test_dpi_inspect_rtp_heuristic() {
    let dpi = DeepPacketInspector::new();

    // RTP-like payload (starts with 0x80)
    let payload = vec![0x80, 0x00, 0x00, 0x00];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 16384, &payload, 100);

    assert_eq!(app, IdentifiedApp::GenericVoIP);
}

#[test]
fn test_dpi_inspect_large_streaming_heuristic() {
    let dpi = DeepPacketInspector::new();

    // Large packet on unknown port
    let payload = vec![0x00; 100];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 12345, &payload, 1200);

    assert_eq!(app, IdentifiedApp::GenericStreaming);
}

#[test]
fn test_dpi_inspect_unknown() {
    let dpi = DeepPacketInspector::new();

    // Unknown traffic
    let payload = vec![0x00; 10];
    let app = dpi.inspect(test_ip(), 12345, dest_ip(), 54321, &payload, 50);

    assert_eq!(app, IdentifiedApp::Unknown);
}

#[test]
fn test_dpi_cache_hit() {
    let dpi = DeepPacketInspector::new();

    let payload = vec![0x16, 0xfe, 0x00];

    // First inspection - cache miss
    let app1 = dpi.inspect(test_ip(), 12345, dest_ip(), 50000, &payload, 100);
    assert_eq!(app1, IdentifiedApp::Discord);
    assert_eq!(dpi.stats.cache_misses.load(Ordering::Relaxed), 1);

    // Second inspection - cache hit
    let app2 = dpi.inspect(test_ip(), 12345, dest_ip(), 50000, &payload, 100);
    assert_eq!(app2, IdentifiedApp::Discord);
    assert_eq!(dpi.stats.cache_hits.load(Ordering::Relaxed), 1);
}

#[test]
fn test_dpi_stats() {
    let dpi = DeepPacketInspector::new();

    let payload = vec![0x00; 50];

    for i in 0..10 {
        let port = if i < 5 { 27015 } else { 54321 }; // 5 CS:GO, 5 unknown
        dpi.inspect(
            test_ip(),
            12345 + i,
            dest_ip(),
            port,
            &payload,
            100,
        );
    }

    assert_eq!(dpi.stats.packets_inspected.load(Ordering::Relaxed), 10);
    assert!(dpi.stats.flows_identified.load(Ordering::Relaxed) >= 5);
}

#[test]
fn test_dpi_cleanup_cache() {
    let dpi = DeepPacketInspector::new();

    let payload = vec![0x00; 50];
    dpi.inspect(test_ip(), 12345, dest_ip(), 27015, &payload, 100);

    // Cleanup should not panic
    dpi.cleanup_cache();
}

#[test]
fn test_traffic_class_eq() {
    assert_eq!(TrafficClass::Gaming, TrafficClass::Gaming);
    assert_ne!(TrafficClass::Gaming, TrafficClass::VoIP);
}

#[test]
fn test_identified_app_eq() {
    assert_eq!(IdentifiedApp::Discord, IdentifiedApp::Discord);
    assert_ne!(IdentifiedApp::Discord, IdentifiedApp::Zoom);
}
