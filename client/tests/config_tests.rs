//! Tests for client config module

use relay_client::config::ClientConfig;

#[test]
fn test_client_config_default() {
    let config = ClientConfig::default();

    assert!(config.enable_compression);
    assert_eq!(config.compression_threshold, 512);
    assert_eq!(config.buffer_size, 65536);
    assert_eq!(config.keepalive_interval, 30);
    assert_eq!(config.reconnect_interval, 5);
    assert!(config.enable_dns_prefetch);
    assert_eq!(config.dns_cache_size, 1000);
    assert_eq!(config.max_packet_queue, 10000);
    assert_eq!(config.packet_mtu, 1500);
}

#[test]
fn test_client_config_header_compression() {
    let config = ClientConfig::default();

    assert!(config.enable_header_compression);
    assert!(config.enable_rohc);
    assert_eq!(config.rohc_max_size, 1500);
}

#[test]
fn test_client_config_0rtt() {
    let config = ClientConfig::default();

    assert!(config.enable_0rtt);
    assert_eq!(config.session_cache_path, "/tmp/oxidize-session-cache");
}

#[test]
fn test_client_config_datagrams() {
    let config = ClientConfig::default();

    assert!(config.enable_datagrams);
    assert_eq!(config.datagram_latency_threshold_ms, 50);
}

#[test]
fn test_client_config_migration() {
    let config = ClientConfig::default();

    assert!(config.enable_migration);
}

#[test]
fn test_client_config_stream_multiplexing() {
    let config = ClientConfig::default();

    assert!(config.enable_stream_multiplexing);
}

#[test]
fn test_client_config_realtime_ports() {
    let config = ClientConfig::default();

    assert!(!config.realtime_ports.is_empty());
    // Check some known gaming/voip ports
    assert!(config.realtime_ports.contains(&3074)); // Xbox Live
    assert!(config.realtime_ports.contains(&27015)); // Steam
    assert!(config.realtime_ports.contains(&5060)); // SIP
}

#[test]
fn test_client_config_multipath() {
    let config = ClientConfig::default();

    assert!(config.enable_multipath);
}

#[test]
fn test_client_config_prefetch() {
    let config = ClientConfig::default();

    assert!(config.enable_prefetch);
}

#[test]
fn test_client_config_ai_engine() {
    let config = ClientConfig::default();

    assert!(config.enable_ai_engine);
}

#[test]
fn test_client_config_reconnection() {
    let config = ClientConfig::default();

    assert_eq!(config.max_reconnect_attempts, 0); // Infinite
    assert_eq!(config.reconnect_delay_ms, 50);
    assert_eq!(config.max_reconnect_delay_ms, 5000);
    assert_eq!(config.reconnect_buffer_size, 1000);
}

#[test]
fn test_client_config_bypass_domains() {
    let config = ClientConfig::default();

    assert!(config.bypass_domains.is_empty());
}

#[test]
fn test_client_config_load_nonexistent() {
    let result = ClientConfig::load("/nonexistent/path/config.toml");
    assert!(result.is_err());
}
