//! Tests for server config module

use relay_server::config::Config;

#[test]
fn test_config_default() {
    let config = Config::default();

    assert_eq!(config.max_connections, 10000);
    assert!(config.enable_compression);
    assert_eq!(config.compression_threshold, 512);
    assert_eq!(config.buffer_size, 65536);
    assert_eq!(config.keepalive_interval, 30);
    assert_eq!(config.connection_timeout, 300);
    assert!(config.enable_tcp_acceleration);
    assert!(config.enable_deduplication);
    assert_eq!(config.rate_limit_per_ip, 100);
    assert_eq!(config.rate_limit_window_secs, 60);
}

#[test]
fn test_config_security_defaults() {
    let config = Config::default();

    assert_eq!(config.max_pps_per_ip, 1000);
    assert_eq!(config.max_bandwidth_per_ip, 10 * 1024 * 1024);
    assert_eq!(config.auto_block_threshold, 10);
    assert!(config.enable_challenges);
}

#[test]
fn test_config_oxtunnel_defaults() {
    let config = Config::default();

    assert!(!config.enable_oxtunnel);
    assert!(config.oxtunnel_port.is_none());
}

#[test]
fn test_config_rohc_defaults() {
    let config = Config::default();

    assert!(config.enable_rohc);
    assert_eq!(config.rohc_max_size, 1500);
}

#[test]
fn test_config_ack_batch_defaults() {
    let config = Config::default();

    assert_eq!(config.ack_batch_size, 8);
}

#[test]
fn test_config_edge_cache_defaults() {
    let config = Config::default();

    assert!(config.enable_edge_cache);
    assert_eq!(config.edge_cache_size, 64 * 1024 * 1024);
    assert_eq!(config.edge_cache_entries, 10000);
}

#[test]
fn test_config_ai_engine_defaults() {
    let config = Config::default();

    assert!(config.enable_ai_engine);
    assert!(config.enable_ml_training_upload);
    assert_eq!(config.ml_upload_interval_secs, 3600);
}

#[test]
fn test_config_0rtt_defaults() {
    let config = Config::default();

    assert!(config.enable_0rtt);
    assert_eq!(config.max_early_data_size, u32::MAX);
}

#[test]
fn test_config_tls_defaults() {
    let config = Config::default();

    assert!(config.tls_cert_path.is_none());
    assert!(config.tls_key_path.is_none());
}

#[test]
fn test_config_load_nonexistent() {
    let result = Config::load("/nonexistent/path/config.toml");
    assert!(result.is_err());
}
