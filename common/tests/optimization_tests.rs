//! Tests for optimization modules: optimization_stats, mptcp_redundancy, handoff_prediction

use oxidize_common::handoff_prediction::{HandoffPredictor, NetworkType};
use oxidize_common::mptcp_redundancy::{MptcpRedundancyScheduler, PacketImportance, RedundancyConfig};
use oxidize_common::optimization_stats::{AtomicOptStats, OptimizationStats};
use std::sync::atomic::Ordering;

// ============================================================================
// OptimizationStats Tests
// ============================================================================

#[test]
fn test_optimization_stats_default() {
    let stats = OptimizationStats::default();
    assert_eq!(stats.redundant_packets_sent, 0);
    assert_eq!(stats.redundant_packets_useful, 0);
    assert_eq!(stats.path_failovers, 0);
    assert_eq!(stats.handoff_predictions, 0);
    assert_eq!(stats.dpi_packets_inspected, 0);
    assert_eq!(stats.ml_predictions_made, 0);
}

#[test]
fn test_optimization_stats_summary() {
    let stats = OptimizationStats {
        ml_predictions_made: 100,
        ml_cwnd_adjustments: 50,
        redundant_packets_sent: 20,
        path_failovers: 2,
        dpi_flows_identified: 15,
        simd_packets_parsed: 1000,
        ..Default::default()
    };

    let summary = stats.summary();
    assert!(summary.contains("100pred"));
    assert!(summary.contains("50cwnd"));
    assert!(summary.contains("20dup"));
    assert!(summary.contains("2fail"));
    assert!(summary.contains("15flows"));
    assert!(summary.contains("1000pkts"));
}

#[test]
fn test_atomic_opt_stats_record_packet() {
    let stats = AtomicOptStats::default();

    stats.record_packet();
    stats.record_packet();
    stats.record_packet();

    assert_eq!(stats.total_packets.load(Ordering::Relaxed), 3);
}

#[test]
fn test_atomic_opt_stats_record_optimization() {
    let stats = AtomicOptStats::default();

    stats.record_packet();
    stats.record_packet();
    stats.record_optimization(100, 500);

    assert_eq!(stats.optimized_packets.load(Ordering::Relaxed), 1);
    assert_eq!(stats.bytes_saved.load(Ordering::Relaxed), 100);
    assert_eq!(stats.latency_improvements_us.load(Ordering::Relaxed), 500);
}

#[test]
fn test_atomic_opt_stats_optimization_rate() {
    let stats = AtomicOptStats::default();

    // No packets yet
    assert_eq!(stats.optimization_rate(), 0.0);

    // Add packets and optimizations
    for _ in 0..10 {
        stats.record_packet();
    }
    for _ in 0..5 {
        stats.record_optimization(50, 100);
    }

    let rate = stats.optimization_rate();
    assert!((rate - 0.5).abs() < 0.01); // 50% optimization rate
}

// ============================================================================
// MptcpRedundancyScheduler Tests
// ============================================================================

#[test]
fn test_mptcp_scheduler_new() {
    let scheduler = MptcpRedundancyScheduler::default();
    assert_eq!(scheduler.get_path_count(), 0);
}

#[test]
fn test_mptcp_scheduler_add_path() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);

    assert_eq!(scheduler.get_path_count(), 2);
}

#[test]
fn test_mptcp_scheduler_update_path() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.update_path(1, 50.0, 0.02, 50_000_000);

    // Path should still exist
    assert_eq!(scheduler.get_path_count(), 1);
}

#[test]
fn test_mptcp_scheduler_schedule_critical() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);

    // Critical packets should be sent on all paths
    let paths = scheduler.schedule_packet(PacketImportance::Critical);
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&1));
    assert!(paths.contains(&2));
}

#[test]
fn test_mptcp_scheduler_schedule_normal() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);
    scheduler.update_path(1, 20.0, 0.01, 100_000_000); // Better path
    scheduler.update_path(2, 100.0, 0.05, 50_000_000); // Worse path

    // Normal packets should use best path only
    let paths = scheduler.schedule_packet(PacketImportance::Normal);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], 1); // Best path
}

#[test]
fn test_mptcp_scheduler_schedule_high_similar_paths() {
    let config = RedundancyConfig {
        enable_redundancy: true,
        rtt_diff_threshold_ms: 50,
        loss_diff_threshold: 0.05,
        max_redundancy_buffer: 64,
    };
    let scheduler = MptcpRedundancyScheduler::new(config);

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);
    // Similar paths - should not duplicate
    scheduler.update_path(1, 30.0, 0.01, 100_000_000);
    scheduler.update_path(2, 35.0, 0.01, 100_000_000);

    let paths = scheduler.schedule_packet(PacketImportance::High);
    assert_eq!(paths.len(), 1); // Similar quality, no duplication
}

#[test]
fn test_mptcp_scheduler_schedule_high_different_paths() {
    let config = RedundancyConfig {
        enable_redundancy: true,
        rtt_diff_threshold_ms: 50,
        loss_diff_threshold: 0.05,
        max_redundancy_buffer: 64,
    };
    let scheduler = MptcpRedundancyScheduler::new(config);

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);
    // Very different paths - should duplicate
    scheduler.update_path(1, 20.0, 0.01, 100_000_000);
    scheduler.update_path(2, 200.0, 0.10, 50_000_000);

    let paths = scheduler.schedule_packet(PacketImportance::High);
    assert_eq!(paths.len(), 2); // Different quality, should duplicate
}

#[test]
fn test_mptcp_scheduler_empty_schedule() {
    let scheduler = MptcpRedundancyScheduler::default();

    // No paths added
    let paths = scheduler.schedule_packet(PacketImportance::Critical);
    assert!(paths.is_empty());
}

#[test]
fn test_mptcp_scheduler_record_failure() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.record_failure(1);
    scheduler.record_failure(1);
    scheduler.record_failure(1);

    // Path should still exist but have failures recorded
    assert_eq!(scheduler.get_path_count(), 1);
}

#[test]
fn test_mptcp_scheduler_failover() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);
    scheduler.update_path(1, 200.0, 0.20, 10_000_000); // Bad primary
    scheduler.update_path(2, 30.0, 0.01, 100_000_000); // Good backup

    // Record failures on primary
    scheduler.record_failure(1);
    scheduler.record_failure(1);
    scheduler.record_failure(1);

    let failover = scheduler.should_failover();
    assert!(failover.is_some());
    assert_eq!(failover.unwrap(), 2);
}

#[test]
fn test_mptcp_scheduler_stats() {
    let scheduler = MptcpRedundancyScheduler::default();

    scheduler.add_path(1, true);
    scheduler.add_path(2, false);

    scheduler.schedule_packet(PacketImportance::Critical);
    scheduler.schedule_packet(PacketImportance::Normal);

    assert!(scheduler.stats.redundant_packets_sent.load(Ordering::Relaxed) >= 1);
    assert!(scheduler.stats.packets_sent_primary.load(Ordering::Relaxed) >= 1);
}

// ============================================================================
// HandoffPredictor Tests
// ============================================================================

#[test]
fn test_handoff_predictor_new() {
    let predictor = HandoffPredictor::new();
    assert_eq!(predictor.get_probability(), 0);
}

#[test]
fn test_handoff_predictor_default() {
    let predictor = HandoffPredictor::default();
    assert_eq!(predictor.get_probability(), 0);
}

#[test]
fn test_handoff_predictor_record_wifi_signal() {
    let predictor = HandoffPredictor::new();

    // Record good WiFi signal
    predictor.record_wifi_signal(-50, 5000);
    predictor.record_wifi_signal(-52, 5100);

    // Should not predict handoff with good signal
    let prob = predictor.predict_handoff();
    assert!(prob < 50);
}

#[test]
fn test_handoff_predictor_weak_wifi() {
    let predictor = HandoffPredictor::new();

    // Record weak and declining WiFi signal
    for rssi in [-60i8, -65, -70, -75, -80, -85] {
        predictor.record_wifi_signal(rssi, 10000);
    }
    // Record available LTE
    predictor.record_lte_signal(-85);

    let prob = predictor.predict_handoff();
    assert!(prob > 50); // Should predict handoff
}

#[test]
fn test_handoff_predictor_set_network() {
    let predictor = HandoffPredictor::new();

    predictor.set_network(NetworkType::WiFi);
    predictor.set_network(NetworkType::LTE);

    // Should record actual handoff
    assert_eq!(predictor.stats.handoffs_actual.load(Ordering::Relaxed), 1);
}

#[test]
fn test_handoff_predictor_no_change() {
    let predictor = HandoffPredictor::new();

    predictor.set_network(NetworkType::WiFi);
    predictor.set_network(NetworkType::WiFi);

    // No handoff if same network
    assert_eq!(predictor.stats.handoffs_actual.load(Ordering::Relaxed), 0);
}

#[test]
fn test_handoff_predictor_should_prepare() {
    let predictor = HandoffPredictor::new();

    // Initially should not prepare
    assert!(!predictor.should_prepare_handoff());

    // Record weak WiFi and available LTE
    for rssi in [-60i8, -70, -75, -80, -85, -90] {
        predictor.record_wifi_signal(rssi, 15000);
    }
    predictor.record_lte_signal(-80);
    predictor.predict_handoff();

    // Now should prepare
    assert!(predictor.should_prepare_handoff());
}

#[test]
fn test_handoff_predictor_get_actions() {
    let predictor = HandoffPredictor::new();

    // Record weak WiFi and good LTE to trigger high probability
    for rssi in [-70i8, -75, -80, -85, -88, -92] {
        predictor.record_wifi_signal(rssi, 20000);
    }
    predictor.record_lte_signal(-75);
    predictor.predict_handoff();

    let actions = predictor.get_actions();
    // High probability should trigger various actions
    if predictor.get_probability() > 70 {
        assert!(actions.duplicate_critical);
    }
    if predictor.get_probability() > 50 {
        assert!(actions.increase_fec);
    }
}

#[test]
fn test_handoff_predictor_stats() {
    let predictor = HandoffPredictor::new();

    predictor.predict_handoff();
    predictor.predict_handoff();
    predictor.predict_handoff();

    assert_eq!(predictor.stats.predictions_made.load(Ordering::Relaxed), 3);
}

#[test]
fn test_handoff_predictor_declining_trend() {
    let predictor = HandoffPredictor::new();

    // Record declining WiFi signal trend
    for rssi in [-50i8, -55, -60, -65, -70] {
        predictor.record_wifi_signal(rssi, 8000);
    }
    predictor.record_lte_signal(-90);

    let prob = predictor.predict_handoff();
    // Should detect declining trend
    assert!(prob > 10);
}

#[test]
fn test_network_type_values() {
    assert_eq!(NetworkType::WiFi as u8, 0);
    assert_eq!(NetworkType::LTE as u8, 1);
    assert_eq!(NetworkType::FiveG as u8, 2);
    assert_eq!(NetworkType::Ethernet as u8, 3);
    assert_eq!(NetworkType::Unknown as u8, 4);
}
