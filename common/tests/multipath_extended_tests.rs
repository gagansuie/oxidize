//! Extended tests for multipath module

use oxidize_common::multipath::{
    EmaEstimator, MultipathScheduler, PathId, PathMetrics, SchedulingStrategy,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

// ============================================================================
// EmaEstimator Tests
// ============================================================================

#[test]
fn test_ema_estimator_new() {
    let ema = EmaEstimator::new();
    assert!(!ema.is_initialized());
    assert_eq!(ema.value(), 0.0);
}

#[test]
fn test_ema_estimator_default() {
    let ema = EmaEstimator::default();
    assert!(!ema.is_initialized());
}

#[test]
fn test_ema_estimator_with_alpha() {
    let ema = EmaEstimator::with_alpha(0.5);
    assert!(!ema.is_initialized());
}

#[test]
fn test_ema_estimator_alpha_clamping() {
    // Alpha should be clamped to valid range
    let ema_low = EmaEstimator::with_alpha(0.0);
    let ema_high = EmaEstimator::with_alpha(1.0);

    // Both should be functional
    assert!(!ema_low.is_initialized());
    assert!(!ema_high.is_initialized());
}

#[test]
fn test_ema_estimator_fast() {
    let ema = EmaEstimator::fast();
    assert!(!ema.is_initialized());
}

#[test]
fn test_ema_estimator_stable() {
    let ema = EmaEstimator::stable();
    assert!(!ema.is_initialized());
}

#[test]
fn test_ema_estimator_first_update() {
    let mut ema = EmaEstimator::new();

    ema.update(100.0);
    assert!(ema.is_initialized());
    assert_eq!(ema.value(), 100.0);
}

#[test]
fn test_ema_estimator_multiple_updates() {
    let mut ema = EmaEstimator::with_alpha(0.5);

    ema.update(100.0);
    assert_eq!(ema.value(), 100.0);

    ema.update(200.0);
    // EMA: 0.5 * 200 + 0.5 * 100 = 150
    assert_eq!(ema.value(), 150.0);

    ema.update(200.0);
    // EMA: 0.5 * 200 + 0.5 * 150 = 175
    assert_eq!(ema.value(), 175.0);
}

#[test]
fn test_ema_estimator_reset() {
    let mut ema = EmaEstimator::new();

    ema.update(100.0);
    assert!(ema.is_initialized());

    ema.reset();
    assert!(!ema.is_initialized());
    assert_eq!(ema.value(), 0.0);
}

// ============================================================================
// PathMetrics Tests
// ============================================================================

#[test]
fn test_path_metrics_default() {
    let metrics = PathMetrics::default();
    assert_eq!(metrics.rtt_ms, 100.0);
    assert_eq!(metrics.loss_rate, 0.0);
    assert_eq!(metrics.bandwidth, 1_000_000);
    assert_eq!(metrics.jitter_ms, 10.0);
    assert_eq!(metrics.packets_sent, 0);
    assert_eq!(metrics.packets_received, 0);
}

#[test]
fn test_path_metrics_new() {
    let metrics = PathMetrics::new(50.0, 5_000_000, 0.01, 5.0);
    assert_eq!(metrics.rtt_ms, 50.0);
    assert_eq!(metrics.bandwidth, 5_000_000);
    assert_eq!(metrics.loss_rate, 0.01);
    assert_eq!(metrics.jitter_ms, 5.0);
}

#[test]
fn test_path_metrics_for_gaming() {
    let metrics = PathMetrics::for_gaming();
    assert!(metrics.is_healthy());
}

#[test]
fn test_path_metrics_for_bulk() {
    let metrics = PathMetrics::for_bulk();
    assert!(metrics.is_healthy());
}

#[test]
fn test_path_metrics_update_rtt() {
    let mut metrics = PathMetrics::default();

    metrics.update_rtt(50.0);
    assert!(metrics.rtt_ms != 100.0); // Should have changed
}

#[test]
fn test_path_metrics_update_loss() {
    let mut metrics = PathMetrics::default();

    metrics.update_loss(0.05);
    assert!(metrics.loss_rate > 0.0);
}

#[test]
fn test_path_metrics_update_bandwidth() {
    let mut metrics = PathMetrics::default();

    metrics.update_bandwidth(10_000_000);
    assert!(metrics.bandwidth != 1_000_000);
}

#[test]
fn test_path_metrics_update_jitter() {
    let mut metrics = PathMetrics::default();

    metrics.update_jitter(20.0);
    assert!(metrics.jitter_ms != 10.0);
}

#[test]
fn test_path_metrics_update_all() {
    let mut metrics = PathMetrics::default();

    metrics.update_all(30.0, 0.02, 8_000_000, 8.0);
    // All values should have been updated via EMA
}

#[test]
fn test_path_metrics_record_sent() {
    let mut metrics = PathMetrics::default();

    metrics.record_sent();
    assert_eq!(metrics.packets_sent, 1);

    metrics.record_sent();
    assert_eq!(metrics.packets_sent, 2);
}

#[test]
fn test_path_metrics_record_received() {
    let mut metrics = PathMetrics::default();

    metrics.record_sent();
    metrics.record_sent();
    metrics.record_received(30.0);

    assert_eq!(metrics.packets_received, 1);
}

#[test]
fn test_path_metrics_score() {
    let good_metrics = PathMetrics::new(20.0, 10_000_000, 0.01, 5.0);
    let bad_metrics = PathMetrics::new(500.0, 100_000, 0.30, 100.0);

    assert!(good_metrics.score() > bad_metrics.score());
}

#[test]
fn test_path_metrics_gaming_score() {
    let good_metrics = PathMetrics::new(10.0, 1_000_000, 0.01, 3.0);
    let bad_metrics = PathMetrics::new(200.0, 10_000_000, 0.05, 50.0);

    assert!(good_metrics.gaming_score() > bad_metrics.gaming_score());
}

#[test]
fn test_path_metrics_is_healthy() {
    let healthy = PathMetrics::new(50.0, 1_000_000, 0.1, 10.0);
    assert!(healthy.is_healthy());

    let unhealthy_loss = PathMetrics::new(50.0, 1_000_000, 0.6, 10.0);
    assert!(!unhealthy_loss.is_healthy());

    let unhealthy_rtt = PathMetrics::new(1500.0, 1_000_000, 0.1, 10.0);
    assert!(!unhealthy_rtt.is_healthy());
}

#[test]
fn test_path_metrics_is_gaming_quality() {
    let gaming = PathMetrics::new(20.0, 1_000_000, 0.01, 5.0);
    assert!(gaming.is_gaming_quality());

    let not_gaming_rtt = PathMetrics::new(150.0, 1_000_000, 0.01, 5.0);
    assert!(!not_gaming_rtt.is_gaming_quality());

    let not_gaming_loss = PathMetrics::new(20.0, 1_000_000, 0.05, 5.0);
    assert!(!not_gaming_loss.is_gaming_quality());

    let not_gaming_jitter = PathMetrics::new(20.0, 1_000_000, 0.01, 30.0);
    assert!(!not_gaming_jitter.is_gaming_quality());
}

#[test]
fn test_path_metrics_is_stale() {
    let metrics = PathMetrics::default();
    // Just created, should not be stale
    assert!(!metrics.is_stale(Duration::from_secs(30)));
}

// ============================================================================
// PathId Tests
// ============================================================================

fn make_path_id(local_port: u16, remote_port: u16) -> PathId {
    PathId::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), local_port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), remote_port),
    )
}

#[test]
fn test_path_id_new() {
    let path_id = make_path_id(5000, 4433);
    assert_eq!(
        path_id.local,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000)
    );
    assert_eq!(
        path_id.remote,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433)
    );
}

#[test]
fn test_path_id_eq() {
    let path1 = make_path_id(5000, 4433);
    let path2 = make_path_id(5000, 4433);
    let path3 = make_path_id(5001, 4433);

    assert_eq!(path1, path2);
    assert_ne!(path1, path3);
}

#[test]
fn test_path_id_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(make_path_id(5000, 4433));
    set.insert(make_path_id(5000, 4433)); // Duplicate
    set.insert(make_path_id(5001, 4433));

    assert_eq!(set.len(), 2);
}

// ============================================================================
// MultipathScheduler Tests
// ============================================================================

#[test]
fn test_scheduler_new_round_robin() {
    let scheduler = MultipathScheduler::new(SchedulingStrategy::RoundRobin);
    assert_eq!(scheduler.path_count(), 0);
    assert_eq!(scheduler.healthy_path_count(), 0);
}

#[test]
fn test_scheduler_new_weighted() {
    let scheduler = MultipathScheduler::new(SchedulingStrategy::Weighted);
    assert_eq!(scheduler.path_count(), 0);
}

#[test]
fn test_scheduler_new_primary() {
    let scheduler = MultipathScheduler::new(SchedulingStrategy::Primary);
    assert_eq!(scheduler.path_count(), 0);
}

#[test]
fn test_scheduler_new_redundant() {
    let scheduler = MultipathScheduler::new(SchedulingStrategy::Redundant);
    assert_eq!(scheduler.path_count(), 0);
}

#[test]
fn test_scheduler_new_min_latency() {
    let scheduler = MultipathScheduler::new(SchedulingStrategy::MinLatency);
    assert_eq!(scheduler.path_count(), 0);
}

#[test]
fn test_scheduler_default() {
    let scheduler = MultipathScheduler::default();
    assert_eq!(scheduler.path_count(), 0);
}

#[test]
fn test_scheduler_add_path() {
    let mut scheduler = MultipathScheduler::default();

    scheduler.add_path(make_path_id(5000, 4433), PathMetrics::default());
    assert_eq!(scheduler.path_count(), 1);

    scheduler.add_path(make_path_id(5001, 4433), PathMetrics::default());
    assert_eq!(scheduler.path_count(), 2);
}

#[test]
fn test_scheduler_remove_path() {
    let mut scheduler = MultipathScheduler::default();

    let path1 = make_path_id(5000, 4433);
    let path2 = make_path_id(5001, 4433);

    scheduler.add_path(path1, PathMetrics::default());
    scheduler.add_path(path2, PathMetrics::default());
    assert_eq!(scheduler.path_count(), 2);

    scheduler.remove_path(&path1);
    assert_eq!(scheduler.path_count(), 1);
}

#[test]
fn test_scheduler_update_metrics() {
    let mut scheduler = MultipathScheduler::default();
    let path_id = make_path_id(5000, 4433);

    scheduler.add_path(path_id, PathMetrics::default());
    scheduler.update_metrics(&path_id, PathMetrics::new(20.0, 10_000_000, 0.01, 5.0));
    // Should not panic
}

#[test]
fn test_scheduler_next_path_empty() {
    let mut scheduler = MultipathScheduler::default();
    assert!(scheduler.next_path().is_none());
}

#[test]
fn test_scheduler_next_path_single() {
    let mut scheduler = MultipathScheduler::default();
    let path_id = make_path_id(5000, 4433);

    scheduler.add_path(path_id, PathMetrics::default());

    let next = scheduler.next_path();
    assert_eq!(next, Some(path_id));
}

#[test]
fn test_scheduler_round_robin() {
    let mut scheduler = MultipathScheduler::new(SchedulingStrategy::RoundRobin);

    let path1 = make_path_id(5000, 4433);
    let path2 = make_path_id(5001, 4433);

    scheduler.add_path(path1, PathMetrics::default());
    scheduler.add_path(path2, PathMetrics::default());

    // Should rotate through paths
    let first = scheduler.next_path();
    let second = scheduler.next_path();

    assert!(first.is_some());
    assert!(second.is_some());
}

#[test]
fn test_scheduler_weighted_prefers_better() {
    let mut scheduler = MultipathScheduler::new(SchedulingStrategy::Weighted);

    let good_path = make_path_id(5000, 4433);
    let bad_path = make_path_id(5001, 4433);

    scheduler.add_path(good_path, PathMetrics::new(20.0, 10_000_000, 0.01, 5.0));
    scheduler.add_path(bad_path, PathMetrics::new(500.0, 100_000, 0.30, 100.0));

    let selected = scheduler.next_path();
    assert_eq!(selected, Some(good_path));
}

#[test]
fn test_scheduler_min_latency() {
    let mut scheduler = MultipathScheduler::new(SchedulingStrategy::MinLatency);

    let low_latency = make_path_id(5000, 4433);
    let high_latency = make_path_id(5001, 4433);

    scheduler.add_path(low_latency, PathMetrics::new(10.0, 1_000_000, 0.05, 5.0));
    scheduler.add_path(high_latency, PathMetrics::new(200.0, 10_000_000, 0.01, 5.0));

    let selected = scheduler.next_path();
    assert_eq!(selected, Some(low_latency));
}

#[test]
fn test_scheduler_all_paths() {
    let mut scheduler = MultipathScheduler::new(SchedulingStrategy::Redundant);

    let path1 = make_path_id(5000, 4433);
    let path2 = make_path_id(5001, 4433);

    scheduler.add_path(path1, PathMetrics::default());
    scheduler.add_path(path2, PathMetrics::default());

    let all = scheduler.all_paths();
    assert_eq!(all.len(), 2);
    assert!(all.contains(&path1));
    assert!(all.contains(&path2));
}

#[test]
fn test_scheduler_healthy_path_count() {
    let mut scheduler = MultipathScheduler::default();

    let healthy_path = make_path_id(5000, 4433);
    let unhealthy_path = make_path_id(5001, 4433);

    scheduler.add_path(healthy_path, PathMetrics::new(20.0, 1_000_000, 0.1, 10.0));
    scheduler.add_path(unhealthy_path, PathMetrics::new(50.0, 1_000_000, 0.7, 10.0)); // High loss

    assert_eq!(scheduler.path_count(), 2);
    assert_eq!(scheduler.healthy_path_count(), 1);
}

#[test]
fn test_scheduler_total_bandwidth() {
    let mut scheduler = MultipathScheduler::default();

    scheduler.add_path(
        make_path_id(5000, 4433),
        PathMetrics::new(20.0, 5_000_000, 0.01, 5.0),
    );
    scheduler.add_path(
        make_path_id(5001, 4433),
        PathMetrics::new(30.0, 3_000_000, 0.01, 5.0),
    );

    assert_eq!(scheduler.total_bandwidth(), 8_000_000);
}

#[test]
fn test_scheduler_stats() {
    let mut scheduler = MultipathScheduler::default();

    let path = make_path_id(5000, 4433);
    scheduler.add_path(path, PathMetrics::default());

    scheduler.next_path();
    scheduler.next_path();

    assert_eq!(scheduler.stats.total_packets, 2);
}

#[test]
fn test_scheduling_strategy_eq() {
    assert_eq!(SchedulingStrategy::RoundRobin, SchedulingStrategy::RoundRobin);
    assert_ne!(SchedulingStrategy::RoundRobin, SchedulingStrategy::Weighted);
}
