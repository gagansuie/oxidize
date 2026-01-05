use oxidize_common::RelayMetrics;

#[test]
fn test_metrics_initialization() {
    let metrics = RelayMetrics::new();
    let stats = metrics.get_stats();

    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.connections_active, 0);
    assert_eq!(stats.connections_total, 0);
}

#[test]
fn test_record_sent() {
    let metrics = RelayMetrics::new();

    metrics.record_sent(100);
    metrics.record_sent(200);

    let stats = metrics.get_stats();
    assert_eq!(stats.bytes_sent, 300);
    assert_eq!(stats.packets_sent, 2);
}

#[test]
fn test_record_received() {
    let metrics = RelayMetrics::new();

    metrics.record_received(150);
    metrics.record_received(250);

    let stats = metrics.get_stats();
    assert_eq!(stats.bytes_received, 400);
    assert_eq!(stats.packets_received, 2);
}

#[test]
fn test_connection_tracking() {
    let metrics = RelayMetrics::new();

    metrics.record_connection_opened();
    metrics.record_connection_opened();

    let stats = metrics.get_stats();
    assert_eq!(stats.connections_active, 2);
    assert_eq!(stats.connections_total, 2);

    metrics.record_connection_closed();
    let stats = metrics.get_stats();
    assert_eq!(stats.connections_active, 1);
    assert_eq!(stats.connections_total, 2);
}

#[test]
fn test_compression_savings() {
    let metrics = RelayMetrics::new();

    metrics.record_compression_saved(1000);
    metrics.record_compression_saved(500);

    let stats = metrics.get_stats();
    assert_eq!(stats.compression_saved, 1500);
}

#[test]
fn test_concurrent_updates() {
    use std::sync::Arc;
    use std::thread;

    let metrics = Arc::new(RelayMetrics::new());
    let mut handles = vec![];

    for _ in 0..10 {
        let m = metrics.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                m.record_sent(1);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let stats = metrics.get_stats();
    assert_eq!(stats.bytes_sent, 1000);
    assert_eq!(stats.packets_sent, 1000);
}
