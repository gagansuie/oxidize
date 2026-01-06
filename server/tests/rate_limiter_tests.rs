use oxidize_common::security::{SecurityAction, SecurityConfig, SecurityManager};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn test_ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

#[test]
fn test_security_allows_within_limit() {
    let config = SecurityConfig {
        max_connections_per_ip: 5,
        ..Default::default()
    };
    let mut mgr = SecurityManager::new(config);
    let ip = test_ip(1);

    for _ in 0..5 {
        assert_eq!(
            mgr.check_connection(ip),
            SecurityAction::Allow,
            "Should allow connections within limit"
        );
    }
}

#[test]
fn test_security_rate_limits_over_limit() {
    let config = SecurityConfig {
        max_connections_per_ip: 3,
        ..Default::default()
    };
    let mut mgr = SecurityManager::new(config);
    let ip = test_ip(2);

    for _ in 0..3 {
        assert_eq!(mgr.check_connection(ip), SecurityAction::Allow);
    }

    assert_eq!(
        mgr.check_connection(ip),
        SecurityAction::RateLimit,
        "Should rate limit connection over limit"
    );
}

#[test]
fn test_security_different_ips() {
    let config = SecurityConfig {
        max_connections_per_ip: 2,
        enable_challenges: false,
        ..Default::default()
    };
    let mut mgr = SecurityManager::new(config);
    let ip1 = test_ip(10);
    let ip2 = test_ip(20);

    assert_eq!(mgr.check_connection(ip1), SecurityAction::Allow);
    assert_eq!(mgr.check_connection(ip1), SecurityAction::Allow);
    assert_eq!(mgr.check_connection(ip1), SecurityAction::RateLimit);

    // Different IP should still be allowed
    assert_eq!(mgr.check_connection(ip2), SecurityAction::Allow);
    assert_eq!(mgr.check_connection(ip2), SecurityAction::Allow);
}

#[test]
fn test_security_blocklist() {
    let mut mgr = SecurityManager::default();
    let ip = test_ip(3);

    mgr.block_ip(ip, Duration::from_secs(60));
    assert_eq!(mgr.check_connection(ip), SecurityAction::Block);

    mgr.unblock_ip(ip);
    assert_eq!(mgr.check_connection(ip), SecurityAction::Allow);
}

#[test]
fn test_security_allowlist() {
    let config = SecurityConfig {
        max_connections_per_ip: 1,
        ..Default::default()
    };
    let mut mgr = SecurityManager::new(config);
    let ip = test_ip(4);

    mgr.allowlist_ip(ip);

    // Should bypass all limits
    for _ in 0..100 {
        assert_eq!(mgr.check_connection(ip), SecurityAction::Allow);
    }
}

#[test]
fn test_security_snapshot() {
    let mut mgr = SecurityManager::default();
    let ip = test_ip(5);

    mgr.check_connection(ip);
    mgr.block_ip(test_ip(100), Duration::from_secs(60));
    mgr.allowlist_ip(test_ip(200));

    let snapshot = mgr.snapshot();
    assert_eq!(snapshot.tracked_ips, 1);
    assert_eq!(snapshot.blocked_ips, 1);
    assert_eq!(snapshot.allowlisted_ips, 1);
}
