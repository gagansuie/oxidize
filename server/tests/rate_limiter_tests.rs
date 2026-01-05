use relay_server::rate_limiter::RateLimiter;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn test_rate_limiter_allows_within_limit() {
    let limiter = RateLimiter::new(5, 60);
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    for _ in 0..5 {
        assert!(
            limiter.check_rate_limit(ip).await,
            "Should allow connections within limit"
        );
    }
}

#[tokio::test]
async fn test_rate_limiter_blocks_over_limit() {
    let limiter = RateLimiter::new(3, 60);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    for _ in 0..3 {
        assert!(limiter.check_rate_limit(ip).await);
    }

    assert!(
        !limiter.check_rate_limit(ip).await,
        "Should block connection over limit"
    );
}

#[tokio::test]
async fn test_rate_limiter_different_ips() {
    let limiter = RateLimiter::new(2, 60);
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    assert!(limiter.check_rate_limit(ip1).await);
    assert!(limiter.check_rate_limit(ip1).await);
    assert!(!limiter.check_rate_limit(ip1).await);

    assert!(limiter.check_rate_limit(ip2).await);
    assert!(limiter.check_rate_limit(ip2).await);
}

#[tokio::test]
async fn test_rate_limiter_stats() {
    let limiter = RateLimiter::new(10, 60);
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

    limiter.check_rate_limit(ip).await;

    let stats = limiter.get_stats().await;
    assert_eq!(stats.max_per_ip, 10);
    assert_eq!(stats.tracked_ips, 1);
}

#[tokio::test]
async fn test_rate_limiter_cleanup() {
    let limiter = RateLimiter::new(5, 1);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));

    limiter.check_rate_limit(ip).await;

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    limiter.cleanup_old_entries().await;

    let stats = limiter.get_stats().await;
    assert_eq!(stats.tracked_ips, 0, "Old entries should be cleaned up");
}
