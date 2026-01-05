use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct RateLimiter {
    limits: Arc<RwLock<HashMap<IpAddr, ConnectionLimit>>>,
    max_connections_per_ip: usize,
    window_duration: Duration,
}

struct ConnectionLimit {
    count: usize,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_connections_per_ip: usize, window_secs: u64) -> Self {
        Self {
            limits: Arc::new(RwLock::new(HashMap::new())),
            max_connections_per_ip,
            window_duration: Duration::from_secs(window_secs),
        }
    }

    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut limits = self.limits.write().await;
        let now = Instant::now();

        let limit = limits.entry(ip).or_insert(ConnectionLimit {
            count: 0,
            window_start: now,
        });

        if now.duration_since(limit.window_start) >= self.window_duration {
            limit.count = 1;
            limit.window_start = now;
            return true;
        }

        if limit.count < self.max_connections_per_ip {
            limit.count += 1;
            true
        } else {
            false
        }
    }

    pub async fn cleanup_old_entries(&self) {
        let mut limits = self.limits.write().await;
        let now = Instant::now();

        limits.retain(|_, limit| now.duration_since(limit.window_start) < self.window_duration * 2);
    }

    pub async fn get_stats(&self) -> RateLimitStats {
        let limits = self.limits.read().await;
        RateLimitStats {
            tracked_ips: limits.len(),
            max_per_ip: self.max_connections_per_ip,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub tracked_ips: usize,
    pub max_per_ip: usize,
}
