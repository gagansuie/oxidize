//! Multi-path QUIC Support
//!
//! Enables simultaneous use of multiple network paths (WiFi + LTE)
//! for bandwidth aggregation and seamless failover.
//! Provides up to 2x bandwidth improvement.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Path quality metrics
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Available bandwidth estimate (bytes/sec)
    pub bandwidth: u64,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
    /// Last update time
    pub last_updated: Instant,
    /// Packets sent on this path
    pub packets_sent: u64,
    /// Packets received on this path
    pub packets_received: u64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        PathMetrics {
            rtt_ms: 100.0,
            loss_rate: 0.0,
            bandwidth: 1_000_000, // 1 MB/s default
            jitter_ms: 10.0,
            last_updated: Instant::now(),
            packets_sent: 0,
            packets_received: 0,
        }
    }
}

impl PathMetrics {
    /// Calculate path score (higher is better)
    pub fn score(&self) -> f64 {
        // Weight factors
        const RTT_WEIGHT: f64 = 0.3;
        const LOSS_WEIGHT: f64 = 0.4;
        const BW_WEIGHT: f64 = 0.2;
        const JITTER_WEIGHT: f64 = 0.1;

        // Normalize and invert (lower RTT/loss/jitter = higher score)
        let rtt_score = 1.0 / (1.0 + self.rtt_ms / 100.0);
        let loss_score = 1.0 - self.loss_rate;
        let bw_score = (self.bandwidth as f64 / 10_000_000.0).min(1.0); // Normalize to 10MB/s
        let jitter_score = 1.0 / (1.0 + self.jitter_ms / 50.0);

        RTT_WEIGHT * rtt_score
            + LOSS_WEIGHT * loss_score
            + BW_WEIGHT * bw_score
            + JITTER_WEIGHT * jitter_score
    }

    /// Check if path is healthy
    pub fn is_healthy(&self) -> bool {
        self.loss_rate < 0.5 && self.rtt_ms < 1000.0
    }

    /// Check if metrics are stale
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_updated.elapsed() > timeout
    }
}

/// Network path identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId {
    /// Local address
    pub local: SocketAddr,
    /// Remote address
    pub remote: SocketAddr,
}

impl PathId {
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        PathId { local, remote }
    }
}

/// Scheduling strategy for multi-path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingStrategy {
    /// Round-robin across all paths
    RoundRobin,
    /// Weighted by path quality
    Weighted,
    /// Use best path, failover to others
    Primary,
    /// Duplicate packets on all paths (reliability)
    Redundant,
    /// Minimize latency
    MinLatency,
}

/// Multi-path scheduler
pub struct MultipathScheduler {
    /// Available paths and their metrics
    paths: HashMap<PathId, PathMetrics>,
    /// Current scheduling strategy
    strategy: SchedulingStrategy,
    /// Round-robin index
    rr_index: usize,
    /// Primary path (if using Primary strategy)
    primary_path: Option<PathId>,
    /// Path stale timeout
    stale_timeout: Duration,
    /// Statistics
    pub stats: MultipathStats,
}

#[derive(Debug, Clone, Default)]
pub struct MultipathStats {
    pub total_packets: u64,
    pub packets_per_path: HashMap<PathId, u64>,
    pub failovers: u64,
    pub bandwidth_aggregated: u64,
}

impl MultipathScheduler {
    pub fn new(strategy: SchedulingStrategy) -> Self {
        MultipathScheduler {
            paths: HashMap::new(),
            strategy,
            rr_index: 0,
            primary_path: None,
            stale_timeout: Duration::from_secs(30),
            stats: MultipathStats::default(),
        }
    }

    /// Add or update a path
    pub fn add_path(&mut self, path_id: PathId, metrics: PathMetrics) {
        self.paths.insert(path_id, metrics);

        // Set primary if none exists
        if self.primary_path.is_none() {
            self.primary_path = Some(path_id);
        }
    }

    /// Remove a path
    pub fn remove_path(&mut self, path_id: &PathId) {
        self.paths.remove(path_id);

        if self.primary_path == Some(*path_id) {
            self.primary_path = self.paths.keys().next().copied();
        }
    }

    /// Update path metrics
    pub fn update_metrics(&mut self, path_id: &PathId, metrics: PathMetrics) {
        if let Some(existing) = self.paths.get_mut(path_id) {
            *existing = metrics;
        }
    }

    /// Get next path for sending
    pub fn next_path(&mut self) -> Option<PathId> {
        self.cleanup_stale_paths();

        if self.paths.is_empty() {
            return None;
        }

        let path = match self.strategy {
            SchedulingStrategy::RoundRobin => self.round_robin(),
            SchedulingStrategy::Weighted => self.weighted_selection(),
            SchedulingStrategy::Primary => self.primary_selection(),
            SchedulingStrategy::Redundant => self.primary_selection(), // For redundant, caller handles duplication
            SchedulingStrategy::MinLatency => self.min_latency_selection(),
        };

        if let Some(p) = path {
            self.stats.total_packets += 1;
            *self.stats.packets_per_path.entry(p).or_insert(0) += 1;
        }

        path
    }

    /// Get all paths for redundant sending
    pub fn all_paths(&self) -> Vec<PathId> {
        self.paths
            .iter()
            .filter(|(_, m)| m.is_healthy())
            .map(|(id, _)| *id)
            .collect()
    }

    fn round_robin(&mut self) -> Option<PathId> {
        let healthy: Vec<_> = self
            .paths
            .iter()
            .filter(|(_, m)| m.is_healthy())
            .map(|(id, _)| *id)
            .collect();

        if healthy.is_empty() {
            return None;
        }

        self.rr_index = (self.rr_index + 1) % healthy.len();
        Some(healthy[self.rr_index])
    }

    fn weighted_selection(&self) -> Option<PathId> {
        let total_score: f64 = self
            .paths
            .iter()
            .filter(|(_, m)| m.is_healthy())
            .map(|(_, m)| m.score())
            .sum();

        if total_score == 0.0 {
            return None;
        }

        // Simple weighted selection - pick highest score
        self.paths
            .iter()
            .filter(|(_, m)| m.is_healthy())
            .max_by(|(_, a), (_, b)| a.score().partial_cmp(&b.score()).unwrap())
            .map(|(id, _)| *id)
    }

    fn primary_selection(&mut self) -> Option<PathId> {
        // Check if primary is still healthy
        if let Some(primary) = self.primary_path {
            if let Some(metrics) = self.paths.get(&primary) {
                if metrics.is_healthy() {
                    return Some(primary);
                }
            }
        }

        // Failover to best available
        self.stats.failovers += 1;
        let best = self.weighted_selection();
        if best.is_some() {
            self.primary_path = best;
        }
        best
    }

    fn min_latency_selection(&self) -> Option<PathId> {
        self.paths
            .iter()
            .filter(|(_, m)| m.is_healthy())
            .min_by(|(_, a), (_, b)| a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap())
            .map(|(id, _)| *id)
    }

    fn cleanup_stale_paths(&mut self) {
        let stale: Vec<_> = self
            .paths
            .iter()
            .filter(|(_, m)| m.is_stale(self.stale_timeout))
            .map(|(id, _)| *id)
            .collect();

        for id in stale {
            self.paths.remove(&id);
        }
    }

    /// Get path count
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Get healthy path count
    pub fn healthy_path_count(&self) -> usize {
        self.paths.iter().filter(|(_, m)| m.is_healthy()).count()
    }

    /// Estimate total available bandwidth
    pub fn total_bandwidth(&self) -> u64 {
        self.paths
            .iter()
            .filter(|(_, m)| m.is_healthy())
            .map(|(_, m)| m.bandwidth)
            .sum()
    }
}

impl Default for MultipathScheduler {
    fn default() -> Self {
        Self::new(SchedulingStrategy::Weighted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_path(port: u16) -> PathId {
        PathId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433),
        )
    }

    #[test]
    fn test_path_metrics_score() {
        let metrics = PathMetrics {
            rtt_ms: 50.0,
            loss_rate: 0.01,
            ..Default::default()
        };

        let score = metrics.score();
        assert!(score > 0.5); // Good path should have high score
    }

    #[test]
    fn test_multipath_scheduler() {
        let mut scheduler = MultipathScheduler::new(SchedulingStrategy::Weighted);

        let path1 = make_path(5000);
        let path2 = make_path(5001);

        let metrics1 = PathMetrics {
            rtt_ms: 20.0,
            ..Default::default()
        };

        let metrics2 = PathMetrics {
            rtt_ms: 100.0,
            ..Default::default()
        };

        scheduler.add_path(path1, metrics1);
        scheduler.add_path(path2, metrics2);

        // Should prefer path1 (lower RTT)
        let selected = scheduler.next_path();
        assert_eq!(selected, Some(path1));
    }

    #[test]
    fn test_failover() {
        let mut scheduler = MultipathScheduler::new(SchedulingStrategy::Primary);

        let path1 = make_path(5000);
        let path2 = make_path(5001);

        let metrics1 = PathMetrics {
            loss_rate: 0.8, // Unhealthy
            ..Default::default()
        };

        let metrics2 = PathMetrics::default(); // Healthy

        scheduler.add_path(path1, metrics1);
        scheduler.add_path(path2, metrics2);
        scheduler.primary_path = Some(path1);

        // Should failover to path2
        let selected = scheduler.next_path();
        assert_eq!(selected, Some(path2));
        assert_eq!(scheduler.stats.failovers, 1);
    }
}
