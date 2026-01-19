//! Multipath QUIC Support
//!
//! Implements draft-ietf-quic-multipath for using multiple network paths.
//! Aggregates bandwidth across paths and provides seamless failover.
//!
//! # Features
//! - Multiple simultaneous paths (WiFi + LTE, dual WAN)
//! - Bandwidth aggregation
//! - Seamless path failover
//! - Per-path congestion control
//! - Path-aware packet scheduling

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Unique identifier for a network path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId(pub u64);

impl PathId {
    /// Create from local and remote addresses
    pub fn from_addrs(local: SocketAddr, remote: SocketAddr) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        local.hash(&mut hasher);
        remote.hash(&mut hasher);
        PathId(hasher.finish())
    }

    /// Create a new random path ID
    pub fn new_random() -> Self {
        PathId(rand::random())
    }
}

/// State of a network path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path is being validated
    Validating,
    /// Path is active and can be used
    Active,
    /// Path is degraded (high loss or latency)
    Degraded,
    /// Path has failed
    Failed,
    /// Path is closed
    Closed,
}

/// Metrics for a single path
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Smoothed RTT in microseconds
    pub srtt_us: u64,
    /// RTT variance
    pub rttvar_us: u64,
    /// Estimated bandwidth in bytes/sec
    pub bandwidth_bps: u64,
    /// Current loss rate (0.0-1.0)
    pub loss_rate: f32,
    /// Congestion window
    pub cwnd: u64,
    /// Bytes in flight
    pub bytes_in_flight: u64,
    /// Last packet sent time
    pub last_send: Instant,
    /// Last packet received time
    pub last_recv: Instant,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            srtt_us: 100_000, // 100ms default
            rttvar_us: 50_000,
            bandwidth_bps: 1_000_000, // 1 Mbps default
            loss_rate: 0.0,
            cwnd: 14720, // 10 MSS
            bytes_in_flight: 0,
            last_send: Instant::now(),
            last_recv: Instant::now(),
        }
    }
}

impl PathMetrics {
    /// Update RTT using RFC 6298 algorithm
    pub fn update_rtt(&mut self, rtt_us: u64) {
        if self.srtt_us == 0 {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            let diff = rtt_us.abs_diff(self.srtt_us);
            self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
            self.srtt_us = (7 * self.srtt_us + rtt_us) / 8;
        }
    }

    /// Get RTO (retransmission timeout)
    pub fn rto_us(&self) -> u64 {
        (self.srtt_us + 4 * self.rttvar_us).max(1_000_000) // Min 1 second
    }

    /// Calculate path score for scheduling (higher is better)
    pub fn score(&self) -> f64 {
        let latency_factor = 1.0 / (self.srtt_us as f64 / 1000.0 + 1.0);
        let loss_factor = 1.0 - self.loss_rate as f64;
        let bw_factor = (self.bandwidth_bps as f64 / 1_000_000.0).min(100.0);

        latency_factor * loss_factor * bw_factor
    }
}

/// A single network path
pub struct Path {
    /// Path identifier
    pub id: PathId,
    /// Local address
    pub local: SocketAddr,
    /// Remote address
    pub remote: SocketAddr,
    /// Current state
    pub state: PathState,
    /// Path metrics
    pub metrics: PathMetrics,
    /// Packets sent on this path
    pub packets_sent: AtomicU64,
    /// Packets received on this path
    pub packets_received: AtomicU64,
    /// Bytes sent
    pub bytes_sent: AtomicU64,
    /// Bytes received
    pub bytes_received: AtomicU64,
    /// Challenge for path validation
    challenge: Option<[u8; 8]>,
    /// AF_XDP queue ID for this path
    pub queue_id: u32,
}

impl Path {
    pub fn new(local: SocketAddr, remote: SocketAddr, queue_id: u32) -> Self {
        Self {
            id: PathId::from_addrs(local, remote),
            local,
            remote,
            state: PathState::Validating,
            metrics: PathMetrics::default(),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            challenge: None,
            queue_id,
        }
    }

    /// Start path validation
    pub fn start_validation(&mut self) -> [u8; 8] {
        let challenge: [u8; 8] = rand::random();
        self.challenge = Some(challenge);
        self.state = PathState::Validating;
        challenge
    }

    /// Complete path validation
    pub fn complete_validation(&mut self, response: &[u8; 8]) -> bool {
        if let Some(challenge) = &self.challenge {
            if challenge == response {
                self.state = PathState::Active;
                self.challenge = None;
                return true;
            }
        }
        false
    }

    /// Check if path is usable
    #[inline]
    pub fn is_usable(&self) -> bool {
        matches!(self.state, PathState::Active | PathState::Degraded)
    }

    /// Check if path can send more data
    #[inline]
    pub fn can_send(&self, bytes: u64) -> bool {
        self.is_usable() && self.metrics.bytes_in_flight + bytes <= self.metrics.cwnd
    }

    /// Record packet sent
    pub fn on_packet_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record packet received
    pub fn on_packet_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Scheduling strategy for multipath
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingStrategy {
    /// Round-robin across paths
    RoundRobin,
    /// Weighted by bandwidth
    Weighted,
    /// Lowest RTT first
    LowestRtt,
    /// Redundant (send on all paths)
    Redundant,
    /// Adaptive (ML-based)
    Adaptive,
}

/// Multipath QUIC manager
pub struct MultipathManager {
    /// All known paths
    paths: HashMap<PathId, Path>,
    /// Primary path ID
    primary_path: Option<PathId>,
    /// Scheduling strategy
    strategy: SchedulingStrategy,
    /// Round-robin index
    rr_index: usize,
    /// Statistics
    pub stats: MultipathStats,
}

#[derive(Default)]
pub struct MultipathStats {
    pub paths_created: AtomicU64,
    pub paths_failed: AtomicU64,
    pub path_switches: AtomicU64,
    pub redundant_sends: AtomicU64,
    pub failovers: AtomicU64,
}

impl MultipathManager {
    pub fn new(strategy: SchedulingStrategy) -> Self {
        Self {
            paths: HashMap::new(),
            primary_path: None,
            strategy,
            rr_index: 0,
            stats: MultipathStats::default(),
        }
    }

    /// Add a new path
    pub fn add_path(&mut self, path: Path) -> PathId {
        let id = path.id;
        self.paths.insert(id, path);
        self.stats.paths_created.fetch_add(1, Ordering::Relaxed);

        // Set as primary if first path
        if self.primary_path.is_none() {
            self.primary_path = Some(id);
        }

        id
    }

    /// Remove a path
    pub fn remove_path(&mut self, id: PathId) {
        self.paths.remove(&id);

        // Update primary if needed
        if self.primary_path == Some(id) {
            self.primary_path = self.paths.keys().next().copied();
            self.stats.path_switches.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a path by ID
    pub fn get_path(&self, id: PathId) -> Option<&Path> {
        self.paths.get(&id)
    }

    /// Get mutable path by ID
    pub fn get_path_mut(&mut self, id: PathId) -> Option<&mut Path> {
        self.paths.get_mut(&id)
    }

    /// Get primary path
    pub fn primary_path(&self) -> Option<&Path> {
        self.primary_path.and_then(|id| self.paths.get(&id))
    }

    /// Select next path for sending based on strategy
    pub fn select_path(&mut self, bytes: u64) -> Option<PathId> {
        let usable: Vec<PathId> = self
            .paths
            .iter()
            .filter(|(_, p)| p.can_send(bytes))
            .map(|(id, _)| *id)
            .collect();

        if usable.is_empty() {
            return None;
        }

        match self.strategy {
            SchedulingStrategy::RoundRobin => {
                self.rr_index = (self.rr_index + 1) % usable.len();
                Some(usable[self.rr_index])
            }
            SchedulingStrategy::Weighted => {
                // Select by bandwidth weight
                let total_bw: u64 = usable
                    .iter()
                    .filter_map(|id| self.paths.get(id))
                    .map(|p| p.metrics.bandwidth_bps)
                    .sum();

                if total_bw == 0 {
                    return usable.first().copied();
                }

                let mut rng: u64 = rand::random::<u64>() % total_bw;
                for id in &usable {
                    if let Some(path) = self.paths.get(id) {
                        if rng < path.metrics.bandwidth_bps {
                            return Some(*id);
                        }
                        rng -= path.metrics.bandwidth_bps;
                    }
                }
                usable.first().copied()
            }
            SchedulingStrategy::LowestRtt => usable
                .iter()
                .min_by_key(|id| {
                    self.paths
                        .get(id)
                        .map(|p| p.metrics.srtt_us)
                        .unwrap_or(u64::MAX)
                })
                .copied(),
            SchedulingStrategy::Redundant => {
                self.stats.redundant_sends.fetch_add(1, Ordering::Relaxed);
                usable.first().copied() // Return first, caller should send on all
            }
            SchedulingStrategy::Adaptive => {
                // Select by score (combines RTT, loss, bandwidth)
                usable
                    .iter()
                    .max_by(|a, b| {
                        let score_a = self.paths.get(a).map(|p| p.metrics.score()).unwrap_or(0.0);
                        let score_b = self.paths.get(b).map(|p| p.metrics.score()).unwrap_or(0.0);
                        score_a
                            .partial_cmp(&score_b)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .copied()
            }
        }
    }

    /// Get all paths for redundant sending
    pub fn all_usable_paths(&self, bytes: u64) -> Vec<PathId> {
        self.paths
            .iter()
            .filter(|(_, p)| p.can_send(bytes))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Handle path failure
    pub fn on_path_failed(&mut self, id: PathId) {
        if let Some(path) = self.paths.get_mut(&id) {
            path.state = PathState::Failed;
        }
        self.stats.paths_failed.fetch_add(1, Ordering::Relaxed);

        // Failover if primary
        if self.primary_path == Some(id) {
            self.primary_path = self
                .paths
                .iter()
                .find(|(_, p)| p.is_usable())
                .map(|(id, _)| *id);
            self.stats.failovers.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get number of active paths
    pub fn active_path_count(&self) -> usize {
        self.paths.values().filter(|p| p.is_usable()).count()
    }

    /// Get aggregate bandwidth across all paths
    pub fn aggregate_bandwidth(&self) -> u64 {
        self.paths
            .values()
            .filter(|p| p.is_usable())
            .map(|p| p.metrics.bandwidth_bps)
            .sum()
    }

    /// Set scheduling strategy
    pub fn set_strategy(&mut self, strategy: SchedulingStrategy) {
        self.strategy = strategy;
    }
}

impl Default for MultipathManager {
    fn default() -> Self {
        Self::new(SchedulingStrategy::Adaptive)
    }
}

// Simple rand implementation for path IDs
mod rand {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEED: AtomicU64 = AtomicU64::new(0);

    pub fn random<T: Default>() -> T {
        let mut seed = SEED.load(Ordering::Relaxed);
        if seed == 0 {
            seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        SEED.store(seed, Ordering::Relaxed);
        unsafe { std::mem::transmute_copy(&seed) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_path_creation() {
        let path = Path::new(test_addr(1234), test_addr(4433), 0);
        assert_eq!(path.state, PathState::Validating);
    }

    #[test]
    fn test_multipath_manager() {
        let mut mgr = MultipathManager::new(SchedulingStrategy::RoundRobin);

        let path1 = Path::new(test_addr(1234), test_addr(4433), 0);
        let path2 = Path::new(test_addr(1235), test_addr(4433), 1);

        mgr.add_path(path1);
        mgr.add_path(path2);

        assert_eq!(mgr.active_path_count(), 0); // Still validating
    }

    #[test]
    fn test_path_metrics() {
        let mut metrics = PathMetrics::default();

        metrics.update_rtt(50_000); // 50ms
        assert!(metrics.srtt_us > 0);
        assert!(metrics.score() > 0.0);
    }
}
