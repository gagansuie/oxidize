//! Multi-Region Relay Mesh
//!
//! Implements relay-to-relay routing for optimal path selection.
//! Supports automatic failover and load balancing across multiple relays.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Relay node identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayId(pub u64);

impl RelayId {
    pub fn new(id: u64) -> Self {
        RelayId(id)
    }

    pub fn from_addr(addr: SocketAddr) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        addr.hash(&mut hasher);
        RelayId(hasher.finish())
    }
}

/// Geographic region
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    UsEast,
    UsWest,
    EuWest,
    EuCentral,
    AsiaPacific,
    SouthAmerica,
    Africa,
    Oceania,
    Custom(u16),
}

impl Region {
    /// Estimate latency between regions (in ms)
    pub fn latency_to(&self, other: &Region) -> u32 {
        use Region::*;
        if self == other {
            return 5; // Same region
        }
        match (self, other) {
            // US internal
            (UsEast, UsWest) | (UsWest, UsEast) => 60,
            // Transatlantic
            (UsEast, EuWest) | (EuWest, UsEast) => 80,
            (UsEast, EuCentral) | (EuCentral, UsEast) => 90,
            // EU internal
            (EuWest, EuCentral) | (EuCentral, EuWest) => 20,
            // Transpacific
            (UsWest, AsiaPacific) | (AsiaPacific, UsWest) => 120,
            // Default cross-region
            _ => 150,
        }
    }
}

/// Relay node information
#[derive(Debug, Clone)]
pub struct RelayNode {
    /// Unique identifier
    pub id: RelayId,
    /// Display name
    pub name: String,
    /// Region
    pub region: Region,
    /// Primary address
    pub address: SocketAddr,
    /// Backup addresses
    pub backup_addresses: Vec<SocketAddr>,
    /// Current health status
    pub health: HealthStatus,
    /// Last health check
    pub last_check: Instant,
    /// Average RTT to this node (from our perspective)
    pub rtt: Duration,
    /// Current load (0-100)
    pub load: u8,
    /// Capacity (connections)
    pub capacity: u32,
    /// Active connections
    pub active_connections: u32,
}

/// Health status of a relay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Healthy and accepting connections
    Healthy,
    /// Degraded performance
    Degraded,
    /// Not accepting new connections
    Draining,
    /// Unreachable
    Unhealthy,
    /// Status unknown
    Unknown,
}

/// Path through the mesh
#[derive(Debug, Clone)]
pub struct MeshPath {
    /// Ordered list of relay IDs
    pub hops: Vec<RelayId>,
    /// Total estimated latency
    pub total_latency: Duration,
    /// Path health score (0-100)
    pub health_score: u8,
    /// When path was computed
    pub computed_at: Instant,
}

/// Mesh routing statistics
#[derive(Debug, Default)]
pub struct MeshStats {
    pub paths_computed: AtomicU64,
    pub failovers: AtomicU64,
    pub health_checks: AtomicU64,
    pub packets_routed: AtomicU64,
}

/// Multi-region relay mesh manager
pub struct RelayMesh {
    /// Known relay nodes
    pub nodes: HashMap<RelayId, RelayNode>,
    /// Direct connections between relays (adjacency)
    pub edges: HashMap<(RelayId, RelayId), EdgeInfo>,
    /// Our local relay ID (if we are a relay)
    local_id: Option<RelayId>,
    /// Cached paths
    path_cache: HashMap<(RelayId, RelayId), MeshPath>,
    /// Configuration
    config: MeshConfig,
    /// Statistics
    pub stats: MeshStats,
}

/// Edge information between two relays
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    /// Measured latency
    pub latency: Duration,
    /// Packet loss rate (0.0-1.0)
    pub loss_rate: f32,
    /// Last measurement
    pub last_measured: Instant,
    /// Is this edge healthy?
    pub healthy: bool,
}

/// Mesh configuration
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Health check interval
    pub health_check_interval: Duration,
    /// Path cache TTL
    pub path_cache_ttl: Duration,
    /// Maximum hops in a path
    pub max_hops: usize,
    /// Prefer lower latency over load balancing
    pub prefer_latency: bool,
    /// Maximum acceptable latency
    pub max_latency: Duration,
}

impl Default for MeshConfig {
    fn default() -> Self {
        MeshConfig {
            health_check_interval: Duration::from_secs(30),
            path_cache_ttl: Duration::from_secs(60),
            max_hops: 3,
            prefer_latency: true,
            max_latency: Duration::from_millis(500),
        }
    }
}

impl RelayMesh {
    pub fn new(config: MeshConfig) -> Self {
        RelayMesh {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            local_id: None,
            path_cache: HashMap::new(),
            config,
            stats: MeshStats::default(),
        }
    }

    /// Set our local relay ID
    pub fn set_local_id(&mut self, id: RelayId) {
        self.local_id = Some(id);
    }

    /// Add or update a relay node
    pub fn add_node(&mut self, node: RelayNode) {
        self.nodes.insert(node.id, node);
    }

    /// Remove a relay node
    pub fn remove_node(&mut self, id: RelayId) {
        self.nodes.remove(&id);
        // Remove edges involving this node
        self.edges.retain(|(a, b), _| *a != id && *b != id);
        // Invalidate cached paths
        self.path_cache.retain(|(a, b), _| *a != id && *b != id);
    }

    /// Update edge information
    pub fn update_edge(&mut self, from: RelayId, to: RelayId, info: EdgeInfo) {
        self.edges.insert((from, to), info);
    }

    /// Get the best path to a destination region
    pub fn best_path_to_region(&mut self, dest_region: Region) -> Option<MeshPath> {
        let local_id = self.local_id?;

        // Find closest healthy node in destination region
        let dest_node = self
            .nodes
            .values()
            .filter(|n| n.region == dest_region && n.health == HealthStatus::Healthy)
            .min_by_key(|n| n.rtt)?;

        self.best_path(local_id, dest_node.id)
    }

    /// Get the best path between two relays
    pub fn best_path(&mut self, from: RelayId, to: RelayId) -> Option<MeshPath> {
        // Check cache first
        if let Some(cached) = self.path_cache.get(&(from, to)) {
            if cached.computed_at.elapsed() < self.config.path_cache_ttl {
                return Some(cached.clone());
            }
        }

        // Compute new path using Dijkstra's algorithm
        let path = self.compute_path(from, to)?;
        self.path_cache.insert((from, to), path.clone());
        self.stats.paths_computed.fetch_add(1, Ordering::Relaxed);

        Some(path)
    }

    /// Compute shortest path using Dijkstra
    fn compute_path(&self, from: RelayId, to: RelayId) -> Option<MeshPath> {
        if from == to {
            return Some(MeshPath {
                hops: vec![from],
                total_latency: Duration::ZERO,
                health_score: 100,
                computed_at: Instant::now(),
            });
        }

        // Simple BFS for now (could optimize with proper Dijkstra)
        let mut visited = HashMap::new();
        let mut queue = vec![(from, vec![from], Duration::ZERO)];

        while let Some((current, path, latency)) = queue.pop() {
            if current == to {
                let health_score = self.calculate_path_health(&path);
                return Some(MeshPath {
                    hops: path,
                    total_latency: latency,
                    health_score,
                    computed_at: Instant::now(),
                });
            }

            if path.len() > self.config.max_hops {
                continue;
            }

            if visited.contains_key(&current) {
                continue;
            }
            visited.insert(current, true);

            // Find neighbors
            for ((a, b), edge) in &self.edges {
                if *a == current && edge.healthy {
                    let mut new_path = path.clone();
                    new_path.push(*b);
                    queue.push((*b, new_path, latency + edge.latency));
                }
            }
        }

        None
    }

    /// Calculate health score for a path
    fn calculate_path_health(&self, path: &[RelayId]) -> u8 {
        if path.is_empty() {
            return 0;
        }

        let mut total_score = 0u32;
        let mut count = 0u32;

        for id in path {
            if let Some(node) = self.nodes.get(id) {
                let node_score = match node.health {
                    HealthStatus::Healthy => 100,
                    HealthStatus::Degraded => 70,
                    HealthStatus::Draining => 30,
                    HealthStatus::Unhealthy | HealthStatus::Unknown => 0,
                };
                total_score += node_score - node.load as u32;
                count += 1;
            }
        }

        if count == 0 {
            0
        } else {
            (total_score / count).min(100) as u8
        }
    }

    /// Get the nearest relay to a client
    pub fn nearest_relay(&self, client_region: Region) -> Option<&RelayNode> {
        self.nodes
            .values()
            .filter(|n| n.health == HealthStatus::Healthy)
            .min_by_key(|n| {
                let region_latency = client_region.latency_to(&n.region);
                let load_penalty = n.load as u32 * 2;
                region_latency + load_penalty
            })
    }

    /// Get all healthy relays in a region
    pub fn relays_in_region(&self, region: Region) -> Vec<&RelayNode> {
        self.nodes
            .values()
            .filter(|n| n.region == region && n.health == HealthStatus::Healthy)
            .collect()
    }

    /// Mark a relay as unhealthy (for failover)
    pub fn mark_unhealthy(&mut self, id: RelayId) {
        if let Some(node) = self.nodes.get_mut(&id) {
            node.health = HealthStatus::Unhealthy;
            node.last_check = Instant::now();
        }
        // Invalidate paths through this node
        self.path_cache
            .retain(|(_, _), path| !path.hops.contains(&id));
        self.stats.failovers.fetch_add(1, Ordering::Relaxed);
    }

    /// Update relay health status
    pub fn update_health(&mut self, id: RelayId, health: HealthStatus, rtt: Duration) {
        if let Some(node) = self.nodes.get_mut(&id) {
            node.health = health;
            node.rtt = rtt;
            node.last_check = Instant::now();
        }
        self.stats.health_checks.fetch_add(1, Ordering::Relaxed);
    }

    /// Get mesh statistics
    pub fn get_stats(&self) -> MeshSnapshot {
        let healthy_count = self
            .nodes
            .values()
            .filter(|n| n.health == HealthStatus::Healthy)
            .count();

        MeshSnapshot {
            total_nodes: self.nodes.len(),
            healthy_nodes: healthy_count,
            total_edges: self.edges.len(),
            cached_paths: self.path_cache.len(),
            paths_computed: self.stats.paths_computed.load(Ordering::Relaxed),
            failovers: self.stats.failovers.load(Ordering::Relaxed),
        }
    }
}

impl Default for RelayMesh {
    fn default() -> Self {
        Self::new(MeshConfig::default())
    }
}

/// Mesh statistics snapshot
#[derive(Debug, Clone)]
pub struct MeshSnapshot {
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub total_edges: usize,
    pub cached_paths: usize,
    pub paths_computed: u64,
    pub failovers: u64,
}

/// Select the best relay based on health and load
pub fn select_best_relay(relays: &[RelayNode]) -> Option<&RelayNode> {
    relays
        .iter()
        .filter(|r| r.health == HealthStatus::Healthy)
        .min_by_key(|r| {
            let load_score = r.load as u32;
            let capacity_score = if r.active_connections < r.capacity {
                0
            } else {
                100
            };
            load_score + capacity_score
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn test_node(id: u64, region: Region, port: u16) -> RelayNode {
        RelayNode {
            id: RelayId::new(id),
            name: format!("relay-{}", id),
            region,
            address: test_addr(port),
            backup_addresses: vec![],
            health: HealthStatus::Healthy,
            last_check: Instant::now(),
            rtt: Duration::from_millis(10),
            load: 20,
            capacity: 1000,
            active_connections: 100,
        }
    }

    #[test]
    fn test_add_nodes() {
        let mut mesh = RelayMesh::default();
        mesh.add_node(test_node(1, Region::UsEast, 4433));
        mesh.add_node(test_node(2, Region::UsWest, 4434));

        assert_eq!(mesh.nodes.len(), 2);
    }

    #[test]
    fn test_nearest_relay() {
        let mut mesh = RelayMesh::default();
        mesh.add_node(test_node(1, Region::UsEast, 4433));
        mesh.add_node(test_node(2, Region::EuWest, 4434));

        let nearest = mesh.nearest_relay(Region::UsEast).unwrap();
        assert_eq!(nearest.id, RelayId::new(1));
    }

    #[test]
    fn test_region_latency() {
        assert_eq!(Region::UsEast.latency_to(&Region::UsEast), 5);
        assert_eq!(Region::UsEast.latency_to(&Region::UsWest), 60);
        assert_eq!(Region::UsEast.latency_to(&Region::EuWest), 80);
    }

    #[test]
    fn test_path_computation() {
        let mut mesh = RelayMesh::default();
        mesh.set_local_id(RelayId::new(1));
        mesh.add_node(test_node(1, Region::UsEast, 4433));
        mesh.add_node(test_node(2, Region::UsWest, 4434));

        mesh.update_edge(
            RelayId::new(1),
            RelayId::new(2),
            EdgeInfo {
                latency: Duration::from_millis(60),
                loss_rate: 0.0,
                last_measured: Instant::now(),
                healthy: true,
            },
        );

        let path = mesh.best_path(RelayId::new(1), RelayId::new(2)).unwrap();
        assert_eq!(path.hops.len(), 2);
        assert_eq!(path.total_latency, Duration::from_millis(60));
    }
}
