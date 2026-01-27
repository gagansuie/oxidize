//! Relay Mesh Manager
//!
//! Server-side integration of the relay mesh for:
//! - Multi-region relay coordination
//! - Health monitoring between relays
//! - Automatic failover
//! - Load balancing

use anyhow::Result;
use oxidize_common::relay_mesh::{
    EdgeInfo, HealthStatus, MeshConfig, MeshSnapshot, Region, RelayId, RelayMesh, RelayNode,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Manages relay mesh for server-to-server coordination
pub struct MeshManager {
    mesh: Arc<RwLock<RelayMesh>>,
    local_addr: SocketAddr,
    local_region: Region,
    config: MeshManagerConfig,
}

/// Configuration for the mesh manager
#[derive(Debug, Clone)]
pub struct MeshManagerConfig {
    /// How often to check peer health
    pub health_check_interval: Duration,
    /// Timeout for health check probes
    pub health_check_timeout: Duration,
    /// This relay's region
    pub region: Region,
    /// This relay's capacity (max connections)
    pub capacity: u32,
    /// Peer relay addresses to connect to
    pub peer_addresses: Vec<SocketAddr>,
}

impl Default for MeshManagerConfig {
    fn default() -> Self {
        MeshManagerConfig {
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(5),
            region: Region::UsEast,
            capacity: 10000,
            peer_addresses: vec![],
        }
    }
}

impl MeshManager {
    /// Create a new mesh manager
    pub fn new(local_addr: SocketAddr, config: MeshManagerConfig) -> Self {
        let mesh_config = MeshConfig {
            health_check_interval: config.health_check_interval,
            path_cache_ttl: Duration::from_secs(60),
            max_hops: 3,
            prefer_latency: true,
            max_latency: Duration::from_millis(500),
        };

        let mut mesh = RelayMesh::new(mesh_config);
        let local_id = RelayId::from_addr(local_addr);
        mesh.set_local_id(local_id);

        // Register ourselves
        let local_node = RelayNode {
            id: local_id,
            name: format!("relay-{}", local_addr.port()),
            region: config.region,
            address: local_addr,
            backup_addresses: vec![],
            health: HealthStatus::Healthy,
            last_check: Instant::now(),
            rtt: Duration::ZERO,
            load: 0,
            capacity: config.capacity,
            active_connections: 0,
        };
        mesh.add_node(local_node);

        MeshManager {
            mesh: Arc::new(RwLock::new(mesh)),
            local_addr,
            local_region: config.region,
            config,
        }
    }

    /// Start the mesh manager background tasks
    pub async fn start(&self) -> Result<()> {
        info!(
            "Starting mesh manager for {} in {:?}",
            self.local_addr, self.local_region
        );

        // Register peer relays
        for peer_addr in &self.config.peer_addresses {
            self.add_peer(*peer_addr, self.local_region).await;
        }

        // Start health check loop
        let mesh = self.mesh.clone();
        let peer_addrs = self.config.peer_addresses.clone();
        let check_interval = self.config.health_check_interval;
        let check_timeout = self.config.health_check_timeout;

        tokio::spawn(async move {
            let mut ticker = interval(check_interval);
            loop {
                ticker.tick().await;
                for peer_addr in &peer_addrs {
                    let peer_id = RelayId::from_addr(*peer_addr);

                    // Measure RTT with a simple probe
                    let start = Instant::now();
                    let health =
                        match tokio::time::timeout(check_timeout, probe_peer(*peer_addr)).await {
                            Ok(Ok(())) => {
                                let rtt = start.elapsed();
                                debug!("Peer {} healthy, RTT: {:?}", peer_addr, rtt);
                                (HealthStatus::Healthy, rtt)
                            }
                            Ok(Err(e)) => {
                                warn!("Peer {} probe failed: {}", peer_addr, e);
                                (HealthStatus::Degraded, Duration::from_secs(999))
                            }
                            Err(_) => {
                                warn!("Peer {} probe timed out", peer_addr);
                                (HealthStatus::Unhealthy, Duration::from_secs(999))
                            }
                        };

                    let mut mesh = mesh.write().await;
                    mesh.update_health(peer_id, health.0, health.1);
                }
            }
        });

        Ok(())
    }

    /// Add a peer relay to the mesh
    pub async fn add_peer(&self, addr: SocketAddr, region: Region) {
        let peer_id = RelayId::from_addr(addr);
        let local_id = RelayId::from_addr(self.local_addr);

        let node = RelayNode {
            id: peer_id,
            name: format!("relay-{}", addr.port()),
            region,
            address: addr,
            backup_addresses: vec![],
            health: HealthStatus::Unknown,
            last_check: Instant::now(),
            rtt: Duration::from_millis(100), // Initial estimate
            load: 0,
            capacity: 10000,
            active_connections: 0,
        };

        let mut mesh = self.mesh.write().await;
        mesh.add_node(node);

        // Add bidirectional edge
        let estimated_latency = Duration::from_millis(self.local_region.latency_to(&region) as u64);
        mesh.update_edge(
            local_id,
            peer_id,
            EdgeInfo {
                latency: estimated_latency,
                loss_rate: 0.0,
                last_measured: Instant::now(),
                healthy: true,
            },
        );
        mesh.update_edge(
            peer_id,
            local_id,
            EdgeInfo {
                latency: estimated_latency,
                loss_rate: 0.0,
                last_measured: Instant::now(),
                healthy: true,
            },
        );

        info!("Added peer relay: {} in {:?}", addr, region);
    }

    /// Update local load metrics
    pub async fn update_local_load(&self, active_connections: u32, load_percent: u8) {
        let local_id = RelayId::from_addr(self.local_addr);
        let mut mesh = self.mesh.write().await;

        if let Some(nodes) = mesh.nodes.get_mut(&local_id) {
            nodes.active_connections = active_connections;
            nodes.load = load_percent;
        }
    }

    /// Get the best relay for a client in a specific region
    pub async fn best_relay_for_region(&self, client_region: Region) -> Option<SocketAddr> {
        let mesh = self.mesh.read().await;
        mesh.nearest_relay(client_region).map(|n| n.address)
    }

    /// Get mesh statistics
    pub async fn get_stats(&self) -> MeshSnapshot {
        let mesh = self.mesh.read().await;
        mesh.get_stats()
    }

    /// Mark a peer as unhealthy (manual failover)
    pub async fn mark_peer_unhealthy(&self, addr: SocketAddr) {
        let peer_id = RelayId::from_addr(addr);
        let mut mesh = self.mesh.write().await;
        mesh.mark_unhealthy(peer_id);
        warn!("Marked peer {} as unhealthy", addr);
    }

    /// Get all healthy peers
    pub async fn healthy_peers(&self) -> Vec<SocketAddr> {
        let mesh = self.mesh.read().await;
        mesh.nodes
            .values()
            .filter(|n| n.health == HealthStatus::Healthy && n.address != self.local_addr)
            .map(|n| n.address)
            .collect()
    }
}

/// Probe a peer relay to check health
async fn probe_peer(addr: SocketAddr) -> Result<()> {
    // Simple TCP connect probe
    let _stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_mesh_manager_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820);
        let config = MeshManagerConfig::default();
        let manager = MeshManager::new(addr, config);

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_nodes, 1); // Just ourselves
    }

    #[tokio::test]
    async fn test_add_peer() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51821);

        let config = MeshManagerConfig::default();
        let manager = MeshManager::new(local, config);

        manager.add_peer(peer, Region::UsWest).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.total_edges, 2); // Bidirectional
    }
}
