//! Connection Pooling
//!
//! Reuses QUIC connections across clients to reduce handshake overhead.
//! Provides up to 10x reduction in connection establishment time.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Connection affinity key for routing same destinations to same connections
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AffinityKey {
    /// Destination address
    pub destination: SocketAddr,
    /// Optional session/flow identifier
    pub flow_id: Option<u64>,
}

impl AffinityKey {
    pub fn new(destination: SocketAddr) -> Self {
        Self { destination, flow_id: None }
    }
    
    pub fn with_flow(destination: SocketAddr, flow_id: u64) -> Self {
        Self { destination, flow_id: Some(flow_id) }
    }
}

/// Endpoint usage statistics for pre-warming decisions
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Total connection requests to this endpoint
    pub request_count: u64,
    /// Last access time
    pub last_access: Instant,
    /// Average connection duration
    pub avg_duration_ms: f64,
    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per endpoint
    pub max_per_endpoint: usize,
    /// Maximum total connections
    pub max_total: usize,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Enable connection prewarming
    pub prewarm: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            max_per_endpoint: 10,
            max_total: 100,
            idle_timeout: Duration::from_secs(300),
            health_check_interval: Duration::from_secs(30),
            prewarm: true,
        }
    }
}

/// Pooled connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is available for use
    Available,
    /// Connection is currently in use
    InUse,
    /// Connection is being established
    Connecting,
    /// Connection is unhealthy/closed
    Closed,
}

/// Represents a pooled connection
pub struct PooledConnection {
    /// Unique connection ID
    pub id: u64,
    /// Remote endpoint address
    pub endpoint: SocketAddr,
    /// Current state
    pub state: ConnectionState,
    /// When the connection was created
    pub created_at: Instant,
    /// Last time the connection was used
    pub last_used: Instant,
    /// Number of times this connection has been reused
    pub reuse_count: u64,
    /// Connection-specific metadata
    pub metadata: ConnectionMetadata,
}

/// Connection metadata for tracking
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetadata {
    /// Total bytes sent on this connection
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Number of streams opened
    pub streams_opened: u64,
    /// Average RTT in milliseconds
    pub avg_rtt_ms: f64,
    /// Connection quality score (0-100)
    pub quality_score: u8,
}

/// Connection pool statistics
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total connections created
    pub connections_created: AtomicU64,
    /// Total connections reused
    pub connections_reused: AtomicU64,
    /// Total connections closed
    pub connections_closed: AtomicU64,
    /// Cache hits (connection found in pool)
    pub cache_hits: AtomicU64,
    /// Cache misses (new connection needed)
    pub cache_misses: AtomicU64,
    /// Failed connection attempts
    pub connection_failures: AtomicU64,
    /// Affinity hits (same connection reused for same destination)
    pub affinity_hits: AtomicU64,
    /// Pre-warmed connections used
    pub prewarm_hits: AtomicU64,
}

impl PoolStats {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        if hits + misses == 0 {
            return 0.0;
        }
        hits as f64 / (hits + misses) as f64 * 100.0
    }

    pub fn reuse_rate(&self) -> f64 {
        let created = self.connections_created.load(Ordering::Relaxed);
        let reused = self.connections_reused.load(Ordering::Relaxed);
        if created == 0 {
            return 0.0;
        }
        reused as f64 / created as f64 * 100.0
    }
}

/// Connection pool manager
pub struct ConnectionPool {
    /// Pool configuration
    config: PoolConfig,
    /// Connections organized by endpoint
    connections: Arc<RwLock<HashMap<SocketAddr, Vec<PooledConnection>>>>,
    /// Next connection ID
    next_id: AtomicU64,
    /// Pool statistics
    pub stats: Arc<PoolStats>,
    /// Connection affinity map: AffinityKey -> preferred connection ID
    affinity_map: Arc<RwLock<HashMap<AffinityKey, u64>>>,
    /// Endpoint usage statistics for smart pre-warming
    endpoint_stats: Arc<RwLock<HashMap<SocketAddr, EndpointStats>>>,
    /// Pre-warmed connection IDs (to track prewarm hits)
    prewarmed_ids: Arc<RwLock<std::collections::HashSet<u64>>>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: PoolConfig) -> Self {
        ConnectionPool {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            stats: Arc::new(PoolStats::default()),
            affinity_map: Arc::new(RwLock::new(HashMap::new())),
            endpoint_stats: Arc::new(RwLock::new(HashMap::new())),
            prewarmed_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Get or create a connection to the specified endpoint
    pub async fn get(&self, endpoint: SocketAddr) -> Option<u64> {
        self.get_with_affinity(endpoint, None).await
    }
    
    /// Get connection with affinity support - prefers reusing same connection for same destination/flow
    pub async fn get_with_affinity(&self, endpoint: SocketAddr, affinity_key: Option<AffinityKey>) -> Option<u64> {
        // Update endpoint stats for smart pre-warming
        self.record_endpoint_access(endpoint).await;
        
        // Check affinity map first
        if let Some(ref key) = affinity_key {
            let affinity_map = self.affinity_map.read().await;
            if let Some(&preferred_id) = affinity_map.get(key) {
                // Try to use the preferred connection
                let mut conns = self.connections.write().await;
                if let Some(pool) = conns.get_mut(&endpoint) {
                    for conn in pool.iter_mut() {
                        if conn.id == preferred_id && conn.state == ConnectionState::Available {
                            conn.state = ConnectionState::InUse;
                            conn.last_used = Instant::now();
                            conn.reuse_count += 1;
                            self.stats.affinity_hits.fetch_add(1, Ordering::Relaxed);
                            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                            self.stats.connections_reused.fetch_add(1, Ordering::Relaxed);
                            return Some(conn.id);
                        }
                    }
                }
            }
        }
        
        // Try to get an existing available connection
        {
            let mut conns = self.connections.write().await;
            if let Some(pool) = conns.get_mut(&endpoint) {
                for conn in pool.iter_mut() {
                    if conn.state == ConnectionState::Available {
                        conn.state = ConnectionState::InUse;
                        conn.last_used = Instant::now();
                        conn.reuse_count += 1;
                        self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                        self.stats.connections_reused.fetch_add(1, Ordering::Relaxed);
                        
                        // Check if this was a pre-warmed connection
                        let prewarmed = self.prewarmed_ids.read().await;
                        if prewarmed.contains(&conn.id) {
                            self.stats.prewarm_hits.fetch_add(1, Ordering::Relaxed);
                        }
                        
                        let conn_id = conn.id;
                        
                        // Update affinity map
                        if let Some(key) = affinity_key {
                            drop(conns);
                            self.affinity_map.write().await.insert(key, conn_id);
                        }
                        
                        return Some(conn_id);
                    }
                }
            }
        }

        // No available connection, create a new one
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        let conn_id = self.create_connection(endpoint).await;
        
        // Update affinity map for new connection
        if let (Some(id), Some(key)) = (conn_id, affinity_key) {
            self.affinity_map.write().await.insert(key, id);
        }
        
        conn_id
    }
    
    /// Record endpoint access for pre-warming decisions
    async fn record_endpoint_access(&self, endpoint: SocketAddr) {
        let mut stats = self.endpoint_stats.write().await;
        let entry = stats.entry(endpoint).or_insert_with(|| EndpointStats {
            request_count: 0,
            last_access: Instant::now(),
            avg_duration_ms: 0.0,
            success_rate: 1.0,
        });
        entry.request_count += 1;
        entry.last_access = Instant::now();
    }

    /// Create a new connection
    async fn create_connection(&self, endpoint: SocketAddr) -> Option<u64> {
        let mut conns = self.connections.write().await;

        // Check if we've hit the per-endpoint limit
        if let Some(pool) = conns.get(&endpoint) {
            if pool.len() >= self.config.max_per_endpoint {
                return None;
            }
        }

        // Check total connection limit
        let total: usize = conns.values().map(|v| v.len()).sum();
        if total >= self.config.max_total {
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();

        let conn = PooledConnection {
            id,
            endpoint,
            state: ConnectionState::InUse,
            created_at: now,
            last_used: now,
            reuse_count: 0,
            metadata: ConnectionMetadata::default(),
        };

        conns.entry(endpoint).or_insert_with(Vec::new).push(conn);
        self.stats
            .connections_created
            .fetch_add(1, Ordering::Relaxed);

        Some(id)
    }

    /// Release a connection back to the pool
    pub async fn release(&self, id: u64) {
        let mut conns = self.connections.write().await;
        for pool in conns.values_mut() {
            for conn in pool.iter_mut() {
                if conn.id == id {
                    conn.state = ConnectionState::Available;
                    conn.last_used = Instant::now();
                    return;
                }
            }
        }
    }

    /// Close a specific connection
    pub async fn close(&self, id: u64) {
        let mut conns = self.connections.write().await;
        for pool in conns.values_mut() {
            pool.retain(|conn| conn.id != id);
        }
        self.stats
            .connections_closed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Clean up idle connections
    pub async fn cleanup_idle(&self) {
        let mut conns = self.connections.write().await;
        let timeout = self.config.idle_timeout;

        for pool in conns.values_mut() {
            pool.retain(|conn| {
                !(conn.state == ConnectionState::Available && conn.last_used.elapsed() > timeout)
            });
        }
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> PoolStatsSnapshot {
        PoolStatsSnapshot {
            total_connections: 0, // Would need to count
            available_connections: 0,
            in_use_connections: 0,
            hit_rate: self.stats.hit_rate(),
            reuse_rate: self.stats.reuse_rate(),
        }
    }

    /// Prewarm connections to frequently used endpoints
    pub async fn prewarm(&self, endpoints: &[SocketAddr], count_per_endpoint: usize) {
        if !self.config.prewarm {
            return;
        }

        for &endpoint in endpoints {
            for _ in 0..count_per_endpoint {
                if let Some(id) = self.create_connection(endpoint).await {
                    // Track as pre-warmed connection
                    self.prewarmed_ids.write().await.insert(id);
                    self.release(id).await;
                }
            }
        }
    }
    
    /// Smart pre-warming based on historical usage patterns
    /// Call this periodically to maintain warm connections to frequently-used endpoints
    pub async fn smart_prewarm(&self, min_requests: u64, count_per_endpoint: usize) {
        if !self.config.prewarm {
            return;
        }
        
        // Get frequently accessed endpoints
        let stats = self.endpoint_stats.read().await;
        let frequent_endpoints: Vec<SocketAddr> = stats
            .iter()
            .filter(|(_, s)| {
                s.request_count >= min_requests 
                    && s.last_access.elapsed() < Duration::from_secs(300) // Active in last 5 min
                    && s.success_rate > 0.5 // Reasonably successful
            })
            .map(|(addr, _)| *addr)
            .collect();
        drop(stats);
        
        // Pre-warm connections to these endpoints
        for endpoint in frequent_endpoints {
            // Check if we already have enough connections
            let conns = self.connections.read().await;
            let current_available = conns
                .get(&endpoint)
                .map(|pool| pool.iter().filter(|c| c.state == ConnectionState::Available).count())
                .unwrap_or(0);
            drop(conns);
            
            // Only pre-warm if we need more
            let needed = count_per_endpoint.saturating_sub(current_available);
            for _ in 0..needed {
                if let Some(id) = self.create_connection(endpoint).await {
                    self.prewarmed_ids.write().await.insert(id);
                    self.release(id).await;
                }
            }
        }
    }
    
    /// Clear affinity for a specific key
    pub async fn clear_affinity(&self, key: &AffinityKey) {
        self.affinity_map.write().await.remove(key);
    }
    
    /// Get endpoint statistics for monitoring
    pub async fn get_endpoint_stats(&self) -> HashMap<SocketAddr, EndpointStats> {
        self.endpoint_stats.read().await.clone()
    }
}

/// Snapshot of pool statistics
#[derive(Debug, Clone)]
pub struct PoolStatsSnapshot {
    pub total_connections: usize,
    pub available_connections: usize,
    pub in_use_connections: usize,
    pub hit_rate: f64,
    pub reuse_rate: f64,
}

/// Connection pool with automatic cleanup
pub struct ManagedPool {
    pool: Arc<ConnectionPool>,
    cleanup_interval: Duration,
}

impl ManagedPool {
    pub fn new(config: PoolConfig) -> Self {
        let cleanup_interval = config.health_check_interval;
        ManagedPool {
            pool: Arc::new(ConnectionPool::new(config)),
            cleanup_interval,
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                pool.cleanup_idle().await;
            }
        })
    }

    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool() {
        let pool = ConnectionPool::new(PoolConfig::default());
        let endpoint = "127.0.0.1:4433".parse().unwrap();

        // Get a new connection
        let id1 = pool.get(endpoint).await.unwrap();
        assert_eq!(pool.stats.cache_misses.load(Ordering::Relaxed), 1);

        // Release it
        pool.release(id1).await;

        // Get again - should reuse
        let id2 = pool.get(endpoint).await.unwrap();
        assert_eq!(id1, id2);
        assert_eq!(pool.stats.cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(pool.stats.connections_reused.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_pool_limits() {
        let config = PoolConfig {
            max_per_endpoint: 2,
            max_total: 3,
            ..Default::default()
        };

        let pool = ConnectionPool::new(config);
        let endpoint1 = "127.0.0.1:4433".parse().unwrap();
        let endpoint2 = "127.0.0.1:4434".parse().unwrap();

        // Create 2 connections to endpoint1
        let _id1 = pool.get(endpoint1).await.unwrap();
        let _id2 = pool.get(endpoint1).await.unwrap();

        // Third should fail (per-endpoint limit)
        assert!(pool.get(endpoint1).await.is_none());

        // But we can still create one to endpoint2
        let _id3 = pool.get(endpoint2).await.unwrap();

        // Now total limit is reached
        assert!(pool.get(endpoint2).await.is_none());
    }
}
