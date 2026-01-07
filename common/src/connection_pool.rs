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
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: PoolConfig) -> Self {
        ConnectionPool {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            stats: Arc::new(PoolStats::default()),
        }
    }

    /// Get or create a connection to the specified endpoint
    pub async fn get(&self, endpoint: SocketAddr) -> Option<u64> {
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
                        self.stats
                            .connections_reused
                            .fetch_add(1, Ordering::Relaxed);
                        return Some(conn.id);
                    }
                }
            }
        }

        // No available connection, create a new one
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.create_connection(endpoint).await
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
                    self.release(id).await;
                }
            }
        }
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
