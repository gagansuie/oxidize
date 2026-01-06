//! Connection Migration
//!
//! Implements QUIC connection migration for seamless network handoff.
//! Allows connections to survive network changes (WiFi → LTE, IP changes).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Connection identifier (QUIC connection ID)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub [u8; 16]);

impl ConnectionId {
    pub fn new(bytes: [u8; 16]) -> Self {
        ConnectionId(bytes)
    }

    pub fn random() -> Self {
        use std::time::SystemTime;
        let mut bytes = [0u8; 16];
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        bytes[0..8].copy_from_slice(&now.as_nanos().to_le_bytes()[0..8]);
        bytes[8..16].copy_from_slice(
            &(now.as_nanos() as u64)
                .wrapping_mul(0x517cc1b727220a95)
                .to_le_bytes(),
        );
        ConnectionId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::random()
    }
}

/// Path state for migration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path is being validated
    Validating,
    /// Path is validated and active
    Active,
    /// Path validation failed
    Failed,
    /// Path is deprecated (old path after migration)
    Deprecated,
}

/// Network path information
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Local address
    pub local: SocketAddr,
    /// Remote address
    pub remote: SocketAddr,
    /// Path state
    pub state: PathState,
    /// When path was created
    pub created_at: Instant,
    /// Last activity time
    pub last_active: Instant,
    /// Path challenge token (for validation)
    pub challenge_token: Option<[u8; 8]>,
    /// RTT estimate for this path
    pub rtt_estimate: Duration,
    /// Packets sent on this path
    pub packets_sent: u64,
    /// Packets received on this path
    pub packets_received: u64,
}

impl PathInfo {
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        let now = Instant::now();
        PathInfo {
            local,
            remote,
            state: PathState::Validating,
            created_at: now,
            last_active: now,
            challenge_token: None,
            rtt_estimate: Duration::from_millis(100), // Initial estimate
            packets_sent: 0,
            packets_received: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.state == PathState::Active
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn idle_time(&self) -> Duration {
        self.last_active.elapsed()
    }
}

/// Migration trigger reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationReason {
    /// Client-initiated (e.g., network change detected)
    ClientInitiated,
    /// NAT rebinding (same network, different port)
    NatRebinding,
    /// Path failure (too much loss)
    PathFailure,
    /// Proactive (better path available)
    Proactive,
    /// Mobility (device moving between networks)
    Mobility,
}

/// Migration event for logging/metrics
#[derive(Debug, Clone)]
pub struct MigrationEvent {
    pub connection_id: ConnectionId,
    pub reason: MigrationReason,
    pub from_path: (SocketAddr, SocketAddr),
    pub to_path: (SocketAddr, SocketAddr),
    pub timestamp: Instant,
    pub success: bool,
}

/// Statistics for connection migration
#[derive(Debug, Default)]
pub struct MigrationStats {
    pub migrations_attempted: AtomicU64,
    pub migrations_successful: AtomicU64,
    pub migrations_failed: AtomicU64,
    pub nat_rebindings: AtomicU64,
    pub path_validations: AtomicU64,
}

/// Connection migration manager
pub struct MigrationManager {
    /// Active paths per connection
    paths: HashMap<ConnectionId, Vec<PathInfo>>,
    /// Primary path index per connection
    primary_path: HashMap<ConnectionId, usize>,
    /// Migration configuration
    config: MigrationConfig,
    /// Statistics
    pub stats: MigrationStats,
    /// Recent migration events
    events: Vec<MigrationEvent>,
}

/// Migration configuration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Enable proactive migration
    pub enable_proactive: bool,
    /// Path validation timeout
    pub validation_timeout: Duration,
    /// Maximum paths per connection
    pub max_paths: usize,
    /// Idle path timeout
    pub idle_timeout: Duration,
    /// Challenge token size
    pub challenge_size: usize,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        MigrationConfig {
            enable_proactive: true,
            validation_timeout: Duration::from_secs(5),
            max_paths: 4,
            idle_timeout: Duration::from_secs(60),
            challenge_size: 8,
        }
    }
}

impl MigrationManager {
    pub fn new(config: MigrationConfig) -> Self {
        MigrationManager {
            paths: HashMap::new(),
            primary_path: HashMap::new(),
            config,
            stats: MigrationStats::default(),
            events: Vec::new(),
        }
    }

    /// Register a new connection with initial path
    pub fn register_connection(
        &mut self,
        conn_id: ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
    ) {
        let mut path = PathInfo::new(local, remote);
        path.state = PathState::Active; // Initial path is active
        self.paths.insert(conn_id, vec![path]);
        self.primary_path.insert(conn_id, 0);
    }

    /// Handle incoming packet from potentially new path
    pub fn on_packet_received(
        &mut self,
        conn_id: ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<MigrationAction> {
        let paths = self.paths.get_mut(&conn_id)?;

        // Check if packet is from known path
        for (idx, path) in paths.iter_mut().enumerate() {
            if path.local == local && path.remote == remote {
                path.last_active = Instant::now();
                path.packets_received += 1;
                return None; // No action needed
            }
        }

        // New path detected - check if it's NAT rebinding or migration
        let primary_idx = *self.primary_path.get(&conn_id)?;
        let primary = &paths[primary_idx];

        let reason = if primary.remote.ip() == remote.ip() {
            // Same IP, different port = NAT rebinding
            self.stats.nat_rebindings.fetch_add(1, Ordering::Relaxed);
            MigrationReason::NatRebinding
        } else {
            // Different IP = actual migration
            MigrationReason::Mobility
        };

        // Add new path for validation
        if paths.len() < self.config.max_paths {
            let mut new_path = PathInfo::new(local, remote);
            new_path.challenge_token = Some(Self::generate_challenge());
            paths.push(new_path);

            self.stats
                .migrations_attempted
                .fetch_add(1, Ordering::Relaxed);
            self.stats.path_validations.fetch_add(1, Ordering::Relaxed);

            return Some(MigrationAction::ValidatePath {
                path_index: paths.len() - 1,
                challenge: paths.last().unwrap().challenge_token.unwrap(),
                reason,
            });
        }

        None
    }

    /// Initiate proactive migration to a new path
    pub fn initiate_migration(
        &mut self,
        conn_id: ConnectionId,
        new_local: SocketAddr,
        new_remote: SocketAddr,
        reason: MigrationReason,
    ) -> Option<MigrationAction> {
        let paths = self.paths.get_mut(&conn_id)?;

        if paths.len() >= self.config.max_paths {
            // Remove oldest deprecated path
            if let Some(idx) = paths.iter().position(|p| p.state == PathState::Deprecated) {
                paths.remove(idx);
            } else {
                return None; // No room for new path
            }
        }

        let mut new_path = PathInfo::new(new_local, new_remote);
        new_path.challenge_token = Some(Self::generate_challenge());
        paths.push(new_path);

        self.stats
            .migrations_attempted
            .fetch_add(1, Ordering::Relaxed);
        self.stats.path_validations.fetch_add(1, Ordering::Relaxed);

        Some(MigrationAction::ValidatePath {
            path_index: paths.len() - 1,
            challenge: paths.last().unwrap().challenge_token.unwrap(),
            reason,
        })
    }

    /// Handle path validation response
    pub fn on_path_response(
        &mut self,
        conn_id: ConnectionId,
        path_index: usize,
        response: [u8; 8],
    ) -> Option<MigrationAction> {
        let paths = self.paths.get_mut(&conn_id)?;

        // Check challenge token first
        let challenge_matches = paths.get(path_index)?.challenge_token == Some(response);

        if challenge_matches {
            // Get path info before mutation
            let path_local = paths[path_index].local;
            let path_remote = paths[path_index].remote;
            let path_created = paths[path_index].created_at;

            // Validation successful - update path
            paths[path_index].state = PathState::Active;
            paths[path_index].challenge_token = None;
            paths[path_index].rtt_estimate = path_created.elapsed();

            // Make this the primary path
            let old_primary = *self.primary_path.get(&conn_id)?;
            if old_primary != path_index {
                // Get old path info before mutation
                let old_local = paths[old_primary].local;
                let old_remote = paths[old_primary].remote;

                paths[old_primary].state = PathState::Deprecated;
                self.primary_path.insert(conn_id, path_index);

                self.stats
                    .migrations_successful
                    .fetch_add(1, Ordering::Relaxed);

                let event = MigrationEvent {
                    connection_id: conn_id,
                    reason: MigrationReason::ClientInitiated,
                    from_path: (old_local, old_remote),
                    to_path: (path_local, path_remote),
                    timestamp: Instant::now(),
                    success: true,
                };
                self.events.push(event);

                return Some(MigrationAction::MigrationComplete {
                    old_path: old_primary,
                    new_path: path_index,
                });
            }
        } else {
            // Validation failed
            paths[path_index].state = PathState::Failed;
            self.stats.migrations_failed.fetch_add(1, Ordering::Relaxed);

            return Some(MigrationAction::ValidationFailed { path_index });
        }

        None
    }

    /// Check for path validation timeouts
    pub fn check_timeouts(&mut self, conn_id: ConnectionId) -> Vec<MigrationAction> {
        let mut actions = Vec::new();

        if let Some(paths) = self.paths.get_mut(&conn_id) {
            for (idx, path) in paths.iter_mut().enumerate() {
                if path.state == PathState::Validating
                    && path.created_at.elapsed() > self.config.validation_timeout
                {
                    path.state = PathState::Failed;
                    self.stats.migrations_failed.fetch_add(1, Ordering::Relaxed);
                    actions.push(MigrationAction::ValidationFailed { path_index: idx });
                }

                // Clean up deprecated paths after idle timeout
                if path.state == PathState::Deprecated
                    && path.idle_time() > self.config.idle_timeout
                {
                    actions.push(MigrationAction::CleanupPath { path_index: idx });
                }
            }
        }

        actions
    }

    /// Get the primary path for a connection
    pub fn get_primary_path(&self, conn_id: ConnectionId) -> Option<&PathInfo> {
        let paths = self.paths.get(&conn_id)?;
        let primary_idx = *self.primary_path.get(&conn_id)?;
        paths.get(primary_idx)
    }

    /// Get all paths for a connection
    pub fn get_paths(&self, conn_id: ConnectionId) -> Option<&Vec<PathInfo>> {
        self.paths.get(&conn_id)
    }

    /// Remove a connection
    pub fn remove_connection(&mut self, conn_id: ConnectionId) {
        self.paths.remove(&conn_id);
        self.primary_path.remove(&conn_id);
    }

    /// Get recent migration events
    pub fn recent_events(&self, limit: usize) -> &[MigrationEvent] {
        let start = self.events.len().saturating_sub(limit);
        &self.events[start..]
    }

    /// Generate a random challenge token
    fn generate_challenge() -> [u8; 8] {
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let mut token = [0u8; 8];
        token.copy_from_slice(&now.as_nanos().to_le_bytes()[0..8]);
        token
    }
}

impl Default for MigrationManager {
    fn default() -> Self {
        Self::new(MigrationConfig::default())
    }
}

/// Actions returned by migration manager
#[derive(Debug, Clone)]
pub enum MigrationAction {
    /// Send path challenge to validate new path
    ValidatePath {
        path_index: usize,
        challenge: [u8; 8],
        reason: MigrationReason,
    },
    /// Migration completed successfully
    MigrationComplete { old_path: usize, new_path: usize },
    /// Path validation failed
    ValidationFailed { path_index: usize },
    /// Clean up old path
    CleanupPath { path_index: usize },
}

/// Detect if network change occurred (for client-side use)
pub fn detect_network_change(
    current_local: SocketAddr,
    previous_local: Option<SocketAddr>,
) -> Option<MigrationReason> {
    let prev = previous_local?;

    if current_local.ip() != prev.ip() {
        // IP changed - likely network switch
        Some(MigrationReason::Mobility)
    } else if current_local.port() != prev.port() {
        // Only port changed - NAT rebinding
        Some(MigrationReason::NatRebinding)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(ip: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip)), port)
    }

    #[test]
    fn test_connection_registration() {
        let mut mgr = MigrationManager::default();
        let conn_id = ConnectionId::random();

        mgr.register_connection(conn_id, addr(1, 5000), addr(2, 4433));

        let path = mgr.get_primary_path(conn_id).unwrap();
        assert!(path.is_active());
        assert_eq!(path.local.port(), 5000);
    }

    #[test]
    fn test_nat_rebinding_detection() {
        let mut mgr = MigrationManager::default();
        let conn_id = ConnectionId::random();

        mgr.register_connection(conn_id, addr(1, 5000), addr(2, 4433));

        // Packet from same IP, different port
        let action = mgr.on_packet_received(conn_id, addr(1, 5001), addr(2, 4433));

        assert!(action.is_some());
        if let Some(MigrationAction::ValidatePath { reason, .. }) = action {
            assert_eq!(reason, MigrationReason::NatRebinding);
        }
    }

    #[test]
    fn test_mobility_detection() {
        let mut mgr = MigrationManager::default();
        let conn_id = ConnectionId::random();

        mgr.register_connection(conn_id, addr(1, 5000), addr(2, 4433));

        // Packet from different IP = mobility
        let action = mgr.on_packet_received(
            conn_id,
            addr(1, 5000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433),
        );

        assert!(action.is_some());
        if let Some(MigrationAction::ValidatePath { reason, .. }) = action {
            assert_eq!(reason, MigrationReason::Mobility);
        }
    }

    #[test]
    fn test_path_validation() {
        let mut mgr = MigrationManager::default();
        let conn_id = ConnectionId::random();

        mgr.register_connection(conn_id, addr(1, 5000), addr(2, 4433));

        let action = mgr.on_packet_received(conn_id, addr(1, 5001), addr(2, 4433));
        let challenge = match action {
            Some(MigrationAction::ValidatePath { challenge, .. }) => challenge,
            _ => panic!("Expected ValidatePath"),
        };

        // Respond with correct challenge
        let result = mgr.on_path_response(conn_id, 1, challenge);
        assert!(matches!(
            result,
            Some(MigrationAction::MigrationComplete { .. })
        ));

        // New path should be primary
        let path = mgr.get_primary_path(conn_id).unwrap();
        assert_eq!(path.local.port(), 5001);
    }
}
