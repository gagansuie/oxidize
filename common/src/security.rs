//! Security Module
//!
//! Provides DDoS protection, rate limiting, and security utilities.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Maximum connections per IP
    pub max_connections_per_ip: u32,
    /// Rate limit window (seconds)
    pub rate_limit_window_secs: u64,
    /// Maximum packets per second per IP
    pub max_pps_per_ip: u32,
    /// Maximum bandwidth per IP (bytes/sec)
    pub max_bandwidth_per_ip: u64,
    /// Enable SYN cookie equivalent for QUIC
    pub enable_stateless_retry: bool,
    /// Blocklist TTL
    pub blocklist_ttl: Duration,
    /// Auto-block threshold (violations before block)
    pub auto_block_threshold: u32,
    /// Challenge suspicious clients
    pub enable_challenges: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            max_connections_per_ip: 100,
            rate_limit_window_secs: 60,
            max_pps_per_ip: 1000,
            max_bandwidth_per_ip: 10 * 1024 * 1024, // 10 MB/s
            enable_stateless_retry: true,
            blocklist_ttl: Duration::from_secs(3600), // 1 hour
            auto_block_threshold: 10,
            enable_challenges: true,
        }
    }
}

/// Per-IP tracking data
#[derive(Debug, Clone)]
pub struct IpTracker {
    /// Connection count
    pub connections: u32,
    /// Packets in current window
    pub packets: u32,
    /// Bytes in current window
    pub bytes: u64,
    /// Window start time
    pub window_start: Instant,
    /// Violation count
    pub violations: u32,
    /// Last activity
    pub last_seen: Instant,
    /// Is this IP challenged?
    pub challenged: bool,
    /// Challenge passed?
    pub verified: bool,
}

impl Default for IpTracker {
    fn default() -> Self {
        let now = Instant::now();
        IpTracker {
            connections: 0,
            packets: 0,
            bytes: 0,
            window_start: now,
            violations: 0,
            last_seen: now,
            challenged: false,
            verified: false,
        }
    }
}

/// Security check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAction {
    /// Allow the connection/packet
    Allow,
    /// Rate limited - drop silently
    RateLimit,
    /// Challenge required (QUIC retry)
    Challenge,
    /// Blocked - reject
    Block,
    /// Bandwidth exceeded
    Throttle,
}

/// Security statistics
#[derive(Debug, Default)]
pub struct SecurityStats {
    pub packets_allowed: AtomicU64,
    pub packets_rate_limited: AtomicU64,
    pub packets_blocked: AtomicU64,
    pub packets_challenged: AtomicU64,
    pub active_blocks: AtomicU64,
    pub total_violations: AtomicU64,
}

/// DDoS protection and security manager
pub struct SecurityManager {
    /// Configuration
    config: SecurityConfig,
    /// Per-IP tracking
    trackers: HashMap<IpAddr, IpTracker>,
    /// Blocked IPs with expiry
    blocklist: HashMap<IpAddr, Instant>,
    /// Permanent allowlist (trusted IPs)
    allowlist: HashSet<IpAddr>,
    /// Statistics
    pub stats: SecurityStats,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        SecurityManager {
            config,
            trackers: HashMap::new(),
            blocklist: HashMap::new(),
            allowlist: HashSet::new(),
            stats: SecurityStats::default(),
        }
    }

    /// Check if a connection should be allowed
    pub fn check_connection(&mut self, ip: IpAddr) -> SecurityAction {
        // Allowlist bypass
        if self.allowlist.contains(&ip) {
            self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
            return SecurityAction::Allow;
        }

        // Blocklist check
        if let Some(expiry) = self.blocklist.get(&ip) {
            if Instant::now() < *expiry {
                self.stats.packets_blocked.fetch_add(1, Ordering::Relaxed);
                return SecurityAction::Block;
            } else {
                self.blocklist.remove(&ip);
                self.stats.active_blocks.fetch_sub(1, Ordering::Relaxed);
            }
        }

        // Get or create tracker
        let tracker = self.trackers.entry(ip).or_default();
        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(tracker.window_start).as_secs() >= self.config.rate_limit_window_secs
        {
            tracker.packets = 0;
            tracker.bytes = 0;
            tracker.window_start = now;
        }

        tracker.last_seen = now;
        tracker.connections += 1;

        // Connection limit check
        if tracker.connections > self.config.max_connections_per_ip {
            self.record_violation(ip);
            self.stats
                .packets_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            return SecurityAction::RateLimit;
        }

        // Challenge unverified IPs with high connection rates
        if self.config.enable_challenges && !tracker.verified && tracker.connections > 10 {
            tracker.challenged = true;
            self.stats
                .packets_challenged
                .fetch_add(1, Ordering::Relaxed);
            return SecurityAction::Challenge;
        }

        self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
        SecurityAction::Allow
    }

    /// Check if a packet should be allowed (for ongoing connections)
    pub fn check_packet(&mut self, ip: IpAddr, packet_size: usize) -> SecurityAction {
        if self.allowlist.contains(&ip) {
            return SecurityAction::Allow;
        }

        if self.blocklist.contains_key(&ip) {
            return SecurityAction::Block;
        }

        let tracker = self.trackers.entry(ip).or_default();
        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(tracker.window_start).as_secs() >= self.config.rate_limit_window_secs
        {
            tracker.packets = 0;
            tracker.bytes = 0;
            tracker.window_start = now;
        }

        tracker.packets += 1;
        tracker.bytes += packet_size as u64;
        tracker.last_seen = now;

        // PPS check
        if tracker.packets > self.config.max_pps_per_ip {
            self.record_violation(ip);
            return SecurityAction::RateLimit;
        }

        // Bandwidth check
        let window_secs = now.duration_since(tracker.window_start).as_secs().max(1);
        let bandwidth = tracker.bytes / window_secs;
        if bandwidth > self.config.max_bandwidth_per_ip {
            return SecurityAction::Throttle;
        }

        SecurityAction::Allow
    }

    /// Record a security violation
    fn record_violation(&mut self, ip: IpAddr) {
        self.stats.total_violations.fetch_add(1, Ordering::Relaxed);

        if let Some(tracker) = self.trackers.get_mut(&ip) {
            tracker.violations += 1;

            // Auto-block after threshold
            if tracker.violations >= self.config.auto_block_threshold {
                self.block_ip(ip, self.config.blocklist_ttl);
            }
        }
    }

    /// Mark IP as verified (passed challenge)
    pub fn mark_verified(&mut self, ip: IpAddr) {
        if let Some(tracker) = self.trackers.get_mut(&ip) {
            tracker.verified = true;
            tracker.challenged = false;
        }
    }

    /// Block an IP
    pub fn block_ip(&mut self, ip: IpAddr, duration: Duration) {
        let expiry = Instant::now() + duration;
        self.blocklist.insert(ip, expiry);
        self.stats.active_blocks.fetch_add(1, Ordering::Relaxed);
    }

    /// Unblock an IP
    pub fn unblock_ip(&mut self, ip: IpAddr) {
        if self.blocklist.remove(&ip).is_some() {
            self.stats.active_blocks.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Add IP to allowlist
    pub fn allowlist_ip(&mut self, ip: IpAddr) {
        self.allowlist.insert(ip);
    }

    /// Remove IP from allowlist
    pub fn remove_from_allowlist(&mut self, ip: IpAddr) {
        self.allowlist.remove(&ip);
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.rate_limit_window_secs * 2);

        // Remove stale trackers
        self.trackers
            .retain(|_, t| now.duration_since(t.last_seen) < window);

        // Remove expired blocks
        let expired: Vec<_> = self
            .blocklist
            .iter()
            .filter(|(_, expiry)| now >= **expiry)
            .map(|(ip, _)| *ip)
            .collect();

        for ip in expired {
            self.blocklist.remove(&ip);
            self.stats.active_blocks.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get security snapshot
    pub fn snapshot(&self) -> SecuritySnapshot {
        SecuritySnapshot {
            tracked_ips: self.trackers.len(),
            blocked_ips: self.blocklist.len(),
            allowlisted_ips: self.allowlist.len(),
            packets_allowed: self.stats.packets_allowed.load(Ordering::Relaxed),
            packets_blocked: self.stats.packets_blocked.load(Ordering::Relaxed),
            packets_rate_limited: self.stats.packets_rate_limited.load(Ordering::Relaxed),
            total_violations: self.stats.total_violations.load(Ordering::Relaxed),
        }
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new(SecurityConfig::default())
    }
}

/// Security statistics snapshot
#[derive(Debug, Clone)]
pub struct SecuritySnapshot {
    pub tracked_ips: usize,
    pub blocked_ips: usize,
    pub allowlisted_ips: usize,
    pub packets_allowed: u64,
    pub packets_blocked: u64,
    pub packets_rate_limited: u64,
    pub total_violations: u64,
}

/// Validate packet for common attack patterns
pub fn validate_packet(data: &[u8]) -> bool {
    // Minimum QUIC packet size
    if data.len() < 20 {
        return false;
    }

    // Maximum reasonable packet size
    if data.len() > 65535 {
        return false;
    }

    // Check for QUIC long header (initial packets)
    let first_byte = data[0];
    let is_long_header = (first_byte & 0x80) != 0;

    if is_long_header {
        // Long header must have version
        if data.len() < 5 {
            return false;
        }
    }

    true
}

/// Generate a challenge token for IP verification
pub fn generate_challenge(ip: IpAddr, secret: &[u8; 32]) -> [u8; 16] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    ip.hash(&mut hasher);
    secret.hash(&mut hasher);

    let hash = hasher.finish();
    let mut token = [0u8; 16];
    token[0..8].copy_from_slice(&hash.to_le_bytes());
    token[8..16].copy_from_slice(&hash.to_be_bytes());
    token
}

/// Verify a challenge response
pub fn verify_challenge(ip: IpAddr, secret: &[u8; 32], response: &[u8; 16]) -> bool {
    let expected = generate_challenge(ip, secret);
    expected == *response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet))
    }

    #[test]
    fn test_allow_normal_traffic() {
        let mut mgr = SecurityManager::default();
        let ip = test_ip(1);

        let action = mgr.check_connection(ip);
        assert_eq!(action, SecurityAction::Allow);
    }

    #[test]
    fn test_rate_limit() {
        let config = SecurityConfig {
            max_connections_per_ip: 5,
            ..Default::default()
        };
        let mut mgr = SecurityManager::new(config);
        let ip = test_ip(2);

        for _ in 0..5 {
            assert_eq!(mgr.check_connection(ip), SecurityAction::Allow);
        }

        // 6th connection should be rate limited
        assert_eq!(mgr.check_connection(ip), SecurityAction::RateLimit);
    }

    #[test]
    fn test_blocklist() {
        let mut mgr = SecurityManager::default();
        let ip = test_ip(3);

        mgr.block_ip(ip, Duration::from_secs(60));
        assert_eq!(mgr.check_connection(ip), SecurityAction::Block);

        mgr.unblock_ip(ip);
        assert_eq!(mgr.check_connection(ip), SecurityAction::Allow);
    }

    #[test]
    fn test_allowlist() {
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
    fn test_challenge() {
        let ip = test_ip(5);
        let secret = [0u8; 32];

        let token = generate_challenge(ip, &secret);
        assert!(verify_challenge(ip, &secret, &token));

        // Wrong IP should fail
        let other_ip = test_ip(6);
        assert!(!verify_challenge(other_ip, &secret, &token));
    }

    #[test]
    fn test_packet_validation() {
        // Too small
        assert!(!validate_packet(&[0; 10]));

        // Valid size
        assert!(validate_packet(&[0x80; 100])); // Long header

        // Short header
        assert!(validate_packet(&[0x40; 50]));
    }
}
