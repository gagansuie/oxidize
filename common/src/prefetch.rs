//! Predictive Prefetching
//!
//! Heuristic-based prefetching for DNS, connections, and resources.
//! Uses pattern recognition instead of ML for simplicity and speed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Prefetch hint with priority
#[derive(Debug, Clone)]
pub struct PrefetchHint {
    /// Resource to prefetch
    pub resource: PrefetchResource,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// When hint was generated
    pub generated_at: Instant,
    /// Time-to-live for this hint
    pub ttl: Duration,
}

/// Types of resources that can be prefetched
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefetchResource {
    /// DNS resolution
    Dns(String),
    /// TCP/QUIC connection
    Connection(String, u16), // host, port
    /// HTTP resource
    Http(String), // URL
    /// TLS session ticket
    TlsTicket(String), // host
}

/// Access pattern for prediction
#[derive(Debug, Clone)]
struct AccessPattern {
    /// Resource accessed
    resource: PrefetchResource,
    /// Access count
    count: u64,
    /// Last access time
    last_access: Instant,
    /// Average time between accesses
    avg_interval: Duration,
    /// Resources commonly accessed after this one
    followers: HashMap<PrefetchResource, u32>,
}

/// Prefetch statistics
#[derive(Debug, Default)]
pub struct PrefetchStats {
    pub hints_generated: AtomicU64,
    pub hints_used: AtomicU64,
    pub hints_expired: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

/// Predictive prefetcher using heuristics
pub struct Prefetcher {
    /// Access patterns by resource
    patterns: HashMap<PrefetchResource, AccessPattern>,
    /// Recently accessed resources (for sequence detection)
    recent_accesses: Vec<(PrefetchResource, Instant)>,
    /// Maximum recent accesses to track
    max_recent: usize,
    /// Pending prefetch hints
    pending_hints: Vec<PrefetchHint>,
    /// Configuration
    config: PrefetchConfig,
    /// Statistics
    pub stats: PrefetchStats,
}

/// Prefetch configuration
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    /// Minimum confidence to generate hint
    pub min_confidence: u8,
    /// Maximum pending hints
    pub max_pending: usize,
    /// Hint TTL
    pub hint_ttl: Duration,
    /// Maximum patterns to track
    pub max_patterns: usize,
    /// Enable DNS prefetching
    pub prefetch_dns: bool,
    /// Enable connection prefetching
    pub prefetch_connections: bool,
    /// Enable resource prefetching
    pub prefetch_resources: bool,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        PrefetchConfig {
            min_confidence: 60,
            max_pending: 100,
            hint_ttl: Duration::from_secs(30),
            max_patterns: 1000,
            prefetch_dns: true,
            prefetch_connections: true,
            prefetch_resources: true,
        }
    }
}

impl Prefetcher {
    pub fn new(config: PrefetchConfig) -> Self {
        Prefetcher {
            patterns: HashMap::new(),
            recent_accesses: Vec::new(),
            max_recent: 50,
            pending_hints: Vec::new(),
            config,
            stats: PrefetchStats::default(),
        }
    }

    /// Record a resource access
    pub fn record_access(&mut self, resource: PrefetchResource) {
        let now = Instant::now();

        // Update pattern for this resource
        if let Some(pattern) = self.patterns.get_mut(&resource) {
            let interval = pattern.last_access.elapsed();
            pattern.count += 1;
            pattern.avg_interval = Duration::from_nanos(
                pattern.avg_interval.as_nanos() as u64 * (pattern.count - 1) / pattern.count
                    + interval.as_nanos() as u64 / pattern.count,
            );
            pattern.last_access = now;
        } else {
            // New pattern
            if self.patterns.len() < self.config.max_patterns {
                self.patterns.insert(
                    resource.clone(),
                    AccessPattern {
                        resource: resource.clone(),
                        count: 1,
                        last_access: now,
                        avg_interval: Duration::from_secs(60),
                        followers: HashMap::new(),
                    },
                );
            }
        }

        // Update follower relationships
        if let Some((prev_resource, prev_time)) = self.recent_accesses.last() {
            if prev_time.elapsed() < Duration::from_secs(5) {
                if let Some(prev_pattern) = self.patterns.get_mut(prev_resource) {
                    *prev_pattern.followers.entry(resource.clone()).or_insert(0) += 1;
                }
            }
        }

        // Add to recent accesses
        self.recent_accesses.push((resource, now));
        if self.recent_accesses.len() > self.max_recent {
            self.recent_accesses.remove(0);
        }

        // Generate new hints based on updated patterns
        self.generate_hints();
    }

    /// Generate prefetch hints based on patterns
    fn generate_hints(&mut self) {
        let now = Instant::now();

        // Clean expired hints
        self.pending_hints
            .retain(|h| h.generated_at.elapsed() < h.ttl);

        // Get the most recent access
        if let Some((recent, _)) = self.recent_accesses.last() {
            if let Some(pattern) = self.patterns.get(recent) {
                // Find likely followers
                let total_follows: u32 = pattern.followers.values().sum();
                if total_follows > 0 {
                    for (follower, count) in &pattern.followers {
                        let confidence = (*count as u64 * 100 / total_follows as u64) as u8;

                        if confidence >= self.config.min_confidence
                            && self.pending_hints.len() < self.config.max_pending
                        {
                            // Check if hint already exists
                            if !self.pending_hints.iter().any(|h| h.resource == *follower) {
                                self.pending_hints.push(PrefetchHint {
                                    resource: follower.clone(),
                                    confidence,
                                    generated_at: now,
                                    ttl: self.config.hint_ttl,
                                });
                                self.stats.hints_generated.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }

        // Time-based predictions (periodic accesses)
        for pattern in self.patterns.values() {
            if pattern.count >= 3 {
                let time_since_last = pattern.last_access.elapsed();
                let expected_next = pattern.avg_interval;

                // If we're approaching the expected next access time
                if time_since_last > expected_next.mul_f32(0.8)
                    && time_since_last < expected_next.mul_f32(1.2)
                {
                    let confidence = 70u8; // Medium confidence for time-based

                    if confidence >= self.config.min_confidence
                        && self.pending_hints.len() < self.config.max_pending
                        && !self
                            .pending_hints
                            .iter()
                            .any(|h| h.resource == pattern.resource)
                    {
                        self.pending_hints.push(PrefetchHint {
                            resource: pattern.resource.clone(),
                            confidence,
                            generated_at: now,
                            ttl: self.config.hint_ttl,
                        });
                        self.stats.hints_generated.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Get pending prefetch hints
    pub fn get_hints(&mut self) -> Vec<PrefetchHint> {
        // Filter by resource type based on config
        self.pending_hints
            .iter()
            .filter(|h| match &h.resource {
                PrefetchResource::Dns(_) => self.config.prefetch_dns,
                PrefetchResource::Connection(_, _) => self.config.prefetch_connections,
                PrefetchResource::Http(_) | PrefetchResource::TlsTicket(_) => {
                    self.config.prefetch_resources
                }
            })
            .cloned()
            .collect()
    }

    /// Mark a hint as used (prefetch was performed)
    pub fn mark_used(&mut self, resource: &PrefetchResource) {
        if let Some(pos) = self
            .pending_hints
            .iter()
            .position(|h| &h.resource == resource)
        {
            self.pending_hints.remove(pos);
            self.stats.hints_used.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get top predicted resources
    pub fn top_predictions(&self, limit: usize) -> Vec<(PrefetchResource, u8)> {
        let mut predictions: Vec<_> = self
            .pending_hints
            .iter()
            .map(|h| (h.resource.clone(), h.confidence))
            .collect();
        predictions.sort_by(|a, b| b.1.cmp(&a.1));
        predictions.truncate(limit);
        predictions
    }

    /// Clear all patterns and hints
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.recent_accesses.clear();
        self.pending_hints.clear();
    }
}

impl Default for Prefetcher {
    fn default() -> Self {
        Self::new(PrefetchConfig::default())
    }
}

/// Helper to extract DNS prefetch hints from URLs
pub fn dns_from_url(url: &str) -> Option<PrefetchResource> {
    // Simple URL parsing
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = url.split('/').next()?;
    let host = host.split(':').next()?;

    if !host.is_empty() && host.contains('.') {
        Some(PrefetchResource::Dns(host.to_string()))
    } else {
        None
    }
}

/// Helper to extract connection prefetch hints from URLs
pub fn connection_from_url(url: &str) -> Option<PrefetchResource> {
    let is_https = url.starts_with("https://");
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_port = url.split('/').next()?;

    let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
        let port_str = &host_port[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            (&host_port[..colon_pos], port)
        } else {
            (host_port, if is_https { 443 } else { 80 })
        }
    } else {
        (host_port, if is_https { 443 } else { 80 })
    };

    if !host.is_empty() {
        Some(PrefetchResource::Connection(host.to_string(), port))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_access() {
        let mut prefetcher = Prefetcher::default();

        prefetcher.record_access(PrefetchResource::Dns("example.com".into()));
        prefetcher.record_access(PrefetchResource::Dns("api.example.com".into()));

        assert_eq!(prefetcher.patterns.len(), 2);
    }

    #[test]
    fn test_follower_detection() {
        let mut prefetcher = Prefetcher::default();

        // Create a pattern: A -> B (repeated)
        for _ in 0..5 {
            prefetcher.record_access(PrefetchResource::Dns("a.com".into()));
            prefetcher.record_access(PrefetchResource::Dns("b.com".into()));
        }

        // Check that B follows A
        let pattern_a = prefetcher
            .patterns
            .get(&PrefetchResource::Dns("a.com".into()))
            .unwrap();
        assert!(pattern_a
            .followers
            .contains_key(&PrefetchResource::Dns("b.com".into())));
    }

    #[test]
    fn test_dns_from_url() {
        assert_eq!(
            dns_from_url("https://example.com/path"),
            Some(PrefetchResource::Dns("example.com".into()))
        );
        assert_eq!(
            dns_from_url("http://api.example.com:8080/"),
            Some(PrefetchResource::Dns("api.example.com".into()))
        );
    }

    #[test]
    fn test_connection_from_url() {
        assert_eq!(
            connection_from_url("https://example.com/path"),
            Some(PrefetchResource::Connection("example.com".into(), 443))
        );
        assert_eq!(
            connection_from_url("http://api.example.com:8080/"),
            Some(PrefetchResource::Connection("api.example.com".into(), 8080))
        );
    }
}
