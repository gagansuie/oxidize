//! Edge Caching
//!
//! Caches static content at relay points to reduce latency.
//! Implements LRU eviction with size-based limits.

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Cache entry
#[derive(Clone)]
pub struct CacheEntry {
    /// Cached data
    pub data: Bytes,
    /// Content type/MIME
    pub content_type: String,
    /// When entry was created
    pub created_at: Instant,
    /// Time-to-live
    pub ttl: Duration,
    /// Number of times accessed
    pub hits: u64,
    /// Last access time
    pub last_accessed: Instant,
    /// ETag for validation
    pub etag: Option<String>,
}

impl CacheEntry {
    pub fn new(data: Bytes, content_type: &str, ttl: Duration) -> Self {
        let now = Instant::now();
        CacheEntry {
            data,
            content_type: content_type.to_string(),
            created_at: now,
            ttl,
            hits: 0,
            last_accessed: now,
            etag: None,
        }
    }

    pub fn with_etag(mut self, etag: String) -> Self {
        self.etag = Some(etag);
        self
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    pub fn size(&self) -> usize {
        self.data.len() + self.content_type.len() + self.etag.as_ref().map(|e| e.len()).unwrap_or(0)
    }
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cache size in bytes
    pub max_size: usize,
    /// Maximum number of entries
    pub max_entries: usize,
    /// Default TTL for entries
    pub default_ttl: Duration,
    /// Enable cache
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_size: 64 * 1024 * 1024, // 64MB
            max_entries: 10000,
            default_ttl: Duration::from_secs(3600), // 1 hour
            enabled: true,
        }
    }
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub bytes_served: AtomicU64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        if hits + misses == 0 {
            return 0.0;
        }
        hits as f64 / (hits + misses) as f64 * 100.0
    }
}

/// LRU Edge Cache
pub struct EdgeCache {
    /// Configuration
    config: CacheConfig,
    /// Cache entries by key
    entries: HashMap<String, CacheEntry>,
    /// Current cache size in bytes
    current_size: usize,
    /// Statistics
    pub stats: CacheStats,
}

impl EdgeCache {
    pub fn new(config: CacheConfig) -> Self {
        EdgeCache {
            config,
            entries: HashMap::new(),
            current_size: 0,
            stats: CacheStats::default(),
        }
    }

    /// Get an entry from cache
    pub fn get(&mut self, key: &str) -> Option<&CacheEntry> {
        if !self.config.enabled {
            return None;
        }

        // Check if entry exists and is not expired
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.is_expired() {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            entry.hits += 1;
            entry.last_accessed = Instant::now();
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_served
                .fetch_add(entry.data.len() as u64, Ordering::Relaxed);

            // Re-borrow as immutable
            return self.entries.get(key);
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert an entry into cache
    pub fn put(&mut self, key: String, entry: CacheEntry) {
        if !self.config.enabled {
            return;
        }

        let entry_size = entry.size();

        // Remove old entry if exists
        if let Some(old) = self.entries.remove(&key) {
            self.current_size -= old.size();
        }

        // Evict entries if necessary
        while self.current_size + entry_size > self.config.max_size
            || self.entries.len() >= self.config.max_entries
        {
            if !self.evict_lru() {
                break;
            }
        }

        // Insert new entry
        self.current_size += entry_size;
        self.entries.insert(key, entry);
    }

    /// Remove an entry
    pub fn remove(&mut self, key: &str) -> Option<CacheEntry> {
        if let Some(entry) = self.entries.remove(key) {
            self.current_size -= entry.size();
            Some(entry)
        } else {
            None
        }
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) -> bool {
        let lru_key = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_accessed)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            if let Some(entry) = self.entries.remove(&key) {
                self.current_size -= entry.size();
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) {
        let expired_keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            self.remove(&key);
        }
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheSnapshot {
        CacheSnapshot {
            entries: self.entries.len(),
            size_bytes: self.current_size,
            max_size: self.config.max_size,
            hit_rate: self.stats.hit_rate(),
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            evictions: self.stats.evictions.load(Ordering::Relaxed),
        }
    }

    /// Check if key exists (without updating stats)
    pub fn contains(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .map(|e| !e.is_expired())
            .unwrap_or(false)
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_size = 0;
    }
}

impl Default for EdgeCache {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

/// Cache statistics snapshot
#[derive(Debug, Clone)]
pub struct CacheSnapshot {
    pub entries: usize,
    pub size_bytes: usize,
    pub max_size: usize,
    pub hit_rate: f64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// Determine if content should be cached based on headers
pub fn should_cache(content_type: &str, size: usize, cache_control: Option<&str>) -> bool {
    // Check cache-control header
    if let Some(cc) = cache_control {
        if cc.contains("no-store") || cc.contains("no-cache") || cc.contains("private") {
            return false;
        }
    }

    // Size limits
    if size > 10 * 1024 * 1024 {
        // Don't cache > 10MB
        return false;
    }
    if size < 100 {
        // Don't cache tiny responses
        return false;
    }

    // Cacheable content types
    let cacheable_types = [
        "text/html",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/json",
        "image/",
        "font/",
        "application/wasm",
    ];

    cacheable_types.iter().any(|t| content_type.starts_with(t))
}

/// Generate cache key from request
pub fn cache_key(host: &str, path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => format!("{}{}?{}", host, path, q),
        _ => format!("{}{}", host, path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic() {
        let mut cache = EdgeCache::default();

        let entry = CacheEntry::new(
            Bytes::from("Hello, World!"),
            "text/plain",
            Duration::from_secs(60),
        );

        cache.put("test".to_string(), entry);

        assert!(cache.contains("test"));
        let retrieved = cache.get("test").unwrap();
        assert_eq!(retrieved.data.as_ref(), b"Hello, World!");
    }

    #[test]
    fn test_cache_eviction() {
        let config = CacheConfig {
            max_size: 100,
            max_entries: 10,
            ..Default::default()
        };
        let mut cache = EdgeCache::new(config);

        // Fill cache
        for i in 0..15 {
            let entry = CacheEntry::new(
                Bytes::from(vec![0u8; 20]),
                "application/octet-stream",
                Duration::from_secs(60),
            );
            cache.put(format!("key{}", i), entry);
        }

        // Should have evicted some entries
        assert!(cache.entries.len() <= 10);
    }

    #[test]
    fn test_cache_key() {
        assert_eq!(
            cache_key("example.com", "/api/data", Some("id=123")),
            "example.com/api/data?id=123"
        );
        assert_eq!(
            cache_key("example.com", "/index.html", None),
            "example.com/index.html"
        );
    }

    #[test]
    fn test_should_cache() {
        assert!(should_cache("text/html", 1000, None));
        assert!(should_cache("image/png", 5000, Some("max-age=3600")));
        assert!(!should_cache("text/html", 1000, Some("no-store")));
        assert!(!should_cache("text/html", 50, None)); // Too small
    }
}
