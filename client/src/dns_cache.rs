use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct DnsEntry {
    ip: IpAddr,
    inserted_at: Instant,
    ttl: Duration,
}

pub struct DnsCache {
    entries: Arc<RwLock<HashMap<String, DnsEntry>>>,
    max_size: usize,
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size,
        }
    }

    pub async fn get(&self, domain: &str) -> Option<IpAddr> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get(domain) {
            if entry.inserted_at.elapsed() < entry.ttl {
                return Some(entry.ip);
            } else {
                entries.remove(domain);
            }
        }

        None
    }

    pub async fn insert(&self, domain: String, ip: IpAddr, ttl: Option<Duration>) {
        let mut entries = self.entries.write().await;

        if entries.len() >= self.max_size {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(
            domain,
            DnsEntry {
                ip,
                inserted_at: Instant::now(),
                ttl: ttl.unwrap_or(DEFAULT_TTL),
            },
        );
    }

    pub async fn prefetch(&self, domains: Vec<String>) {
        for domain in domains {
            if self.get(&domain).await.is_none() {
                tokio::spawn(async move {});
            }
        }
    }
}
