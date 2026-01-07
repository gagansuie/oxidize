use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const MAX_CACHE_SIZE: usize = 1000;
const CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct CacheEntry {
    data: Vec<u8>,
    inserted_at: Instant,
    access_count: usize,
}

pub struct DataCache {
    entries: Arc<RwLock<HashMap<u64, CacheEntry>>>,
}

impl Default for DataCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DataCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, data: &[u8]) -> Option<Vec<u8>> {
        let hash = Self::hash_data(data);
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(&hash) {
            if entry.inserted_at.elapsed() < CACHE_TTL {
                entry.access_count += 1;
                return Some(entry.data.clone());
            } else {
                entries.remove(&hash);
            }
        }

        None
    }

    pub async fn insert(&self, data: Vec<u8>) {
        let hash = Self::hash_data(&data);
        let mut entries = self.entries.write().await;

        if entries.len() >= MAX_CACHE_SIZE {
            Self::evict_oldest(&mut entries);
        }

        entries.insert(
            hash,
            CacheEntry {
                data,
                inserted_at: Instant::now(),
                access_count: 1,
            },
        );
    }

    fn hash_data(data: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }

    fn evict_oldest(entries: &mut HashMap<u64, CacheEntry>) {
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(key, _)| *key)
        {
            entries.remove(&oldest_key);
        }
    }
}
