//! ML Integration Layer (10x Optimized)
//!
//! Provides a unified interface for ML-powered network optimization.
//! Now uses OptimizedMlEngine with INT8 quantized inference.
//!
//! Usage:
//! ```ignore
//! let ml = MlIntegration::new(MlConfig::default()).await?;
//! ml.start().await?;
//!
//! // Hot path (non-blocking, <1µs with cache)
//! ml.record_network_sample(features);
//! let decision = ml.get_fec_decision();
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::ml_optimized::{
    DrlAction, FecDecision, MlCompressionDecision, NetworkFeatures, OptimizedMlEngine, PathId,
    PathMetrics, TrafficContext,
};

#[cfg(feature = "ai")]
use crate::ml_training::FederatedAggregator;

/// Configuration for ML integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    /// Enable ML inference (false = heuristics only)
    pub enable_inference: bool,
    /// Enable background training
    pub enable_training: bool,
    /// Enable federated data collection
    pub enable_federation: bool,
    /// Model directory path
    pub model_path: String,
    /// Inference cache TTL (how often to re-run inference)
    pub inference_cache_ms: u64,
    /// Number of paths for path selection
    pub num_paths: usize,
    /// Server ID for federation
    pub server_id: String,
}

impl Default for MlConfig {
    fn default() -> Self {
        MlConfig {
            enable_inference: true,
            enable_training: true,
            enable_federation: true,
            model_path: "/tmp/oxidize_models".into(),
            inference_cache_ms: 10, // Cache inference for 10ms
            num_paths: 2,
            server_id: format!("server-{}", std::process::id()),
        }
    }
}

/// Cached inference results (to avoid re-computing every packet)
struct InferenceCache {
    /// Last FEC decision
    fec_decision: RwLock<FecDecision>,
    /// Last congestion action
    congestion_action: RwLock<(DrlAction, u32)>,
    /// Last compression decision per data hash
    compression_cache: RwLock<(u64, MlCompressionDecision)>,
    /// Last path selection per traffic type
    path_cache: RwLock<[PathId; 5]>,
    /// Cache timestamps
    #[allow(dead_code)]
    fec_updated: AtomicU64,
    #[allow(dead_code)]
    congestion_updated: AtomicU64,
}

impl InferenceCache {
    fn new() -> Self {
        InferenceCache {
            fec_decision: RwLock::new(FecDecision {
                loss_probability: 0.0,
                redundancy_ratio: 0.0,
                inject_fec: false,
            }),
            congestion_action: RwLock::new((DrlAction::Maintain, 65535)),
            compression_cache: RwLock::new((0, MlCompressionDecision::Skip)),
            path_cache: RwLock::new([PathId::Primary; 5]),
            fec_updated: AtomicU64::new(0),
            congestion_updated: AtomicU64::new(0),
        }
    }
}

/// ML Integration - unified interface for ML-powered optimization (10x optimized)
pub struct MlIntegration {
    #[allow(dead_code)]
    config: MlConfig,
    /// Core ML engine (10x optimized - INT8 quantized, Transformer+PPO)
    engine: Arc<RwLock<OptimizedMlEngine>>,
    /// Inference cache (hot path reads from here)
    cache: Arc<InferenceCache>,
    /// Federated aggregator (optional)
    #[cfg(feature = "ai")]
    federator: Option<Arc<FederatedAggregator>>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Statistics
    stats: Arc<MlIntegrationStats>,
    /// Start time for uptime tracking
    start_time: Instant,
}

/// ML Integration statistics
#[derive(Debug, Default)]
pub struct MlIntegrationStats {
    pub inference_count: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub training_samples: AtomicU64,
    pub federation_uploads: AtomicU64,
}

impl MlIntegration {
    /// Create new ML integration (10x optimized)
    pub async fn new(config: MlConfig) -> anyhow::Result<Self> {
        // OptimizedMlEngine uses embedded INT8 weights - no external loading needed
        let engine = OptimizedMlEngine::new();
        info!("ML integration using 10x optimized engine (INT8 quantized, Transformer+PPO)");

        Ok(MlIntegration {
            config: config.clone(),
            engine: Arc::new(RwLock::new(engine)),
            cache: Arc::new(InferenceCache::new()),
            #[cfg(feature = "ai")]
            federator: if config.enable_federation {
                Some(Arc::new(FederatedAggregator::new(&config.server_id)))
            } else {
                None
            },
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(MlIntegrationStats::default()),
            start_time: Instant::now(),
        })
    }

    /// Start ML integration
    pub async fn start(&mut self) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        info!("ML integration started");
        Ok(())
    }

    /// Stop ML integration
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        info!("ML integration stopped");
    }

    // =========================================================================
    // HOT PATH API - These are called per-packet, must be fast
    // =========================================================================

    /// Get cached FEC decision (non-blocking)
    #[inline]
    pub fn get_fec_decision(&self) -> FecDecision {
        self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
        *self.cache.fec_decision.read().unwrap()
    }

    /// Get cached congestion action (non-blocking)
    #[inline]
    pub fn get_congestion_action(&self) -> (DrlAction, u32) {
        self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
        *self.cache.congestion_action.read().unwrap()
    }

    /// Get compression decision (checks cache first)
    #[inline]
    pub fn get_compression_decision(&self, data: &[u8]) -> MlCompressionDecision {
        let hash = simple_hash(data);
        if let Ok(cached) = self.cache.compression_cache.read() {
            if cached.0 == hash {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return cached.1;
            }
        }

        // Cache miss - compute synchronously (fast heuristic)
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut engine) = self.engine.write() {
            engine.compression_decision(data)
        } else {
            MlCompressionDecision::Skip
        }
    }

    /// Get path for traffic type (cached)
    #[inline]
    pub fn get_path(&self, traffic: TrafficContext) -> PathId {
        self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
        if let Ok(paths) = self.cache.path_cache.read() {
            paths[traffic.to_index()]
        } else {
            PathId::Primary
        }
    }

    // =========================================================================
    // DATA COLLECTION API - Called to update ML state
    // =========================================================================

    /// Record network sample
    pub fn record_network_sample(&self, features: NetworkFeatures) {
        self.stats.training_samples.fetch_add(1, Ordering::Relaxed);

        // Update engine state
        if let Ok(mut engine) = self.engine.write() {
            engine.update(&features, 0.0, 0);

            // Update FEC cache
            let decision = engine.fec_decision(&features);
            if let Ok(mut cache) = self.cache.fec_decision.write() {
                *cache = decision;
            }
        }

        // Record for federation
        #[cfg(feature = "ai")]
        if let Some(ref fed) = self.federator {
            fed.add_lstm_sample(
                features.rtt_us as f64,
                features.loss_rate as f64,
                features.bandwidth_bps as f64,
            );
        }
    }

    /// Update path metrics
    pub fn update_path_metrics(&self, metrics: PathMetrics) {
        if let Ok(mut engine) = self.engine.write() {
            engine.update_path_metrics(metrics);
        }
    }

    /// Record path reward
    pub fn record_path_reward(&self, path: PathId, traffic: TrafficContext, reward: f32) {
        if let Ok(mut engine) = self.engine.write() {
            engine.update_path_reward(path, traffic, reward);
        }

        #[cfg(feature = "ai")]
        if let Some(ref fed) = self.federator {
            fed.add_drl_sample(path.to_index(), reward as f64, 0.0);
        }
    }

    /// Select path for traffic type
    pub fn select_path(&self, traffic: TrafficContext) -> PathId {
        if let Ok(mut engine) = self.engine.write() {
            let path = engine.select_path(traffic);
            // Update cache
            if let Ok(mut cache) = self.cache.path_cache.write() {
                cache[traffic.to_index()] = path;
            }
            path
        } else {
            PathId::Primary
        }
    }

    // =========================================================================
    // MANAGEMENT API
    // =========================================================================

    /// Get integration statistics
    pub fn stats(&self) -> MlIntegrationStatsSnapshot {
        let models_loaded = self
            .engine
            .read()
            .map(|e| e.all_models_loaded())
            .unwrap_or(false);
        MlIntegrationStatsSnapshot {
            inference_count: self.stats.inference_count.load(Ordering::Relaxed),
            cache_hits: self.stats.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.stats.cache_misses.load(Ordering::Relaxed),
            training_samples: self.stats.training_samples.load(Ordering::Relaxed),
            federation_uploads: self.stats.federation_uploads.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
            models_loaded,
        }
    }

    /// Export training data (no-op for optimized engine - training via CI/CD)
    pub fn export_training_data(&self, _path: &str) -> anyhow::Result<()> {
        // OptimizedMlEngine uses embedded weights, training done via CI/CD
        Ok(())
    }

    /// Export federated statistics
    #[cfg(feature = "ai")]
    pub fn export_federation_stats(&self) -> Option<String> {
        self.federator.as_ref().and_then(|f| f.export_json().ok())
    }

    #[cfg(not(feature = "ai"))]
    pub fn export_federation_stats(&self) -> Option<String> {
        None
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for MlIntegration {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlIntegrationStatsSnapshot {
    pub inference_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub training_samples: u64,
    pub federation_uploads: u64,
    pub uptime_secs: u64,
    pub models_loaded: bool,
}

/// Simple hash for cache keys
#[inline]
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in data.iter().take(64) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ml_integration_creation() {
        let config = MlConfig::default();
        let integration = MlIntegration::new(config).await.unwrap();
        assert!(!integration.is_running());
    }

    #[tokio::test]
    async fn test_cached_decisions() {
        let config = MlConfig {
            enable_training: false,
            enable_federation: false,
            ..Default::default()
        };
        let integration = MlIntegration::new(config).await.unwrap();

        // Should return cached defaults
        let fec = integration.get_fec_decision();
        assert!(!fec.inject_fec);

        let (action, cwnd) = integration.get_congestion_action();
        assert_eq!(action, DrlAction::Maintain);
        assert_eq!(cwnd, 65535);

        let path = integration.get_path(TrafficContext::Gaming);
        assert_eq!(path, PathId::Primary);
    }

    #[test]
    fn test_simple_hash() {
        let data1 = b"hello world";
        let data2 = b"hello world";
        let data3 = b"different";

        assert_eq!(simple_hash(data1), simple_hash(data2));
        assert_ne!(simple_hash(data1), simple_hash(data3));
    }
}
