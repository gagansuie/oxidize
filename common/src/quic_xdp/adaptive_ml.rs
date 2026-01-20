//! Adaptive ML Engine with Online Learning + Hugging Face Integration
//!
//! Fully integrated ML pipeline:
//! - Downloads pre-trained models from HuggingFace Hub at startup
//! - Collects training observations in real-time
//! - Uploads training data to HF Hub for nightly retraining
//! - Auto-refreshes lookup tables from updated models
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                Adaptive ML Engine + HuggingFace                          │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  STARTUP:                                                               │
//! │    HF Hub (gagansuie/oxidize-models)                                    │
//! │         │                                                               │
//! │         ▼                                                               │
//! │    Download safetensors ──▶ Load weights ──▶ Generate lookup tables     │
//! │                                                                          │
//! │  RUNTIME:                                                               │
//! │    Lookup Tables (<100ns) ──▶ Live ML (~1µs) ──▶ Record observations     │
//! │                                                                          │
//! │  HOURLY:                                                                │
//! │    Upload observations to HF ──▶ Refresh tables from online learning    │
//! │                                                                          │
//! │  NIGHTLY (CI/CD):                                                       │
//! │    Aggregate training data ──▶ Retrain models ──▶ Push to HF Hub        │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::ml_lookup::MlLookupEngine;
use crate::model_hub::{HubConfig, ModelHub, ModelPaths};

/// Network observation for online learning
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    /// RTT in microseconds
    pub rtt_us: u64,
    /// Observed loss rate
    pub loss_rate: f32,
    /// Bandwidth estimate (Mbps)
    pub bandwidth_mbps: f64,
    /// CWND that was used
    pub cwnd_used: u64,
    /// Throughput achieved (bytes/sec)
    pub throughput_achieved: u64,
    /// Was this decision good? (throughput / expected)
    pub reward: f32,
    /// Timestamp
    pub timestamp: Instant,
}

impl Observation {
    /// Create new observation
    pub fn new(
        rtt_us: u64,
        loss_rate: f32,
        bandwidth_mbps: f64,
        cwnd_used: u64,
        throughput_achieved: u64,
    ) -> Self {
        // Calculate reward: ratio of achieved vs expected throughput
        let expected = (bandwidth_mbps * 125_000.0) as u64; // Mbps to bytes/sec
        let reward = if expected > 0 {
            (throughput_achieved as f32 / expected as f32).min(1.5)
        } else {
            1.0
        };

        Self {
            rtt_us,
            loss_rate,
            bandwidth_mbps,
            cwnd_used,
            throughput_achieved,
            reward,
            timestamp: Instant::now(),
        }
    }

    /// Convert to feature vector for ML
    pub fn to_features(&self) -> [f32; 8] {
        [
            self.rtt_us as f32 / 320_000.0,         // Normalized RTT (max 320ms)
            self.loss_rate,                         // Loss rate (0-1)
            (self.bandwidth_mbps / 10000.0) as f32, // Normalized BW (max 10Gbps)
            self.cwnd_used as f32 / 134_217_728.0,  // Normalized CWND (max 128MB)
            self.throughput_achieved as f32 / 1_250_000_000.0, // Normalized (max 10Gbps)
            self.reward,                            // Reward signal
            0.0,                                    // Reserved
            0.0,                                    // Reserved
        ]
    }
}

/// Serializable observation for HF upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableObservation {
    pub rtt_us: u64,
    pub loss_rate: f32,
    pub bandwidth_mbps: f64,
    pub cwnd_used: u64,
    pub throughput_achieved: u64,
    pub reward: f32,
    pub timestamp_ms: u64,
}

impl From<&Observation> for SerializableObservation {
    fn from(obs: &Observation) -> Self {
        Self {
            rtt_us: obs.rtt_us,
            loss_rate: obs.loss_rate,
            bandwidth_mbps: obs.bandwidth_mbps,
            cwnd_used: obs.cwnd_used,
            throughput_achieved: obs.throughput_achieved,
            reward: obs.reward,
            timestamp_ms: obs.timestamp.elapsed().as_millis() as u64,
        }
    }
}

/// Adaptive ML Engine with online learning + HuggingFace integration
pub struct AdaptiveMlEngine {
    /// Fast path: pre-computed lookup tables
    lookup: Arc<RwLock<MlLookupEngine>>,

    /// Online learning: observation buffer (circular, max 100K observations)
    observations: Arc<RwLock<VecDeque<Observation>>>,
    max_observations: usize,

    /// Model weights (updated by online learning)
    cwnd_weights: Arc<RwLock<Vec<f32>>>,
    fec_weights: Arc<RwLock<Vec<f32>>>,

    /// Refresh configuration
    refresh_interval: Duration,
    last_refresh: Arc<RwLock<Instant>>,
    observations_since_refresh: AtomicU64,
    min_observations_for_refresh: u64,

    /// HuggingFace Hub integration
    hub: Arc<RwLock<Option<ModelHub>>>,
    hf_upload_enabled: AtomicBool,
    last_hf_upload: Arc<RwLock<Instant>>,
    hf_upload_interval: Duration,

    /// Model paths from HF
    model_paths: Arc<RwLock<Option<ModelPaths>>>,

    /// Whether models were loaded from HF
    models_loaded: AtomicBool,

    /// Statistics
    pub stats: AdaptiveStats,
}

#[derive(Default)]
pub struct AdaptiveStats {
    /// Total decisions made
    pub total_decisions: AtomicU64,
    /// Decisions from lookup table
    pub lookup_decisions: AtomicU64,
    /// Decisions from live ML
    pub live_ml_decisions: AtomicU64,
    /// Observations recorded
    pub observations_recorded: AtomicU64,
    /// Table refreshes performed
    pub table_refreshes: AtomicU64,
    /// Model updates performed
    pub model_updates: AtomicU64,
    /// Average reward (quality metric)
    pub total_reward: AtomicU64,
    pub reward_count: AtomicU64,
}

impl AdaptiveStats {
    pub fn avg_reward(&self) -> f64 {
        let total = self.total_reward.load(Ordering::Relaxed);
        let count = self.reward_count.load(Ordering::Relaxed);
        if count == 0 {
            1.0
        } else {
            total as f64 / count as f64 / 1000.0
        }
    }

    pub fn lookup_rate(&self) -> f64 {
        let total = self.total_decisions.load(Ordering::Relaxed);
        let lookup = self.lookup_decisions.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            lookup as f64 / total as f64
        }
    }
}

impl AdaptiveMlEngine {
    /// Create new adaptive ML engine with HuggingFace integration
    /// Automatically downloads models from HF Hub and initializes
    pub fn new() -> Self {
        let mut engine = Self {
            lookup: Arc::new(RwLock::new(MlLookupEngine::new())),
            observations: Arc::new(RwLock::new(VecDeque::with_capacity(100_000))),
            max_observations: 100_000,
            cwnd_weights: Arc::new(RwLock::new(Vec::new())),
            fec_weights: Arc::new(RwLock::new(Vec::new())),
            refresh_interval: Duration::from_secs(3600), // 1 hour
            last_refresh: Arc::new(RwLock::new(Instant::now())),
            observations_since_refresh: AtomicU64::new(0),
            min_observations_for_refresh: 10_000,
            hub: Arc::new(RwLock::new(None)),
            hf_upload_enabled: AtomicBool::new(true),
            last_hf_upload: Arc::new(RwLock::new(Instant::now())),
            hf_upload_interval: Duration::from_secs(3600), // Upload hourly
            model_paths: Arc::new(RwLock::new(None)),
            models_loaded: AtomicBool::new(false),
            stats: AdaptiveStats::default(),
        };

        // Auto-initialize from HF Hub
        engine.init_from_huggingface();

        engine
    }

    /// Initialize and download models from HuggingFace Hub
    fn init_from_huggingface(&mut self) {
        tracing::info!("Initializing ML engine from HuggingFace Hub...");

        let hub = ModelHub::new(HubConfig::default());

        // Try to download models
        match hub.download_models() {
            Ok(paths) => {
                tracing::info!("Downloaded models from HuggingFace Hub");
                self.load_weights_from_paths(&paths);
                *self.model_paths.write().unwrap() = Some(paths);
                self.models_loaded.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to download from HF Hub: {}, using embedded weights",
                    e
                );
                // Load from local hf_repo if available
                self.load_from_local_repo();
            }
        }

        *self.hub.write().unwrap() = Some(hub);

        // Regenerate lookup tables from loaded weights
        self.regenerate_lookup_tables();
    }

    /// Load weights from local hf_repo directory
    fn load_from_local_repo(&mut self) {
        let local_paths = [
            "hf_repo/transformer_loss.safetensors",
            "hf_repo/ppo_congestion.safetensors",
        ];

        for path in &local_paths {
            let full_path = PathBuf::from(path);
            if full_path.exists() {
                tracing::info!("Loading weights from local: {}", path);
                self.load_safetensors_weights(&full_path);
            }
        }
    }

    /// Load weights from model paths
    fn load_weights_from_paths(&mut self, paths: &ModelPaths) {
        if let Some(ref transformer_path) = paths.transformer {
            self.load_safetensors_weights(transformer_path);
        }
        if let Some(ref ppo_path) = paths.ppo {
            self.load_safetensors_weights(ppo_path);
        }
    }

    /// Load weights from safetensors file
    fn load_safetensors_weights(&mut self, path: &PathBuf) {
        match safetensors::SafeTensors::deserialize(&std::fs::read(path).unwrap_or_default()) {
            Ok(tensors) => {
                // Extract weights based on tensor names
                for (name, tensor) in tensors.tensors() {
                    let data: Vec<f32> = tensor
                        .data()
                        .chunks(4)
                        .filter_map(|b| b.try_into().ok())
                        .map(f32::from_le_bytes)
                        .collect();

                    if name.contains("cwnd")
                        || name.contains("congestion")
                        || name.contains("policy")
                    {
                        *self.cwnd_weights.write().unwrap() = data;
                        tracing::info!(
                            "Loaded CWND weights: {} params",
                            self.cwnd_weights.read().unwrap().len()
                        );
                    } else if name.contains("fec") || name.contains("loss") {
                        *self.fec_weights.write().unwrap() = data.into_iter().take(16).collect();
                        tracing::info!("Loaded FEC weights");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to load safetensors {}: {}", path.display(), e);
            }
        }
    }

    /// Regenerate lookup tables from current weights
    fn regenerate_lookup_tables(&self) {
        let new_lookup = MlLookupEngine::from_model(
            |rtt_us, loss_rate, bw_mbps, features| {
                self.infer_cwnd_with_updated_weights(rtt_us, loss_rate, bw_mbps, features)
            },
            |loss_rate| self.infer_fec_with_updated_weights(loss_rate),
        );

        if let Ok(mut lookup) = self.lookup.write() {
            *lookup = new_lookup;
        }

        tracing::info!("Lookup tables regenerated from trained weights");
    }

    /// Create with custom refresh interval
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Create with custom observation buffer size
    pub fn with_max_observations(mut self, max: usize) -> Self {
        self.max_observations = max;
        self
    }

    /// Enable/disable HuggingFace upload
    pub fn with_hf_upload(self, enabled: bool) -> Self {
        self.hf_upload_enabled.store(enabled, Ordering::SeqCst);
        self
    }

    /// Check if models were successfully loaded
    pub fn models_loaded(&self) -> bool {
        self.models_loaded.load(Ordering::SeqCst)
    }

    /// Get CWND decision (fast path → slow path fallback)
    #[inline]
    pub fn get_cwnd(&self, rtt_us: u64, loss_rate: f32, bandwidth_mbps: f64) -> u64 {
        self.stats.total_decisions.fetch_add(1, Ordering::Relaxed);

        // Try fast path first (lookup table)
        if let Ok(lookup) = self.lookup.read() {
            if let Some(cwnd) = lookup.get_cwnd(rtt_us, loss_rate, bandwidth_mbps) {
                self.stats.lookup_decisions.fetch_add(1, Ordering::Relaxed);
                return cwnd;
            }
        }

        // Slow path: live ML inference
        self.stats.live_ml_decisions.fetch_add(1, Ordering::Relaxed);
        self.infer_cwnd_live(rtt_us, loss_rate, bandwidth_mbps)
    }

    /// Live ML inference for edge cases
    fn infer_cwnd_live(&self, rtt_us: u64, loss_rate: f32, bandwidth_mbps: f64) -> u64 {
        let features = [
            rtt_us as f32 / 320_000.0,
            loss_rate,
            (bandwidth_mbps / 10000.0) as f32,
            0.5,
            0.5,
            0.1,
            0.5,
            0.0,
        ];

        // Get multiplier from weights
        let multiplier =
            self.infer_cwnd_with_updated_weights(rtt_us, loss_rate, bandwidth_mbps, &features)
                as f32
                / 65536.0;

        // Base CWND from BDP
        let rtt_sec = rtt_us as f64 / 1_000_000.0;
        let bw_bytes = bandwidth_mbps * 125_000.0;
        let bdp = (bw_bytes * rtt_sec) as u64;

        // Apply multiplier with bounds
        ((bdp as f64 * multiplier as f64) as u64)
            .max(4 * 1460)
            .min(128 * 1024 * 1024)
    }

    /// Get FEC ratio
    #[inline]
    pub fn get_fec_ratio(&self, loss_rate: f32) -> f32 {
        if let Ok(lookup) = self.lookup.read() {
            return lookup.get_fec_ratio(loss_rate);
        }
        // Fallback
        (loss_rate * 2.0).min(0.5)
    }

    /// Record an observation for online learning
    /// Call this after each packet/batch with ground truth
    pub fn observe(&self, obs: Observation) {
        self.stats
            .observations_recorded
            .fetch_add(1, Ordering::Relaxed);
        self.observations_since_refresh
            .fetch_add(1, Ordering::Relaxed);

        // Record reward for quality tracking
        self.stats
            .total_reward
            .fetch_add((obs.reward * 1000.0) as u64, Ordering::Relaxed);
        self.stats.reward_count.fetch_add(1, Ordering::Relaxed);

        // Add to observation buffer
        if let Ok(mut observations) = self.observations.write() {
            if observations.len() >= self.max_observations {
                observations.pop_front(); // Remove oldest
            }
            observations.push_back(obs);
        }

        // Check if refresh needed
        self.maybe_refresh();
    }

    /// Convenience method to record observation from raw values
    pub fn record(
        &self,
        rtt_us: u64,
        loss_rate: f32,
        bandwidth_mbps: f64,
        cwnd_used: u64,
        throughput_achieved: u64,
    ) {
        self.observe(Observation::new(
            rtt_us,
            loss_rate,
            bandwidth_mbps,
            cwnd_used,
            throughput_achieved,
        ));
    }

    /// Check if table refresh is needed and perform it
    fn maybe_refresh(&self) {
        let should_refresh = {
            let last = self.last_refresh.read().unwrap();
            let obs_count = self.observations_since_refresh.load(Ordering::Relaxed);

            last.elapsed() >= self.refresh_interval
                && obs_count >= self.min_observations_for_refresh
        };

        if should_refresh {
            self.refresh_tables();

            // Also upload to HF if enabled
            if self.hf_upload_enabled.load(Ordering::Relaxed) {
                self.maybe_upload_to_hf();
            }
        }
    }

    /// Upload training observations to HuggingFace Hub
    fn maybe_upload_to_hf(&self) {
        let should_upload = {
            let last = self.last_hf_upload.read().unwrap();
            last.elapsed() >= self.hf_upload_interval
        };

        if !should_upload {
            return;
        }

        // Get observations to upload
        let observations: Vec<SerializableObservation> = {
            let obs = self.observations.read().unwrap();
            obs.iter().map(SerializableObservation::from).collect()
        };

        if observations.is_empty() {
            return;
        }

        // Upload in background thread to not block hot path
        let hub = self.hub.clone();
        let last_upload = self.last_hf_upload.clone();

        std::thread::spawn(move || {
            if let Some(ref hub) = *hub.read().unwrap() {
                // Convert to LossSample format for hub
                let loss_samples: Vec<crate::ml_optimized::LossSample> = observations
                    .iter()
                    .map(|o| crate::ml_optimized::LossSample {
                        timestamp_ms: o.timestamp_ms,
                        rtt_us: o.rtt_us,
                        rtt_var_us: 0,
                        bandwidth_bps: (o.bandwidth_mbps * 1_000_000.0) as u64,
                        loss_rate: o.loss_rate,
                        inflight: o.cwnd_used as u32,
                        buffer_occupancy: 0.0,
                        ipg_us: 0,
                        future_loss: o.loss_rate,
                    })
                    .collect();

                match hub.upload_training_data(&loss_samples, &[]) {
                    Ok(()) => {
                        tracing::info!(
                            "Uploaded {} observations to HuggingFace Hub",
                            observations.len()
                        );
                        *last_upload.write().unwrap() = Instant::now();
                    }
                    Err(e) => {
                        tracing::warn!("Failed to upload to HF Hub: {}", e);
                    }
                }
            }
        });
    }

    /// Force upload observations to HuggingFace Hub
    pub fn force_upload_to_hf(&self) -> Result<(), String> {
        let observations: Vec<SerializableObservation> = {
            let obs = self.observations.read().unwrap();
            obs.iter().map(SerializableObservation::from).collect()
        };

        if observations.is_empty() {
            return Err("No observations to upload".into());
        }

        let hub_guard = self.hub.read().unwrap();
        let hub = hub_guard.as_ref().ok_or("HF Hub not initialized")?;

        let loss_samples: Vec<crate::ml_optimized::LossSample> = observations
            .iter()
            .map(|o| crate::ml_optimized::LossSample {
                timestamp_ms: o.timestamp_ms,
                rtt_us: o.rtt_us,
                rtt_var_us: 0,
                bandwidth_bps: (o.bandwidth_mbps * 1_000_000.0) as u64,
                loss_rate: o.loss_rate,
                inflight: o.cwnd_used as u32,
                buffer_occupancy: 0.0,
                ipg_us: 0,
                future_loss: o.loss_rate,
            })
            .collect();

        hub.upload_training_data(&loss_samples, &[])
            .map_err(|e| e.to_string())?;

        *self.last_hf_upload.write().unwrap() = Instant::now();
        tracing::info!(
            "Force uploaded {} observations to HuggingFace Hub",
            observations.len()
        );

        Ok(())
    }

    /// Sync models from HuggingFace Hub (download latest)
    pub fn sync_from_hf(&mut self) -> Result<(), String> {
        let hub_guard = self.hub.read().unwrap();
        let hub = hub_guard.as_ref().ok_or("HF Hub not initialized")?;

        let paths = hub.download_models().map_err(|e| e.to_string())?;
        drop(hub_guard);

        self.load_weights_from_paths(&paths);
        self.regenerate_lookup_tables();
        self.models_loaded.store(true, Ordering::SeqCst);

        tracing::info!("Synced models from HuggingFace Hub");
        Ok(())
    }

    /// Force refresh lookup tables from current observations
    pub fn refresh_tables(&self) {
        let start = Instant::now();

        // Get observations snapshot
        let observations: Vec<Observation> = {
            let obs = self.observations.read().unwrap();
            obs.iter().copied().collect()
        };

        if observations.is_empty() {
            return;
        }

        tracing::info!(
            "Refreshing ML tables from {} observations...",
            observations.len()
        );

        // Update model weights from observations (simple online gradient descent)
        self.update_model_weights(&observations);

        // Regenerate lookup tables with updated model
        let new_lookup = MlLookupEngine::from_model(
            |rtt_us, loss_rate, bw_mbps, features| {
                self.infer_cwnd_with_updated_weights(rtt_us, loss_rate, bw_mbps, features)
            },
            |loss_rate| self.infer_fec_with_updated_weights(loss_rate),
        );

        // Swap in new tables
        if let Ok(mut lookup) = self.lookup.write() {
            *lookup = new_lookup;
        }

        // Reset counters
        *self.last_refresh.write().unwrap() = Instant::now();
        self.observations_since_refresh.store(0, Ordering::Relaxed);
        self.stats.table_refreshes.fetch_add(1, Ordering::Relaxed);

        tracing::info!(
            "ML tables refreshed in {:?}, avg_reward: {:.3}",
            start.elapsed(),
            self.stats.avg_reward()
        );
    }

    /// Update model weights using online learning from observations
    fn update_model_weights(&self, observations: &[Observation]) {
        // Simple exponential moving average update
        // In production, use proper SGD/Adam optimizer

        let learning_rate = 0.01;
        let mut cwnd_weights = self.cwnd_weights.write().unwrap();
        let mut fec_weights = self.fec_weights.write().unwrap();

        // Initialize weights if empty
        if cwnd_weights.is_empty() {
            *cwnd_weights = vec![0.5; 64]; // Simple weight vector
        }
        if fec_weights.is_empty() {
            *fec_weights = vec![0.5; 16];
        }

        // Update from recent observations
        for obs in observations.iter().rev().take(10_000) {
            let features = obs.to_features();
            let reward = obs.reward;

            // Simple gradient: if reward > 1, we did well, reinforce
            // if reward < 1, we did poorly, adjust
            let gradient = reward - 1.0;

            // Update CWND weights
            for (i, w) in cwnd_weights.iter_mut().enumerate() {
                let feature_idx = i % features.len();
                *w += learning_rate * gradient * features[feature_idx];
                *w = w.clamp(-2.0, 2.0); // Bound weights
            }

            // Update FEC weights based on loss correlation
            let loss_idx = (obs.loss_rate * 100.0) as usize % fec_weights.len();
            fec_weights[loss_idx] += learning_rate * gradient * 0.1;
            fec_weights[loss_idx] = fec_weights[loss_idx].clamp(0.0, 1.0);
        }

        self.stats.model_updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Inference using updated weights
    fn infer_cwnd_with_updated_weights(
        &self,
        rtt_us: u64,
        loss_rate: f32,
        bandwidth_mbps: f64,
        features: &[f32],
    ) -> u64 {
        let weights = self.cwnd_weights.read().unwrap();

        if weights.is_empty() {
            // Fall back to base inference
            return self.infer_cwnd_live(rtt_us, loss_rate, bandwidth_mbps);
        }

        // Simple weighted sum
        let mut score: f32 = 0.0;
        for (i, &f) in features.iter().enumerate() {
            let w_idx = i % weights.len();
            score += f * weights[w_idx];
        }

        // Convert score to CWND multiplier (sigmoid)
        let multiplier = 0.5 + 1.5 / (1.0 + (-score).exp());

        // Base CWND from BDP
        let rtt_sec = rtt_us as f64 / 1_000_000.0;
        let bw_bytes = bandwidth_mbps * 125_000.0;
        let bdp = (bw_bytes * rtt_sec) as u64;

        ((bdp as f64 * multiplier as f64) as u64)
            .max(4 * 1460)
            .min(128 * 1024 * 1024)
    }

    /// FEC inference using updated weights
    fn infer_fec_with_updated_weights(&self, loss_rate: f32) -> f32 {
        let weights = self.fec_weights.read().unwrap();

        if weights.is_empty() {
            return (loss_rate * 2.0).min(0.5);
        }

        let idx = (loss_rate * 100.0) as usize % weights.len();
        let base = loss_rate * 2.0;
        let adjustment = weights[idx];

        (base * (0.5 + adjustment)).min(0.5)
    }

    /// Get statistics summary
    pub fn stats_summary(&self) -> String {
        format!(
            "Adaptive ML: {:.1}% lookup, {:.3} avg_reward, {} refreshes, {} observations",
            self.stats.lookup_rate() * 100.0,
            self.stats.avg_reward(),
            self.stats.table_refreshes.load(Ordering::Relaxed),
            self.stats.observations_recorded.load(Ordering::Relaxed),
        )
    }

    /// Start background refresh task
    pub fn start_background_refresh(self: Arc<Self>) {
        let engine = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(engine.refresh_interval);
            engine.refresh_tables();
        });
    }
}

impl Default for AdaptiveMlEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observation() {
        let obs = Observation::new(50_000, 0.01, 100.0, 100_000, 10_000_000);
        assert!(obs.reward > 0.0);

        let features = obs.to_features();
        assert_eq!(features.len(), 8);
    }

    #[test]
    fn test_adaptive_engine() {
        let engine = AdaptiveMlEngine::new();

        // Should get CWND without crashing
        let cwnd = engine.get_cwnd(50_000, 0.01, 100.0);
        assert!(cwnd > 0);

        // Should record observation
        engine.record(50_000, 0.01, 100.0, cwnd, 10_000_000);
        assert_eq!(
            engine.stats.observations_recorded.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_refresh() {
        let engine = AdaptiveMlEngine::new()
            .with_refresh_interval(Duration::from_millis(1))
            .with_max_observations(100);

        // Record some observations
        for i in 0..100 {
            engine.record(50_000 + i * 1000, 0.01, 100.0, 100_000, 10_000_000);
        }

        // Manual refresh
        engine.refresh_tables();
        assert_eq!(engine.stats.table_refreshes.load(Ordering::Relaxed), 1);
    }
}
