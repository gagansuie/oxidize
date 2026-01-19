//! Adaptive ML Engine with Online Learning
//!
//! Continuously learns from network observations and auto-refreshes lookup tables.
//! No restart needed - model improves in real-time.
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                      Adaptive ML Engine                                  │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
//! │  │   Lookup     │────▶│   Live ML    │────▶│   Online     │            │
//! │  │   Tables     │     │   Inference  │     │   Learning   │            │
//! │  │   (<100ns)   │     │   (~1µs)     │     │              │            │
//! │  └──────┬───────┘     └──────────────┘     └──────┬───────┘            │
//! │         │                                         │                     │
//! │         │         ┌──────────────┐               │                     │
//! │         └────────▶│   Table      │◀──────────────┘                     │
//! │                   │   Refresh    │                                      │
//! │                   │   (hourly)   │                                      │
//! │                   └──────────────┘                                      │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Flow
//! 1. **Fast path**: Lookup table hit → <100ns decision
//! 2. **Slow path**: Table miss → Live ML inference (~1µs)
//! 3. **Learning**: Every packet → Record observation
//! 4. **Refresh**: Every hour → Retrain model, regenerate tables

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::ml_lookup::MlLookupEngine;
use super::onnx_ml::OnnxInference;

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

/// Adaptive ML Engine with online learning
pub struct AdaptiveMlEngine {
    /// Fast path: pre-computed lookup tables
    lookup: Arc<RwLock<MlLookupEngine>>,

    /// Slow path: live ML inference for edge cases
    live_cwnd_model: OnnxInference,
    live_fec_model: OnnxInference,

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
    /// Create new adaptive ML engine
    pub fn new() -> Self {
        Self {
            lookup: Arc::new(RwLock::new(MlLookupEngine::new())),
            live_cwnd_model: OnnxInference::new(super::onnx_ml::ModelType::CongestionController),
            live_fec_model: OnnxInference::new(super::onnx_ml::ModelType::FecDecision),
            observations: Arc::new(RwLock::new(VecDeque::with_capacity(100_000))),
            max_observations: 100_000,
            cwnd_weights: Arc::new(RwLock::new(Vec::new())),
            fec_weights: Arc::new(RwLock::new(Vec::new())),
            refresh_interval: Duration::from_secs(3600), // 1 hour
            last_refresh: Arc::new(RwLock::new(Instant::now())),
            observations_since_refresh: AtomicU64::new(0),
            min_observations_for_refresh: 10_000,
            stats: AdaptiveStats::default(),
        }
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

        // Get multiplier from ML
        let multiplier = self.live_cwnd_model.infer(&features);

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
        }
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
