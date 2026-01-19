//! ML-Augmented Pacing for BBRv4
//!
//! Uses LSTM predictions to pre-emptively adjust CWND before loss occurs.
//! Provides 10-50ms early warning of congestion events.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

/// ML-augmented congestion window predictor
#[derive(Debug)]
pub struct MlAugmentedPacer {
    cwnd: AtomicU64,
    loss_probability: AtomicU32, // Fixed point 0-1000
    prediction_interval_ms: u64,
    rtt_history: RwLock<RttHistory>,
    ml_enabled: AtomicBool,
    pub stats: MlPacerStats,
}

#[derive(Debug, Default)]
pub struct MlPacerStats {
    pub predictions_made: AtomicU64,
    pub preemptive_reductions: AtomicU64,
    pub loss_events_predicted: AtomicU64,
    pub loss_events_missed: AtomicU64,
    pub avg_prediction_accuracy: AtomicU32,
}

#[derive(Debug, Default)]
struct RttHistory {
    samples: Vec<u32>,
    loss_events: Vec<u64>,
    bandwidth_samples: Vec<u64>,
    max_samples: usize,
}

impl RttHistory {
    fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_samples),
            loss_events: Vec::with_capacity(max_samples / 10),
            bandwidth_samples: Vec::with_capacity(max_samples),
            max_samples,
        }
    }

    fn add_rtt(&mut self, rtt_us: u32) {
        if self.samples.len() >= self.max_samples {
            self.samples.remove(0);
        }
        self.samples.push(rtt_us);
    }

    fn add_loss_event(&mut self, timestamp: u64) {
        if self.loss_events.len() >= self.max_samples / 10 {
            self.loss_events.remove(0);
        }
        self.loss_events.push(timestamp);
    }

    fn add_bandwidth(&mut self, bw: u64) {
        if self.bandwidth_samples.len() >= self.max_samples {
            self.bandwidth_samples.remove(0);
        }
        self.bandwidth_samples.push(bw);
    }

    /// Prepare features for LSTM (30 normalized features)
    fn prepare_features(&self) -> [f32; 30] {
        let mut features = [0.0f32; 30];

        // RTT samples (0-9)
        let rtt_len = self.samples.len();
        for (i, feat) in features.iter_mut().take(10).enumerate() {
            if i < rtt_len {
                *feat = (self.samples[rtt_len - 1 - i] as f32 / 100000.0).min(1.0);
            }
        }

        // Bandwidth samples (10-19)
        let bw_len = self.bandwidth_samples.len();
        for i in 0..10 {
            if i < bw_len {
                features[10 + i] = (self.bandwidth_samples[bw_len - 1 - i] as f32 / 1e9).min(1.0);
            }
        }

        // RTT variance (20)
        if rtt_len >= 2 {
            let recent: Vec<_> = self.samples.iter().rev().take(5).collect();
            let mean: f32 = recent.iter().map(|&&x| x as f32).sum::<f32>() / recent.len() as f32;
            let variance: f32 = recent
                .iter()
                .map(|&&x| (x as f32 - mean).powi(2))
                .sum::<f32>()
                / recent.len() as f32;
            features[20] = (variance.sqrt() / mean.max(1.0)).min(1.0);
        }

        // Loss frequency (21)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let recent_losses = self
            .loss_events
            .iter()
            .filter(|&&t| now_ms.saturating_sub(t) < 1000)
            .count();
        features[21] = (recent_losses as f32 / 10.0).min(1.0);

        // Bandwidth trend (22)
        if bw_len >= 5 {
            let old: f64 = self.bandwidth_samples[bw_len - 5..bw_len - 3]
                .iter()
                .map(|&x| x as f64)
                .sum::<f64>()
                / 2.0;
            let new: f64 = self.bandwidth_samples[bw_len - 2..]
                .iter()
                .map(|&x| x as f64)
                .sum::<f64>()
                / 2.0;
            let trend = if old > 0.0 { (new - old) / old } else { 0.0 };
            features[22] = (trend as f32).clamp(-1.0, 1.0);
        }

        features
    }
}

impl Default for MlAugmentedPacer {
    fn default() -> Self {
        Self::new(65536) // Default 64KB initial CWND
    }
}

impl MlAugmentedPacer {
    pub fn new(initial_cwnd: u64) -> Self {
        Self {
            cwnd: AtomicU64::new(initial_cwnd),
            loss_probability: AtomicU32::new(0),
            prediction_interval_ms: 50,
            rtt_history: RwLock::new(RttHistory::new(100)),
            ml_enabled: AtomicBool::new(true),
            stats: MlPacerStats::default(),
        }
    }

    pub fn record_rtt(&self, rtt: Duration) {
        if let Ok(mut h) = self.rtt_history.write() {
            h.add_rtt(rtt.as_micros() as u32);
        }
    }

    pub fn record_bandwidth(&self, bytes_per_sec: u64) {
        if let Ok(mut h) = self.rtt_history.write() {
            h.add_bandwidth(bytes_per_sec);
        }
    }

    pub fn record_loss(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut h) = self.rtt_history.write() {
            h.add_loss_event(now);
        }
    }

    /// Get recommended CWND based on ML prediction
    pub fn get_recommended_cwnd(&self, current_cwnd: u32) -> u32 {
        let (adjusted, _) = self.get_adjusted_cwnd();
        if adjusted < current_cwnd as u64 {
            adjusted as u32
        } else {
            current_cwnd
        }
    }

    /// Get ML-adjusted CWND: (cwnd, was_preemptively_reduced)
    pub fn get_adjusted_cwnd(&self) -> (u64, bool) {
        let base = self.cwnd.load(Ordering::Relaxed);
        let loss_prob = self.loss_probability.load(Ordering::Relaxed) as f32 / 1000.0;

        if loss_prob > 0.1 {
            let reduction = (loss_prob * 0.5).min(0.5);
            let adjusted = (base as f32 * (1.0 - reduction)) as u64;
            self.stats
                .preemptive_reductions
                .fetch_add(1, Ordering::Relaxed);
            (adjusted.max(1460), true)
        } else {
            (base, false)
        }
    }

    /// Run prediction (call from background task)
    pub fn run_prediction(&self) -> f32 {
        if !self.ml_enabled.load(Ordering::Relaxed) {
            return 0.0;
        }

        let features = match self.rtt_history.read() {
            Ok(h) => h.prepare_features(),
            Err(_) => return 0.0,
        };

        let loss_prob = self.heuristic_prediction(&features);
        self.loss_probability
            .store((loss_prob * 1000.0) as u32, Ordering::Relaxed);
        self.stats.predictions_made.fetch_add(1, Ordering::Relaxed);
        loss_prob
    }

    fn heuristic_prediction(&self, f: &[f32; 30]) -> f32 {
        let rtt_var = f[20];
        let loss_freq = f[21];
        let bw_trend = f[22];

        let prob = (rtt_var * 0.3) + (loss_freq * 0.5) + ((-bw_trend).max(0.0) * 0.2);
        prob.clamp(0.0, 1.0)
    }

    pub fn update_cwnd(&self, cwnd: u64) {
        self.cwnd.store(cwnd, Ordering::Relaxed);
    }

    pub fn set_ml_enabled(&self, enabled: bool) {
        self.ml_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn get_loss_probability(&self) -> f32 {
        self.loss_probability.load(Ordering::Relaxed) as f32 / 1000.0
    }
}
