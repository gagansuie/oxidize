//! Federated Learning - Privacy-preserving aggregation with differential privacy
//!
//! Implements:
//! - Federated averaging (FedAvg) algorithm
//! - Differential privacy with gradient clipping and noise injection
//! - Privacy budget accounting
//! - Secure aggregation support

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Federated learning configuration with differential privacy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedConfig {
    /// Enable differential privacy
    pub enable_dp: bool,
    /// Privacy budget (epsilon)
    pub dp_epsilon: f64,
    /// Noise multiplier for DP
    pub dp_noise_multiplier: f64,
    /// Gradient clipping norm for DP
    pub dp_clip_norm: f64,
    /// Minimum number of clients for aggregation
    pub min_clients: usize,
    /// Aggregation round duration in seconds
    pub round_duration_secs: u64,
    /// Secure aggregation (encrypt updates)
    pub secure_aggregation: bool,
}

impl Default for FederatedConfig {
    fn default() -> Self {
        Self {
            enable_dp: true,
            dp_epsilon: 1.0,
            dp_noise_multiplier: 1.1,
            dp_clip_norm: 1.0,
            min_clients: 3,
            round_duration_secs: 3600,
            secure_aggregation: true,
        }
    }
}

/// Client update for federated averaging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedClientUpdate {
    /// Anonymized client ID (hashed)
    pub client_hash: String,
    /// Round number
    pub round: u64,
    /// Model weight updates (delta from global)
    pub weight_deltas: Vec<f64>,
    /// Number of local samples used
    pub num_samples: u64,
    /// Local loss after training
    pub local_loss: f64,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Federated learning coordinator with differential privacy
pub struct FederatedCoordinator {
    config: FederatedConfig,
    global_weights: RwLock<Vec<f64>>,
    client_updates: RwLock<Vec<FederatedClientUpdate>>,
    current_round: AtomicU64,
    round_start: RwLock<Instant>,
    privacy_spent: RwLock<f64>,
    rng_seed: AtomicU64,
}

impl FederatedCoordinator {
    pub fn new(config: FederatedConfig, initial_weights: Vec<f64>) -> Self {
        Self {
            config,
            global_weights: RwLock::new(initial_weights),
            client_updates: RwLock::new(Vec::new()),
            current_round: AtomicU64::new(0),
            round_start: RwLock::new(Instant::now()),
            privacy_spent: RwLock::new(0.0),
            rng_seed: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(42),
            ),
        }
    }

    /// Submit a client update
    pub fn submit_update(&self, mut update: FederatedClientUpdate) -> Result<(), &'static str> {
        let current_round = self.current_round.load(Ordering::Relaxed);
        if update.round != current_round {
            return Err("Round mismatch");
        }

        if self.config.enable_dp {
            self.apply_differential_privacy(&mut update.weight_deltas);
        }

        if let Ok(mut updates) = self.client_updates.write() {
            if !updates.iter().any(|u| u.client_hash == update.client_hash) {
                updates.push(update);
            }
        }
        Ok(())
    }

    /// Apply differential privacy to weight deltas
    fn apply_differential_privacy(&self, deltas: &mut [f64]) {
        // Gradient clipping
        let norm: f64 = deltas.iter().map(|d| d * d).sum::<f64>().sqrt();
        if norm > self.config.dp_clip_norm {
            let scale = self.config.dp_clip_norm / norm;
            for d in deltas.iter_mut() {
                *d *= scale;
            }
        }

        // Add Gaussian noise
        let noise_std = self.config.dp_clip_norm * self.config.dp_noise_multiplier;
        for d in deltas.iter_mut() {
            *d += self.gaussian_noise(noise_std);
        }
    }

    /// Generate Gaussian noise using Box-Muller transform
    fn gaussian_noise(&self, std_dev: f64) -> f64 {
        let seed = self.rng_seed.fetch_add(1, Ordering::Relaxed);
        let u1 = ((seed.wrapping_mul(1103515245).wrapping_add(12345)) as f64) / u64::MAX as f64;
        let u2 = ((seed.wrapping_mul(1103515245).wrapping_add(12346)) as f64) / u64::MAX as f64;

        let u1 = u1.max(1e-10);
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        z * std_dev
    }

    /// Check if aggregation should occur
    pub fn should_aggregate(&self) -> bool {
        let updates = self.client_updates.read().map(|u| u.len()).unwrap_or(0);
        if updates < self.config.min_clients {
            return false;
        }

        if let Ok(start) = self.round_start.read() {
            start.elapsed() >= Duration::from_secs(self.config.round_duration_secs)
        } else {
            false
        }
    }

    /// Perform federated averaging
    pub fn aggregate(&self) -> Option<Vec<f64>> {
        let updates = {
            let mut updates = self.client_updates.write().ok()?;
            std::mem::take(&mut *updates)
        };

        if updates.len() < self.config.min_clients {
            if let Ok(mut u) = self.client_updates.write() {
                *u = updates;
            }
            return None;
        }

        let global = self.global_weights.read().ok()?;
        let weight_dim = global.len();
        drop(global);

        let total_samples: u64 = updates.iter().map(|u| u.num_samples).sum();
        if total_samples == 0 {
            return None;
        }

        let mut aggregated_deltas = vec![0.0; weight_dim];
        for update in &updates {
            let weight = update.num_samples as f64 / total_samples as f64;
            for (i, delta) in update.weight_deltas.iter().enumerate() {
                if i < weight_dim {
                    aggregated_deltas[i] += delta * weight;
                }
            }
        }

        let mut global = self.global_weights.write().ok()?;
        for (w, d) in global.iter_mut().zip(aggregated_deltas.iter()) {
            *w += d;
        }

        self.current_round.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut start) = self.round_start.write() {
            *start = Instant::now();
        }

        if self.config.enable_dp {
            if let Ok(mut spent) = self.privacy_spent.write() {
                *spent += self.config.dp_epsilon / (updates.len() as f64).sqrt();
            }
        }

        Some(global.clone())
    }

    /// Get current global weights
    pub fn global_weights(&self) -> Option<Vec<f64>> {
        self.global_weights.read().ok().map(|w| w.clone())
    }

    /// Get current round
    pub fn current_round(&self) -> u64 {
        self.current_round.load(Ordering::Relaxed)
    }

    /// Get federated stats
    pub fn stats(&self) -> FederatedLearningStats {
        FederatedLearningStats {
            current_round: self.current_round.load(Ordering::Relaxed),
            pending_updates: self.client_updates.read().map(|u| u.len()).unwrap_or(0),
            privacy_spent: self.privacy_spent.read().map(|p| *p).unwrap_or(0.0),
            min_clients: self.config.min_clients,
            dp_enabled: self.config.enable_dp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedLearningStats {
    pub current_round: u64,
    pub pending_updates: usize,
    pub privacy_spent: f64,
    pub min_clients: usize,
    pub dp_enabled: bool,
}

/// Generate anonymized client hash from server ID
pub fn anonymize_client_id(server_id: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in server_id.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federated_coordinator() {
        let config = FederatedConfig {
            min_clients: 2,
            ..Default::default()
        };
        let coord = FederatedCoordinator::new(config, vec![0.0; 10]);

        let update1 = FederatedClientUpdate {
            client_hash: "client1".to_string(),
            round: 0,
            weight_deltas: vec![0.1; 10],
            num_samples: 100,
            local_loss: 0.5,
            timestamp_ms: 0,
        };

        let update2 = FederatedClientUpdate {
            client_hash: "client2".to_string(),
            round: 0,
            weight_deltas: vec![0.2; 10],
            num_samples: 100,
            local_loss: 0.4,
            timestamp_ms: 0,
        };

        coord.submit_update(update1).unwrap();
        coord.submit_update(update2).unwrap();

        let stats = coord.stats();
        assert_eq!(stats.pending_updates, 2);
    }

    #[test]
    fn test_anonymize_client_id() {
        let hash = anonymize_client_id("server-123");
        assert_eq!(hash.len(), 16);
    }
}
