//! A/B Testing Framework for Model Deployment
//!
//! Implements:
//! - Statistical significance testing (t-test)
//! - Deterministic user assignment
//! - Early stopping on significance
//! - Experiment lifecycle management

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use super::{AB_TEST_CONFIDENCE_LEVEL, AB_TEST_MIN_SAMPLES};

/// A/B test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestConfig {
    pub min_samples: usize,
    pub confidence_level: f64,
    pub treatment_fraction: f64,
    pub max_duration_secs: u64,
    pub early_stopping: bool,
}

impl Default for ABTestConfig {
    fn default() -> Self {
        Self {
            min_samples: AB_TEST_MIN_SAMPLES,
            confidence_level: AB_TEST_CONFIDENCE_LEVEL,
            treatment_fraction: 0.5,
            max_duration_secs: 86400,
            early_stopping: true,
        }
    }
}

/// Model variant in A/B test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVariant {
    pub name: String,
    pub model_path: String,
    pub is_treatment: bool,
}

/// A/B test experiment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABExperiment {
    pub id: String,
    pub name: String,
    pub control: ModelVariant,
    pub treatment: ModelVariant,
    pub config: ABTestConfig,
    pub created_at_ms: u64,
}

/// Sample result from A/B test
#[derive(Debug, Clone)]
pub struct ABSample {
    pub is_treatment: bool,
    pub metric_value: f64,
    pub timestamp_ms: u64,
}

/// A/B testing framework for model deployment
pub struct ABTestingFramework {
    experiments: RwLock<HashMap<String, ABExperiment>>,
    samples: RwLock<HashMap<String, Vec<ABSample>>>,
    assignments: RwLock<HashMap<String, bool>>,
    results: RwLock<HashMap<String, ABTestResult>>,
    rng_seed: AtomicU64,
}

impl ABTestingFramework {
    pub fn new() -> Self {
        Self {
            experiments: RwLock::new(HashMap::new()),
            samples: RwLock::new(HashMap::new()),
            assignments: RwLock::new(HashMap::new()),
            results: RwLock::new(HashMap::new()),
            rng_seed: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(42),
            ),
        }
    }

    /// Create a new A/B experiment
    pub fn create_experiment(
        &self,
        name: String,
        control: ModelVariant,
        treatment: ModelVariant,
        config: ABTestConfig,
    ) -> String {
        let id = format!(
            "exp_{}",
            self.rng_seed.fetch_add(1, Ordering::Relaxed) % 1_000_000
        );

        let experiment = ABExperiment {
            id: id.clone(),
            name,
            control,
            treatment,
            config,
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };

        if let Ok(mut experiments) = self.experiments.write() {
            experiments.insert(id.clone(), experiment);
        }
        if let Ok(mut samples) = self.samples.write() {
            samples.insert(id.clone(), Vec::new());
        }

        id
    }

    /// Get assignment for a user in an experiment
    pub fn get_assignment(&self, experiment_id: &str, user_id: &str) -> Option<bool> {
        let cache_key = format!("{}:{}", experiment_id, user_id);
        if let Ok(assignments) = self.assignments.read() {
            if let Some(&is_treatment) = assignments.get(&cache_key) {
                return Some(is_treatment);
            }
        }

        let treatment_fraction = self.experiments.read().ok().and_then(|e| {
            e.get(experiment_id)
                .map(|exp| exp.config.treatment_fraction)
        })?;

        let hash = self.hash_user(user_id);
        let is_treatment = (hash as f64 / u64::MAX as f64) < treatment_fraction;

        if let Ok(mut assignments) = self.assignments.write() {
            assignments.insert(cache_key, is_treatment);
        }

        Some(is_treatment)
    }

    /// Get the model path for a user
    pub fn get_model_path(&self, experiment_id: &str, user_id: &str) -> Option<String> {
        let is_treatment = self.get_assignment(experiment_id, user_id)?;

        self.experiments.read().ok().and_then(|e| {
            e.get(experiment_id).map(|exp| {
                if is_treatment {
                    exp.treatment.model_path.clone()
                } else {
                    exp.control.model_path.clone()
                }
            })
        })
    }

    fn hash_user(&self, user_id: &str) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in user_id.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Record a sample result
    pub fn record_sample(&self, experiment_id: &str, sample: ABSample) {
        if let Ok(mut samples) = self.samples.write() {
            if let Some(exp_samples) = samples.get_mut(experiment_id) {
                exp_samples.push(sample);
            }
        }

        if let Ok(experiments) = self.experiments.read() {
            if let Some(exp) = experiments.get(experiment_id) {
                if exp.config.early_stopping {
                    drop(experiments);
                    self.check_significance(experiment_id);
                }
            }
        }
    }

    fn check_significance(&self, experiment_id: &str) {
        let (control_samples, treatment_samples, config) = {
            let samples = match self.samples.read() {
                Ok(s) => s,
                Err(_) => return,
            };
            let exp_samples = match samples.get(experiment_id) {
                Some(s) => s,
                None => return,
            };

            let experiments = match self.experiments.read() {
                Ok(e) => e,
                Err(_) => return,
            };
            let exp = match experiments.get(experiment_id) {
                Some(e) => e,
                None => return,
            };

            let control: Vec<f64> = exp_samples
                .iter()
                .filter(|s| !s.is_treatment)
                .map(|s| s.metric_value)
                .collect();
            let treatment: Vec<f64> = exp_samples
                .iter()
                .filter(|s| s.is_treatment)
                .map(|s| s.metric_value)
                .collect();

            (control, treatment, exp.config.clone())
        };

        if control_samples.len() < config.min_samples
            || treatment_samples.len() < config.min_samples
        {
            return;
        }

        let result = self.compute_ttest(&control_samples, &treatment_samples, &config);

        if result.is_significant {
            if let Ok(mut results) = self.results.write() {
                results.insert(experiment_id.to_string(), result);
            }
        }
    }

    fn compute_ttest(
        &self,
        control: &[f64],
        treatment: &[f64],
        config: &ABTestConfig,
    ) -> ABTestResult {
        let n1 = control.len() as f64;
        let n2 = treatment.len() as f64;

        let mean1: f64 = control.iter().sum::<f64>() / n1;
        let mean2: f64 = treatment.iter().sum::<f64>() / n2;

        let var1: f64 =
            control.iter().map(|x| (x - mean1).powi(2)).sum::<f64>() / (n1 - 1.0).max(1.0);
        let var2: f64 =
            treatment.iter().map(|x| (x - mean2).powi(2)).sum::<f64>() / (n2 - 1.0).max(1.0);

        let se = ((var1 / n1) + (var2 / n2)).sqrt();
        let t_stat = if se > 0.0 { (mean2 - mean1) / se } else { 0.0 };

        let p_value = 2.0 * (1.0 - self.normal_cdf(t_stat.abs()));

        let is_significant = p_value < (1.0 - config.confidence_level);
        let winner = if is_significant && mean2 > mean1 {
            "treatment"
        } else if is_significant {
            "control"
        } else {
            "none"
        };

        ABTestResult {
            control_mean: mean1,
            treatment_mean: mean2,
            control_samples: control.len(),
            treatment_samples: treatment.len(),
            t_statistic: t_stat,
            p_value,
            is_significant,
            winner: winner.to_string(),
            lift_percent: if mean1 > 0.0 {
                (mean2 - mean1) / mean1 * 100.0
            } else {
                0.0
            },
        }
    }

    fn normal_cdf(&self, x: f64) -> f64 {
        let a1 = 0.254829592;
        let a2 = -0.284496736;
        let a3 = 1.421413741;
        let a4 = -1.453152027;
        let a5 = 1.061405429;
        let p = 0.3275911;

        let sign = if x < 0.0 { -1.0 } else { 1.0 };
        let x = x.abs() / std::f64::consts::SQRT_2;

        let t = 1.0 / (1.0 + p * x);
        let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

        0.5 * (1.0 + sign * y)
    }

    /// Get experiment result
    pub fn get_result(&self, experiment_id: &str) -> Option<ABTestResult> {
        self.results
            .read()
            .ok()
            .and_then(|r| r.get(experiment_id).cloned())
    }

    /// Get experiment statistics
    pub fn get_stats(&self, experiment_id: &str) -> Option<ABTestStats> {
        let samples = self.samples.read().ok()?;
        let exp_samples = samples.get(experiment_id)?;

        let control_count = exp_samples.iter().filter(|s| !s.is_treatment).count();
        let treatment_count = exp_samples.iter().filter(|s| s.is_treatment).count();

        Some(ABTestStats {
            experiment_id: experiment_id.to_string(),
            control_samples: control_count,
            treatment_samples: treatment_count,
            is_concluded: self
                .results
                .read()
                .map(|r| r.contains_key(experiment_id))
                .unwrap_or(false),
        })
    }

    /// List all experiments
    pub fn list_experiments(&self) -> Vec<String> {
        self.experiments
            .read()
            .map(|e| e.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Stop an experiment and compute final results
    pub fn conclude_experiment(&self, experiment_id: &str) -> Option<ABTestResult> {
        let (control_samples, treatment_samples, config) = {
            let samples = self.samples.read().ok()?;
            let exp_samples = samples.get(experiment_id)?;

            let experiments = self.experiments.read().ok()?;
            let exp = experiments.get(experiment_id)?;

            let control: Vec<f64> = exp_samples
                .iter()
                .filter(|s| !s.is_treatment)
                .map(|s| s.metric_value)
                .collect();
            let treatment: Vec<f64> = exp_samples
                .iter()
                .filter(|s| s.is_treatment)
                .map(|s| s.metric_value)
                .collect();

            (control, treatment, exp.config.clone())
        };

        let result = self.compute_ttest(&control_samples, &treatment_samples, &config);

        if let Ok(mut results) = self.results.write() {
            results.insert(experiment_id.to_string(), result.clone());
        }

        Some(result)
    }

    /// Delete an experiment
    pub fn delete_experiment(&self, experiment_id: &str) {
        if let Ok(mut experiments) = self.experiments.write() {
            experiments.remove(experiment_id);
        }
        if let Ok(mut samples) = self.samples.write() {
            samples.remove(experiment_id);
        }
        if let Ok(mut results) = self.results.write() {
            results.remove(experiment_id);
        }
    }
}

impl Default for ABTestingFramework {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestResult {
    pub control_mean: f64,
    pub treatment_mean: f64,
    pub control_samples: usize,
    pub treatment_samples: usize,
    pub t_statistic: f64,
    pub p_value: f64,
    pub is_significant: bool,
    pub winner: String,
    pub lift_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestStats {
    pub experiment_id: String,
    pub control_samples: usize,
    pub treatment_samples: usize,
    pub is_concluded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ab_testing_framework() {
        let framework = ABTestingFramework::new();

        let control = ModelVariant {
            name: "lstm_v1".to_string(),
            model_path: "/models/lstm_v1.onnx".to_string(),
            is_treatment: false,
        };

        let treatment = ModelVariant {
            name: "transformer_v1".to_string(),
            model_path: "/models/transformer_v1.onnx".to_string(),
            is_treatment: true,
        };

        let exp_id = framework.create_experiment(
            "lstm_vs_transformer".to_string(),
            control,
            treatment,
            ABTestConfig::default(),
        );

        assert!(!exp_id.is_empty());

        let assignment1 = framework.get_assignment(&exp_id, "user1");
        let assignment2 = framework.get_assignment(&exp_id, "user1");
        assert_eq!(assignment1, assignment2); // Deterministic

        let experiments = framework.list_experiments();
        assert_eq!(experiments.len(), 1);
    }

    #[test]
    fn test_statistical_significance() {
        let framework = ABTestingFramework::new();

        let control = ModelVariant {
            name: "control".to_string(),
            model_path: "/models/control.onnx".to_string(),
            is_treatment: false,
        };

        let treatment = ModelVariant {
            name: "treatment".to_string(),
            model_path: "/models/treatment.onnx".to_string(),
            is_treatment: true,
        };

        let config = ABTestConfig {
            min_samples: 10,
            ..Default::default()
        };

        let exp_id = framework.create_experiment("test".to_string(), control, treatment, config);

        // Add samples with clear difference
        for i in 0..20 {
            framework.record_sample(
                &exp_id,
                ABSample {
                    is_treatment: false,
                    metric_value: 100.0 + (i as f64),
                    timestamp_ms: i as u64,
                },
            );
            framework.record_sample(
                &exp_id,
                ABSample {
                    is_treatment: true,
                    metric_value: 150.0 + (i as f64),
                    timestamp_ms: i as u64,
                },
            );
        }

        let result = framework.conclude_experiment(&exp_id);
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(result.treatment_mean > result.control_mean);
    }
}
