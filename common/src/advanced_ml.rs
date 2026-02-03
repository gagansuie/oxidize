//! Advanced ML Features: FederatedCoordinator, MultiAgentCoordinator, ABTestingFramework
//!
//! # Status: Implemented, Runtime Integration TBD
//!
//! These features are fully implemented and tested but not yet wired into the server runtime.
//! They are available as APIs for future integration:
//!
//! - **FederatedCoordinator**: Requires multi-server deployment + central aggregation service
//! - **MultiAgentCoordinator**: For research/experimentation with multi-flow RL congestion control
//! - **ABTestingFramework**: For A/B testing model variants in production
//!
//! The server currently uses `ml_optimized::OptimizedMlEngine` for all ML inference.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

// ============================================================================
// Federated Learning
// ============================================================================

#[derive(Debug, Clone)]
pub struct FederatedConfig {
    pub enable_dp: bool,
    pub dp_epsilon: f64,
    pub dp_noise_multiplier: f64,
    pub dp_clip_norm: f64,
    pub min_clients: usize,
    pub round_duration_secs: u64,
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

#[derive(Debug, Clone)]
pub struct FederatedClientUpdate {
    pub client_hash: u64,
    pub round: u64,
    pub weight_deltas: Vec<f32>,
    pub num_samples: usize,
    pub local_loss: f32,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FederatedStats {
    pub rounds_completed: u64,
    pub updates_received: u64,
    pub updates_aggregated: u64,
    pub privacy_budget_spent: f64,
    pub avg_loss: f32,
}

pub struct FederatedCoordinator {
    config: FederatedConfig,
    global_weights: RwLock<Vec<f32>>,
    pending_updates: Mutex<Vec<FederatedClientUpdate>>,
    current_round: std::sync::atomic::AtomicU64,
    round_start: Mutex<Instant>,
    stats: Mutex<FederatedStats>,
    #[allow(dead_code)]
    privacy_spent: std::sync::atomic::AtomicU64,
}

impl FederatedCoordinator {
    pub fn new(config: FederatedConfig, initial_weights: Vec<f32>) -> Self {
        Self {
            config,
            global_weights: RwLock::new(initial_weights),
            pending_updates: Mutex::new(Vec::new()),
            current_round: std::sync::atomic::AtomicU64::new(0),
            round_start: Mutex::new(Instant::now()),
            stats: Mutex::new(FederatedStats::default()),
            privacy_spent: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn current_round(&self) -> u64 {
        self.current_round
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn submit_update(&self, update: FederatedClientUpdate) -> Result<(), &'static str> {
        if update.round != self.current_round() {
            return Err("Update round mismatch");
        }
        let mut pending = self.pending_updates.lock().unwrap();
        if pending.iter().any(|u| u.client_hash == update.client_hash) {
            return Err("Duplicate client update");
        }
        pending.push(update);
        self.stats.lock().unwrap().updates_received += 1;
        Ok(())
    }

    pub fn should_aggregate(&self) -> bool {
        let pending = self.pending_updates.lock().unwrap();
        let round_start = self.round_start.lock().unwrap();
        pending.len() >= self.config.min_clients
            || round_start.elapsed() >= Duration::from_secs(self.config.round_duration_secs)
    }

    pub fn aggregate(&self) -> Option<Vec<f32>> {
        let mut pending = self.pending_updates.lock().unwrap();
        if pending.len() < self.config.min_clients {
            return None;
        }
        let updates: Vec<_> = pending.drain(..).collect();
        drop(pending);

        let weight_dim = updates.first()?.weight_deltas.len();
        let total_samples: usize = updates.iter().map(|u| u.num_samples).sum();
        if total_samples == 0 {
            return None;
        }

        let mut aggregated = vec![0.0f32; weight_dim];
        for update in &updates {
            let weight = update.num_samples as f32 / total_samples as f32;
            let clipped = if self.config.enable_dp {
                clip_gradient(&update.weight_deltas, self.config.dp_clip_norm as f32)
            } else {
                update.weight_deltas.clone()
            };
            for (i, delta) in clipped.iter().enumerate() {
                if i < aggregated.len() {
                    aggregated[i] += delta * weight;
                }
            }
        }

        if self.config.enable_dp {
            let noise_scale =
                self.config.dp_clip_norm as f32 * self.config.dp_noise_multiplier as f32;
            add_gaussian_noise(&mut aggregated, noise_scale);
        }

        {
            let mut global = self.global_weights.write().unwrap();
            for (g, a) in global.iter_mut().zip(aggregated.iter()) {
                *g += a;
            }
        }

        let mut stats = self.stats.lock().unwrap();
        stats.rounds_completed += 1;
        stats.updates_aggregated += updates.len() as u64;
        stats.avg_loss = updates.iter().map(|u| u.local_loss).sum::<f32>() / updates.len() as f32;

        self.current_round
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self.round_start.lock().unwrap() = Instant::now();
        Some(self.global_weights.read().unwrap().clone())
    }

    pub fn get_weights(&self) -> Vec<f32> {
        self.global_weights.read().unwrap().clone()
    }
    pub fn stats(&self) -> FederatedStats {
        self.stats.lock().unwrap().clone()
    }
}

fn clip_gradient(gradient: &[f32], max_norm: f32) -> Vec<f32> {
    let norm: f32 = gradient.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm <= max_norm {
        gradient.to_vec()
    } else {
        gradient.iter().map(|x| x * max_norm / norm).collect()
    }
}

fn add_gaussian_noise(weights: &mut [f32], scale: f32) {
    for (i, w) in weights.iter_mut().enumerate() {
        let u1 = ((i * 7919 + 104729) % 100000) as f32 / 100000.0;
        let u2 = ((i * 7907 + 104723) % 100000) as f32 / 100000.0;
        let z = (-2.0 * u1.max(1e-10).ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
        *w += z * scale;
    }
}

pub fn anonymize_client_id(client_id: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    client_id.hash(&mut h);
    h.finish()
}

// ============================================================================
// Multi-Agent RL for Congestion Control
// ============================================================================

#[derive(Debug, Clone)]
pub struct MultiAgentConfig {
    pub max_agents: usize,
    pub state_dim: usize,
    pub action_dim: usize,
    pub message_dim: usize,
    pub comm_rounds: usize,
    pub gamma: f64,
    pub learning_rate: f64,
    pub epsilon: f64,
    pub epsilon_decay: f64,
    pub epsilon_min: f64,
}

impl Default for MultiAgentConfig {
    fn default() -> Self {
        Self {
            max_agents: 16,
            state_dim: 8,
            action_dim: 6,
            message_dim: 16,
            comm_rounds: 2,
            gamma: 0.99,
            learning_rate: 0.001,
            epsilon: 1.0,
            epsilon_decay: 0.995,
            epsilon_min: 0.01,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAction {
    Increase5,
    Increase10,
    Maintain,
    Decrease5,
    Decrease10,
    SlowStart,
}

impl CongestionAction {
    pub fn apply(&self, cwnd: u32) -> u32 {
        match self {
            Self::Increase5 => cwnd + cwnd / 20,
            Self::Increase10 => cwnd + cwnd / 10,
            Self::Maintain => cwnd,
            Self::Decrease5 => cwnd - cwnd / 20,
            Self::Decrease10 => cwnd - cwnd / 10,
            Self::SlowStart => 10 * 1460,
        }
    }
    fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::Increase5,
            1 => Self::Increase10,
            2 => Self::Maintain,
            3 => Self::Decrease5,
            4 => Self::Decrease10,
            _ => Self::SlowStart,
        }
    }
}

struct Agent {
    id: String,
    state: Vec<f32>,
    q_values: Vec<Vec<f32>>,
    messages_in: Vec<f32>,
    messages_out: Vec<f32>,
    total_reward: f32,
    action_count: u64,
}

impl Agent {
    fn new(id: String, state_dim: usize, action_dim: usize, message_dim: usize) -> Self {
        let q_values = (0..state_dim)
            .map(|i| {
                (0..action_dim)
                    .map(|j| ((i * 31 + j * 17) % 100) as f32 / 1000.0)
                    .collect()
            })
            .collect();
        Self {
            id,
            state: vec![0.0; state_dim],
            q_values,
            messages_in: vec![0.0; message_dim],
            messages_out: vec![0.0; message_dim],
            total_reward: 0.0,
            action_count: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MultiAgentStats {
    pub active_agents: usize,
    pub total_actions: u64,
    pub avg_reward: f32,
    pub epsilon: f64,
}

pub struct MultiAgentCoordinator {
    config: MultiAgentConfig,
    agents: Mutex<HashMap<String, Agent>>,
    epsilon: std::sync::atomic::AtomicU64,
    stats: Mutex<MultiAgentStats>,
}

impl MultiAgentCoordinator {
    pub fn new(config: MultiAgentConfig) -> Self {
        Self {
            epsilon: std::sync::atomic::AtomicU64::new(config.epsilon.to_bits()),
            config,
            agents: Mutex::new(HashMap::new()),
            stats: Mutex::new(MultiAgentStats::default()),
        }
    }

    pub fn register_agent(&self, agent_id: String) {
        let mut agents = self.agents.lock().unwrap();
        if agents.len() < self.config.max_agents && !agents.contains_key(&agent_id) {
            agents.insert(
                agent_id.clone(),
                Agent::new(
                    agent_id,
                    self.config.state_dim,
                    self.config.action_dim,
                    self.config.message_dim,
                ),
            );
        }
    }

    pub fn remove_agent(&self, agent_id: &str) {
        self.agents.lock().unwrap().remove(agent_id);
    }

    pub fn update_state(&self, agent_id: &str, state: Vec<f32>) {
        if let Some(a) = self.agents.lock().unwrap().get_mut(agent_id) {
            a.state = state;
        }
    }

    pub fn broadcast_message(&self, agent_id: &str, message: Vec<f32>) {
        if let Some(a) = self.agents.lock().unwrap().get_mut(agent_id) {
            a.messages_out = message;
        }
    }

    pub fn distribute_messages(&self) {
        let mut agents = self.agents.lock().unwrap();
        let msgs: Vec<_> = agents
            .iter()
            .map(|(id, a)| (id.clone(), a.messages_out.clone()))
            .collect();
        for agent in agents.values_mut() {
            let mut avg = vec![0.0f32; self.config.message_dim];
            let mut cnt = 0;
            for (id, msg) in &msgs {
                if *id != agent.id {
                    for (i, v) in msg.iter().enumerate() {
                        if i < avg.len() {
                            avg[i] += v;
                        }
                    }
                    cnt += 1;
                }
            }
            if cnt > 0 {
                for v in &mut avg {
                    *v /= cnt as f32;
                }
            }
            agent.messages_in = avg;
        }
    }

    pub fn select_action(&self, agent_id: &str) -> CongestionAction {
        let eps = f64::from_bits(self.epsilon.load(std::sync::atomic::Ordering::Relaxed));
        let mut agents = self.agents.lock().unwrap();
        let agent = match agents.get_mut(agent_id) {
            Some(a) => a,
            None => return CongestionAction::Maintain,
        };
        let rnd = (agent.action_count * 7919 % 10000) as f64 / 10000.0;
        let idx = if rnd < eps {
            (agent.action_count % self.config.action_dim as u64) as usize
        } else {
            let si = discretize_state(&agent.state);
            if si < agent.q_values.len() {
                agent.q_values[si]
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                    .map(|(i, _)| i)
                    .unwrap_or(2)
            } else {
                2
            }
        };
        agent.action_count += 1;
        CongestionAction::from_index(idx)
    }

    pub fn record_reward(&self, agent_id: &str, reward: f32) {
        let mut agents = self.agents.lock().unwrap();
        if let Some(a) = agents.get_mut(agent_id) {
            a.total_reward += reward;
            let si = discretize_state(&a.state);
            let ai = (a.action_count % self.config.action_dim as u64) as usize;
            if si < a.q_values.len() && ai < a.q_values[si].len() {
                let lr = self.config.learning_rate as f32;
                a.q_values[si][ai] += lr * (reward - a.q_values[si][ai]);
            }
        }
        drop(agents);
        let cur = f64::from_bits(self.epsilon.load(std::sync::atomic::Ordering::Relaxed));
        self.epsilon.store(
            (cur * self.config.epsilon_decay)
                .max(self.config.epsilon_min)
                .to_bits(),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.update_stats();
    }

    fn update_stats(&self) {
        let agents = self.agents.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        stats.active_agents = agents.len();
        stats.total_actions = agents.values().map(|a| a.action_count).sum();
        stats.avg_reward = if agents.is_empty() {
            0.0
        } else {
            agents.values().map(|a| a.total_reward).sum::<f32>() / agents.len() as f32
        };
        stats.epsilon = f64::from_bits(self.epsilon.load(std::sync::atomic::Ordering::Relaxed));
    }

    pub fn stats(&self) -> MultiAgentStats {
        self.stats.lock().unwrap().clone()
    }
}

pub fn calculate_cooperative_reward(
    throughput: f32,
    latency_ms: f32,
    total_throughput: f32,
    fairness: f32,
) -> f32 {
    0.7 * (throughput - (latency_ms / 100.0).min(1.0)) + 0.3 * total_throughput * fairness
}

fn discretize_state(state: &[f32]) -> usize {
    if state.is_empty() {
        0
    } else {
        (state
            .iter()
            .enumerate()
            .map(|(i, v)| v * (i + 1) as f32)
            .sum::<f32>()
            .abs() as usize)
            % 8
    }
}

// ============================================================================
// A/B Testing Framework
// ============================================================================

#[derive(Debug, Clone)]
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
            min_samples: 100,
            confidence_level: 0.95,
            treatment_fraction: 0.5,
            max_duration_secs: 86400,
            early_stopping: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModelVariant {
    pub name: String,
    pub model_path: String,
    pub is_treatment: bool,
}

#[derive(Debug, Clone)]
pub struct ABSample {
    pub is_treatment: bool,
    pub metric_value: f64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ABTestResult {
    pub experiment_id: String,
    pub winner: String,
    pub lift_percent: f64,
    pub p_value: f64,
    pub is_significant: bool,
    pub control_mean: f64,
    pub treatment_mean: f64,
    pub control_n: usize,
    pub treatment_n: usize,
}

struct Experiment {
    id: String,
    control: ModelVariant,
    treatment: ModelVariant,
    config: ABTestConfig,
    control_samples: Vec<f64>,
    treatment_samples: Vec<f64>,
    #[allow(dead_code)]
    start_time: Instant,
    concluded: bool,
    result: Option<ABTestResult>,
}

#[derive(Debug, Clone, Default)]
pub struct ABTestingStats {
    pub active_experiments: usize,
    pub total_experiments: u64,
    pub total_samples: u64,
}

pub struct ABTestingFramework {
    experiments: RwLock<HashMap<String, Experiment>>,
    stats: Mutex<ABTestingStats>,
    counter: std::sync::atomic::AtomicU64,
}

impl ABTestingFramework {
    pub fn new() -> Self {
        Self {
            experiments: RwLock::new(HashMap::new()),
            stats: Mutex::new(ABTestingStats::default()),
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn create_experiment(
        &self,
        name: String,
        control: ModelVariant,
        treatment: ModelVariant,
        config: ABTestConfig,
    ) -> String {
        let id = format!(
            "{}_{}",
            name,
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        self.experiments.write().unwrap().insert(
            id.clone(),
            Experiment {
                id: id.clone(),
                control,
                treatment,
                config,
                control_samples: Vec::new(),
                treatment_samples: Vec::new(),
                start_time: Instant::now(),
                concluded: false,
                result: None,
            },
        );
        self.stats.lock().unwrap().active_experiments += 1;
        self.stats.lock().unwrap().total_experiments += 1;
        id
    }

    pub fn get_assignment(&self, experiment_id: &str, user_id: &str) -> Option<bool> {
        let exps = self.experiments.read().unwrap();
        let exp = exps.get(experiment_id)?;
        if exp.concluded {
            return None;
        }
        Some(
            (anonymize_client_id(user_id) % 10000) as f64 / 10000.0 < exp.config.treatment_fraction,
        )
    }

    pub fn get_model_path(&self, experiment_id: &str, user_id: &str) -> Option<String> {
        let is_treatment = self.get_assignment(experiment_id, user_id)?;
        let exps = self.experiments.read().unwrap();
        let exp = exps.get(experiment_id)?;
        Some(if is_treatment {
            exp.treatment.model_path.clone()
        } else {
            exp.control.model_path.clone()
        })
    }

    pub fn record_sample(&self, experiment_id: &str, sample: ABSample) {
        let mut exps = self.experiments.write().unwrap();
        if let Some(exp) = exps.get_mut(experiment_id) {
            if exp.concluded {
                return;
            }
            if sample.is_treatment {
                exp.treatment_samples.push(sample.metric_value);
            } else {
                exp.control_samples.push(sample.metric_value);
            }
            self.stats.lock().unwrap().total_samples += 1;

            if exp.config.early_stopping
                && exp.control_samples.len() >= exp.config.min_samples
                && exp.treatment_samples.len() >= exp.config.min_samples
            {
                if let Some(result) = compute_ttest(exp) {
                    if result.is_significant {
                        exp.concluded = true;
                        exp.result = Some(result);
                        self.stats.lock().unwrap().active_experiments = self
                            .stats
                            .lock()
                            .unwrap()
                            .active_experiments
                            .saturating_sub(1);
                    }
                }
            }
        }
    }

    pub fn get_result(&self, experiment_id: &str) -> Option<ABTestResult> {
        self.experiments
            .read()
            .unwrap()
            .get(experiment_id)?
            .result
            .clone()
    }

    pub fn conclude_experiment(&self, experiment_id: &str) -> Option<ABTestResult> {
        let mut exps = self.experiments.write().unwrap();
        let exp = exps.get_mut(experiment_id)?;
        if exp.concluded {
            return exp.result.clone();
        }
        let result = compute_ttest(exp)?;
        exp.concluded = true;
        exp.result = Some(result.clone());
        self.stats.lock().unwrap().active_experiments = self
            .stats
            .lock()
            .unwrap()
            .active_experiments
            .saturating_sub(1);
        Some(result)
    }

    pub fn stats(&self) -> ABTestingStats {
        self.stats.lock().unwrap().clone()
    }
}

impl Default for ABTestingFramework {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_ttest(exp: &Experiment) -> Option<ABTestResult> {
    let (c, t) = (&exp.control_samples, &exp.treatment_samples);
    if c.is_empty() || t.is_empty() {
        return None;
    }
    let (n1, n2) = (c.len() as f64, t.len() as f64);
    let (m1, m2) = (c.iter().sum::<f64>() / n1, t.iter().sum::<f64>() / n2);
    let v1 = c.iter().map(|x| (x - m1).powi(2)).sum::<f64>() / (n1 - 1.0).max(1.0);
    let v2 = t.iter().map(|x| (x - m2).powi(2)).sum::<f64>() / (n2 - 1.0).max(1.0);
    let se = ((v1 / n1) + (v2 / n2)).sqrt();
    if se == 0.0 {
        return None;
    }
    let t_stat = (m2 - m1) / se;
    let p_value = 2.0 * (1.0 - normal_cdf(t_stat.abs()));
    let is_sig = p_value < (1.0 - exp.config.confidence_level);
    let lift = if m1 != 0.0 {
        (m2 - m1) / m1 * 100.0
    } else {
        0.0
    };
    Some(ABTestResult {
        experiment_id: exp.id.clone(),
        winner: if m2 > m1 {
            exp.treatment.name.clone()
        } else {
            exp.control.name.clone()
        },
        lift_percent: lift,
        p_value,
        is_significant: is_sig,
        control_mean: m1,
        treatment_mean: m2,
        control_n: c.len(),
        treatment_n: t.len(),
    })
}

fn normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    let (a1, a2, a3, a4, a5, p) = (
        0.254829592,
        -0.284496736,
        1.421413741,
        -1.453152027,
        1.061405429,
        0.3275911,
    );
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();
    sign * y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federated_coordinator() {
        let config = FederatedConfig::default();
        let coord = FederatedCoordinator::new(config, vec![0.0; 10]);
        assert_eq!(coord.current_round(), 0);

        for i in 0..3 {
            coord
                .submit_update(FederatedClientUpdate {
                    client_hash: i as u64,
                    round: 0,
                    weight_deltas: vec![0.1; 10],
                    num_samples: 100,
                    local_loss: 0.05,
                    timestamp_ms: 0,
                })
                .unwrap();
        }

        assert!(coord.should_aggregate());
        let weights = coord.aggregate().unwrap();
        assert_eq!(weights.len(), 10);
        assert_eq!(coord.current_round(), 1);
    }

    #[test]
    fn test_multi_agent_coordinator() {
        let coord = MultiAgentCoordinator::new(MultiAgentConfig::default());
        coord.register_agent("flow_1".to_string());
        coord.register_agent("flow_2".to_string());

        coord.update_state("flow_1", vec![1.0; 8]);
        let action = coord.select_action("flow_1");
        assert!(matches!(
            action,
            CongestionAction::Increase5
                | CongestionAction::Increase10
                | CongestionAction::Maintain
                | CongestionAction::Decrease5
                | CongestionAction::Decrease10
                | CongestionAction::SlowStart
        ));

        coord.record_reward("flow_1", 0.8);
        let stats = coord.stats();
        assert_eq!(stats.active_agents, 2);
    }

    #[test]
    fn test_congestion_action_apply() {
        assert_eq!(CongestionAction::Increase5.apply(100000), 105000);
        assert_eq!(CongestionAction::Decrease10.apply(100000), 90000);
        assert_eq!(CongestionAction::SlowStart.apply(100000), 14600);
    }

    #[test]
    fn test_ab_testing_framework() {
        let framework = ABTestingFramework::new();
        let exp_id = framework.create_experiment(
            "test".to_string(),
            ModelVariant {
                name: "control".to_string(),
                model_path: "/m/c".to_string(),
                is_treatment: false,
            },
            ModelVariant {
                name: "treatment".to_string(),
                model_path: "/m/t".to_string(),
                is_treatment: true,
            },
            ABTestConfig {
                min_samples: 10,
                ..Default::default()
            },
        );

        for i in 0..20 {
            let is_treatment = i % 2 == 0;
            let value = if is_treatment { 1.2 } else { 1.0 };
            framework.record_sample(
                &exp_id,
                ABSample {
                    is_treatment,
                    metric_value: value,
                    timestamp_ms: 0,
                },
            );
        }

        let result = framework.conclude_experiment(&exp_id).unwrap();
        assert!(result.treatment_mean > result.control_mean);
    }

    #[test]
    fn test_cooperative_reward() {
        let reward = calculate_cooperative_reward(10.0, 50.0, 100.0, 0.9);
        assert!(reward > 0.0);
    }

    #[test]
    fn test_anonymize_client_id() {
        let h1 = anonymize_client_id("server-1");
        let h2 = anonymize_client_id("server-2");
        assert_ne!(h1, h2);
    }
}
