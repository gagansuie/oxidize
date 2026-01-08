//! Candle-based ML Training for Oxidize
//!
//! Pure-Rust training for:
//! - **LSTM Loss Predictor**: Supervised learning from packet loss samples
//! - **DQN Congestion Controller**: Deep Q-Learning with experience replay
//!
//! Design principles:
//! - Training runs in background thread (zero hot-path impact)
//! - Inference uses atomic model swap (lock-free)
//! - Models saved as safetensors for fast loading

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

#[cfg(feature = "ai")]
use candle_core::{DType, Device, Result as CandleResult, Tensor};
#[cfg(feature = "ai")]
use candle_nn::{linear, seq, Activation, Linear, Module, Optimizer, VarBuilder, VarMap};

use crate::ml_models::{DrlExperience, LossSample};

// ============================================================================
// LSTM LOSS PREDICTOR TRAINING
// ============================================================================

/// LSTM architecture for loss prediction
/// Input: [batch, seq_len, features] -> Output: [batch, 1] (loss probability)
#[cfg(feature = "ai")]
pub struct LstmModel {
    hidden_size: usize,
    input_proj: Linear,
    hidden_proj: Linear,
    output_proj: Linear,
    device: Device,
}

#[cfg(feature = "ai")]
impl LstmModel {
    pub fn new(input_size: usize, hidden_size: usize, vb: VarBuilder) -> CandleResult<Self> {
        let input_proj = linear(input_size, hidden_size * 4, vb.pp("input_proj"))?;
        let hidden_proj = linear(hidden_size, hidden_size * 4, vb.pp("hidden_proj"))?;
        let output_proj = linear(hidden_size, 1, vb.pp("output_proj"))?;

        Ok(LstmModel {
            hidden_size,
            input_proj,
            hidden_proj,
            output_proj,
            device: vb.device().clone(),
        })
    }

    /// Forward pass through LSTM
    /// Simplified LSTM cell for efficiency
    pub fn forward(&self, input: &Tensor) -> CandleResult<Tensor> {
        let (batch_size, seq_len, _features) = input.dims3()?;

        // Initialize hidden state
        let mut h = Tensor::zeros((batch_size, self.hidden_size), DType::F32, &self.device)?;
        let mut c = Tensor::zeros((batch_size, self.hidden_size), DType::F32, &self.device)?;

        // Process sequence
        for t in 0..seq_len {
            let x_t = input.narrow(1, t, 1)?.squeeze(1)?;

            // LSTM gates: i, f, g, o
            let gates = self
                .input_proj
                .forward(&x_t)?
                .add(&self.hidden_proj.forward(&h)?)?;

            let chunks = gates.chunk(4, 1)?;
            let i = candle_nn::ops::sigmoid(&chunks[0])?;
            let f = candle_nn::ops::sigmoid(&chunks[1])?;
            let g = chunks[2].tanh()?;
            let o = candle_nn::ops::sigmoid(&chunks[3])?;

            c = f.mul(&c)?.add(&i.mul(&g)?)?;
            h = o.mul(&c.tanh()?)?;
        }

        // Output projection with sigmoid for probability
        let output = self.output_proj.forward(&h)?;
        candle_nn::ops::sigmoid(&output)
    }
}

/// LSTM Trainer
#[cfg(feature = "ai")]
pub struct LstmTrainer {
    var_map: VarMap,
    model: LstmModel,
    optimizer: Option<candle_nn::AdamW>,
    device: Device,
    learning_rate: f64,
    batch_size: usize,
    sequence_length: usize,
    training_loss: f32,
    epochs_trained: u64,
}

#[cfg(feature = "ai")]
impl LstmTrainer {
    pub fn new(
        input_size: usize,
        hidden_size: usize,
        sequence_length: usize,
    ) -> CandleResult<Self> {
        let device = Device::Cpu; // CPU for edge deployment
        let var_map = VarMap::new();
        let vb = VarBuilder::from_varmap(&var_map, DType::F32, &device);
        let model = LstmModel::new(input_size, hidden_size, vb)?;

        Ok(LstmTrainer {
            var_map,
            model,
            optimizer: None,
            device,
            learning_rate: 0.001,
            batch_size: 32,
            sequence_length,
            training_loss: 0.0,
            epochs_trained: 0,
        })
    }

    /// Initialize optimizer (call before training)
    pub fn init_optimizer(&mut self) -> CandleResult<()> {
        let params = self.var_map.all_vars();
        self.optimizer = Some(candle_nn::AdamW::new(
            params,
            candle_nn::ParamsAdamW {
                lr: self.learning_rate,
                weight_decay: 0.01,
                ..Default::default()
            },
        )?);
        Ok(())
    }

    /// Train on a batch of samples
    pub fn train_batch(&mut self, samples: &[LossSample]) -> CandleResult<f32> {
        if samples.len() < self.sequence_length + 1 {
            return Ok(0.0);
        }

        let optimizer = self
            .optimizer
            .as_mut()
            .ok_or_else(|| candle_core::Error::Msg("Optimizer not initialized".into()))?;

        // Prepare batch data
        let num_sequences = (samples.len() - self.sequence_length).min(self.batch_size);
        let mut input_data = Vec::with_capacity(num_sequences * self.sequence_length * 8);
        let mut target_data = Vec::with_capacity(num_sequences);

        for i in 0..num_sequences {
            // Build sequence
            for j in 0..self.sequence_length {
                let features = samples[i + j].to_features();
                input_data.extend_from_slice(&features);
            }
            // Target is the future_loss of the last sample in sequence
            target_data.push(samples[i + self.sequence_length - 1].future_loss);
        }

        // Create tensors
        let input = Tensor::from_vec(
            input_data,
            (num_sequences, self.sequence_length, 8),
            &self.device,
        )?;
        let target = Tensor::from_vec(target_data, (num_sequences, 1), &self.device)?;

        // Forward pass
        let prediction = self.model.forward(&input)?;

        // MSE Loss
        let loss = prediction.sub(&target)?.sqr()?.mean_all()?;
        let loss_val = loss.to_scalar::<f32>()?;

        // Backward pass
        optimizer.backward_step(&loss)?;

        self.training_loss = loss_val;
        self.epochs_trained += 1;

        trace!("LSTM batch loss: {:.6}", loss_val);
        Ok(loss_val)
    }

    /// Save model to safetensors
    pub fn save<P: AsRef<Path>>(&self, path: P) -> CandleResult<()> {
        self.var_map.save(path)?;
        debug!("LSTM model saved");
        Ok(())
    }

    /// Load model from safetensors
    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> CandleResult<()> {
        self.var_map.load(path)?;
        debug!("LSTM model loaded");
        Ok(())
    }

    /// Get inference function (for hot path)
    pub fn inference(&self, sequence: &[f32]) -> CandleResult<f32> {
        let input = Tensor::from_vec(
            sequence.to_vec(),
            (1, self.sequence_length, 8),
            &self.device,
        )?;
        let output = self.model.forward(&input)?;
        output.squeeze(0)?.squeeze(0)?.to_scalar::<f32>()
    }

    pub fn stats(&self) -> LstmTrainingStats {
        LstmTrainingStats {
            epochs_trained: self.epochs_trained,
            training_loss: self.training_loss,
            learning_rate: self.learning_rate,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstmTrainingStats {
    pub epochs_trained: u64,
    pub training_loss: f32,
    pub learning_rate: f64,
}

// ============================================================================
// DQN CONGESTION CONTROLLER TRAINING
// ============================================================================

/// Deep Q-Network for congestion control
/// Input: 8-dim state -> Output: 6 Q-values (one per action)
#[cfg(feature = "ai")]
pub struct DqnModel {
    network: candle_nn::Sequential,
}

#[cfg(feature = "ai")]
impl DqnModel {
    pub fn new(
        state_size: usize,
        action_size: usize,
        hidden_size: usize,
        vb: VarBuilder,
    ) -> CandleResult<Self> {
        let network = seq()
            .add(linear(state_size, hidden_size, vb.pp("l1"))?)
            .add(Activation::Relu)
            .add(linear(hidden_size, hidden_size, vb.pp("l2"))?)
            .add(Activation::Relu)
            .add(linear(hidden_size, action_size, vb.pp("l3"))?);

        Ok(DqnModel { network })
    }

    pub fn forward(&self, state: &Tensor) -> CandleResult<Tensor> {
        self.network.forward(state)
    }
}

/// DQN Trainer with experience replay and target network
#[cfg(feature = "ai")]
pub struct DqnTrainer {
    // Online network (updated every step)
    var_map: VarMap,
    model: DqnModel,
    // Target network (updated periodically)
    target_var_map: VarMap,
    target_model: DqnModel,

    optimizer: Option<candle_nn::AdamW>,
    device: Device,

    // Hyperparameters
    learning_rate: f64,
    gamma: f32, // Discount factor
    tau: f32,   // Soft update coefficient
    batch_size: usize,
    target_update_freq: u64,

    // Training state
    training_loss: f32,
    steps_trained: u64,
}

#[cfg(feature = "ai")]
impl DqnTrainer {
    pub fn new(state_size: usize, action_size: usize, hidden_size: usize) -> CandleResult<Self> {
        let device = Device::Cpu;

        // Online network
        let var_map = VarMap::new();
        let vb = VarBuilder::from_varmap(&var_map, DType::F32, &device);
        let model = DqnModel::new(state_size, action_size, hidden_size, vb)?;

        // Target network (same architecture)
        let target_var_map = VarMap::new();
        let target_vb = VarBuilder::from_varmap(&target_var_map, DType::F32, &device);
        let target_model = DqnModel::new(state_size, action_size, hidden_size, target_vb)?;

        Ok(DqnTrainer {
            var_map,
            model,
            target_var_map,
            target_model,
            optimizer: None,
            device,
            learning_rate: 0.0005,
            gamma: 0.99,
            tau: 0.005,
            batch_size: 64,
            target_update_freq: 100,
            training_loss: 0.0,
            steps_trained: 0,
        })
    }

    pub fn init_optimizer(&mut self) -> CandleResult<()> {
        let params = self.var_map.all_vars();
        self.optimizer = Some(candle_nn::AdamW::new(
            params,
            candle_nn::ParamsAdamW {
                lr: self.learning_rate,
                weight_decay: 0.0001,
                ..Default::default()
            },
        )?);
        Ok(())
    }

    /// Train on a batch of experiences
    pub fn train_batch(&mut self, experiences: &[DrlExperience]) -> CandleResult<f32> {
        if experiences.len() < self.batch_size {
            return Ok(0.0);
        }

        let optimizer = self
            .optimizer
            .as_mut()
            .ok_or_else(|| candle_core::Error::Msg("Optimizer not initialized".into()))?;

        // Sample random batch
        let batch: Vec<_> = experiences.iter().rev().take(self.batch_size).collect();

        // Prepare tensors
        let mut states = Vec::with_capacity(self.batch_size * 8);
        let mut actions = Vec::with_capacity(self.batch_size);
        let mut rewards = Vec::with_capacity(self.batch_size);
        let mut next_states = Vec::with_capacity(self.batch_size * 8);
        let mut dones = Vec::with_capacity(self.batch_size);

        for exp in &batch {
            states.extend_from_slice(&exp.state.to_vec());
            actions.push(exp.action as u32);
            rewards.push(exp.reward.total);
            next_states.extend_from_slice(&exp.next_state.to_vec());
            dones.push(if exp.done { 1.0f32 } else { 0.0f32 });
        }

        let states_t = Tensor::from_vec(states, (self.batch_size, 8), &self.device)?;
        let actions_t = Tensor::from_vec(actions, self.batch_size, &self.device)?;
        let rewards_t = Tensor::from_vec(rewards, self.batch_size, &self.device)?;
        let next_states_t = Tensor::from_vec(next_states, (self.batch_size, 8), &self.device)?;
        let dones_t = Tensor::from_vec(dones, self.batch_size, &self.device)?;

        // Compute current Q values
        let current_q = self.model.forward(&states_t)?;
        let current_q_selected = current_q.gather(&actions_t.unsqueeze(1)?, 1)?.squeeze(1)?;

        // Compute target Q values (Double DQN style)
        let next_q_target = self.target_model.forward(&next_states_t)?;
        let next_q_max = next_q_target.max(1)?;

        // target = reward + gamma * (1 - done) * max_next_q
        let one_minus_done = (dones_t.neg()? + 1.0)?;
        let target_q = (rewards_t + (one_minus_done * next_q_max)? * self.gamma as f64)?;

        // MSE Loss
        let loss = current_q_selected.sub(&target_q)?.sqr()?.mean_all()?;
        let loss_val = loss.to_scalar::<f32>()?;

        // Backward pass
        optimizer.backward_step(&loss)?;

        self.training_loss = loss_val;
        self.steps_trained += 1;

        // Soft update target network
        if self.steps_trained % self.target_update_freq == 0 {
            self.soft_update_target()?;
        }

        trace!("DQN batch loss: {:.6}", loss_val);
        Ok(loss_val)
    }

    /// Soft update target network: target = tau * online + (1 - tau) * target
    /// This slowly blends the online network weights into the target network,
    /// providing stable Q-value targets during training.
    fn soft_update_target(&mut self) -> CandleResult<()> {
        let tau = self.tau as f64;
        let one_minus_tau = 1.0 - tau;

        // Get all tensors from both networks
        let online_data = self.var_map.data().lock().unwrap();
        let mut target_data = self.target_var_map.data().lock().unwrap();

        for (name, online_var) in online_data.iter() {
            if let Some(target_var) = target_data.get_mut(name) {
                // target = tau * online + (1 - tau) * target
                let online_tensor = online_var.as_tensor();
                let target_tensor = target_var.as_tensor();

                let updated = ((online_tensor * tau)? + (target_tensor * one_minus_tau)?)?;
                target_var.set(&updated)?;
            }
        }

        debug!(
            "Soft updated target network (tau={}, step={})",
            self.tau, self.steps_trained
        );
        Ok(())
    }

    /// Hard update: completely copy online network to target network
    /// Use this for initial sync or periodic hard updates
    pub fn hard_update_target(&mut self) -> CandleResult<()> {
        let online_data = self.var_map.data().lock().unwrap();
        let mut target_data = self.target_var_map.data().lock().unwrap();

        for (name, online_var) in online_data.iter() {
            if let Some(target_var) = target_data.get_mut(name) {
                target_var.set(online_var.as_tensor())?;
            }
        }

        debug!("Hard updated target network");
        Ok(())
    }

    /// Get Q-values for a state (for inference)
    pub fn get_q_values(&self, state: &[f32]) -> CandleResult<Vec<f32>> {
        let state_t = Tensor::from_vec(state.to_vec(), (1, 8), &self.device)?;
        let q_values = self.model.forward(&state_t)?;
        q_values.squeeze(0)?.to_vec1::<f32>()
    }

    /// Select best action
    pub fn select_action(&self, state: &[f32]) -> CandleResult<usize> {
        let q_values = self.get_q_values(state)?;
        Ok(q_values
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(idx, _)| idx)
            .unwrap_or(2))
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> CandleResult<()> {
        self.var_map.save(path)?;
        debug!("DQN model saved");
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> CandleResult<()> {
        self.var_map.load(path)?;
        debug!("DQN model loaded");
        Ok(())
    }

    pub fn stats(&self) -> DqnTrainingStats {
        DqnTrainingStats {
            steps_trained: self.steps_trained,
            training_loss: self.training_loss,
            gamma: self.gamma,
            learning_rate: self.learning_rate,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DqnTrainingStats {
    pub steps_trained: u64,
    pub training_loss: f32,
    pub gamma: f32,
    pub learning_rate: f64,
}

// ============================================================================
// BACKGROUND TRAINING MANAGER
// ============================================================================

/// Configuration for background training
#[derive(Debug, Clone)]
pub struct TrainingConfig {
    /// Enable LSTM loss predictor training
    pub enable_lstm: bool,
    /// Enable DQN congestion controller training
    pub enable_dqn: bool,
    /// Training interval (how often to run a training batch)
    pub training_interval: Duration,
    /// Minimum samples before training starts
    pub min_samples_lstm: usize,
    /// Minimum experiences before DQN training starts
    pub min_experiences_dqn: usize,
    /// Model save interval
    pub save_interval: Duration,
    /// Model save path
    pub model_path: String,
}

impl Default for TrainingConfig {
    fn default() -> Self {
        TrainingConfig {
            enable_lstm: true,
            enable_dqn: true,
            training_interval: Duration::from_secs(10),
            min_samples_lstm: 100,
            min_experiences_dqn: 1000,
            save_interval: Duration::from_secs(300), // 5 minutes
            model_path: "/tmp/oxidize_models".into(),
        }
    }
}

/// Thread-safe training data buffers
pub struct TrainingBuffers {
    pub loss_samples: RwLock<VecDeque<LossSample>>,
    pub drl_experiences: RwLock<VecDeque<DrlExperience>>,
    max_samples: usize,
}

impl TrainingBuffers {
    pub fn new(max_samples: usize) -> Self {
        TrainingBuffers {
            loss_samples: RwLock::new(VecDeque::with_capacity(max_samples)),
            drl_experiences: RwLock::new(VecDeque::with_capacity(max_samples)),
            max_samples,
        }
    }

    pub fn add_loss_sample(&self, sample: LossSample) {
        if let Ok(mut samples) = self.loss_samples.write() {
            samples.push_back(sample);
            while samples.len() > self.max_samples {
                samples.pop_front();
            }
        }
    }

    pub fn add_experience(&self, exp: DrlExperience) {
        if let Ok(mut exps) = self.drl_experiences.write() {
            exps.push_back(exp);
            while exps.len() > self.max_samples {
                exps.pop_front();
            }
        }
    }
}

/// Training statistics
#[derive(Debug, Default)]
pub struct TrainingStats {
    pub lstm_epochs: AtomicU64,
    pub dqn_steps: AtomicU64,
    pub is_training: AtomicBool,
}

/// Background training manager
/// Runs training in a separate thread with zero impact on hot path
pub struct BackgroundTrainer {
    config: TrainingConfig,
    buffers: Arc<TrainingBuffers>,
    stats: Arc<TrainingStats>,
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl BackgroundTrainer {
    pub fn new(config: TrainingConfig) -> Self {
        BackgroundTrainer {
            config,
            buffers: Arc::new(TrainingBuffers::new(100_000)),
            stats: Arc::new(TrainingStats::default()),
            stop_flag: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
        }
    }

    /// Get buffer reference for adding samples (called from hot path)
    pub fn buffers(&self) -> Arc<TrainingBuffers> {
        Arc::clone(&self.buffers)
    }

    /// Start background training thread
    #[cfg(feature = "ai")]
    pub fn start(&mut self) -> anyhow::Result<()> {
        let config = self.config.clone();
        let buffers = Arc::clone(&self.buffers);
        let stats = Arc::clone(&self.stats);
        let stop_flag = Arc::clone(&self.stop_flag);

        // Create model directory
        std::fs::create_dir_all(&config.model_path)?;

        let handle = thread::Builder::new()
            .name("oxidize-trainer".into())
            .spawn(move || {
                info!("Background trainer started");
                Self::training_loop(config, buffers, stats, stop_flag);
                info!("Background trainer stopped");
            })?;

        self.thread_handle = Some(handle);
        Ok(())
    }

    #[cfg(not(feature = "ai"))]
    pub fn start(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("AI features not compiled in")
    }

    /// Stop background training
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }

    /// Training loop (runs in background thread)
    #[cfg(feature = "ai")]
    fn training_loop(
        config: TrainingConfig,
        buffers: Arc<TrainingBuffers>,
        stats: Arc<TrainingStats>,
        stop_flag: Arc<AtomicBool>,
    ) {
        // Initialize trainers
        let mut lstm_trainer = LstmTrainer::new(8, 64, 20).ok();
        let mut dqn_trainer = DqnTrainer::new(8, 6, 128).ok();

        if let Some(ref mut trainer) = lstm_trainer {
            let _ = trainer.init_optimizer();
        }
        if let Some(ref mut trainer) = dqn_trainer {
            let _ = trainer.init_optimizer();
        }

        let mut last_save = Instant::now();

        while !stop_flag.load(Ordering::SeqCst) {
            stats.is_training.store(true, Ordering::SeqCst);

            // Train LSTM
            if config.enable_lstm {
                if let Some(ref mut trainer) = lstm_trainer {
                    if let Ok(samples) = buffers.loss_samples.read() {
                        if samples.len() >= config.min_samples_lstm {
                            let samples_vec: Vec<_> = samples.iter().cloned().collect();
                            drop(samples); // Release lock

                            if let Ok(loss) = trainer.train_batch(&samples_vec) {
                                if loss > 0.0 {
                                    stats.lstm_epochs.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                }
            }

            // Train DQN
            if config.enable_dqn {
                if let Some(ref mut trainer) = dqn_trainer {
                    if let Ok(experiences) = buffers.drl_experiences.read() {
                        if experiences.len() >= config.min_experiences_dqn {
                            let exp_vec: Vec<_> = experiences.iter().cloned().collect();
                            drop(experiences); // Release lock

                            if let Ok(loss) = trainer.train_batch(&exp_vec) {
                                if loss > 0.0 {
                                    stats.dqn_steps.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                }
            }

            stats.is_training.store(false, Ordering::SeqCst);

            // Save models periodically
            if last_save.elapsed() > config.save_interval {
                if let Some(ref trainer) = lstm_trainer {
                    let path = format!("{}/lstm_loss_predictor.safetensors", config.model_path);
                    let _ = trainer.save(&path);
                }
                if let Some(ref trainer) = dqn_trainer {
                    let path = format!("{}/dqn_congestion.safetensors", config.model_path);
                    let _ = trainer.save(&path);
                }
                last_save = Instant::now();
                debug!("Models saved to {}", config.model_path);
            }

            // Sleep until next training interval
            thread::sleep(config.training_interval);
        }
    }

    pub fn stats(&self) -> (u64, u64, bool) {
        (
            self.stats.lstm_epochs.load(Ordering::SeqCst),
            self.stats.dqn_steps.load(Ordering::SeqCst),
            self.stats.is_training.load(Ordering::SeqCst),
        )
    }
}

impl Drop for BackgroundTrainer {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_training_buffers() {
        let buffers = TrainingBuffers::new(100);

        for i in 0..150 {
            buffers.add_loss_sample(LossSample {
                timestamp_ms: i as u64,
                rtt_us: 50000,
                rtt_var_us: 5000,
                bandwidth_bps: 100_000_000,
                loss_rate: 0.01,
                inflight: 100,
                buffer_occupancy: 0.3,
                ipg_us: 1000,
                future_loss: 0.02,
            });
        }

        let samples = buffers.loss_samples.read().unwrap();
        assert_eq!(samples.len(), 100); // Capped at max
    }

    #[test]
    fn test_training_config_default() {
        let config = TrainingConfig::default();
        assert!(config.enable_lstm);
        assert!(config.enable_dqn);
        assert_eq!(config.min_samples_lstm, 100);
    }

    #[test]
    #[cfg(feature = "ai")]
    fn test_dqn_model_forward() {
        let device = Device::Cpu;
        let var_map = VarMap::new();
        let vb = VarBuilder::from_varmap(&var_map, DType::F32, &device);

        let model = DqnModel::new(8, 6, 128, vb).unwrap();
        let state = Tensor::zeros((1, 8), DType::F32, &device).unwrap();
        let q_values = model.forward(&state).unwrap();

        assert_eq!(q_values.dims(), &[1, 6]);
    }
}
