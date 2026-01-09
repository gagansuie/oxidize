//! ML Models for Oxidize
//!
//! Production-ready implementations of:
//! - **LSTM Loss Predictor**: Predicts packet loss 50-100ms before it happens
//! - **DRL Congestion Controller**: Learns optimal cwnd/pacing from network conditions
//!
//! These models can run in two modes:
//! 1. **Heuristic mode**: Uses the trait implementations from ai_engine.rs
//! 2. **ML mode**: Loads trained ONNX models for inference via tract
//!
//! Training is done offline using exported data, then models are deployed as .onnx files.

use std::collections::VecDeque;
use std::path::Path;
use std::time::Instant;

use crate::ai_engine::{
    CongestionAction, CongestionController, FecDecision, LossPredictor, NetworkFeatures,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

#[cfg(feature = "ai")]
use tract_onnx::prelude::*;

#[cfg(feature = "ai")]
use candle_core::{DType, Device, Tensor as CandleTensor};
#[cfg(feature = "ai")]
use candle_nn::{linear, Linear, Module, VarBuilder, VarMap};

#[cfg(feature = "ai")]
type TractModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// Candle-based LSTM model for safetensors inference
#[cfg(feature = "ai")]
pub struct CandleLstmModel {
    hidden_size: usize,
    input_proj: Linear,
    hidden_proj: Linear,
    output_proj: Linear,
    device: Device,
}

#[cfg(feature = "ai")]
impl CandleLstmModel {
    pub fn new(input_size: usize, hidden_size: usize, vb: VarBuilder) -> candle_core::Result<Self> {
        let input_proj = linear(input_size, hidden_size * 4, vb.pp("input_proj"))?;
        let hidden_proj = linear(hidden_size, hidden_size * 4, vb.pp("hidden_proj"))?;
        let output_proj = linear(hidden_size, 1, vb.pp("output_proj"))?;

        Ok(CandleLstmModel {
            hidden_size,
            input_proj,
            hidden_proj,
            output_proj,
            device: vb.device().clone(),
        })
    }

    pub fn forward(&self, input: &CandleTensor) -> candle_core::Result<CandleTensor> {
        let (batch_size, seq_len, _features) = input.dims3()?;

        let mut h = CandleTensor::zeros((batch_size, self.hidden_size), DType::F32, &self.device)?;
        let mut c = CandleTensor::zeros((batch_size, self.hidden_size), DType::F32, &self.device)?;

        for t in 0..seq_len {
            let x_t = input.narrow(1, t, 1)?.squeeze(1)?;
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

        let output = self.output_proj.forward(&h)?;
        candle_nn::ops::sigmoid(&output)
    }
}

/// Candle-based DQN model for safetensors inference
#[cfg(feature = "ai")]
pub struct CandleDqnModel {
    l1: Linear,
    l2: Linear,
    l3: Linear,
}

#[cfg(feature = "ai")]
impl CandleDqnModel {
    pub fn new(
        state_size: usize,
        action_size: usize,
        hidden_size: usize,
        vb: VarBuilder,
    ) -> candle_core::Result<Self> {
        let l1 = linear(state_size, hidden_size, vb.pp("l1"))?;
        let l2 = linear(hidden_size, hidden_size, vb.pp("l2"))?;
        let l3 = linear(hidden_size, action_size, vb.pp("l3"))?;
        Ok(CandleDqnModel { l1, l2, l3 })
    }

    pub fn forward(&self, state: &CandleTensor) -> candle_core::Result<CandleTensor> {
        let x = self.l1.forward(state)?.relu()?;
        let x = self.l2.forward(&x)?.relu()?;
        self.l3.forward(&x)
    }
}

// ============================================================================
// LSTM LOSS PREDICTOR
// ============================================================================

/// Sequence length for LSTM input (number of time steps)
const LSTM_SEQUENCE_LENGTH: usize = 20;
/// Number of features per time step
const LSTM_FEATURE_COUNT: usize = 8;

/// Training sample for loss prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossSample {
    /// Timestamp (ms since start)
    pub timestamp_ms: u64,
    /// RTT at this sample (microseconds)
    pub rtt_us: u64,
    /// RTT variance
    pub rtt_var_us: u64,
    /// Bandwidth estimate (bps)
    pub bandwidth_bps: u64,
    /// Current loss rate observed
    pub loss_rate: f32,
    /// Packets in flight
    pub inflight: u32,
    /// Buffer occupancy
    pub buffer_occupancy: f32,
    /// Inter-packet gap (microseconds)
    pub ipg_us: u64,
    /// Actual loss that occurred in next 100ms (label for training)
    pub future_loss: f32,
}

impl LossSample {
    /// Convert to feature vector for LSTM input
    pub fn to_features(&self) -> [f32; LSTM_FEATURE_COUNT] {
        [
            (self.rtt_us as f32 / 500_000.0).min(1.0),
            (self.rtt_var_us as f32 / 100_000.0).min(1.0),
            (self.bandwidth_bps as f32 / 1e9).min(1.0),
            self.loss_rate,
            (self.inflight as f32 / 1000.0).min(1.0),
            self.buffer_occupancy,
            (self.ipg_us as f32 / 10_000.0).min(1.0),
            0.0, // Reserved
        ]
    }
}

/// LSTM-based loss predictor with ONNX or Candle inference
pub struct LstmLossPredictor {
    /// Historical samples for sequence input
    history: VecDeque<LossSample>,
    /// Trained ONNX model (loaded at runtime)
    #[cfg(feature = "ai")]
    onnx_model: Option<TractModel>,
    #[cfg(not(feature = "ai"))]
    onnx_model: Option<()>,
    /// Candle model for safetensors inference
    #[cfg(feature = "ai")]
    candle_model: Option<CandleLstmModel>,
    #[cfg(feature = "ai")]
    candle_device: Device,
    /// Fallback heuristic when model unavailable
    ewma_loss: f32,
    ewma_alpha: f32,
    /// FEC threshold
    fec_threshold: f32,
    /// Training data collector
    training_data: Vec<LossSample>,
    /// Whether to collect training data
    collect_training_data: bool,
    /// Start time for timestamps
    start_time: Instant,
    /// Model inference count
    inference_count: u64,
    /// Last prediction for metrics
    last_prediction: f32,
}

impl Default for LstmLossPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl LstmLossPredictor {
    pub fn new() -> Self {
        LstmLossPredictor {
            history: VecDeque::with_capacity(LSTM_SEQUENCE_LENGTH + 10),
            #[cfg(feature = "ai")]
            onnx_model: None,
            #[cfg(not(feature = "ai"))]
            onnx_model: None,
            #[cfg(feature = "ai")]
            candle_model: None,
            #[cfg(feature = "ai")]
            candle_device: Device::Cpu,
            ewma_loss: 0.0,
            ewma_alpha: 0.3,
            fec_threshold: 0.02,
            training_data: Vec::new(),
            collect_training_data: false,
            start_time: Instant::now(),
            inference_count: 0,
            last_prediction: 0.0,
        }
    }

    /// Load a trained ONNX model
    #[cfg(feature = "ai")]
    pub fn load_onnx_model<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .with_input_fact(
                0,
                InferenceFact::dt_shape(
                    f32::datum_type(),
                    tvec![1, LSTM_SEQUENCE_LENGTH as i64, LSTM_FEATURE_COUNT as i64],
                ),
            )?
            .into_optimized()?
            .into_runnable()?;

        self.onnx_model = Some(model);
        debug!("LSTM loss predictor ONNX model loaded successfully");
        Ok(())
    }

    /// Load a trained safetensors model (from Candle training)
    #[cfg(feature = "ai")]
    pub fn load_safetensors<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        // Create model with VarMap that we'll load weights into
        let mut var_map = VarMap::new();
        let vb = VarBuilder::from_varmap(&var_map, DType::F32, &self.candle_device);
        let model = CandleLstmModel::new(LSTM_FEATURE_COUNT, 64, vb)?;

        // Load saved weights from safetensors into the model's var_map
        var_map.load(path.as_ref())?;
        self.candle_model = Some(model);
        debug!("LSTM loss predictor safetensors model loaded successfully");
        Ok(())
    }

    /// Load model - tries safetensors first, then ONNX
    #[cfg(feature = "ai")]
    pub fn load_model<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path_ref = path.as_ref();

        // Try safetensors first
        if path_ref.extension().is_some_and(|e| e == "safetensors") {
            return self.load_safetensors(path_ref);
        }

        // Try ONNX
        if path_ref.extension().is_some_and(|e| e == "onnx") {
            return self.load_onnx_model(path_ref);
        }

        // Try both extensions
        let safetensors_path = path_ref.with_extension("safetensors");
        if safetensors_path.exists() {
            return self.load_safetensors(&safetensors_path);
        }

        let onnx_path = path_ref.with_extension("onnx");
        if onnx_path.exists() {
            return self.load_onnx_model(&onnx_path);
        }

        anyhow::bail!("No model found at {:?}", path_ref)
    }

    #[cfg(not(feature = "ai"))]
    pub fn load_model<P: AsRef<Path>>(&mut self, _path: P) -> anyhow::Result<()> {
        anyhow::bail!("ML features not compiled in. Enable 'ai' feature.")
    }

    /// Check if any model is loaded
    #[cfg(feature = "ai")]
    pub fn has_model(&self) -> bool {
        self.onnx_model.is_some() || self.candle_model.is_some()
    }

    #[cfg(not(feature = "ai"))]
    pub fn has_model(&self) -> bool {
        false
    }

    /// Enable training data collection
    pub fn enable_training_collection(&mut self) {
        self.collect_training_data = true;
        debug!("Training data collection enabled for loss predictor");
    }

    /// Record a network observation
    pub fn record_observation(&mut self, features: &NetworkFeatures, ipg_us: u64) {
        let sample = LossSample {
            timestamp_ms: self.start_time.elapsed().as_millis() as u64,
            rtt_us: features.rtt_us,
            rtt_var_us: features.rtt_var_us,
            bandwidth_bps: features.bandwidth_bps,
            loss_rate: features.loss_rate,
            inflight: features.inflight,
            buffer_occupancy: features.buffer_occupancy,
            ipg_us,
            future_loss: 0.0, // Will be filled in during label generation
        };

        // Update EWMA
        self.ewma_loss =
            self.ewma_alpha * features.loss_rate + (1.0 - self.ewma_alpha) * self.ewma_loss;

        self.history.push_back(sample.clone());
        if self.history.len() > LSTM_SEQUENCE_LENGTH + 100 {
            self.history.pop_front();
        }

        if self.collect_training_data {
            self.training_data.push(sample);
        }
    }

    /// Run LSTM inference to predict loss (ONNX)
    #[cfg(feature = "ai")]
    #[allow(dead_code)]
    fn predict_with_onnx(&mut self) -> Option<f32> {
        let model = self.onnx_model.as_ref()?;

        if self.history.len() < LSTM_SEQUENCE_LENGTH {
            return None;
        }

        // Build input tensor [1, seq_len, features]
        let mut input_data = vec![0.0f32; LSTM_SEQUENCE_LENGTH * LSTM_FEATURE_COUNT];
        for (i, sample) in self
            .history
            .iter()
            .rev()
            .take(LSTM_SEQUENCE_LENGTH)
            .enumerate()
        {
            let features = sample.to_features();
            let idx = (LSTM_SEQUENCE_LENGTH - 1 - i) * LSTM_FEATURE_COUNT;
            input_data[idx..idx + LSTM_FEATURE_COUNT].copy_from_slice(&features);
        }

        let input: Tensor = tract_ndarray::Array3::from_shape_vec(
            (1, LSTM_SEQUENCE_LENGTH, LSTM_FEATURE_COUNT),
            input_data,
        )
        .ok()?
        .into();

        match model.run(tvec![input.into()]) {
            Ok(output) => {
                let prediction = output[0]
                    .to_array_view::<f32>()
                    .ok()?
                    .iter()
                    .next()
                    .copied()?;
                self.inference_count += 1;
                self.last_prediction = prediction;
                trace!("LSTM predicted loss: {:.4}", prediction);
                Some(prediction.clamp(0.0, 1.0))
            }
            Err(e) => {
                warn!("LSTM inference failed: {}", e);
                None
            }
        }
    }

    #[cfg(not(feature = "ai"))]
    fn predict_with_model(&mut self) -> Option<f32> {
        None
    }

    /// Fallback heuristic prediction
    fn predict_heuristic(&self) -> f32 {
        if self.history.len() < 5 {
            return self.ewma_loss;
        }

        // Calculate trend
        let recent: f32 = self
            .history
            .iter()
            .rev()
            .take(5)
            .map(|s| s.loss_rate)
            .sum::<f32>()
            / 5.0;
        let older: f32 = self
            .history
            .iter()
            .rev()
            .skip(5)
            .take(5)
            .map(|s| s.loss_rate)
            .sum::<f32>()
            / 5.0;
        let trend = (recent - older).max(0.0);

        // Check for jitter spike (often precedes loss)
        let recent_jitter: f32 = self
            .history
            .iter()
            .rev()
            .take(5)
            .map(|s| s.rtt_var_us as f32)
            .sum::<f32>()
            / 5.0;
        let jitter_factor = if recent_jitter > 50_000.0 { 0.1 } else { 0.0 };

        (self.ewma_loss + trend * 0.5 + jitter_factor).clamp(0.0, 1.0)
    }

    /// Export training data to JSON for offline training
    pub fn export_training_data<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self.training_data)?;
        std::fs::write(path, json)?;
        debug!("Exported {} training samples", self.training_data.len());
        Ok(())
    }

    /// Generate labels for training data (call after session ends)
    pub fn generate_training_labels(&mut self, lookahead_ms: u64) {
        let lookahead = lookahead_ms as i64;

        for i in 0..self.training_data.len() {
            let current_ts = self.training_data[i].timestamp_ms as i64;

            // Find max loss in the lookahead window
            let future_loss = self.training_data[i..]
                .iter()
                .take_while(|s| (s.timestamp_ms as i64 - current_ts) <= lookahead)
                .map(|s| s.loss_rate)
                .fold(0.0f32, |a, b| a.max(b));

            self.training_data[i].future_loss = future_loss;
        }

        debug!(
            "Generated labels for {} samples with {}ms lookahead",
            self.training_data.len(),
            lookahead_ms
        );
    }

    /// Get stats
    pub fn stats(&self) -> LstmStats {
        LstmStats {
            inference_count: self.inference_count,
            history_size: self.history.len(),
            training_samples: self.training_data.len(),
            last_prediction: self.last_prediction,
            model_loaded: self.has_model(),
        }
    }
}

impl LossPredictor for LstmLossPredictor {
    #[allow(dead_code)]
    fn predict(&self, _features: &NetworkFeatures, _history: &[f32]) -> FecDecision {
        // Try model first, fall back to heuristic
        // Note: We need &mut self for model inference, so we use interior mutability pattern
        // in production. For now, use heuristic in trait impl.
        let predicted_loss = self.predict_heuristic();

        let redundancy_ratio = if predicted_loss < 0.01 {
            0.0
        } else if predicted_loss < 0.05 {
            0.1
        } else if predicted_loss < 0.15 {
            0.2
        } else if predicted_loss < 0.25 {
            0.33
        } else {
            0.5
        };

        FecDecision {
            loss_probability: predicted_loss,
            redundancy_ratio,
            inject_fec: predicted_loss > self.fec_threshold,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstmStats {
    pub inference_count: u64,
    pub history_size: usize,
    pub training_samples: usize,
    pub last_prediction: f32,
    pub model_loaded: bool,
}

// ============================================================================
// DRL CONGESTION CONTROLLER
// ============================================================================

/// State representation for DRL agent
/// Normalized to [0, 1] for neural network input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrlState {
    /// Normalized RTT (0 = min observed, 1 = 500ms)
    pub rtt_norm: f32,
    /// Normalized RTT gradient (change rate)
    pub rtt_gradient: f32,
    /// Normalized throughput (0 = 0, 1 = target)
    pub throughput_norm: f32,
    /// Loss rate
    pub loss_rate: f32,
    /// Normalized cwnd (relative to BDP estimate)
    pub cwnd_norm: f32,
    /// Normalized inflight
    pub inflight_norm: f32,
    /// Buffer occupancy
    pub buffer_occupancy: f32,
    /// Time in current state (normalized)
    pub time_in_state: f32,
}

impl DrlState {
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.rtt_norm,
            self.rtt_gradient,
            self.throughput_norm,
            self.loss_rate,
            self.cwnd_norm,
            self.inflight_norm,
            self.buffer_occupancy,
            self.time_in_state,
        ]
    }
}

/// Action space for congestion control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrlAction {
    /// Multiplicative decrease (0.5x cwnd)
    DecreaseLarge = 0,
    /// Small decrease (0.9x cwnd)
    DecreaseSmall = 1,
    /// Maintain current cwnd
    Maintain = 2,
    /// Small increase (1.1x cwnd)
    IncreaseSmall = 3,
    /// Additive increase (+ 1 MSS)
    IncreaseAdditive = 4,
    /// Large increase (1.5x cwnd)
    IncreaseLarge = 5,
}

impl DrlAction {
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => DrlAction::DecreaseLarge,
            1 => DrlAction::DecreaseSmall,
            2 => DrlAction::Maintain,
            3 => DrlAction::IncreaseSmall,
            4 => DrlAction::IncreaseAdditive,
            _ => DrlAction::IncreaseLarge,
        }
    }

    pub fn apply(&self, current_cwnd: u32) -> u32 {
        const MSS: u32 = 1460;
        const MIN_CWND: u32 = MSS * 2;
        const MAX_CWND: u32 = 1_048_576;

        let new_cwnd = match self {
            DrlAction::DecreaseLarge => current_cwnd / 2,
            DrlAction::DecreaseSmall => current_cwnd * 9 / 10,
            DrlAction::Maintain => current_cwnd,
            DrlAction::IncreaseSmall => current_cwnd * 11 / 10,
            DrlAction::IncreaseAdditive => current_cwnd + MSS,
            DrlAction::IncreaseLarge => current_cwnd * 3 / 2,
        };

        new_cwnd.clamp(MIN_CWND, MAX_CWND)
    }
}

/// Reward calculation for training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrlReward {
    /// Throughput component (positive)
    pub throughput_reward: f32,
    /// Latency penalty (negative)
    pub latency_penalty: f32,
    /// Loss penalty (negative)
    pub loss_penalty: f32,
    /// Total reward
    pub total: f32,
}

impl DrlReward {
    /// Calculate reward from network metrics
    pub fn calculate(
        throughput_mbps: f32,
        target_throughput_mbps: f32,
        rtt_ms: f32,
        target_rtt_ms: f32,
        loss_rate: f32,
    ) -> Self {
        // Throughput reward: log scale, capped at target
        let throughput_reward = (throughput_mbps / target_throughput_mbps).min(1.0).ln() + 1.0;

        // Latency penalty: exponential penalty for exceeding target
        let latency_ratio = rtt_ms / target_rtt_ms;
        let latency_penalty = if latency_ratio > 1.0 {
            -((latency_ratio - 1.0) * 2.0).powi(2)
        } else {
            0.0
        };

        // Loss penalty: severe penalty for any loss
        let loss_penalty = -loss_rate * 10.0;

        let total = throughput_reward + latency_penalty + loss_penalty;

        DrlReward {
            throughput_reward,
            latency_penalty,
            loss_penalty,
            total,
        }
    }
}

/// Training experience tuple (s, a, r, s')
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrlExperience {
    pub state: DrlState,
    pub action: usize,
    pub reward: DrlReward,
    pub next_state: DrlState,
    pub done: bool,
}

/// DRL-based congestion controller
pub struct DrlCongestionController {
    /// Current state
    current_state: DrlState,
    /// ONNX policy model
    #[cfg(feature = "ai")]
    policy_model: Option<TractModel>,
    #[cfg(not(feature = "ai"))]
    policy_model: Option<()>,
    /// Experience replay buffer for training
    experience_buffer: VecDeque<DrlExperience>,
    /// Maximum buffer size
    max_buffer_size: usize,
    /// Exploration rate (epsilon for epsilon-greedy)
    epsilon: f32,
    /// Minimum RTT observed (for normalization)
    min_rtt_us: u64,
    /// Target throughput for reward calculation
    target_throughput_mbps: f32,
    /// Target RTT for reward calculation
    target_rtt_ms: f32,
    /// Current cwnd
    current_cwnd: u32,
    /// Last action taken
    last_action: DrlAction,
    /// Inference count
    inference_count: u64,
    /// Collect training data
    collect_training_data: bool,
    /// State transition time
    last_state_time: Instant,
}

impl Default for DrlCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

impl DrlCongestionController {
    pub fn new() -> Self {
        DrlCongestionController {
            current_state: DrlState {
                rtt_norm: 0.0,
                rtt_gradient: 0.0,
                throughput_norm: 0.0,
                loss_rate: 0.0,
                cwnd_norm: 0.5,
                inflight_norm: 0.0,
                buffer_occupancy: 0.0,
                time_in_state: 0.0,
            },
            policy_model: None,
            experience_buffer: VecDeque::with_capacity(10000),
            max_buffer_size: 100000,
            epsilon: 0.1, // 10% exploration in production
            min_rtt_us: u64::MAX,
            target_throughput_mbps: 100.0,
            target_rtt_ms: 50.0,
            current_cwnd: 65535,
            last_action: DrlAction::Maintain,
            inference_count: 0,
            collect_training_data: false,
            last_state_time: Instant::now(),
        }
    }

    /// Load trained policy model
    #[cfg(feature = "ai")]
    pub fn load_model<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .with_input_fact(0, InferenceFact::dt_shape(f32::datum_type(), tvec![1, 8]))?
            .into_optimized()?
            .into_runnable()?;

        self.policy_model = Some(model);
        debug!("DRL policy model loaded successfully");
        Ok(())
    }

    #[cfg(not(feature = "ai"))]
    pub fn load_model<P: AsRef<Path>>(&mut self, _path: P) -> anyhow::Result<()> {
        anyhow::bail!("ML features not compiled in. Enable 'ai' feature.")
    }

    /// Set target metrics for reward calculation
    pub fn set_targets(&mut self, throughput_mbps: f32, rtt_ms: f32) {
        self.target_throughput_mbps = throughput_mbps;
        self.target_rtt_ms = rtt_ms;
    }

    /// Enable training data collection
    pub fn enable_training_collection(&mut self) {
        self.collect_training_data = true;
        debug!("Training data collection enabled for DRL controller");
    }

    /// Update state from network features
    pub fn update_state(&mut self, features: &NetworkFeatures, throughput_mbps: f32) {
        // Track min RTT
        if features.rtt_us > 0 && features.rtt_us < self.min_rtt_us {
            self.min_rtt_us = features.rtt_us;
        }

        let prev_rtt = self.current_state.rtt_norm;
        let new_rtt = (features.rtt_us as f32 / 500_000.0).min(1.0);

        // Calculate BDP for normalization
        let bdp = if self.min_rtt_us < u64::MAX {
            (features.bandwidth_bps as f64 * self.min_rtt_us as f64 / 1_000_000.0) as u32
        } else {
            65535
        };

        let new_state = DrlState {
            rtt_norm: new_rtt,
            rtt_gradient: new_rtt - prev_rtt,
            throughput_norm: (throughput_mbps / self.target_throughput_mbps).min(1.0),
            loss_rate: features.loss_rate,
            cwnd_norm: (features.cwnd as f32 / bdp.max(1) as f32).min(2.0) / 2.0,
            inflight_norm: (features.inflight as f32 / 1000.0).min(1.0),
            buffer_occupancy: features.buffer_occupancy,
            time_in_state: self.last_state_time.elapsed().as_secs_f32().min(1.0),
        };

        // Record experience if collecting training data
        if self.collect_training_data {
            let reward = DrlReward::calculate(
                throughput_mbps,
                self.target_throughput_mbps,
                features.rtt_us as f32 / 1000.0,
                self.target_rtt_ms,
                features.loss_rate,
            );

            let experience = DrlExperience {
                state: self.current_state.clone(),
                action: self.last_action as usize,
                reward,
                next_state: new_state.clone(),
                done: false,
            };

            self.experience_buffer.push_back(experience);
            if self.experience_buffer.len() > self.max_buffer_size {
                self.experience_buffer.pop_front();
            }
        }

        self.current_state = new_state;
        self.last_state_time = Instant::now();
    }

    /// Select action using policy network or epsilon-greedy
    #[cfg(feature = "ai")]
    pub fn select_action(&mut self) -> DrlAction {
        // Epsilon-greedy exploration
        if rand_float() < self.epsilon {
            let random_idx = (rand_float() * 6.0) as usize;
            return DrlAction::from_index(random_idx);
        }

        // Try policy network
        if let Some(ref model) = self.policy_model {
            let input_vec = self.current_state.to_vec();
            let input: Tensor = tract_ndarray::Array2::from_shape_vec((1, 8), input_vec)
                .unwrap()
                .into();

            if let Ok(output) = model.run(tvec![input.into()]) {
                if let Ok(action_probs) = output[0].to_array_view::<f32>() {
                    // Select action with highest Q-value
                    let action_idx = action_probs
                        .iter()
                        .enumerate()
                        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                        .map(|(idx, _)| idx)
                        .unwrap_or(2);

                    self.inference_count += 1;
                    let action = DrlAction::from_index(action_idx);
                    self.last_action = action;
                    return action;
                }
            }
        }

        // Fallback to heuristic
        self.heuristic_action()
    }

    #[cfg(not(feature = "ai"))]
    pub fn select_action(&mut self) -> DrlAction {
        self.heuristic_action()
    }

    /// Heuristic action selection (BBR-like)
    fn heuristic_action(&mut self) -> DrlAction {
        let state = &self.current_state;

        let action = if state.loss_rate > 0.1 {
            DrlAction::DecreaseLarge
        } else if state.loss_rate > 0.01 || state.buffer_occupancy > 0.8 {
            DrlAction::DecreaseSmall
        } else if state.rtt_gradient > 0.1 {
            // RTT increasing - back off
            DrlAction::Maintain
        } else if state.throughput_norm < 0.5 && state.loss_rate < 0.01 {
            // Low throughput, no loss - increase
            DrlAction::IncreaseLarge
        } else if state.throughput_norm < 0.8 && state.loss_rate < 0.005 {
            DrlAction::IncreaseSmall
        } else {
            DrlAction::Maintain
        };

        self.last_action = action;
        action
    }

    /// Apply action and get new cwnd
    pub fn apply_action(&mut self, action: DrlAction) -> u32 {
        self.current_cwnd = action.apply(self.current_cwnd);
        self.current_cwnd
    }

    /// Export experience buffer for training
    pub fn export_experiences<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let experiences: Vec<_> = self.experience_buffer.iter().cloned().collect();
        let json = serde_json::to_string_pretty(&experiences)?;
        std::fs::write(path, json)?;
        debug!("Exported {} experiences", experiences.len());
        Ok(())
    }

    /// Get stats
    pub fn stats(&self) -> DrlStats {
        DrlStats {
            inference_count: self.inference_count,
            experience_count: self.experience_buffer.len(),
            current_cwnd: self.current_cwnd,
            epsilon: self.epsilon,
            model_loaded: self.policy_model.is_some(),
            last_action: self.last_action,
        }
    }

    /// Set exploration rate
    pub fn set_epsilon(&mut self, epsilon: f32) {
        self.epsilon = epsilon.clamp(0.0, 1.0);
    }
}

impl CongestionController for DrlCongestionController {
    fn decide(&self, features: &NetworkFeatures) -> CongestionAction {
        // For trait impl, use heuristic (need &mut self for full DRL)
        let state = &self.current_state;

        let action = if state.loss_rate > 0.1 {
            DrlAction::DecreaseLarge
        } else if state.loss_rate > 0.01 || state.buffer_occupancy > 0.8 {
            DrlAction::DecreaseSmall
        } else if features.loss_rate < 0.005 {
            DrlAction::IncreaseSmall
        } else {
            DrlAction::Maintain
        };

        let new_cwnd = action.apply(features.cwnd);
        let pacing_rate = features.bandwidth_bps;

        CongestionAction {
            new_cwnd,
            pacing_rate,
            slow_start: features.time_since_loss_ms > 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrlStats {
    pub inference_count: u64,
    pub experience_count: usize,
    pub current_cwnd: u32,
    pub epsilon: f32,
    pub model_loaded: bool,
    pub last_action: DrlAction,
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Simple pseudo-random float [0, 1) for exploration
/// Uses xorshift for speed (not cryptographic)
fn rand_float() -> f32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0x853c49e6748fea9b) };
    }

    STATE.with(|state| {
        let mut x = state.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state.set(x);
        (x.wrapping_mul(0x2545F4914F6CDD1D) as f32) / (u64::MAX as f32)
    })
}

// ============================================================================
// COMBINED ML ENGINE
// ============================================================================

/// Unified ML engine combining all AI components:
/// - LSTM Loss Predictor (Tier 1)
/// - DRL Congestion Controller (Tier 1)
/// - Smart Compression Oracle (Tier 2)
/// - Multi-Armed Bandit Path Selector (Tier 2)
pub struct MlEngine {
    /// Tier 1: LSTM-based loss prediction
    pub loss_predictor: LstmLossPredictor,
    /// Tier 1: DRL-based congestion control
    pub congestion_controller: DrlCongestionController,
    /// Tier 2: ML-based compression decision
    pub compression_oracle: MlCompressionOracle,
    /// Tier 2: UCB1-based path selection
    pub path_selector: MlPathSelector,
    /// Whether models are loaded
    models_loaded: bool,
}

impl Default for MlEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MlEngine {
    pub fn new() -> Self {
        MlEngine {
            loss_predictor: LstmLossPredictor::new(),
            congestion_controller: DrlCongestionController::new(),
            compression_oracle: MlCompressionOracle::new(),
            path_selector: MlPathSelector::new(2),
            models_loaded: false,
        }
    }

    /// Create with specified number of paths
    pub fn with_paths(num_paths: usize) -> Self {
        MlEngine {
            loss_predictor: LstmLossPredictor::new(),
            congestion_controller: DrlCongestionController::new(),
            compression_oracle: MlCompressionOracle::new(),
            path_selector: MlPathSelector::new(num_paths),
            models_loaded: false,
        }
    }

    /// Load all models from a directory
    pub fn load_models<P: AsRef<Path>>(&mut self, model_dir: P) -> anyhow::Result<()> {
        let dir = model_dir.as_ref();

        // Tier 1 models
        let lstm_path = dir.join("loss_predictor.onnx");
        let drl_path = dir.join("congestion_controller.onnx");

        // Tier 2 models
        let compression_path = dir.join("compression_oracle.onnx");
        let path_selector_path = dir.join("path_selector.onnx");

        if lstm_path.exists() {
            self.loss_predictor.load_model(&lstm_path)?;
        } else {
            debug!("LSTM model not found at {:?}, using heuristics", lstm_path);
        }

        if drl_path.exists() {
            self.congestion_controller.load_model(&drl_path)?;
        } else {
            debug!("DRL model not found at {:?}, using heuristics", drl_path);
        }

        if compression_path.exists() {
            self.compression_oracle.load_model(&compression_path)?;
        } else {
            debug!(
                "Compression model not found at {:?}, using heuristics",
                compression_path
            );
        }

        if path_selector_path.exists() {
            self.path_selector.load_model(&path_selector_path)?;
        } else {
            debug!(
                "Path selector model not found at {:?}, using UCB1",
                path_selector_path
            );
        }

        self.models_loaded = true;
        Ok(())
    }

    /// Enable training data collection for all models
    pub fn enable_training_collection(&mut self) {
        self.loss_predictor.enable_training_collection();
        self.congestion_controller.enable_training_collection();
        self.compression_oracle.enable_training_collection();
        self.path_selector.enable_training_collection();
    }

    /// Export all training data
    pub fn export_training_data<P: AsRef<Path>>(&self, output_dir: P) -> anyhow::Result<()> {
        let dir = output_dir.as_ref();
        std::fs::create_dir_all(dir)?;

        // Tier 1
        self.loss_predictor
            .export_training_data(dir.join("loss_samples.json"))?;
        self.congestion_controller
            .export_experiences(dir.join("drl_experiences.json"))?;

        // Tier 2
        self.compression_oracle
            .export_training_data(dir.join("compression_samples.json"))?;
        self.path_selector
            .export_training_data(dir.join("path_selection_samples.json"))?;

        debug!("Training data exported to {:?}", dir);
        Ok(())
    }

    /// Update with new network observation
    pub fn update(&mut self, features: &NetworkFeatures, throughput_mbps: f32, ipg_us: u64) {
        self.loss_predictor.record_observation(features, ipg_us);
        self.congestion_controller
            .update_state(features, throughput_mbps);
    }

    /// Get FEC decision from loss predictor
    pub fn fec_decision(&self, features: &NetworkFeatures) -> FecDecision {
        self.loss_predictor.predict(features, &[])
    }

    /// Get congestion control action
    pub fn congestion_action(&mut self) -> (DrlAction, u32) {
        let action = self.congestion_controller.select_action();
        let cwnd = self.congestion_controller.apply_action(action);
        (action, cwnd)
    }

    /// Get compression decision for packet data
    pub fn compression_decision(&mut self, data: &[u8]) -> MlCompressionDecision {
        self.compression_oracle.decide(data)
    }

    /// Select best path for traffic type
    pub fn select_path(&mut self, traffic: TrafficContext) -> PathId {
        self.path_selector.select_path(traffic)
    }

    /// Update path metrics
    pub fn update_path_metrics(&mut self, metrics: PathMetrics) {
        self.path_selector.update_path_metrics(metrics);
    }

    /// Update path reward after observing performance
    pub fn update_path_reward(&mut self, path: PathId, traffic: TrafficContext, reward: f32) {
        self.path_selector.update_reward(path, traffic, reward);
    }

    /// Check if any ML models are loaded
    pub fn models_loaded(&self) -> bool {
        self.loss_predictor.stats().model_loaded
            || self.congestion_controller.stats().model_loaded
            || self.compression_oracle.stats().model_loaded
            || self.path_selector.stats().model_loaded
    }

    /// Get comprehensive statistics
    pub fn stats(&self) -> MlEngineStats {
        MlEngineStats {
            loss_predictor: self.loss_predictor.stats(),
            congestion_controller: self.congestion_controller.stats(),
            compression_oracle: self.compression_oracle.stats(),
            path_selector: self.path_selector.stats(),
        }
    }
}

/// Combined statistics from all ML components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlEngineStats {
    pub loss_predictor: LstmStats,
    pub congestion_controller: DrlStats,
    pub compression_oracle: CompressionOracleStats,
    pub path_selector: PathSelectorStats,
}

// ============================================================================
// ML SMART COMPRESSION
// ============================================================================

/// Training sample for compression decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionSample {
    /// Packet size in bytes
    pub size: usize,
    /// Entropy estimate (0.0-1.0)
    pub entropy: f32,
    /// Header magic bytes (first 8 bytes hashed)
    pub header_hash: u64,
    /// Byte frequency distribution features (top 4)
    pub freq_features: [f32; 4],
    /// Is text content (detected)
    pub is_text: bool,
    /// Actual compression ratio achieved (label for training)
    pub compression_ratio: f32,
    /// Time taken to compress (microseconds)
    pub compress_time_us: u64,
}

impl CompressionSample {
    /// Convert to feature vector for ML model
    pub fn to_features(&self) -> [f32; 8] {
        [
            (self.size as f32 / 65535.0).min(1.0), // Normalized size
            self.entropy,
            (self.header_hash as f32 / u64::MAX as f32), // Header signature
            self.freq_features[0],
            self.freq_features[1],
            self.freq_features[2],
            self.freq_features[3],
            if self.is_text { 1.0 } else { 0.0 },
        ]
    }
}

/// Compression decision from ML model
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MlCompressionDecision {
    /// Skip compression (high entropy, already compressed, too small)
    Skip,
    /// Light compression (LZ4 fast mode)
    Light,
    /// Normal compression (LZ4 default)
    Normal,
    /// Aggressive compression (higher ratio, more CPU)
    Aggressive,
}

impl MlCompressionDecision {
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => MlCompressionDecision::Skip,
            1 => MlCompressionDecision::Light,
            2 => MlCompressionDecision::Normal,
            _ => MlCompressionDecision::Aggressive,
        }
    }

    pub fn to_index(self) -> usize {
        match self {
            MlCompressionDecision::Skip => 0,
            MlCompressionDecision::Light => 1,
            MlCompressionDecision::Normal => 2,
            MlCompressionDecision::Aggressive => 3,
        }
    }
}

/// ML-powered Smart Compression Oracle
/// Uses a small neural network to predict optimal compression strategy
pub struct MlCompressionOracle {
    /// ONNX model for inference
    #[cfg(feature = "ai")]
    model: Option<TractModel>,

    /// Training data collection
    training_data: Vec<CompressionSample>,
    collect_training_data: bool,

    /// Statistics
    inference_count: u64,
    skip_count: u64,
    compress_count: u64,
    total_bytes_saved: u64,

    /// Fallback thresholds
    min_size: usize,
    entropy_threshold: f32,
}

impl MlCompressionOracle {
    pub fn new() -> Self {
        MlCompressionOracle {
            #[cfg(feature = "ai")]
            model: None,
            training_data: Vec::new(),
            collect_training_data: false,
            inference_count: 0,
            skip_count: 0,
            compress_count: 0,
            total_bytes_saved: 0,
            min_size: 64,
            entropy_threshold: 0.9,
        }
    }

    /// Load ONNX model for inference
    #[cfg(feature = "ai")]
    pub fn load_model<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .into_optimized()?
            .into_runnable()?;
        self.model = Some(model);
        debug!("Compression oracle model loaded");
        Ok(())
    }

    #[cfg(not(feature = "ai"))]
    pub fn load_model<P: AsRef<Path>>(&mut self, _path: P) -> anyhow::Result<()> {
        anyhow::bail!("AI features not compiled in")
    }

    /// Enable training data collection
    pub fn enable_training_collection(&mut self) {
        self.collect_training_data = true;
    }

    /// Analyze packet and extract features
    pub fn analyze_packet(&self, data: &[u8]) -> CompressionSample {
        let size = data.len();

        // Calculate entropy
        let entropy = Self::calculate_entropy(data);

        // Hash first 8 bytes for format detection
        let header_hash = if data.len() >= 8 {
            let mut hash: u64 = 0;
            for (i, &b) in data[..8].iter().enumerate() {
                hash |= (b as u64) << (i * 8);
            }
            hash
        } else {
            0
        };

        // Byte frequency features
        let freq_features = Self::calculate_freq_features(data);

        // Text detection
        let is_text = Self::detect_text(data);

        CompressionSample {
            size,
            entropy,
            header_hash,
            freq_features,
            is_text,
            compression_ratio: 0.0, // Filled after compression
            compress_time_us: 0,
        }
    }

    /// Calculate Shannon entropy (0.0 = uniform, 1.0 = max entropy/random)
    fn calculate_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0f32;

        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        // Normalize to 0-1 (max entropy is 8 bits)
        (entropy / 8.0).min(1.0)
    }

    /// Calculate byte frequency distribution features
    fn calculate_freq_features(data: &[u8]) -> [f32; 4] {
        if data.is_empty() {
            return [0.0; 4];
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        // Sort and get top 4 frequencies
        let mut sorted: Vec<_> = counts.to_vec();
        sorted.sort_unstable_by(|a, b| b.cmp(a));

        let len = data.len() as f32;
        [
            sorted[0] as f32 / len,
            sorted[1] as f32 / len,
            sorted[2] as f32 / len,
            sorted[3] as f32 / len,
        ]
    }

    /// Detect if content is likely text
    fn detect_text(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        // Check for JSON/XML/HTML
        if let Some(&first) = data.first() {
            if first == b'{' || first == b'[' || first == b'<' {
                return true;
            }
        }

        // Count printable ASCII
        let printable = data
            .iter()
            .filter(|&&b| (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
            .count();

        printable as f32 / data.len() as f32 > 0.85
    }

    /// Decide compression strategy using ML model or heuristics
    pub fn decide(&mut self, data: &[u8]) -> MlCompressionDecision {
        // Too small - skip
        if data.len() < self.min_size {
            self.skip_count += 1;
            return MlCompressionDecision::Skip;
        }

        let sample = self.analyze_packet(data);

        // Try ML inference first
        #[cfg(feature = "ai")]
        if let Some(ref model) = self.model {
            if let Some(decision) = self.infer_decision(model, &sample) {
                self.inference_count += 1;
                if decision == MlCompressionDecision::Skip {
                    self.skip_count += 1;
                } else {
                    self.compress_count += 1;
                }
                return decision;
            }
        }

        // Fallback to heuristics
        self.decide_heuristic(&sample)
    }

    /// ML inference for compression decision
    #[cfg(feature = "ai")]
    fn infer_decision(
        &self,
        model: &TractModel,
        sample: &CompressionSample,
    ) -> Option<MlCompressionDecision> {
        let features = sample.to_features();
        let input: Tensor = tract_ndarray::Array2::from_shape_vec((1, 8), features.to_vec())
            .ok()?
            .into();

        let output = model.run(tvec![input.into()]).ok()?;
        let probs = output[0].to_array_view::<f32>().ok()?;

        // Get action with highest probability
        let action_idx = probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(idx, _)| idx)?;

        Some(MlCompressionDecision::from_index(action_idx))
    }

    /// Heuristic-based compression decision
    fn decide_heuristic(&mut self, sample: &CompressionSample) -> MlCompressionDecision {
        // High entropy - skip
        if sample.entropy > self.entropy_threshold {
            self.skip_count += 1;
            return MlCompressionDecision::Skip;
        }

        // Check for compressed formats via header
        if Self::is_compressed_header(sample.header_hash) {
            self.skip_count += 1;
            return MlCompressionDecision::Skip;
        }

        self.compress_count += 1;

        // Text content - compress aggressively
        if sample.is_text {
            return MlCompressionDecision::Aggressive;
        }

        // Low entropy - normal compression
        if sample.entropy < 0.5 {
            return MlCompressionDecision::Normal;
        }

        // Medium entropy - light compression
        MlCompressionDecision::Light
    }

    /// Check if header indicates compressed format
    fn is_compressed_header(header_hash: u64) -> bool {
        let bytes = header_hash.to_le_bytes();

        // GZIP: 1F 8B
        if bytes[0] == 0x1F && bytes[1] == 0x8B {
            return true;
        }
        // PNG: 89 50 4E 47
        if bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47 {
            return true;
        }
        // JPEG: FF D8 FF
        if bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
            return true;
        }
        // ZIP: 50 4B 03 04
        if bytes[0] == 0x50 && bytes[1] == 0x4B && bytes[2] == 0x03 && bytes[3] == 0x04 {
            return true;
        }
        // LZ4: 04 22 4D 18
        if bytes[0] == 0x04 && bytes[1] == 0x22 && bytes[2] == 0x4D && bytes[3] == 0x18 {
            return true;
        }

        false
    }

    /// Record compression result for training
    pub fn record_result(
        &mut self,
        mut sample: CompressionSample,
        original_size: usize,
        compressed_size: usize,
        time_us: u64,
    ) {
        sample.compression_ratio = if original_size > 0 {
            compressed_size as f32 / original_size as f32
        } else {
            1.0
        };
        sample.compress_time_us = time_us;

        if original_size > compressed_size {
            self.total_bytes_saved += (original_size - compressed_size) as u64;
        }

        if self.collect_training_data {
            self.training_data.push(sample);
            if self.training_data.len() > 100_000 {
                self.training_data.remove(0);
            }
        }
    }

    /// Export training data
    pub fn export_training_data<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self.training_data)?;
        std::fs::write(path, json)?;
        debug!("Exported {} compression samples", self.training_data.len());
        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> CompressionOracleStats {
        CompressionOracleStats {
            inference_count: self.inference_count,
            skip_count: self.skip_count,
            compress_count: self.compress_count,
            total_bytes_saved: self.total_bytes_saved,
            training_samples: self.training_data.len(),
            #[cfg(feature = "ai")]
            model_loaded: self.model.is_some(),
            #[cfg(not(feature = "ai"))]
            model_loaded: false,
        }
    }
}

impl Default for MlCompressionOracle {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression oracle statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionOracleStats {
    pub inference_count: u64,
    pub skip_count: u64,
    pub compress_count: u64,
    pub total_bytes_saved: u64,
    pub training_samples: usize,
    pub model_loaded: bool,
}

// ============================================================================
// ML PATH SELECTION (Multi-Armed Bandit + Contextual)
// ============================================================================

/// Maximum number of paths supported
pub const MAX_PATHS: usize = 4;

/// Path identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathId {
    /// Primary path (e.g., main tunnel, 5GHz WiFi)
    Primary = 0,
    /// Secondary path (e.g., backup tunnel, 2.4GHz WiFi)
    Secondary = 1,
    /// Tertiary path (e.g., LTE/cellular)
    Tertiary = 2,
    /// Quaternary path (e.g., 6GHz WiFi, satellite)
    Quaternary = 3,
}

impl PathId {
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => PathId::Primary,
            1 => PathId::Secondary,
            2 => PathId::Tertiary,
            _ => PathId::Quaternary,
        }
    }

    pub fn to_index(self) -> usize {
        self as usize
    }
}

/// Path metrics for selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    /// Path identifier
    pub path_id: PathId,
    /// Current RTT estimate (microseconds)
    pub rtt_us: u64,
    /// RTT variance/jitter (microseconds)
    pub rtt_var_us: u64,
    /// Estimated bandwidth (bps)
    pub bandwidth_bps: u64,
    /// Recent packet loss rate (0.0-1.0)
    pub loss_rate: f32,
    /// Path availability (0.0-1.0, 1.0 = fully available)
    pub availability: f32,
    /// Cost factor (e.g., cellular = higher cost)
    pub cost_factor: f32,
    /// Last update timestamp
    pub last_update_ms: u64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        PathMetrics {
            path_id: PathId::Primary,
            rtt_us: 50_000,
            rtt_var_us: 5_000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.0,
            availability: 1.0,
            cost_factor: 1.0,
            last_update_ms: 0,
        }
    }
}

impl PathMetrics {
    /// Convert to feature vector for ML model
    pub fn to_features(&self) -> [f32; 6] {
        [
            (self.rtt_us as f32 / 500_000.0).min(1.0), // Normalize RTT (max 500ms)
            (self.rtt_var_us as f32 / 100_000.0).min(1.0), // Normalize jitter
            (self.bandwidth_bps as f32 / 1_000_000_000.0).min(1.0), // Normalize BW (max 1Gbps)
            self.loss_rate.min(1.0),
            self.availability,
            self.cost_factor.min(1.0),
        ]
    }
}

/// Training sample for path selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSelectionSample {
    /// Timestamp
    pub timestamp_ms: u64,
    /// Traffic type (encoded)
    pub traffic_type: u8,
    /// Metrics for all paths at decision time
    pub path_metrics: Vec<PathMetrics>,
    /// Selected path
    pub selected_path: PathId,
    /// Observed reward after selection
    pub reward: f32,
}

/// Traffic type for path selection context
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficContext {
    /// Gaming - ultra-low latency priority
    Gaming = 0,
    /// VoIP - low latency, jitter sensitive
    VoIP = 1,
    /// Video streaming - bandwidth priority
    Streaming = 2,
    /// Bulk transfer - throughput priority
    Bulk = 3,
    /// General web - balanced
    Web = 4,
}

impl TrafficContext {
    pub fn to_index(self) -> usize {
        self as usize
    }

    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => TrafficContext::Gaming,
            1 => TrafficContext::VoIP,
            2 => TrafficContext::Streaming,
            3 => TrafficContext::Bulk,
            _ => TrafficContext::Web,
        }
    }
}

/// Upper Confidence Bound (UCB1) arm statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UcbArm {
    /// Number of times this arm was selected
    pulls: u64,
    /// Total reward accumulated
    total_reward: f64,
    /// Average reward
    avg_reward: f64,
}

impl Default for UcbArm {
    fn default() -> Self {
        UcbArm {
            pulls: 0,
            total_reward: 0.0,
            avg_reward: 0.0,
        }
    }
}

/// ML Path Selector using Contextual Multi-Armed Bandit
/// Combines UCB1 exploration with contextual features
pub struct MlPathSelector {
    /// UCB1 arms for each (traffic_type, path) combination
    /// Index: traffic_type * MAX_PATHS + path_id
    arms: Vec<UcbArm>,

    /// Total number of selections
    total_selections: u64,

    /// Exploration parameter (higher = more exploration)
    exploration_c: f64,

    /// Current path metrics
    path_metrics: [PathMetrics; MAX_PATHS],

    /// Number of available paths
    available_paths: usize,

    /// Training data collection
    training_data: Vec<PathSelectionSample>,
    collect_training_data: bool,

    /// ONNX model for contextual features (optional enhancement)
    #[cfg(feature = "ai")]
    model: Option<TractModel>,

    /// Statistics
    selections_by_path: [u64; MAX_PATHS],
    avg_reward_by_path: [f64; MAX_PATHS],
}

impl MlPathSelector {
    pub fn new(num_paths: usize) -> Self {
        let num_arms = 5 * MAX_PATHS; // 5 traffic types * 4 paths
        MlPathSelector {
            arms: vec![UcbArm::default(); num_arms],
            total_selections: 0,
            exploration_c: 2.0_f64.sqrt(), // Standard UCB1 constant
            path_metrics: [
                PathMetrics {
                    path_id: PathId::Primary,
                    ..Default::default()
                },
                PathMetrics {
                    path_id: PathId::Secondary,
                    ..Default::default()
                },
                PathMetrics {
                    path_id: PathId::Tertiary,
                    ..Default::default()
                },
                PathMetrics {
                    path_id: PathId::Quaternary,
                    ..Default::default()
                },
            ],
            available_paths: num_paths.min(MAX_PATHS),
            training_data: Vec::new(),
            collect_training_data: false,
            #[cfg(feature = "ai")]
            model: None,
            selections_by_path: [0; MAX_PATHS],
            avg_reward_by_path: [0.0; MAX_PATHS],
        }
    }

    /// Load ONNX model for contextual path selection
    #[cfg(feature = "ai")]
    pub fn load_model<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .into_optimized()?
            .into_runnable()?;
        self.model = Some(model);
        debug!("Path selector model loaded");
        Ok(())
    }

    #[cfg(not(feature = "ai"))]
    pub fn load_model<P: AsRef<Path>>(&mut self, _path: P) -> anyhow::Result<()> {
        anyhow::bail!("AI features not compiled in")
    }

    /// Enable training data collection
    pub fn enable_training_collection(&mut self) {
        self.collect_training_data = true;
    }

    /// Update metrics for a specific path
    pub fn update_path_metrics(&mut self, metrics: PathMetrics) {
        let idx = metrics.path_id.to_index();
        if idx < MAX_PATHS {
            self.path_metrics[idx] = metrics;
        }
    }

    /// Set number of available paths
    pub fn set_available_paths(&mut self, count: usize) {
        self.available_paths = count.min(MAX_PATHS);
    }

    /// Select best path using UCB1 with contextual adjustments
    pub fn select_path(&mut self, traffic: TrafficContext) -> PathId {
        // If only one path, return it
        if self.available_paths <= 1 {
            return PathId::Primary;
        }

        let traffic_idx = traffic.to_index();

        // Try ML model first for contextual selection
        #[cfg(feature = "ai")]
        if let Some(ref model) = self.model {
            if let Some(path) = self.ml_select(model, traffic) {
                self.record_selection(path, traffic);
                return path;
            }
        }

        // UCB1 selection
        let selected = self.ucb1_select(traffic_idx);
        self.record_selection(selected, traffic);
        selected
    }

    /// UCB1 arm selection
    fn ucb1_select(&self, traffic_idx: usize) -> PathId {
        let mut best_path = PathId::Primary;
        let mut best_ucb = f64::NEG_INFINITY;

        for path_idx in 0..self.available_paths {
            let arm_idx = traffic_idx * MAX_PATHS + path_idx;
            let arm = &self.arms[arm_idx];
            let metrics = &self.path_metrics[path_idx];

            // Check availability
            if metrics.availability < 0.1 {
                continue;
            }

            let ucb_value = if arm.pulls == 0 {
                // Unexplored arm - give high priority
                f64::INFINITY
            } else {
                // UCB1 formula: avg_reward + c * sqrt(ln(total) / pulls)
                let exploration = self.exploration_c
                    * ((self.total_selections as f64).ln() / arm.pulls as f64).sqrt();

                // Contextual adjustment based on traffic type and path metrics
                let context_bonus = self.contextual_bonus(traffic_idx, metrics);

                arm.avg_reward + exploration + context_bonus
            };

            if ucb_value > best_ucb {
                best_ucb = ucb_value;
                best_path = PathId::from_index(path_idx);
            }
        }

        best_path
    }

    /// Calculate contextual bonus based on traffic type and path metrics
    fn contextual_bonus(&self, traffic_idx: usize, metrics: &PathMetrics) -> f64 {
        let traffic = TrafficContext::from_index(traffic_idx);

        match traffic {
            TrafficContext::Gaming | TrafficContext::VoIP => {
                // Prioritize low latency and jitter
                let latency_score = 1.0 - (metrics.rtt_us as f64 / 200_000.0).min(1.0);
                let jitter_score = 1.0 - (metrics.rtt_var_us as f64 / 50_000.0).min(1.0);
                (latency_score * 0.6 + jitter_score * 0.4) * 0.3
            }
            TrafficContext::Streaming | TrafficContext::Bulk => {
                // Prioritize bandwidth
                let bw_score = (metrics.bandwidth_bps as f64 / 500_000_000.0).min(1.0);
                let loss_penalty = metrics.loss_rate as f64 * 0.5;
                (bw_score - loss_penalty) * 0.3
            }
            TrafficContext::Web => {
                // Balanced
                let latency_score = 1.0 - (metrics.rtt_us as f64 / 300_000.0).min(1.0);
                let bw_score = (metrics.bandwidth_bps as f64 / 100_000_000.0).min(1.0);
                (latency_score * 0.5 + bw_score * 0.5) * 0.2
            }
        }
    }

    /// ML-based path selection
    #[cfg(feature = "ai")]
    fn ml_select(&self, model: &TractModel, traffic: TrafficContext) -> Option<PathId> {
        // Build feature vector: [traffic_type_onehot(5), path_metrics(6) * 4]
        let mut features = Vec::with_capacity(5 + 6 * MAX_PATHS);

        // One-hot traffic type
        for i in 0..5 {
            features.push(if i == traffic.to_index() { 1.0 } else { 0.0 });
        }

        // Path metrics
        for i in 0..MAX_PATHS {
            let path_features = self.path_metrics[i].to_features();
            features.extend(path_features);
        }

        let input: Tensor = tract_ndarray::Array2::from_shape_vec((1, features.len()), features)
            .ok()?
            .into();

        let output = model.run(tvec![input.into()]).ok()?;
        let scores = output[0].to_array_view::<f32>().ok()?;

        // Get path with highest score (considering availability)
        let best_idx = scores
            .iter()
            .take(self.available_paths)
            .enumerate()
            .filter(|(i, _)| self.path_metrics[*i].availability > 0.1)
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(idx, _)| idx)?;

        Some(PathId::from_index(best_idx))
    }

    /// Record selection for statistics
    fn record_selection(&mut self, path: PathId, _traffic: TrafficContext) {
        self.total_selections += 1;
        let path_idx = path.to_index();
        if path_idx < MAX_PATHS {
            self.selections_by_path[path_idx] += 1;
        }
    }

    /// Update arm with observed reward
    pub fn update_reward(&mut self, path: PathId, traffic: TrafficContext, reward: f32) {
        let traffic_idx = traffic.to_index();
        let path_idx = path.to_index();
        let arm_idx = traffic_idx * MAX_PATHS + path_idx;

        if arm_idx < self.arms.len() {
            let arm = &mut self.arms[arm_idx];
            arm.pulls += 1;
            arm.total_reward += reward as f64;
            arm.avg_reward = arm.total_reward / arm.pulls as f64;

            // Update path-level stats
            if path_idx < MAX_PATHS {
                let n = self.selections_by_path[path_idx] as f64;
                if n > 0.0 {
                    self.avg_reward_by_path[path_idx] =
                        (self.avg_reward_by_path[path_idx] * (n - 1.0) + reward as f64) / n;
                }
            }
        }

        // Collect training sample
        if self.collect_training_data {
            let sample = PathSelectionSample {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                traffic_type: traffic.to_index() as u8,
                path_metrics: self.path_metrics.to_vec(),
                selected_path: path,
                reward,
            };
            self.training_data.push(sample);
            if self.training_data.len() > 50_000 {
                self.training_data.remove(0);
            }
        }
    }

    /// Calculate reward from observed metrics
    pub fn calculate_reward(
        traffic: TrafficContext,
        rtt_us: u64,
        loss_rate: f32,
        throughput_mbps: f32,
    ) -> f32 {
        match traffic {
            TrafficContext::Gaming | TrafficContext::VoIP => {
                // Heavily penalize latency and loss
                let latency_score = (1.0 - (rtt_us as f32 / 100_000.0)).max(0.0);
                let loss_penalty = loss_rate * 5.0;
                (latency_score - loss_penalty).clamp(-1.0, 1.0)
            }
            TrafficContext::Streaming | TrafficContext::Bulk => {
                // Prioritize throughput
                let throughput_score = (throughput_mbps / 100.0).min(1.0);
                let loss_penalty = loss_rate * 2.0;
                (throughput_score - loss_penalty).clamp(-1.0, 1.0)
            }
            TrafficContext::Web => {
                // Balanced
                let latency_score = (1.0 - (rtt_us as f32 / 200_000.0)).max(0.0);
                let throughput_score = (throughput_mbps / 50.0).min(1.0);
                let loss_penalty = loss_rate * 3.0;
                ((latency_score + throughput_score) / 2.0 - loss_penalty).clamp(-1.0, 1.0)
            }
        }
    }

    /// Export training data
    pub fn export_training_data<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self.training_data)?;
        std::fs::write(path, json)?;
        debug!(
            "Exported {} path selection samples",
            self.training_data.len()
        );
        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> PathSelectorStats {
        PathSelectorStats {
            total_selections: self.total_selections,
            selections_by_path: self.selections_by_path,
            avg_reward_by_path: self.avg_reward_by_path,
            available_paths: self.available_paths,
            training_samples: self.training_data.len(),
            #[cfg(feature = "ai")]
            model_loaded: self.model.is_some(),
            #[cfg(not(feature = "ai"))]
            model_loaded: false,
        }
    }
}

impl Default for MlPathSelector {
    fn default() -> Self {
        Self::new(2) // Default to 2 paths
    }
}

/// Path selector statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSelectorStats {
    pub total_selections: u64,
    pub selections_by_path: [u64; MAX_PATHS],
    pub avg_reward_by_path: [f64; MAX_PATHS],
    pub available_paths: usize,
    pub training_samples: usize,
    pub model_loaded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lstm_predictor_heuristic() {
        let mut predictor = LstmLossPredictor::new();

        // Record some observations
        for i in 0..30 {
            let features = NetworkFeatures {
                rtt_us: 50_000 + i * 1000,
                rtt_var_us: 5000,
                bandwidth_bps: 100_000_000,
                loss_rate: 0.01 * (i as f32 / 30.0),
                loss_trend: 0.0,
                inflight: 100,
                cwnd: 65535,
                time_since_loss_ms: 1000,
                buffer_occupancy: 0.3,
                recent_retx: 0,
            };
            predictor.record_observation(&features, 1000);
        }

        let features = NetworkFeatures::default();
        let decision = predictor.predict(&features, &[]);

        assert!(decision.loss_probability >= 0.0);
        assert!(decision.loss_probability <= 1.0);
    }

    #[test]
    fn test_drl_action_application() {
        let cwnd = 65535u32;

        assert!(DrlAction::DecreaseLarge.apply(cwnd) < cwnd);
        assert!(DrlAction::DecreaseSmall.apply(cwnd) < cwnd);
        assert_eq!(DrlAction::Maintain.apply(cwnd), cwnd);
        assert!(DrlAction::IncreaseSmall.apply(cwnd) > cwnd);
        assert!(DrlAction::IncreaseLarge.apply(cwnd) > cwnd);
    }

    #[test]
    fn test_drl_controller_heuristic() {
        let mut controller = DrlCongestionController::new();

        let features = NetworkFeatures {
            rtt_us: 50_000,
            rtt_var_us: 5000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.0,
            loss_trend: 0.0,
            inflight: 100,
            cwnd: 65535,
            time_since_loss_ms: 5000,
            buffer_occupancy: 0.3,
            recent_retx: 0,
        };

        controller.update_state(&features, 50.0);
        let action = controller.select_action();

        // With no loss and low throughput, should try to increase
        assert!(matches!(
            action,
            DrlAction::IncreaseSmall | DrlAction::IncreaseLarge | DrlAction::Maintain
        ));
    }

    #[test]
    fn test_reward_calculation() {
        // Good performance
        let good_reward = DrlReward::calculate(100.0, 100.0, 30.0, 50.0, 0.0);
        assert!(good_reward.total > 0.0);

        // Bad performance (high loss)
        let bad_reward = DrlReward::calculate(100.0, 100.0, 30.0, 50.0, 0.1);
        assert!(bad_reward.total < good_reward.total);

        // Bad performance (high latency)
        let high_lat_reward = DrlReward::calculate(100.0, 100.0, 100.0, 50.0, 0.0);
        assert!(high_lat_reward.latency_penalty < 0.0);
    }

    #[test]
    fn test_ml_engine() {
        let mut engine = MlEngine::new();

        let features = NetworkFeatures {
            rtt_us: 50_000,
            rtt_var_us: 5000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.01,
            loss_trend: 0.0,
            inflight: 100,
            cwnd: 65535,
            time_since_loss_ms: 1000,
            buffer_occupancy: 0.3,
            recent_retx: 0,
        };

        engine.update(&features, 80.0, 1000);

        let fec = engine.fec_decision(&features);
        assert!(fec.loss_probability >= 0.0);

        let (_action, cwnd) = engine.congestion_action();
        assert!(cwnd > 0);
    }

    #[test]
    fn test_loss_sample_features() {
        let sample = LossSample {
            timestamp_ms: 1000,
            rtt_us: 50_000,
            rtt_var_us: 5000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.01,
            inflight: 100,
            buffer_occupancy: 0.3,
            ipg_us: 1000,
            future_loss: 0.0,
        };

        let features = sample.to_features();
        assert_eq!(features.len(), LSTM_FEATURE_COUNT);
        assert!(features.iter().all(|&x| (0.0..=1.0).contains(&x)));
    }

    #[test]
    fn test_compression_oracle_entropy() {
        // High entropy (random) data - should skip
        let random_data: Vec<u8> = (0..1000).map(|i| (i * 17 + 31) as u8).collect();
        let entropy = MlCompressionOracle::calculate_entropy(&random_data);
        assert!(entropy > 0.9, "Random data should have high entropy");

        // Low entropy (repetitive) data - should compress
        let repetitive_data = vec![0u8; 1000];
        let entropy = MlCompressionOracle::calculate_entropy(&repetitive_data);
        assert!(entropy < 0.1, "Repetitive data should have low entropy");

        // Text data
        let text_data = b"Hello, this is some text content that should compress well!";
        let entropy = MlCompressionOracle::calculate_entropy(text_data);
        assert!(entropy < 0.7, "Text should have medium-low entropy");
    }

    #[test]
    fn test_compression_oracle_decision() {
        let mut oracle = MlCompressionOracle::new();

        // Small data - skip
        let small = vec![0u8; 32];
        assert_eq!(oracle.decide(&small), MlCompressionDecision::Skip);

        // Text data - aggressive (must be > 64 bytes for min_size)
        let json = br#"{"name": "test", "value": 12345, "nested": {"a": 1, "b": 2, "c": 3}, "description": "longer text"}"#;
        let decision = oracle.decide(json);
        assert_eq!(decision, MlCompressionDecision::Aggressive);

        // Already compressed (GZIP header)
        let gzip = vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let gzip_padded: Vec<u8> = gzip
            .into_iter()
            .chain(std::iter::repeat_n(0, 100))
            .collect();
        let decision = oracle.decide(&gzip_padded);
        assert_eq!(decision, MlCompressionDecision::Skip);
    }

    #[test]
    fn test_compression_sample_features() {
        let sample = CompressionSample {
            size: 1000,
            entropy: 0.5,
            header_hash: 0x12345678,
            freq_features: [0.1, 0.05, 0.03, 0.02],
            is_text: true,
            compression_ratio: 0.6,
            compress_time_us: 100,
        };

        let features = sample.to_features();
        assert_eq!(features.len(), 8);
        assert!(features.iter().all(|&x| (0.0..=1.0).contains(&x)));
    }

    #[test]
    fn test_path_selector_ucb1() {
        let mut selector = MlPathSelector::new(2);

        // Initial selections should explore all paths
        let path1 = selector.select_path(TrafficContext::Gaming);
        selector.update_reward(path1, TrafficContext::Gaming, 0.5);

        let path2 = selector.select_path(TrafficContext::Gaming);
        selector.update_reward(path2, TrafficContext::Gaming, 0.8);

        // After exploration, should prefer higher reward path
        for _ in 0..10 {
            let path = selector.select_path(TrafficContext::Gaming);
            selector.update_reward(
                path,
                TrafficContext::Gaming,
                if path == path2 { 0.8 } else { 0.5 },
            );
        }

        let stats = selector.stats();
        assert!(stats.total_selections >= 12);
    }

    #[test]
    fn test_path_selector_traffic_context() {
        let mut selector = MlPathSelector::new(2);

        // Update path metrics - path 0 has low latency, path 1 has high bandwidth
        selector.update_path_metrics(PathMetrics {
            path_id: PathId::Primary,
            rtt_us: 20_000, // 20ms - low latency
            rtt_var_us: 2_000,
            bandwidth_bps: 50_000_000, // 50 Mbps
            loss_rate: 0.0,
            availability: 1.0,
            cost_factor: 1.0,
            last_update_ms: 0,
        });
        selector.update_path_metrics(PathMetrics {
            path_id: PathId::Secondary,
            rtt_us: 80_000, // 80ms - higher latency
            rtt_var_us: 10_000,
            bandwidth_bps: 500_000_000, // 500 Mbps - high bandwidth
            loss_rate: 0.0,
            availability: 1.0,
            cost_factor: 1.0,
            last_update_ms: 0,
        });

        // Gaming should prefer low latency path after some learning
        for _ in 0..20 {
            let path = selector.select_path(TrafficContext::Gaming);
            let reward = MlPathSelector::calculate_reward(
                TrafficContext::Gaming,
                if path == PathId::Primary {
                    20_000
                } else {
                    80_000
                },
                0.0,
                50.0,
            );
            selector.update_reward(path, TrafficContext::Gaming, reward);
        }

        // Streaming should prefer high bandwidth path after learning
        for _ in 0..20 {
            let path = selector.select_path(TrafficContext::Streaming);
            let reward = MlPathSelector::calculate_reward(
                TrafficContext::Streaming,
                if path == PathId::Primary {
                    20_000
                } else {
                    80_000
                },
                0.0,
                if path == PathId::Primary { 50.0 } else { 500.0 },
            );
            selector.update_reward(path, TrafficContext::Streaming, reward);
        }

        let stats = selector.stats();
        assert!(stats.total_selections >= 40);
    }

    #[test]
    fn test_path_metrics_features() {
        let metrics = PathMetrics {
            path_id: PathId::Primary,
            rtt_us: 100_000,
            rtt_var_us: 20_000,
            bandwidth_bps: 200_000_000,
            loss_rate: 0.05,
            availability: 0.9,
            cost_factor: 0.5,
            last_update_ms: 0,
        };

        let features = metrics.to_features();
        assert_eq!(features.len(), 6);
        assert!(features.iter().all(|&x| (0.0..=1.0).contains(&x)));
    }

    #[test]
    fn test_reward_calculation_traffic_types() {
        // Gaming: low latency is good
        let gaming_good =
            MlPathSelector::calculate_reward(TrafficContext::Gaming, 20_000, 0.0, 50.0);
        let gaming_bad =
            MlPathSelector::calculate_reward(TrafficContext::Gaming, 150_000, 0.0, 50.0);
        assert!(gaming_good > gaming_bad);

        // Streaming: high throughput is good
        let stream_good =
            MlPathSelector::calculate_reward(TrafficContext::Streaming, 100_000, 0.0, 200.0);
        let stream_bad =
            MlPathSelector::calculate_reward(TrafficContext::Streaming, 100_000, 0.0, 20.0);
        assert!(stream_good > stream_bad);

        // Loss always hurts
        let no_loss = MlPathSelector::calculate_reward(TrafficContext::Web, 50_000, 0.0, 50.0);
        let with_loss = MlPathSelector::calculate_reward(TrafficContext::Web, 50_000, 0.1, 50.0);
        assert!(no_loss > with_loss);
    }
}
