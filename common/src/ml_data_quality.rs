//! Data Quality Guards for ML Training
//!
//! Prevents training on garbage data during DDoS attacks or network anomalies.
//! Validates `LossSample` and `DrlExperience` before they enter training buffers.
//!
//! ## Design Principles
//! - **Fail-safe**: Invalid data is rejected, not silently corrected
//! - **Fast**: Validation adds <1µs overhead per sample
//! - **Comprehensive**: Checks ranges, consistency, and anomaly patterns
//! - **DDoS-aware**: Detects and rejects synthetic/malicious patterns

use std::time::{Duration, Instant};

use crate::ml_optimized::{DrlExperience, DrlState, LossSample};

// ============================================================================
// VALIDATION THRESHOLDS
// ============================================================================

/// Maximum RTT considered valid (10 seconds)
const MAX_RTT_US: u64 = 10_000_000;

/// Maximum RTT variance considered valid (5 seconds)
const MAX_RTT_VAR_US: u64 = 5_000_000;

/// Maximum bandwidth considered valid (100 Gbps)
const MAX_BANDWIDTH_BPS: u64 = 100_000_000_000;

/// Maximum loss rate (100%)
const MAX_LOSS_RATE: f32 = 1.0;

/// Maximum inflight packets
const MAX_INFLIGHT: u32 = 100_000;

/// Maximum buffer occupancy (100%)
const MAX_BUFFER_OCCUPANCY: f32 = 1.0;

/// Maximum inter-packet gap (1 second)
const MAX_IPG_US: u64 = 1_000_000;

/// Maximum reward magnitude
const MAX_REWARD: f32 = 100.0;

/// Minimum RTT to be considered valid (100µs)
const MIN_RTT_US: u64 = 100;

/// Minimum bandwidth to be considered valid (1 Kbps)
const MIN_BANDWIDTH_BPS: u64 = 1_000;

// ============================================================================
// VALIDATION ERRORS
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    /// RTT out of valid range
    InvalidRtt(u64),
    /// RTT variance out of valid range
    InvalidRttVar(u64),
    /// Bandwidth out of valid range
    InvalidBandwidth(u64),
    /// Loss rate out of valid range [0, 1]
    InvalidLossRate(f32),
    /// Inflight packets out of valid range
    InvalidInflight(u32),
    /// Buffer occupancy out of valid range [0, 1]
    InvalidBufferOccupancy(f32),
    /// Inter-packet gap out of valid range
    InvalidIpg(u64),
    /// Future loss out of valid range
    InvalidFutureLoss(f32),
    /// Timestamp is in the future or too old
    InvalidTimestamp(u64),
    /// DRL state values out of valid range
    InvalidDrlState(String),
    /// DRL action out of valid range [0, 5]
    InvalidDrlAction(usize),
    /// DRL reward magnitude too large
    InvalidDrlReward(f32),
    /// Inconsistent data (e.g., RTT variance > RTT)
    InconsistentData(String),
    /// Detected synthetic/malicious pattern
    SyntheticPattern(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidRtt(v) => write!(f, "Invalid RTT: {}µs", v),
            ValidationError::InvalidRttVar(v) => write!(f, "Invalid RTT variance: {}µs", v),
            ValidationError::InvalidBandwidth(v) => write!(f, "Invalid bandwidth: {} bps", v),
            ValidationError::InvalidLossRate(v) => write!(f, "Invalid loss rate: {}", v),
            ValidationError::InvalidInflight(v) => write!(f, "Invalid inflight: {}", v),
            ValidationError::InvalidBufferOccupancy(v) => {
                write!(f, "Invalid buffer occupancy: {}", v)
            }
            ValidationError::InvalidIpg(v) => write!(f, "Invalid IPG: {}µs", v),
            ValidationError::InvalidFutureLoss(v) => write!(f, "Invalid future loss: {}", v),
            ValidationError::InvalidTimestamp(v) => write!(f, "Invalid timestamp: {}ms", v),
            ValidationError::InvalidDrlState(s) => write!(f, "Invalid DRL state: {}", s),
            ValidationError::InvalidDrlAction(v) => write!(f, "Invalid DRL action: {}", v),
            ValidationError::InvalidDrlReward(v) => write!(f, "Invalid DRL reward: {}", v),
            ValidationError::InconsistentData(s) => write!(f, "Inconsistent data: {}", s),
            ValidationError::SyntheticPattern(s) => write!(f, "Synthetic pattern detected: {}", s),
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// DATA QUALITY VALIDATOR
// ============================================================================

/// Data quality validator with DDoS detection
pub struct DataQualityValidator {
    /// Track recent samples for anomaly detection
    recent_samples: Vec<(Instant, LossSampleFingerprint)>,
    /// Maximum age for recent samples
    sample_window: Duration,
    /// Maximum samples to track
    max_tracked_samples: usize,
}

/// Fingerprint of a LossSample for duplicate/pattern detection
#[derive(Debug, Clone, PartialEq)]
struct LossSampleFingerprint {
    rtt_bucket: u8,       // RTT in 10ms buckets
    loss_bucket: u8,      // Loss rate in 1% buckets
    bandwidth_bucket: u8, // Bandwidth in 10Mbps buckets
}

impl DataQualityValidator {
    pub fn new() -> Self {
        Self {
            recent_samples: Vec::with_capacity(1000),
            sample_window: Duration::from_secs(60),
            max_tracked_samples: 1000,
        }
    }

    /// Validate a LossSample before adding to training buffers
    pub fn validate_loss_sample(&mut self, sample: &LossSample) -> Result<(), ValidationError> {
        // 1. Range validation
        self.validate_loss_sample_ranges(sample)?;

        // 2. Consistency validation
        self.validate_loss_sample_consistency(sample)?;

        // 3. Timestamp validation
        self.validate_timestamp(sample.timestamp_ms)?;

        // 4. Anomaly detection (DDoS patterns)
        self.detect_loss_sample_anomalies(sample)?;

        // 5. Track this sample
        self.track_loss_sample(sample);

        Ok(())
    }

    /// Validate a DrlExperience before adding to training buffers
    pub fn validate_drl_experience(&self, exp: &DrlExperience) -> Result<(), ValidationError> {
        // 1. Validate state
        self.validate_drl_state(&exp.state, "state")?;
        self.validate_drl_state(&exp.next_state, "next_state")?;

        // 2. Validate action
        if exp.action > 5 {
            return Err(ValidationError::InvalidDrlAction(exp.action));
        }

        // 3. Validate reward
        if exp.reward.total.abs() > MAX_REWARD {
            return Err(ValidationError::InvalidDrlReward(exp.reward.total));
        }

        // 4. Consistency checks
        let total_reward =
            exp.reward.throughput_reward + exp.reward.latency_penalty + exp.reward.loss_penalty;
        if (total_reward - exp.reward.total).abs() > 0.1 {
            return Err(ValidationError::InconsistentData(format!(
                "Reward components don't sum to total: {} vs {}",
                total_reward, exp.reward.total
            )));
        }

        Ok(())
    }

    // =========================================================================
    // PRIVATE VALIDATION METHODS
    // =========================================================================

    fn validate_loss_sample_ranges(&self, sample: &LossSample) -> Result<(), ValidationError> {
        // RTT validation
        if sample.rtt_us < MIN_RTT_US || sample.rtt_us > MAX_RTT_US {
            return Err(ValidationError::InvalidRtt(sample.rtt_us));
        }

        // RTT variance validation
        if sample.rtt_var_us > MAX_RTT_VAR_US {
            return Err(ValidationError::InvalidRttVar(sample.rtt_var_us));
        }

        // Bandwidth validation
        if sample.bandwidth_bps < MIN_BANDWIDTH_BPS || sample.bandwidth_bps > MAX_BANDWIDTH_BPS {
            return Err(ValidationError::InvalidBandwidth(sample.bandwidth_bps));
        }

        // Loss rate validation
        if sample.loss_rate < 0.0 || sample.loss_rate > MAX_LOSS_RATE {
            return Err(ValidationError::InvalidLossRate(sample.loss_rate));
        }

        // Future loss validation
        if sample.future_loss < 0.0 || sample.future_loss > MAX_LOSS_RATE {
            return Err(ValidationError::InvalidFutureLoss(sample.future_loss));
        }

        // Inflight validation
        if sample.inflight > MAX_INFLIGHT {
            return Err(ValidationError::InvalidInflight(sample.inflight));
        }

        // Buffer occupancy validation
        if sample.buffer_occupancy < 0.0 || sample.buffer_occupancy > MAX_BUFFER_OCCUPANCY {
            return Err(ValidationError::InvalidBufferOccupancy(
                sample.buffer_occupancy,
            ));
        }

        // IPG validation
        if sample.ipg_us > MAX_IPG_US {
            return Err(ValidationError::InvalidIpg(sample.ipg_us));
        }

        Ok(())
    }

    fn validate_loss_sample_consistency(&self, sample: &LossSample) -> Result<(), ValidationError> {
        // RTT variance should not exceed RTT
        if sample.rtt_var_us > sample.rtt_us {
            return Err(ValidationError::InconsistentData(format!(
                "RTT variance ({}µs) exceeds RTT ({}µs)",
                sample.rtt_var_us, sample.rtt_us
            )));
        }

        // Future loss should be correlated with current loss (within reason)
        let loss_diff = (sample.future_loss - sample.loss_rate).abs();
        if loss_diff > 0.5 {
            return Err(ValidationError::InconsistentData(format!(
                "Future loss ({}) too different from current loss ({})",
                sample.future_loss, sample.loss_rate
            )));
        }

        // High loss should correlate with high RTT variance (usually)
        if sample.loss_rate > 0.2 && sample.rtt_var_us < 1000 {
            // This could be legitimate, but suspicious
            // Allow it but could be flagged in production
        }

        Ok(())
    }

    fn validate_timestamp(&self, timestamp_ms: u64) -> Result<(), ValidationError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Reject timestamps in the future
        if timestamp_ms > now_ms + 60_000 {
            // Allow 60s clock skew
            return Err(ValidationError::InvalidTimestamp(timestamp_ms));
        }

        // Reject timestamps older than 24 hours
        if now_ms > timestamp_ms && (now_ms - timestamp_ms) > 86_400_000 {
            return Err(ValidationError::InvalidTimestamp(timestamp_ms));
        }

        Ok(())
    }

    fn detect_loss_sample_anomalies(&self, sample: &LossSample) -> Result<(), ValidationError> {
        let fingerprint = LossSampleFingerprint {
            rtt_bucket: (sample.rtt_us / 10_000).min(255) as u8,
            loss_bucket: (sample.loss_rate * 100.0).min(255.0) as u8,
            bandwidth_bucket: (sample.bandwidth_bps / 10_000_000).min(255) as u8,
        };

        // Count identical fingerprints in recent window
        let cutoff = Instant::now() - self.sample_window;
        let identical_count = self
            .recent_samples
            .iter()
            .filter(|(ts, fp)| ts > &cutoff && fp == &fingerprint)
            .count();

        // If we see too many identical samples, it's likely synthetic/malicious
        if identical_count > 50 {
            return Err(ValidationError::SyntheticPattern(format!(
                "Too many identical samples: {} in last 60s",
                identical_count
            )));
        }

        // Detect all-zeros pattern (common in DDoS)
        // Note: This check happens after range validation, so if we get here
        // with rtt_us=0 or bandwidth_bps=0, it already failed range checks
        if sample.loss_rate == 0.0
            && sample.future_loss == 0.0
            && sample.buffer_occupancy == 0.0
            && sample.inflight == 0
        {
            return Err(ValidationError::SyntheticPattern(
                "All-zeros pattern detected".to_string(),
            ));
        }

        // Detect suspiciously perfect values (multiples of 1000, etc.)
        if sample.rtt_us.is_multiple_of(1000)
            && sample.rtt_var_us.is_multiple_of(1000)
            && sample.bandwidth_bps.is_multiple_of(1_000_000)
        {
            // Could be legitimate, but suspicious
            // In production, might want to flag this
        }

        Ok(())
    }

    fn validate_drl_state(&self, state: &DrlState, name: &str) -> Result<(), ValidationError> {
        // All normalized values should be in [0, 1] or [-1, 1] for gradients
        if state.rtt_norm < 0.0 || state.rtt_norm > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.rtt_norm out of range: {}",
                name, state.rtt_norm
            )));
        }

        if state.rtt_gradient < -1.0 || state.rtt_gradient > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.rtt_gradient out of range: {}",
                name, state.rtt_gradient
            )));
        }

        if state.throughput_norm < 0.0 || state.throughput_norm > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.throughput_norm out of range: {}",
                name, state.throughput_norm
            )));
        }

        if state.loss_rate < 0.0 || state.loss_rate > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.loss_rate out of range: {}",
                name, state.loss_rate
            )));
        }

        if state.cwnd_norm < 0.0 || state.cwnd_norm > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.cwnd_norm out of range: {}",
                name, state.cwnd_norm
            )));
        }

        if state.inflight_norm < 0.0 || state.inflight_norm > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.inflight_norm out of range: {}",
                name, state.inflight_norm
            )));
        }

        if state.buffer_occupancy < 0.0 || state.buffer_occupancy > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.buffer_occupancy out of range: {}",
                name, state.buffer_occupancy
            )));
        }

        if state.time_in_state < 0.0 || state.time_in_state > 1.0 {
            return Err(ValidationError::InvalidDrlState(format!(
                "{}.time_in_state out of range: {}",
                name, state.time_in_state
            )));
        }

        Ok(())
    }

    fn track_loss_sample(&mut self, sample: &LossSample) {
        let fingerprint = LossSampleFingerprint {
            rtt_bucket: (sample.rtt_us / 10_000).min(255) as u8,
            loss_bucket: (sample.loss_rate * 100.0).min(255.0) as u8,
            bandwidth_bucket: (sample.bandwidth_bps / 10_000_000).min(255) as u8,
        };

        self.recent_samples.push((Instant::now(), fingerprint));

        // Prune old samples
        let cutoff = Instant::now() - self.sample_window;
        self.recent_samples.retain(|(ts, _)| ts > &cutoff);

        // Limit size
        if self.recent_samples.len() > self.max_tracked_samples {
            self.recent_samples
                .drain(0..(self.recent_samples.len() - self.max_tracked_samples));
        }
    }

    /// Clear tracking history (useful for testing)
    pub fn clear_history(&mut self) {
        self.recent_samples.clear();
    }

    /// Get statistics about recent validation
    pub fn stats(&self) -> ValidationStats {
        let cutoff = Instant::now() - self.sample_window;
        let recent_count = self
            .recent_samples
            .iter()
            .filter(|(ts, _)| ts > &cutoff)
            .count();

        ValidationStats {
            tracked_samples: recent_count,
            window_seconds: self.sample_window.as_secs(),
        }
    }
}

impl Default for DataQualityValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub tracked_samples: usize,
    pub window_seconds: u64,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_optimized::{DrlReward, DrlState};

    fn valid_loss_sample() -> LossSample {
        LossSample {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            rtt_us: 50_000,
            rtt_var_us: 5_000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.01,
            inflight: 100,
            buffer_occupancy: 0.5,
            ipg_us: 1000,
            future_loss: 0.02,
        }
    }

    fn valid_drl_experience() -> DrlExperience {
        DrlExperience {
            state: DrlState {
                rtt_norm: 0.5,
                rtt_gradient: 0.1,
                throughput_norm: 0.8,
                loss_rate: 0.01,
                cwnd_norm: 0.6,
                inflight_norm: 0.4,
                buffer_occupancy: 0.3,
                time_in_state: 0.5,
            },
            action: 2,
            reward: DrlReward {
                throughput_reward: 0.5,
                latency_penalty: -0.1,
                loss_penalty: -0.05,
                total: 0.35,
            },
            next_state: DrlState {
                rtt_norm: 0.5,
                rtt_gradient: 0.0,
                throughput_norm: 0.85,
                loss_rate: 0.01,
                cwnd_norm: 0.65,
                inflight_norm: 0.45,
                buffer_occupancy: 0.3,
                time_in_state: 0.6,
            },
            done: false,
        }
    }

    #[test]
    fn test_valid_loss_sample() {
        let mut validator = DataQualityValidator::new();
        let sample = valid_loss_sample();
        assert!(validator.validate_loss_sample(&sample).is_ok());
    }

    #[test]
    fn test_invalid_rtt() {
        let mut validator = DataQualityValidator::new();
        let mut sample = valid_loss_sample();
        sample.rtt_us = MAX_RTT_US + 1;
        assert!(matches!(
            validator.validate_loss_sample(&sample),
            Err(ValidationError::InvalidRtt(_))
        ));
    }

    #[test]
    fn test_invalid_loss_rate() {
        let mut validator = DataQualityValidator::new();
        let mut sample = valid_loss_sample();
        sample.loss_rate = 1.5;
        assert!(matches!(
            validator.validate_loss_sample(&sample),
            Err(ValidationError::InvalidLossRate(_))
        ));
    }

    #[test]
    fn test_inconsistent_rtt_variance() {
        let mut validator = DataQualityValidator::new();
        let mut sample = valid_loss_sample();
        sample.rtt_var_us = sample.rtt_us + 1000;
        assert!(matches!(
            validator.validate_loss_sample(&sample),
            Err(ValidationError::InconsistentData(_))
        ));
    }

    #[test]
    fn test_synthetic_pattern_detection() {
        let mut validator = DataQualityValidator::new();
        let sample = valid_loss_sample();

        // Add same sample 51 times
        for _ in 0..51 {
            let _ = validator.validate_loss_sample(&sample);
        }

        // 52nd should be rejected
        assert!(matches!(
            validator.validate_loss_sample(&sample),
            Err(ValidationError::SyntheticPattern(_))
        ));
    }

    #[test]
    fn test_valid_drl_experience() {
        let validator = DataQualityValidator::new();
        let exp = valid_drl_experience();
        assert!(validator.validate_drl_experience(&exp).is_ok());
    }

    #[test]
    fn test_invalid_drl_action() {
        let validator = DataQualityValidator::new();
        let mut exp = valid_drl_experience();
        exp.action = 10;
        assert!(matches!(
            validator.validate_drl_experience(&exp),
            Err(ValidationError::InvalidDrlAction(_))
        ));
    }

    #[test]
    fn test_invalid_drl_state() {
        let validator = DataQualityValidator::new();
        let mut exp = valid_drl_experience();
        exp.state.rtt_norm = 1.5;
        assert!(matches!(
            validator.validate_drl_experience(&exp),
            Err(ValidationError::InvalidDrlState(_))
        ));
    }

    #[test]
    fn test_all_zeros_pattern() {
        let mut validator = DataQualityValidator::new();
        let mut sample = valid_loss_sample();
        // Set multiple fields to zero to trigger all-zeros pattern
        sample.loss_rate = 0.0;
        sample.future_loss = 0.0;
        sample.buffer_occupancy = 0.0;
        sample.inflight = 0;
        assert!(matches!(
            validator.validate_loss_sample(&sample),
            Err(ValidationError::SyntheticPattern(_))
        ));
    }

    #[test]
    fn test_zero_rtt_rejected() {
        let mut validator = DataQualityValidator::new();
        let mut sample = valid_loss_sample();
        sample.rtt_us = 0;
        // Should fail range validation, not synthetic pattern
        assert!(matches!(
            validator.validate_loss_sample(&sample),
            Err(ValidationError::InvalidRtt(_))
        ));
    }
}
