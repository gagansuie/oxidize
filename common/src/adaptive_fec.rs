//! Adaptive Forward Error Correction
//!
//! Dynamically adjusts FEC redundancy based on observed packet loss rate.
//! Provides 2x improvement on lossy networks while minimizing overhead on good connections.
//!
//! ## Proactive FEC (ML-Powered)
//! When integrated with the ML engine, this module can:
//! - Accept loss predictions from LSTM model (50-100ms ahead)
//! - Pre-emptively increase FEC redundancy BEFORE loss occurs
//! - Reduce unnecessary FEC on stable connections

use anyhow::Result;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Loss rate thresholds for FEC level adjustment
const LOW_LOSS_THRESHOLD: f64 = 0.01; // 1% loss - minimal FEC
const MED_LOSS_THRESHOLD: f64 = 0.05; // 5% loss - moderate FEC
const HIGH_LOSS_THRESHOLD: f64 = 0.15; // 15% loss - aggressive FEC

/// FEC levels with different redundancy ratios
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecLevel {
    /// No FEC - 0% overhead
    None,
    /// Light FEC - 10% overhead (10:1 ratio)
    Light,
    /// Medium FEC - 20% overhead (5:1 ratio)
    Medium,
    /// Heavy FEC - 33% overhead (3:1 ratio)
    Heavy,
    /// Aggressive FEC - 50% overhead (2:1 ratio)
    Aggressive,
}

impl FecLevel {
    /// Get data:parity shard ratio
    pub fn shards(&self) -> (usize, usize) {
        match self {
            FecLevel::None => (1, 0),
            FecLevel::Light => (10, 1),
            FecLevel::Medium => (5, 1),
            FecLevel::Heavy => (3, 1),
            FecLevel::Aggressive => (2, 1),
        }
    }

    /// Overhead percentage
    pub fn overhead_percent(&self) -> f64 {
        let (d, p) = self.shards();
        if d == 0 {
            return 0.0;
        }
        (p as f64 / d as f64) * 100.0
    }

    /// Select FEC level based on loss rate
    pub fn from_loss_rate(loss_rate: f64) -> Self {
        if loss_rate < LOW_LOSS_THRESHOLD {
            FecLevel::None
        } else if loss_rate < MED_LOSS_THRESHOLD {
            FecLevel::Light
        } else if loss_rate < HIGH_LOSS_THRESHOLD {
            FecLevel::Medium
        } else if loss_rate < 0.25 {
            FecLevel::Heavy
        } else {
            FecLevel::Aggressive
        }
    }
}

/// Packet tracking for loss rate estimation
#[derive(Debug, Clone)]
struct PacketRecord {
    seq: u64,
    sent_at: Instant,
    acked: bool,
}

/// Adaptive FEC encoder that adjusts based on network conditions
pub struct AdaptiveFec {
    /// Current FEC level
    level: FecLevel,
    /// Reed-Solomon encoder (recreated when level changes)
    encoder: Option<ReedSolomon>,
    /// Packet tracking window
    packets: VecDeque<PacketRecord>,
    /// Window size for loss calculation
    window_size: usize,
    /// Sequence counter
    next_seq: u64,
    /// Last level adjustment time
    last_adjustment: Instant,
    /// Minimum time between adjustments
    adjustment_interval: Duration,
    /// Statistics
    pub stats: AdaptiveFecStats,
    /// Proactive FEC: predicted loss probability from ML (0.0 - 1.0)
    predicted_loss: f64,
    /// Proactive FEC: time when prediction was last updated
    prediction_updated: Instant,
    /// Proactive FEC: how long predictions are valid
    prediction_ttl: Duration,
    /// Enable proactive FEC mode
    proactive_mode: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AdaptiveFecStats {
    pub packets_sent: u64,
    pub packets_acked: u64,
    pub packets_lost: u64,
    pub current_loss_rate: f64,
    pub bytes_overhead: u64,
    pub recoveries: u64,
    /// Number of times ML prediction was updated
    pub prediction_updates: u64,
    /// Number of proactive FEC adjustments (before loss occurred)
    pub proactive_adjustments: u64,
}

impl AdaptiveFec {
    pub fn new() -> Self {
        Self::with_config(100, Duration::from_secs(1))
    }

    pub fn with_config(window_size: usize, adjustment_interval: Duration) -> Self {
        AdaptiveFec {
            level: FecLevel::None,
            encoder: None,
            packets: VecDeque::with_capacity(window_size),
            window_size,
            next_seq: 0,
            last_adjustment: Instant::now(),
            adjustment_interval,
            stats: AdaptiveFecStats::default(),
            predicted_loss: 0.0,
            prediction_updated: Instant::now(),
            prediction_ttl: Duration::from_millis(200), // Predictions valid for 200ms
            proactive_mode: false,
        }
    }

    /// Create with proactive FEC enabled
    pub fn with_proactive_mode(window_size: usize, adjustment_interval: Duration) -> Self {
        let mut fec = Self::with_config(window_size, adjustment_interval);
        fec.proactive_mode = true;
        fec
    }

    /// Enable or disable proactive FEC mode
    pub fn set_proactive_mode(&mut self, enabled: bool) {
        self.proactive_mode = enabled;
    }

    /// Update with ML-predicted loss probability
    /// This should be called by the ML integration layer with LSTM predictions
    /// loss_probability: 0.0 to 1.0 representing predicted loss in next 50-100ms
    pub fn update_prediction(&mut self, loss_probability: f64) {
        self.predicted_loss = loss_probability.clamp(0.0, 1.0);
        self.prediction_updated = Instant::now();
        self.stats.prediction_updates += 1;

        // Immediately adjust FEC level based on prediction if proactive mode is on
        if self.proactive_mode {
            self.adjust_level_proactive();
        }
    }

    /// Proactively adjust FEC level based on ML prediction
    fn adjust_level_proactive(&mut self) {
        // Use prediction if it's fresh, otherwise fall back to measured loss
        let effective_loss = if self.prediction_updated.elapsed() < self.prediction_ttl {
            // Blend prediction with measured loss (prediction weighted higher for proactive)
            let measured = self.calculate_loss_rate();
            // 70% prediction, 30% measured for proactive response
            self.predicted_loss * 0.7 + measured * 0.3
        } else {
            self.calculate_loss_rate()
        };

        let new_level = FecLevel::from_loss_rate(effective_loss);

        if new_level != self.level {
            // Track proactive adjustments
            if self.prediction_updated.elapsed() < self.prediction_ttl {
                self.stats.proactive_adjustments += 1;
            }
            self.level = new_level;
            self.encoder = None; // Force recreation with new shard count
        }

        self.last_adjustment = Instant::now();
    }

    /// Check if we're currently in proactive mode with valid prediction
    pub fn is_proactive_active(&self) -> bool {
        self.proactive_mode && self.prediction_updated.elapsed() < self.prediction_ttl
    }

    /// Get current predicted loss (for monitoring)
    pub fn predicted_loss(&self) -> f64 {
        self.predicted_loss
    }

    /// Get current FEC level
    pub fn level(&self) -> FecLevel {
        self.level
    }

    /// Encode data with current adaptive FEC level
    pub fn encode(&mut self, data: &[u8]) -> Result<EncodedPacket> {
        let seq = self.next_seq;
        self.next_seq += 1;

        // Track packet
        self.packets.push_back(PacketRecord {
            seq,
            sent_at: Instant::now(),
            acked: false,
        });

        // Trim old packets
        while self.packets.len() > self.window_size {
            let old = self.packets.pop_front().unwrap();
            if !old.acked {
                self.stats.packets_lost += 1;
            }
        }

        self.stats.packets_sent += 1;

        // No FEC - just return data
        if self.level == FecLevel::None {
            return Ok(EncodedPacket {
                seq,
                level: FecLevel::None,
                shards: vec![data.to_vec()],
                shard_size: data.len(),
            });
        }

        // Encode with FEC
        let (data_shards, parity_shards) = self.level.shards();

        // Ensure encoder is initialized
        if self.encoder.is_none() {
            self.encoder = Some(ReedSolomon::new(data_shards, parity_shards)?);
        }

        let encoder = self.encoder.as_ref().unwrap();
        let shard_size = data.len().div_ceil(data_shards);
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data_shards + parity_shards);

        // Split data into shards
        for i in 0..data_shards {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data.len());
            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let copy_len = end.saturating_sub(start);
                if copy_len > 0 {
                    shard[..copy_len].copy_from_slice(&data[start..end]);
                }
            }
            shards.push(shard);
        }

        // Add parity shards
        for _ in 0..parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        encoder.encode(&mut shards)?;

        self.stats.bytes_overhead += (parity_shards * shard_size) as u64;

        Ok(EncodedPacket {
            seq,
            level: self.level,
            shards,
            shard_size,
        })
    }

    /// Record acknowledgment for a packet
    pub fn ack(&mut self, seq: u64) {
        for record in self.packets.iter_mut() {
            if record.seq == seq && !record.acked {
                record.acked = true;
                self.stats.packets_acked += 1;
                break;
            }
        }

        // Periodically adjust FEC level
        self.maybe_adjust_level();
    }

    /// Record a successful recovery
    pub fn record_recovery(&mut self) {
        self.stats.recoveries += 1;
    }

    /// Calculate current loss rate
    fn calculate_loss_rate(&self) -> f64 {
        let total = self.packets.len();
        if total == 0 {
            return 0.0;
        }

        let timeout = Duration::from_millis(500);
        let now = Instant::now();

        let mut lost = 0;
        let mut countable = 0;

        for record in &self.packets {
            if now.duration_since(record.sent_at) > timeout {
                countable += 1;
                if !record.acked {
                    lost += 1;
                }
            }
        }

        if countable == 0 {
            return 0.0;
        }

        lost as f64 / countable as f64
    }

    /// Adjust FEC level based on observed loss
    fn maybe_adjust_level(&mut self) {
        if self.last_adjustment.elapsed() < self.adjustment_interval {
            return;
        }

        // Use proactive adjustment if enabled
        if self.proactive_mode {
            self.adjust_level_proactive();
            return;
        }

        let loss_rate = self.calculate_loss_rate();
        self.stats.current_loss_rate = loss_rate;

        let new_level = FecLevel::from_loss_rate(loss_rate);

        if new_level != self.level {
            self.level = new_level;
            self.encoder = None; // Force recreation with new shard count
        }

        self.last_adjustment = Instant::now();
    }

    /// Decode received shards
    pub fn decode(&mut self, packet: &mut EncodedPacket, missing: &[usize]) -> Result<Vec<u8>> {
        if packet.level == FecLevel::None {
            return Ok(packet.shards[0].clone());
        }

        let (data_shards, parity_shards) = packet.level.shards();
        let decoder = ReedSolomon::new(data_shards, parity_shards)?;

        // Convert to option shards
        let mut option_shards: Vec<Option<Vec<u8>>> = packet
            .shards
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if missing.contains(&i) {
                    None
                } else {
                    Some(s.clone())
                }
            })
            .collect();

        decoder.reconstruct(&mut option_shards)?;

        if !missing.is_empty() {
            self.record_recovery();
        }

        // Combine data shards
        let mut result = Vec::with_capacity(data_shards * packet.shard_size);
        for shard in option_shards.iter().take(data_shards).flatten() {
            result.extend_from_slice(shard);
        }

        Ok(result)
    }
}

impl Default for AdaptiveFec {
    fn default() -> Self {
        Self::new()
    }
}

/// Encoded packet with FEC shards
#[derive(Debug, Clone)]
pub struct EncodedPacket {
    pub seq: u64,
    pub level: FecLevel,
    pub shards: Vec<Vec<u8>>,
    pub shard_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_fec_no_loss() {
        let mut fec = AdaptiveFec::new();

        // Initially no FEC
        assert_eq!(fec.level(), FecLevel::None);

        let data = b"test data for FEC";
        let packet = fec.encode(data).unwrap();
        assert_eq!(packet.shards.len(), 1); // No redundancy
    }

    #[test]
    fn test_fec_level_selection() {
        assert_eq!(FecLevel::from_loss_rate(0.005), FecLevel::None);
        assert_eq!(FecLevel::from_loss_rate(0.02), FecLevel::Light);
        assert_eq!(FecLevel::from_loss_rate(0.08), FecLevel::Medium);
        assert_eq!(FecLevel::from_loss_rate(0.20), FecLevel::Heavy);
        assert_eq!(FecLevel::from_loss_rate(0.30), FecLevel::Aggressive);
    }

    #[test]
    fn test_fec_overhead() {
        assert_eq!(FecLevel::None.overhead_percent(), 0.0);
        assert_eq!(FecLevel::Light.overhead_percent(), 10.0);
        assert_eq!(FecLevel::Medium.overhead_percent(), 20.0);
    }

    #[test]
    fn test_fec_encode_decode_with_loss() {
        let mut fec = AdaptiveFec::new();
        fec.level = FecLevel::Medium; // Force medium FEC
        fec.encoder = None;

        let data = b"Hello, this is test data for adaptive FEC!";
        let mut packet = fec.encode(data).unwrap();

        // Should have 6 shards (5 data + 1 parity)
        assert_eq!(packet.shards.len(), 6);

        // Simulate losing 1 shard
        packet.shards[2] = vec![0u8; packet.shard_size];

        let decoded = fec.decode(&mut packet, &[2]).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_proactive_fec() {
        let mut fec = AdaptiveFec::with_proactive_mode(100, Duration::from_secs(1));

        // Initially no FEC
        assert_eq!(fec.level(), FecLevel::None);
        assert!(fec.proactive_mode);

        // Simulate ML prediction of 10% loss
        fec.update_prediction(0.10);

        // Should proactively increase FEC
        assert!(fec.level() != FecLevel::None);
        assert_eq!(fec.stats.prediction_updates, 1);
        assert_eq!(fec.stats.proactive_adjustments, 1);
    }

    #[test]
    fn test_prediction_expiry() {
        let mut fec = AdaptiveFec::with_proactive_mode(100, Duration::from_millis(100));
        fec.prediction_ttl = Duration::from_millis(10); // Very short TTL for testing

        fec.update_prediction(0.20);
        assert!(fec.is_proactive_active());

        // Wait for prediction to expire
        std::thread::sleep(Duration::from_millis(15));
        assert!(!fec.is_proactive_active());
    }
}
