//! AI-Ready Heuristic Engine
//!
//! A trait-based decision engine that uses heuristics today but can be
//! replaced with trained ML models (ONNX, tract, etc.) in the future.
//!
//! Covers four AI pillars:
//! 1. **Loss Prediction (DeepRS)** - Predict packet loss to proactively inject FEC
//! 2. **Congestion Control (DRL-CC)** - Adaptive cwnd based on network state
//! 3. **Spectral Steering** - Context-aware band/path selection
//! 4. **Smart Compression** - Skip compression for already-compressed/encrypted data

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ============================================================================
// FEATURE EXTRACTION - Data structures that ML models would consume
// ============================================================================

/// Network state features for ML models
/// These are the inputs an LSTM or DRL agent would need
#[derive(Debug, Clone, Default)]
pub struct NetworkFeatures {
    /// Round-trip time in microseconds (smoothed)
    pub rtt_us: u64,
    /// RTT variance (jitter indicator)
    pub rtt_var_us: u64,
    /// Estimated bandwidth in bytes/sec
    pub bandwidth_bps: u64,
    /// Current packet loss rate (0.0 - 1.0)
    pub loss_rate: f32,
    /// Loss rate trend (positive = increasing loss)
    pub loss_trend: f32,
    /// Packets in flight
    pub inflight: u32,
    /// Current congestion window size
    pub cwnd: u32,
    /// Time since last loss event (ms)
    pub time_since_loss_ms: u64,
    /// Receive buffer occupancy (0.0 - 1.0)
    pub buffer_occupancy: f32,
    /// Recent retransmission count
    pub recent_retx: u32,
}

impl NetworkFeatures {
    /// Convert to feature vector for ML inference
    /// Normalized to [0, 1] range for neural networks
    pub fn to_feature_vec(&self) -> [f32; 12] {
        [
            (self.rtt_us as f32 / 500_000.0).min(1.0), // Normalize to 500ms max
            (self.rtt_var_us as f32 / 100_000.0).min(1.0), // Normalize to 100ms max
            (self.bandwidth_bps as f32 / 1e9).min(1.0), // Normalize to 1Gbps
            self.loss_rate,
            (self.loss_trend + 1.0) / 2.0, // Map [-1, 1] to [0, 1]
            (self.inflight as f32 / 1000.0).min(1.0), // Normalize to 1000 packets
            (self.cwnd as f32 / 65535.0).min(1.0), // Normalize to 64KB
            (self.time_since_loss_ms as f32 / 10_000.0).min(1.0), // Normalize to 10s
            self.buffer_occupancy,
            (self.recent_retx as f32 / 100.0).min(1.0), // Normalize to 100 retx
            0.0,                                        // Reserved for future features
            0.0,                                        // Reserved for future features
        ]
    }
}

/// Packet features for compression/classification decisions
#[derive(Debug, Clone)]
pub struct PacketFeatures {
    /// Packet size in bytes
    pub size: usize,
    /// IP protocol (6=TCP, 17=UDP, etc.)
    pub ip_protocol: u8,
    /// Destination port
    pub dst_port: u16,
    /// Source port
    pub src_port: u16,
    /// First 16 bytes of payload (for content detection)
    pub header_sample: [u8; 16],
    /// Entropy estimate of payload (0.0 = uniform, 1.0 = random/encrypted)
    pub entropy: f32,
    /// Is this a known encrypted protocol?
    pub is_encrypted: bool,
    /// Packet inter-arrival time (microseconds)
    pub iat_us: u64,
}

impl PacketFeatures {
    /// Extract features from raw packet data
    pub fn extract(data: &[u8], src_port: u16, dst_port: u16, ip_protocol: u8) -> Self {
        let mut header_sample = [0u8; 16];
        let copy_len = data.len().min(16);
        header_sample[..copy_len].copy_from_slice(&data[..copy_len]);

        let entropy = Self::calculate_entropy(data);
        let is_encrypted = Self::detect_encrypted(data, dst_port);

        PacketFeatures {
            size: data.len(),
            ip_protocol,
            dst_port,
            src_port,
            header_sample,
            entropy,
            is_encrypted,
            iat_us: 0, // Set by caller with timing info
        }
    }

    /// Calculate Shannon entropy (0.0 - 1.0)
    /// High entropy suggests encrypted/compressed data
    fn calculate_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        // Sample for performance (max 1KB)
        let sample_size = data.len().min(1024);
        let sample = &data[..sample_size];

        let mut freq = [0u32; 256];
        for &byte in sample {
            freq[byte as usize] += 1;
        }

        let len = sample_size as f32;
        let mut entropy = 0.0f32;

        for &count in &freq {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        // Normalize to [0, 1] (max entropy is 8 bits)
        entropy / 8.0
    }

    /// Detect if payload is likely encrypted/compressed
    fn detect_encrypted(data: &[u8], dst_port: u16) -> bool {
        if data.len() < 4 {
            return false;
        }

        // TLS record
        if data[0] == 0x17 && data[1] == 0x03 {
            return true;
        }

        // HTTPS port with high entropy
        if dst_port == 443 && Self::calculate_entropy(data) > 0.9 {
            return true;
        }

        // Known encrypted protocols by port
        matches!(dst_port, 443 | 993 | 995 | 465 | 587 | 22)
    }

    /// Convert to feature vector for ML classifier
    pub fn to_feature_vec(&self) -> [f32; 24] {
        let mut features = [0.0f32; 24];

        features[0] = (self.size as f32 / 65535.0).min(1.0);
        features[1] = self.ip_protocol as f32 / 255.0;
        features[2] = self.dst_port as f32 / 65535.0;
        features[3] = self.src_port as f32 / 65535.0;
        features[4] = self.entropy;
        features[5] = if self.is_encrypted { 1.0 } else { 0.0 };
        features[6] = (self.iat_us as f32 / 1_000_000.0).min(1.0);

        // Header bytes as features (normalized)
        for (i, &byte) in self.header_sample.iter().enumerate() {
            features[7 + i] = byte as f32 / 255.0;
        }

        features
    }
}

// ============================================================================
// DECISION TRAITS - Swap heuristics for ML models
// ============================================================================

/// Compression decision output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDecision {
    /// Don't compress - already compressed/encrypted or too small
    Skip,
    /// Light compression (fast, low ratio)
    Light,
    /// Aggressive compression (slower, high ratio)
    Aggressive,
}

/// Trait for compression decision making
/// Implement with ML model for AI-enhanced version
pub trait CompressionOracle: Send + Sync {
    /// Decide whether and how to compress a packet
    fn should_compress(&self, features: &PacketFeatures) -> CompressionDecision;
}

/// FEC injection decision
#[derive(Debug, Clone, Copy)]
pub struct FecDecision {
    /// Probability of loss in next window (0.0 - 1.0)
    pub loss_probability: f32,
    /// Recommended FEC redundancy ratio (0.0 = none, 0.5 = 50% overhead)
    pub redundancy_ratio: f32,
    /// Should proactively inject FEC now?
    pub inject_fec: bool,
}

/// Trait for packet loss prediction
/// Replace with LSTM for AI-enhanced version
pub trait LossPredictor: Send + Sync {
    /// Predict packet loss probability
    fn predict(&self, features: &NetworkFeatures, history: &[f32]) -> FecDecision;
}

/// Congestion control action
#[derive(Debug, Clone, Copy)]
pub struct CongestionAction {
    /// New congestion window size (bytes)
    pub new_cwnd: u32,
    /// Pacing rate (bytes/sec)
    pub pacing_rate: u64,
    /// Should enter slow start?
    pub slow_start: bool,
}

/// Trait for congestion control decisions
/// Replace with DRL agent for AI-enhanced version
pub trait CongestionController: Send + Sync {
    /// Decide congestion window adjustment
    fn decide(&self, features: &NetworkFeatures) -> CongestionAction;
}

/// Path/band selection decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDecision {
    /// Primary path (e.g., 5GHz WiFi, main tunnel)
    Primary,
    /// Secondary path (e.g., 2.4GHz WiFi, backup tunnel)
    Secondary,
    /// Tertiary path (e.g., 6GHz WiFi, LTE backup)
    Tertiary,
    /// Multipath - use all available
    Multipath,
}

/// Trait for path selection
/// Replace with Multi-Armed Bandit or DRL for AI-enhanced version
pub trait PathSelector: Send + Sync {
    /// Select optimal path for traffic type
    fn select(&self, features: &NetworkFeatures, traffic_class: TrafficType) -> PathDecision;
}

/// Traffic type for path selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficType {
    /// Gaming - ultra-low latency
    Gaming,
    /// VoIP - low latency, jitter sensitive
    VoIP,
    /// Video streaming - high bandwidth, tolerates latency
    Streaming,
    /// Bulk download - throughput priority
    Bulk,
    /// General web - balanced
    Web,
}

// ============================================================================
// HEURISTIC IMPLEMENTATIONS - The "brains" before AI
// ============================================================================

/// Heuristic-based compression oracle
/// Uses entropy and content detection instead of ML
pub struct HeuristicCompressionOracle {
    /// Minimum size worth compressing
    min_size: usize,
    /// Entropy threshold above which we skip (likely encrypted/compressed)
    entropy_threshold: f32,
}

impl Default for HeuristicCompressionOracle {
    fn default() -> Self {
        Self {
            min_size: 128,
            entropy_threshold: 0.85,
        }
    }
}

impl HeuristicCompressionOracle {
    pub fn new(min_size: usize, entropy_threshold: f32) -> Self {
        Self {
            min_size,
            entropy_threshold,
        }
    }

    /// Check if content is already compressed based on magic bytes
    fn is_compressed_format(header: &[u8; 16]) -> bool {
        // JPEG
        if header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF {
            return true;
        }
        // PNG
        if header[0..4] == [0x89, 0x50, 0x4E, 0x47] {
            return true;
        }
        // GIF
        if header[0..3] == [0x47, 0x49, 0x46] {
            return true;
        }
        // GZIP
        if header[0] == 0x1F && header[1] == 0x8B {
            return true;
        }
        // ZLIB
        if header[0] == 0x78 && (header[1] == 0x9C || header[1] == 0xDA || header[1] == 0x01) {
            return true;
        }
        // ZIP/DOCX/XLSX
        if header[0..4] == [0x50, 0x4B, 0x03, 0x04] {
            return true;
        }
        // MP4/MOV
        if header[4..8] == [0x66, 0x74, 0x79, 0x70] {
            return true;
        }
        // WebM/MKV
        if header[0..4] == [0x1A, 0x45, 0xDF, 0xA3] {
            return true;
        }
        // MP3
        if header[0..2] == [0xFF, 0xFB] || header[0..3] == [0x49, 0x44, 0x33] {
            return true;
        }
        // Brotli
        if header[0] == 0xCE && header[1] == 0xB2 {
            return true;
        }
        // LZ4
        if header[0..4] == [0x04, 0x22, 0x4D, 0x18] {
            return true;
        }
        false
    }

    /// Check if content is likely text/JSON (compresses well)
    fn is_text_content(header: &[u8; 16]) -> bool {
        // JSON
        if header[0] == b'{' || header[0] == b'[' {
            return true;
        }
        // XML/HTML
        if header[0] == b'<' {
            return true;
        }
        // HTTP
        if header.starts_with(b"HTTP") || header.starts_with(b"GET ") || header.starts_with(b"POST")
        {
            return true;
        }
        // Check if mostly printable ASCII
        let printable_count = header.iter().filter(|&&b| b >= 0x20 && b < 0x7F).count();
        printable_count > 12
    }
}

impl CompressionOracle for HeuristicCompressionOracle {
    fn should_compress(&self, features: &PacketFeatures) -> CompressionDecision {
        // Too small to benefit
        if features.size < self.min_size {
            return CompressionDecision::Skip;
        }

        // Already encrypted - compression won't help
        if features.is_encrypted {
            return CompressionDecision::Skip;
        }

        // High entropy - likely already compressed or encrypted
        if features.entropy > self.entropy_threshold {
            return CompressionDecision::Skip;
        }

        // Check for known compressed formats
        if Self::is_compressed_format(&features.header_sample) {
            return CompressionDecision::Skip;
        }

        // Text content - compress aggressively
        if Self::is_text_content(&features.header_sample) {
            return CompressionDecision::Aggressive;
        }

        // Medium entropy - light compression
        if features.entropy > 0.6 {
            return CompressionDecision::Light;
        }

        // Low entropy - compress aggressively
        CompressionDecision::Aggressive
    }
}

/// Heuristic-based loss predictor
/// Uses exponential smoothing instead of LSTM
pub struct HeuristicLossPredictor {
    /// Loss history window
    history: VecDeque<f32>,
    /// Smoothing factor for EWMA
    alpha: f32,
    /// Threshold for FEC injection
    fec_threshold: f32,
}

impl Default for HeuristicLossPredictor {
    fn default() -> Self {
        Self {
            history: VecDeque::with_capacity(100),
            alpha: 0.3,
            fec_threshold: 0.02, // 2% loss triggers FEC
        }
    }
}

impl HeuristicLossPredictor {
    pub fn new(alpha: f32, fec_threshold: f32) -> Self {
        Self {
            history: VecDeque::with_capacity(100),
            alpha,
            fec_threshold,
        }
    }

    /// Record a new loss sample
    pub fn record_sample(&mut self, loss_rate: f32) {
        self.history.push_back(loss_rate);
        if self.history.len() > 100 {
            self.history.pop_front();
        }
    }

    /// Calculate exponentially weighted moving average
    fn ewma(&self) -> f32 {
        if self.history.is_empty() {
            return 0.0;
        }

        let mut ewma = self.history[0];
        for &sample in self.history.iter().skip(1) {
            ewma = self.alpha * sample + (1.0 - self.alpha) * ewma;
        }
        ewma
    }

    /// Detect trend (positive = increasing loss)
    fn trend(&self) -> f32 {
        if self.history.len() < 10 {
            return 0.0;
        }

        let recent: f32 = self.history.iter().rev().take(10).sum::<f32>() / 10.0;
        let older: f32 = self.history.iter().take(10).sum::<f32>() / 10.0;

        recent - older
    }
}

impl LossPredictor for HeuristicLossPredictor {
    fn predict(&self, features: &NetworkFeatures, _history: &[f32]) -> FecDecision {
        let ewma_loss = self.ewma();
        let trend = self.trend();

        // Combine current observation with history
        let predicted_loss = 0.5 * features.loss_rate + 0.5 * ewma_loss + 0.2 * trend.max(0.0);

        // High RTT variance often precedes loss
        let jitter_factor = if features.rtt_var_us > 50_000 {
            0.1
        } else {
            0.0
        };
        let adjusted_loss = (predicted_loss + jitter_factor).min(1.0);

        // Calculate redundancy based on predicted loss
        let redundancy_ratio = if adjusted_loss < 0.01 {
            0.0 // No FEC needed
        } else if adjusted_loss < 0.05 {
            0.1 // 10% redundancy
        } else if adjusted_loss < 0.15 {
            0.2 // 20% redundancy
        } else if adjusted_loss < 0.25 {
            0.33 // 33% redundancy
        } else {
            0.5 // 50% redundancy
        };

        FecDecision {
            loss_probability: adjusted_loss,
            redundancy_ratio,
            inject_fec: adjusted_loss > self.fec_threshold,
        }
    }
}

/// Heuristic-based congestion controller (BBR-like)
pub struct HeuristicCongestionController {
    /// Minimum RTT observed
    min_rtt_us: u64,
    /// Maximum bandwidth observed
    max_bw_bps: u64,
    /// Pacing gain
    pacing_gain: f32,
    /// CWND gain
    cwnd_gain: f32,
}

impl Default for HeuristicCongestionController {
    fn default() -> Self {
        Self {
            min_rtt_us: u64::MAX,
            max_bw_bps: 0,
            pacing_gain: 1.0,
            cwnd_gain: 2.0,
        }
    }
}

impl HeuristicCongestionController {
    /// Update estimates with new observation
    pub fn update(&mut self, rtt_us: u64, bandwidth_bps: u64) {
        self.min_rtt_us = self.min_rtt_us.min(rtt_us);
        self.max_bw_bps = self.max_bw_bps.max(bandwidth_bps);
    }
}

impl CongestionController for HeuristicCongestionController {
    fn decide(&self, features: &NetworkFeatures) -> CongestionAction {
        // BDP = bandwidth × RTT
        let bdp = if self.min_rtt_us > 0 && self.min_rtt_us < u64::MAX {
            (self.max_bw_bps as f64 * self.min_rtt_us as f64 / 1_000_000.0) as u32
        } else {
            features.cwnd
        };

        // Adjust based on loss
        let loss_factor = if features.loss_rate > 0.1 {
            0.5 // Halve on high loss
        } else if features.loss_rate > 0.01 {
            0.8 // Reduce slightly on loss
        } else {
            1.0 // No loss - maintain or grow
        };

        // Adjust based on buffer occupancy
        let buffer_factor = if features.buffer_occupancy > 0.8 {
            0.9 // Back off if buffer filling
        } else {
            1.0
        };

        let new_cwnd = ((bdp as f32 * self.cwnd_gain * loss_factor * buffer_factor) as u32)
            .max(1460) // At least 1 MSS
            .min(1_048_576); // Cap at 1MB

        let pacing_rate = (self.max_bw_bps as f32 * self.pacing_gain * loss_factor) as u64;

        CongestionAction {
            new_cwnd,
            pacing_rate,
            slow_start: features.time_since_loss_ms > 10_000, // Haven't seen loss in 10s
        }
    }
}

/// Heuristic-based path selector
pub struct HeuristicPathSelector {
    /// Primary path quality (0.0 - 1.0)
    primary_quality: f32,
    /// Secondary path quality
    secondary_quality: f32,
    /// Last quality update
    last_update: Instant,
}

impl Default for HeuristicPathSelector {
    fn default() -> Self {
        Self {
            primary_quality: 1.0,
            secondary_quality: 0.8,
            last_update: Instant::now(),
        }
    }
}

impl HeuristicPathSelector {
    /// Update path quality based on observations
    pub fn update_quality(&mut self, path: PathDecision, quality: f32) {
        match path {
            PathDecision::Primary => self.primary_quality = quality,
            PathDecision::Secondary => self.secondary_quality = quality,
            _ => {}
        }
        self.last_update = Instant::now();
    }

    /// Calculate path quality from network features
    fn calculate_quality(features: &NetworkFeatures) -> f32 {
        let latency_score = 1.0 - (features.rtt_us as f32 / 500_000.0).min(1.0);
        let loss_score = 1.0 - features.loss_rate;
        let jitter_score = 1.0 - (features.rtt_var_us as f32 / 100_000.0).min(1.0);

        // Weighted combination
        0.4 * latency_score + 0.4 * loss_score + 0.2 * jitter_score
    }
}

impl PathSelector for HeuristicPathSelector {
    fn select(&self, features: &NetworkFeatures, traffic_class: TrafficType) -> PathDecision {
        let quality = Self::calculate_quality(features);

        match traffic_class {
            TrafficType::Gaming | TrafficType::VoIP => {
                // Ultra-low latency - use best path, never multipath (avoids reordering)
                if self.primary_quality > 0.7 {
                    PathDecision::Primary
                } else if self.secondary_quality > 0.7 {
                    PathDecision::Secondary
                } else {
                    PathDecision::Primary // Stick with primary even if degraded
                }
            }
            TrafficType::Bulk => {
                // Throughput priority - multipath if available
                if quality > 0.8 && self.secondary_quality > 0.6 {
                    PathDecision::Multipath
                } else {
                    PathDecision::Primary
                }
            }
            TrafficType::Streaming => {
                // Bandwidth over latency - can tolerate some buffering
                if quality < 0.5 && self.secondary_quality > 0.6 {
                    PathDecision::Secondary
                } else {
                    PathDecision::Primary
                }
            }
            TrafficType::Web => {
                // Balanced - use primary unless it's really bad
                if quality < 0.3 {
                    PathDecision::Secondary
                } else {
                    PathDecision::Primary
                }
            }
        }
    }
}

// ============================================================================
// UNIFIED ENGINE - Combines all heuristics
// ============================================================================

/// The unified AI-ready heuristic engine
/// All decisions can be replaced with ML inference by swapping trait implementations
pub struct HeuristicEngine {
    compression: Box<dyn CompressionOracle>,
    loss_predictor: Box<dyn LossPredictor>,
    congestion: Box<dyn CongestionController>,
    path_selector: Box<dyn PathSelector>,
    /// Statistics for monitoring
    pub stats: EngineStats,
}

#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    pub compression_skipped: u64,
    pub compression_light: u64,
    pub compression_aggressive: u64,
    pub fec_injected: u64,
    pub path_switches: u64,
    pub cwnd_adjustments: u64,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicEngine {
    /// Create with default heuristic implementations
    pub fn new() -> Self {
        Self {
            compression: Box::new(HeuristicCompressionOracle::default()),
            loss_predictor: Box::new(HeuristicLossPredictor::default()),
            congestion: Box::new(HeuristicCongestionController::default()),
            path_selector: Box::new(HeuristicPathSelector::default()),
            stats: EngineStats::default(),
        }
    }

    /// Create with custom implementations (for ML models)
    pub fn with_oracles(
        compression: Box<dyn CompressionOracle>,
        loss_predictor: Box<dyn LossPredictor>,
        congestion: Box<dyn CongestionController>,
        path_selector: Box<dyn PathSelector>,
    ) -> Self {
        Self {
            compression,
            loss_predictor,
            congestion,
            path_selector,
            stats: EngineStats::default(),
        }
    }

    /// Decide compression for a packet
    pub fn compression_decision(&mut self, features: &PacketFeatures) -> CompressionDecision {
        let decision = self.compression.should_compress(features);
        match decision {
            CompressionDecision::Skip => self.stats.compression_skipped += 1,
            CompressionDecision::Light => self.stats.compression_light += 1,
            CompressionDecision::Aggressive => self.stats.compression_aggressive += 1,
        }
        decision
    }

    /// Predict loss and get FEC recommendation
    pub fn fec_decision(&mut self, features: &NetworkFeatures) -> FecDecision {
        let decision = self.loss_predictor.predict(features, &[]);
        if decision.inject_fec {
            self.stats.fec_injected += 1;
        }
        decision
    }

    /// Get congestion control action
    pub fn congestion_decision(&mut self, features: &NetworkFeatures) -> CongestionAction {
        self.stats.cwnd_adjustments += 1;
        self.congestion.decide(features)
    }

    /// Select optimal path for traffic
    pub fn path_decision(
        &mut self,
        features: &NetworkFeatures,
        traffic_class: TrafficType,
    ) -> PathDecision {
        self.path_selector.select(features, traffic_class)
    }

    /// Quick compression check (for hot path)
    /// Returns true if compression should be skipped
    pub fn should_skip_compression(&self, data: &[u8], dst_port: u16) -> bool {
        // Fast path checks without full feature extraction
        if data.len() < 128 {
            return true;
        }

        // Known encrypted ports
        if matches!(dst_port, 443 | 993 | 995 | 465 | 22) {
            return true;
        }

        // Quick entropy check on first 64 bytes
        if data.len() >= 64 {
            let sample = &data[..64];
            let unique: std::collections::HashSet<u8> = sample.iter().copied().collect();
            // High diversity suggests compression won't help
            if unique.len() > 56 {
                return true;
            }
        }

        // Check magic bytes for compressed formats
        if data.len() >= 4 {
            // GZIP
            if data[0] == 0x1F && data[1] == 0x8B {
                return true;
            }
            // ZLIB
            if data[0] == 0x78 {
                return true;
            }
            // ZIP
            if data[..4] == [0x50, 0x4B, 0x03, 0x04] {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// NETWORK STATE TRACKER - Maintains rolling state for predictions
// ============================================================================

/// Tracks network state over time for feature extraction
pub struct NetworkStateTracker {
    /// RTT samples (microseconds)
    rtt_samples: VecDeque<u64>,
    /// Loss events (timestamps)
    loss_events: VecDeque<Instant>,
    /// Bandwidth samples (bytes/sec)
    bw_samples: VecDeque<u64>,
    /// Packets sent in current window
    packets_sent: u64,
    /// Packets acked in current window
    packets_acked: u64,
    /// Last update time
    last_update: Instant,
    /// Window duration
    window: Duration,
}

impl Default for NetworkStateTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl NetworkStateTracker {
    pub fn new(window: Duration) -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(1000),
            loss_events: VecDeque::with_capacity(100),
            bw_samples: VecDeque::with_capacity(100),
            packets_sent: 0,
            packets_acked: 0,
            last_update: Instant::now(),
            window,
        }
    }

    /// Record an RTT sample
    pub fn record_rtt(&mut self, rtt_us: u64) {
        self.rtt_samples.push_back(rtt_us);
        if self.rtt_samples.len() > 1000 {
            self.rtt_samples.pop_front();
        }
    }

    /// Record a loss event
    pub fn record_loss(&mut self) {
        self.loss_events.push_back(Instant::now());
        self.prune_old_events();
    }

    /// Record packet sent
    pub fn record_sent(&mut self) {
        self.packets_sent += 1;
    }

    /// Record packet acked
    pub fn record_ack(&mut self) {
        self.packets_acked += 1;
    }

    /// Record bandwidth sample
    pub fn record_bandwidth(&mut self, bw_bps: u64) {
        self.bw_samples.push_back(bw_bps);
        if self.bw_samples.len() > 100 {
            self.bw_samples.pop_front();
        }
    }

    /// Remove events outside the window
    fn prune_old_events(&mut self) {
        let cutoff = Instant::now() - self.window;
        while self
            .loss_events
            .front()
            .map(|&t| t < cutoff)
            .unwrap_or(false)
        {
            self.loss_events.pop_front();
        }
    }

    /// Extract current network features
    pub fn extract_features(&self, cwnd: u32, inflight: u32) -> NetworkFeatures {
        self.prune_old_events_const();

        let rtt_us = self.rtt_samples.back().copied().unwrap_or(50_000);
        let rtt_var_us = self.calculate_rtt_variance();
        let bandwidth_bps = self.bw_samples.back().copied().unwrap_or(1_000_000);

        let loss_rate = if self.packets_sent > 0 {
            1.0 - (self.packets_acked as f32 / self.packets_sent as f32)
        } else {
            0.0
        };

        let time_since_loss_ms = self
            .loss_events
            .back()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(u64::MAX);

        NetworkFeatures {
            rtt_us,
            rtt_var_us,
            bandwidth_bps,
            loss_rate,
            loss_trend: 0.0, // Would need more history to calculate
            inflight,
            cwnd,
            time_since_loss_ms,
            buffer_occupancy: 0.0, // Would need buffer state
            recent_retx: self.loss_events.len() as u32,
        }
    }

    fn prune_old_events_const(&self) {
        // Note: In real impl, this would be mutable
        // For const access, we just filter during extraction
    }

    fn calculate_rtt_variance(&self) -> u64 {
        if self.rtt_samples.len() < 2 {
            return 0;
        }

        let mean: f64 =
            self.rtt_samples.iter().map(|&x| x as f64).sum::<f64>() / self.rtt_samples.len() as f64;

        let variance: f64 = self
            .rtt_samples
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / self.rtt_samples.len() as f64;

        variance.sqrt() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_features_entropy() {
        // Random-ish data (high entropy)
        let random_data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let features = PacketFeatures::extract(&random_data, 12345, 443, 6);
        assert!(features.entropy > 0.9);

        // Repetitive data (low entropy)
        let repetitive_data = vec![0u8; 1024];
        let features = PacketFeatures::extract(&repetitive_data, 12345, 80, 6);
        assert!(features.entropy < 0.1);
    }

    #[test]
    fn test_compression_oracle_skip_encrypted() {
        let oracle = HeuristicCompressionOracle::default();

        // Encrypted port
        let features = PacketFeatures {
            size: 1000,
            ip_protocol: 6,
            dst_port: 443,
            src_port: 12345,
            header_sample: [0x17, 0x03, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // TLS
            entropy: 0.95,
            is_encrypted: true,
            iat_us: 0,
        };

        assert_eq!(oracle.should_compress(&features), CompressionDecision::Skip);
    }

    #[test]
    fn test_compression_oracle_compress_json() {
        let oracle = HeuristicCompressionOracle::default();

        let mut header = [0u8; 16];
        header[0] = b'{';
        header[1] = b'"';

        let features = PacketFeatures {
            size: 1000,
            ip_protocol: 6,
            dst_port: 80,
            src_port: 12345,
            header_sample: header,
            entropy: 0.4,
            is_encrypted: false,
            iat_us: 0,
        };

        assert_eq!(
            oracle.should_compress(&features),
            CompressionDecision::Aggressive
        );
    }

    #[test]
    fn test_loss_predictor() {
        let predictor = HeuristicLossPredictor::default();

        let features = NetworkFeatures {
            loss_rate: 0.05,
            rtt_var_us: 10_000,
            ..Default::default()
        };

        let decision = predictor.predict(&features, &[]);
        assert!(decision.inject_fec);
        assert!(decision.redundancy_ratio > 0.0);
    }

    #[test]
    fn test_path_selector_gaming() {
        let selector = HeuristicPathSelector::default();

        let features = NetworkFeatures {
            rtt_us: 20_000,
            loss_rate: 0.01,
            ..Default::default()
        };

        let decision = selector.select(&features, TrafficType::Gaming);
        assert_eq!(decision, PathDecision::Primary);
    }

    #[test]
    fn test_engine_quick_skip() {
        let engine = HeuristicEngine::new();

        // Small packet - should skip
        assert!(engine.should_skip_compression(&[0u8; 50], 80));

        // GZIP data - should skip
        let gzip = [0x1F, 0x8B, 0x08, 0x00];
        assert!(engine.should_skip_compression(&gzip, 80));

        // HTTPS port - should skip
        assert!(engine.should_skip_compression(&[0u8; 1000], 443));
    }

    #[test]
    fn test_feature_vectors() {
        let net_features = NetworkFeatures {
            rtt_us: 50_000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.01,
            ..Default::default()
        };

        let vec = net_features.to_feature_vec();
        assert_eq!(vec.len(), 12);
        assert!(vec.iter().all(|&x| x >= 0.0 && x <= 1.0));
    }
}
