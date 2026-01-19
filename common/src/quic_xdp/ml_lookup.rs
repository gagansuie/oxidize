//! ML Lookup Tables for Sub-Microsecond Decisions
//!
//! Pre-computed lookup tables generated FROM the trained ML model.
//! Provides ML-quality decisions with <100ns latency.
//!
//! # Strategy
//! 1. At initialization, query ML model for all bucket combinations
//! 2. Store results in O(1) lookup table
//! 3. Runtime: instant lookup with same quality as ML
//! 4. Edge cases outside table bounds fall back to live ML
//!
//! # Table Generation
//! - CWND table: 32 RTT × 16 loss × 16 bandwidth = 8,192 ML queries at startup
//! - FEC table: 16 loss buckets = 16 ML queries at startup
//! - Total startup cost: ~80ms (one-time)
//! - Runtime cost: <100ns per decision

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Discretization parameters
const RTT_BUCKETS: usize = 32; // 0-320ms in 10ms increments
const LOSS_BUCKETS: usize = 16; // 0-16% in 1% increments
const BW_BUCKETS: usize = 16; // 0-10Gbps in logarithmic scale

/// Pre-computed CWND lookup table
/// Index: [rtt_bucket][loss_bucket][bw_bucket]
pub struct CwndLookupTable {
    /// 3D lookup table for CWND values
    table: Box<[[[u64; BW_BUCKETS]; LOSS_BUCKETS]; RTT_BUCKETS]>,
    /// Statistics
    pub stats: LookupStats,
}

/// Pre-computed FEC lookup table
/// Index: [loss_bucket] -> FEC ratio (0-255 = 0-100%)
pub struct FecLookupTable {
    /// 1D lookup table for FEC ratios
    table: [u8; LOSS_BUCKETS],
    /// Thresholds for when to apply FEC
    thresholds: [f32; LOSS_BUCKETS],
    /// Statistics
    pub stats: LookupStats,
}

#[derive(Default)]
pub struct LookupStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub ml_fallbacks: AtomicU64,
}

impl LookupStats {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let total = hits + self.misses.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

impl CwndLookupTable {
    /// Create CWND lookup table from ML model
    ///
    /// Queries the ML model for every bucket combination and caches results.
    /// This is the preferred constructor - uses actual ML predictions.
    ///
    /// # Arguments
    /// * `ml_fn` - Function that takes (rtt_us, loss_rate, bandwidth_mbps, features) and returns CWND
    pub fn from_model<F>(ml_fn: F) -> Self
    where
        F: Fn(u64, f32, f64, &[f32]) -> u64,
    {
        let start = Instant::now();
        let mut table = Box::new([[[0u64; BW_BUCKETS]; LOSS_BUCKETS]; RTT_BUCKETS]);
        let mut queries = 0u32;

        // Query ML model for each bucket combination
        for rtt_idx in 0..RTT_BUCKETS {
            let rtt_us = ((rtt_idx as u64 + 1) * 10) * 1000; // 10-320ms in microseconds
            let rtt_ms = rtt_us as f32 / 1000.0;

            for loss_idx in 0..LOSS_BUCKETS {
                let loss_rate = loss_idx as f32 / 100.0; // 0-16%

                for bw_idx in 0..BW_BUCKETS {
                    // Logarithmic bandwidth scale: 1Mbps to 10Gbps
                    let bw_mbps = 10.0_f64.powf(bw_idx as f64 / 4.0);

                    // Build feature vector for ML model
                    // [rtt_ms, loss_rate, bandwidth_mbps, bytes_in_flight_normalized,
                    //  cwnd_normalized, rtt_var, delivery_rate, is_app_limited]
                    let features = [
                        rtt_ms / 320.0,             // Normalized RTT
                        loss_rate,                  // Loss rate (already 0-1)
                        (bw_mbps / 10000.0) as f32, // Normalized bandwidth
                        0.5,                        // Default bytes_in_flight
                        0.5,                        // Default cwnd
                        0.1,                        // Default RTT variance
                        0.5,                        // Default delivery rate
                        0.0,                        // Not app limited
                    ];

                    // Query ML model
                    let cwnd = ml_fn(rtt_us, loss_rate, bw_mbps, &features);
                    table[rtt_idx][loss_idx][bw_idx] = cwnd;
                    queries += 1;
                }
            }
        }

        tracing::info!(
            "CWND lookup table generated: {} ML queries in {:?}",
            queries,
            start.elapsed()
        );

        Self {
            table,
            stats: LookupStats::default(),
        }
    }

    /// Create with BDP-based fallback (no ML model available)
    ///
    /// Uses mathematical formula as fallback when ML model isn't loaded.
    /// Less optimal than from_model() but works without trained weights.
    pub fn new() -> Self {
        Self::from_model(|rtt_us, loss_rate, bw_mbps, _features| {
            // BDP-based fallback formula
            let rtt_sec = rtt_us as f64 / 1_000_000.0;
            let bw_bytes_sec = bw_mbps * 125_000.0; // Mbps to bytes/sec
            let bdp = bw_bytes_sec * rtt_sec;

            // Loss adjustment
            let loss_factor = 1.0 / (1.0 + loss_rate as f64 * 10.0);

            (bdp * loss_factor)
                .max(4.0 * 1460.0)
                .min(128.0 * 1024.0 * 1024.0) as u64
        })
    }

    /// Look up optimal CWND
    /// Returns None if parameters are outside table bounds (requires ML)
    #[inline]
    pub fn lookup(&self, rtt_us: u64, loss_rate: f32, bandwidth_mbps: f64) -> Option<u64> {
        let rtt_ms = rtt_us / 1000;

        // Check bounds
        if rtt_ms > 320 || loss_rate > 0.16 || bandwidth_mbps > 10000.0 {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Discretize
        let rtt_idx = ((rtt_ms / 10) as usize).min(RTT_BUCKETS - 1);
        let loss_idx = ((loss_rate * 100.0) as usize).min(LOSS_BUCKETS - 1);
        let bw_idx = ((bandwidth_mbps.log10() * 4.0) as usize).min(BW_BUCKETS - 1);

        self.stats.hits.fetch_add(1, Ordering::Relaxed);
        Some(self.table[rtt_idx][loss_idx][bw_idx])
    }

    /// Lookup with ML fallback
    #[inline]
    pub fn lookup_or<F>(&self, rtt_us: u64, loss_rate: f32, bandwidth_mbps: f64, ml_fn: F) -> u64
    where
        F: FnOnce() -> u64,
    {
        match self.lookup(rtt_us, loss_rate, bandwidth_mbps) {
            Some(cwnd) => cwnd,
            None => {
                self.stats.ml_fallbacks.fetch_add(1, Ordering::Relaxed);
                ml_fn()
            }
        }
    }
}

impl Default for CwndLookupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FecLookupTable {
    /// Create FEC lookup table from ML model
    ///
    /// # Arguments
    /// * `ml_fn` - Function that takes loss_rate and returns optimal FEC ratio (0.0-1.0)
    pub fn from_model<F>(ml_fn: F) -> Self
    where
        F: Fn(f32) -> f32,
    {
        let start = Instant::now();
        let mut table = [0u8; LOSS_BUCKETS];
        let mut thresholds = [0.0f32; LOSS_BUCKETS];

        // Query ML model for each loss bucket
        for i in 0..LOSS_BUCKETS {
            let loss_rate = i as f32 / 100.0;

            // Query ML for optimal FEC ratio
            let fec_ratio = ml_fn(loss_rate).clamp(0.0, 1.0);
            table[i] = (fec_ratio * 255.0) as u8;

            // Threshold for this bucket
            thresholds[i] = if i < 2 { 0.0 } else { (i - 1) as f32 / 100.0 };
        }

        tracing::info!(
            "FEC lookup table generated: {} ML queries in {:?}",
            LOSS_BUCKETS,
            start.elapsed()
        );

        Self {
            table,
            thresholds,
            stats: LookupStats::default(),
        }
    }

    /// Create with formula-based fallback (no ML model)
    pub fn new() -> Self {
        Self::from_model(|loss_rate| {
            // Formula: FEC ratio ~= 2x loss rate, capped at 50%
            (loss_rate * 2.0).min(0.5)
        })
    }

    /// Look up FEC ratio (0.0-1.0) for given loss rate
    #[inline]
    pub fn lookup_ratio(&self, loss_rate: f32) -> f32 {
        let idx = ((loss_rate * 100.0) as usize).min(LOSS_BUCKETS - 1);
        self.stats.hits.fetch_add(1, Ordering::Relaxed);
        self.table[idx] as f32 / 255.0
    }

    /// Check if FEC should be applied
    #[inline]
    pub fn should_apply_fec(&self, loss_rate: f32) -> bool {
        // Apply FEC if loss > 1%
        loss_rate > 0.01
    }

    /// Get number of FEC packets to send for N data packets
    #[inline]
    pub fn fec_packets_for(&self, data_packets: usize, loss_rate: f32) -> usize {
        let ratio = self.lookup_ratio(loss_rate);
        ((data_packets as f32) * ratio).ceil() as usize
    }
}

impl Default for FecLookupTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined lookup engine for all ML decisions
pub struct MlLookupEngine {
    /// CWND lookup table
    pub cwnd_table: CwndLookupTable,
    /// FEC lookup table
    pub fec_table: FecLookupTable,
    /// Fast path counter (decisions made without ML)
    pub fast_path_decisions: AtomicU64,
    /// Slow path counter (decisions requiring ML)
    pub slow_path_decisions: AtomicU64,
}

impl MlLookupEngine {
    /// Create lookup engine with formula-based tables (fallback)
    pub fn new() -> Self {
        Self {
            cwnd_table: CwndLookupTable::new(),
            fec_table: FecLookupTable::new(),
            fast_path_decisions: AtomicU64::new(0),
            slow_path_decisions: AtomicU64::new(0),
        }
    }

    /// Create lookup engine from trained ML model
    ///
    /// This is the preferred constructor. Generates lookup tables by querying
    /// the ML model for all bucket combinations at startup.
    ///
    /// # Arguments
    /// * `cwnd_fn` - ML function for CWND: (rtt_us, loss_rate, bw_mbps, features) -> cwnd
    /// * `fec_fn` - ML function for FEC: (loss_rate) -> fec_ratio
    pub fn from_model<C, F>(cwnd_fn: C, fec_fn: F) -> Self
    where
        C: Fn(u64, f32, f64, &[f32]) -> u64,
        F: Fn(f32) -> f32,
    {
        let start = Instant::now();

        let engine = Self {
            cwnd_table: CwndLookupTable::from_model(cwnd_fn),
            fec_table: FecLookupTable::from_model(fec_fn),
            fast_path_decisions: AtomicU64::new(0),
            slow_path_decisions: AtomicU64::new(0),
        };

        tracing::info!(
            "ML Lookup Engine initialized in {:?} ({} bytes)",
            start.elapsed(),
            engine.memory_size_bytes()
        );

        engine
    }

    /// Create from OptimizedMlEngine
    pub fn from_ml_engine(engine: &crate::ml_optimized::OptimizedMlEngine) -> Self {
        Self::from_model(
            |rtt_us, loss_rate, bw_mbps, features| {
                // Build state for congestion controller
                let rtt_sec = rtt_us as f64 / 1_000_000.0;
                let bw_bytes = bw_mbps * 125_000.0;
                let bdp = (bw_bytes * rtt_sec) as u64;

                // Get CWND from ML (returns value, not multiplier in this context)
                engine.get_cwnd(rtt_us, features).max(bdp / 2).min(bdp * 2)
            },
            |loss_rate| {
                // Predict loss and convert to FEC ratio
                let features = [loss_rate, loss_rate * 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
                let loss_prob = engine.predict_loss(0, &features);
                // FEC ratio = ~2x predicted loss probability
                (loss_prob * 2.0).min(0.5)
            },
        )
    }

    /// Get CWND decision (fast path if possible)
    #[inline]
    pub fn get_cwnd(&self, rtt_us: u64, loss_rate: f32, bandwidth_mbps: f64) -> Option<u64> {
        let result = self.cwnd_table.lookup(rtt_us, loss_rate, bandwidth_mbps);
        if result.is_some() {
            self.fast_path_decisions.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Get FEC decision (always fast path)
    #[inline]
    pub fn get_fec_ratio(&self, loss_rate: f32) -> f32 {
        self.fast_path_decisions.fetch_add(1, Ordering::Relaxed);
        self.fec_table.lookup_ratio(loss_rate)
    }

    /// Get fast path hit rate
    pub fn fast_path_rate(&self) -> f64 {
        let fast = self.fast_path_decisions.load(Ordering::Relaxed);
        let slow = self.slow_path_decisions.load(Ordering::Relaxed);
        let total = fast + slow;
        if total == 0 {
            0.0
        } else {
            fast as f64 / total as f64
        }
    }

    /// Memory size of all lookup tables
    pub fn memory_size_bytes(&self) -> usize {
        RTT_BUCKETS * LOSS_BUCKETS * BW_BUCKETS * 8 + // CWND table
        LOSS_BUCKETS * 2 // FEC table
    }
}

impl Default for MlLookupEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwnd_lookup() {
        let table = CwndLookupTable::new();

        // Normal conditions should hit
        let cwnd = table.lookup(50_000, 0.01, 100.0);
        assert!(cwnd.is_some());
        assert!(cwnd.unwrap() > 0);

        // Edge case should miss
        let cwnd = table.lookup(500_000, 0.5, 100000.0);
        assert!(cwnd.is_none());
    }

    #[test]
    fn test_fec_lookup() {
        let table = FecLookupTable::new();

        // Low loss = low FEC
        let ratio = table.lookup_ratio(0.01);
        assert!(ratio < 0.1);

        // High loss = high FEC
        let ratio = table.lookup_ratio(0.10);
        assert!(ratio > 0.1);
    }

    #[test]
    fn test_ml_lookup_engine() {
        let engine = MlLookupEngine::new();

        // Should be reasonably small (< 1MB)
        assert!(engine.memory_size_bytes() < 1_000_000);
    }
}
