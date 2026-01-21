//! Unified Optimization Statistics
//!
//! Aggregates stats from all optimization modules for monitoring and analytics.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Unified optimization statistics for analytics dashboard
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OptimizationStats {
    // MPTCP Redundancy Stats
    pub redundant_packets_sent: u64,
    pub redundant_packets_useful: u64,
    pub path_failovers: u64,

    // Handoff Prediction Stats
    pub handoff_predictions: u64,
    pub handoffs_predicted: u64,
    pub handoffs_actual: u64,
    pub handoff_probability: u32,

    // Deep Packet Inspection Stats
    pub dpi_packets_inspected: u64,
    pub dpi_flows_identified: u64,
    pub dpi_cache_hit_rate: f32,

    // ML Stats
    pub ml_predictions_made: u64,
    pub ml_cwnd_adjustments: u64,
    pub ml_loss_probability: f32,

    // SIMD Stats
    pub simd_packets_parsed: u64,
}

impl OptimizationStats {
    /// Collect stats from optimization modules
    pub fn collect(
        mptcp: Option<&crate::mptcp_redundancy::MptcpRedundancyScheduler>,
        handoff: Option<&crate::handoff_prediction::HandoffPredictor>,
        dpi: Option<&crate::deep_packet_inspection::DeepPacketInspector>,
    ) -> Self {
        let mut stats = Self::default();

        // MPTCP Redundancy
        if let Some(m) = mptcp {
            stats.redundant_packets_sent = m.stats.redundant_packets_sent.load(Ordering::Relaxed);
            stats.redundant_packets_useful =
                m.stats.redundant_packets_useful.load(Ordering::Relaxed);
            stats.path_failovers = m.stats.failovers.load(Ordering::Relaxed);
        }

        // Handoff Prediction
        if let Some(h) = handoff {
            stats.handoff_predictions = h.stats.predictions_made.load(Ordering::Relaxed);
            stats.handoffs_predicted = h.stats.handoffs_predicted.load(Ordering::Relaxed);
            stats.handoffs_actual = h.stats.handoffs_actual.load(Ordering::Relaxed);
            stats.handoff_probability = h.get_probability();
        }

        // DPI
        if let Some(d) = dpi {
            stats.dpi_packets_inspected = d.stats.packets_inspected.load(Ordering::Relaxed);
            stats.dpi_flows_identified = d.stats.flows_identified.load(Ordering::Relaxed);
            let hits = d.stats.cache_hits.load(Ordering::Relaxed);
            let misses = d.stats.cache_misses.load(Ordering::Relaxed);
            stats.dpi_cache_hit_rate = if hits + misses > 0 {
                hits as f32 / (hits + misses) as f32
            } else {
                0.0
            };
        }

        stats
    }

    /// Get summary for logging
    pub fn summary(&self) -> String {
        format!(
            "ML: {}pred/{}cwnd | MPTCP: {}dup/{}fail | DPI: {}flows | SIMD: {}pkts",
            self.ml_predictions_made,
            self.ml_cwnd_adjustments,
            self.redundant_packets_sent,
            self.path_failovers,
            self.dpi_flows_identified,
            self.simd_packets_parsed,
        )
    }
}

/// Atomic counters for real-time stats (cache-line aligned)
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct AtomicOptStats {
    pub total_packets: AtomicU64,
    pub optimized_packets: AtomicU64,
    pub bytes_saved: AtomicU64,
    pub latency_improvements_us: AtomicU64,
}

impl AtomicOptStats {
    pub fn record_optimization(&self, bytes_saved: u64, latency_saved_us: u64) {
        self.optimized_packets.fetch_add(1, Ordering::Relaxed);
        self.bytes_saved.fetch_add(bytes_saved, Ordering::Relaxed);
        self.latency_improvements_us
            .fetch_add(latency_saved_us, Ordering::Relaxed);
    }

    pub fn record_packet(&self) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn optimization_rate(&self) -> f64 {
        let total = self.total_packets.load(Ordering::Relaxed);
        let opt = self.optimized_packets.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            opt as f64 / total as f64
        }
    }
}
