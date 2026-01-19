//! Unified Optimization Statistics
//!
//! Aggregates stats from all optimization modules for monitoring and analytics.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Unified optimization statistics for analytics dashboard
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OptimizationStats {
    // ML Pacing Stats
    pub ml_predictions_made: u64,
    pub ml_preemptive_reductions: u64,
    pub ml_loss_probability: f32,

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

    // Protocol Optimization Stats
    pub varint_bytes_saved: u64,
    pub encryption_skipped: u64,
    pub trusted_connections: u64,

    // Buffer Pool Stats
    pub buffer_pool_size: usize,
    pub buffer_pool_utilization: f32,
    pub buffer_expansions: u64,
    pub buffer_contractions: u64,

    // NUMA Stats
    pub numa_nodes: usize,
    pub numa_local_allocs: u64,
    pub numa_remote_allocs: u64,

    // SIMD Stats
    pub simd_avx512_ops: u64,
    pub simd_avx2_ops: u64,
    pub simd_scalar_ops: u64,
    pub simd_packets_parsed: u64,
}

impl OptimizationStats {
    /// Collect stats from all optimization modules
    pub fn collect(
        ml_pacer: Option<&crate::ml_pacing::MlAugmentedPacer>,
        mptcp: Option<&crate::mptcp_redundancy::MptcpRedundancyScheduler>,
        handoff: Option<&crate::handoff_prediction::HandoffPredictor>,
        dpi: Option<&crate::deep_packet_inspection::DeepPacketInspector>,
        trusted: Option<&crate::protocol_optimizations::TrustedNetworkDetector>,
        buffer_pool: Option<&crate::protocol_optimizations::DynamicBufferPool>,
        numa: Option<&crate::protocol_optimizations::NumaAllocator>,
        simd: Option<&crate::simd_avx512::SimdParser>,
    ) -> Self {
        let mut stats = Self::default();

        // ML Pacing
        if let Some(p) = ml_pacer {
            stats.ml_predictions_made = p.stats.predictions_made.load(Ordering::Relaxed);
            stats.ml_preemptive_reductions = p.stats.preemptive_reductions.load(Ordering::Relaxed);
            stats.ml_loss_probability = p.get_loss_probability();
        }

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

        // Trusted Networks
        if let Some(t) = trusted {
            stats.encryption_skipped = t.stats.encryption_skipped.load(Ordering::Relaxed);
            stats.trusted_connections = t.stats.trusted_connections.load(Ordering::Relaxed);
        }

        // Buffer Pool
        if let Some(b) = buffer_pool {
            stats.buffer_pool_size = b.size();
            stats.buffer_pool_utilization = b.utilization();
            stats.buffer_expansions = b.stats.expansions.load(Ordering::Relaxed);
            stats.buffer_contractions = b.stats.contractions.load(Ordering::Relaxed);
        }

        // NUMA
        if let Some(n) = numa {
            stats.numa_nodes = n.node_count();
            stats.numa_local_allocs = n.stats.local_allocations.load(Ordering::Relaxed);
            stats.numa_remote_allocs = n.stats.remote_allocations.load(Ordering::Relaxed);
        }

        // SIMD
        if let Some(s) = simd {
            stats.simd_avx512_ops = s.stats.avx512_ops.load(Ordering::Relaxed);
            stats.simd_avx2_ops = s.stats.avx2_ops.load(Ordering::Relaxed);
            stats.simd_scalar_ops = s.stats.scalar_ops.load(Ordering::Relaxed);
            stats.simd_packets_parsed = s.stats.packets_parsed.load(Ordering::Relaxed);
        }

        stats
    }

    /// Get summary for logging
    pub fn summary(&self) -> String {
        format!(
            "ML: {}pred/{}reduce | MPTCP: {}dup/{}fail | DPI: {}flows | SIMD: {}avx512/{}avx2",
            self.ml_predictions_made,
            self.ml_preemptive_reductions,
            self.redundant_packets_sent,
            self.path_failovers,
            self.dpi_flows_identified,
            self.simd_avx512_ops,
            self.simd_avx2_ops,
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
