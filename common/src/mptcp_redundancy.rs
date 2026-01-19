//! MPTCP-Style Redundancy for Multipath
//!
//! Sends critical packets on multiple paths for reliability.
//! Gaming/VoIP traffic is duplicated on all available paths.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

/// Packet importance for redundancy decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketImportance {
    Critical, // Always send on all paths (gaming, VoIP)
    High,     // Send on primary + backup if quality differs
    Normal,   // Best path only
    Low,      // Bulk transfer, can be delayed
}

/// MPTCP-style scheduler with redundancy
#[derive(Debug)]
pub struct MptcpRedundancyScheduler {
    paths: RwLock<HashMap<u32, PathState>>,
    config: RedundancyConfig,
    pub stats: RedundancyStats,
}

#[derive(Debug, Clone)]
pub struct RedundancyConfig {
    pub enable_redundancy: bool,
    pub rtt_diff_threshold_ms: u32,
    pub loss_diff_threshold: f32,
    pub max_redundancy_buffer: usize,
}

impl Default for RedundancyConfig {
    fn default() -> Self {
        Self {
            enable_redundancy: true,
            rtt_diff_threshold_ms: 50,
            loss_diff_threshold: 0.05,
            max_redundancy_buffer: 64,
        }
    }
}

#[derive(Debug, Default)]
pub struct RedundancyStats {
    pub packets_sent_primary: AtomicU64,
    pub packets_sent_backup: AtomicU64,
    pub redundant_packets_sent: AtomicU64,
    pub redundant_packets_useful: AtomicU64,
    pub failovers: AtomicU64,
}

#[derive(Debug, Clone)]
struct PathState {
    id: u32,
    rtt_ms: f32,
    loss_rate: f32,
    bandwidth_bps: u64,
    is_primary: bool,
    last_updated: Instant,
    consecutive_failures: u32,
}

impl Default for MptcpRedundancyScheduler {
    fn default() -> Self {
        Self::new(RedundancyConfig::default())
    }
}

impl MptcpRedundancyScheduler {
    pub fn new(config: RedundancyConfig) -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            config,
            stats: RedundancyStats::default(),
        }
    }

    pub fn add_path(&self, path_id: u32, is_primary: bool) {
        if let Ok(mut paths) = self.paths.write() {
            paths.insert(
                path_id,
                PathState {
                    id: path_id,
                    rtt_ms: 100.0,
                    loss_rate: 0.0,
                    bandwidth_bps: 100_000_000,
                    is_primary,
                    last_updated: Instant::now(),
                    consecutive_failures: 0,
                },
            );
        }
    }

    pub fn update_path(&self, path_id: u32, rtt_ms: f32, loss_rate: f32, bandwidth_bps: u64) {
        if let Ok(mut paths) = self.paths.write() {
            if let Some(path) = paths.get_mut(&path_id) {
                path.rtt_ms = rtt_ms;
                path.loss_rate = loss_rate;
                path.bandwidth_bps = bandwidth_bps;
                path.last_updated = Instant::now();
                if loss_rate < 0.01 {
                    path.consecutive_failures = 0;
                }
            }
        }
    }

    pub fn record_failure(&self, path_id: u32) {
        if let Ok(mut paths) = self.paths.write() {
            if let Some(path) = paths.get_mut(&path_id) {
                path.consecutive_failures += 1;
            }
        }
    }

    /// Decide which paths to send packet on
    pub fn schedule_packet(&self, importance: PacketImportance) -> Vec<u32> {
        let paths = match self.paths.read() {
            Ok(p) => p,
            Err(_) => return vec![],
        };

        if paths.is_empty() {
            return vec![];
        }

        let mut sorted: Vec<_> = paths.values().collect();
        sorted.sort_by(|a, b| {
            let sa = a.rtt_ms + (a.loss_rate * 1000.0);
            let sb = b.rtt_ms + (b.loss_rate * 1000.0);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        });

        match importance {
            PacketImportance::Critical => {
                self.stats
                    .redundant_packets_sent
                    .fetch_add(1, Ordering::Relaxed);
                sorted.iter().map(|p| p.id).collect()
            }
            PacketImportance::High => {
                if sorted.len() >= 2 && self.config.enable_redundancy {
                    let best = sorted[0];
                    let second = sorted[1];
                    let rtt_diff = (best.rtt_ms - second.rtt_ms).abs();
                    let loss_diff = (best.loss_rate - second.loss_rate).abs();

                    if rtt_diff > self.config.rtt_diff_threshold_ms as f32
                        || loss_diff > self.config.loss_diff_threshold
                    {
                        self.stats
                            .redundant_packets_sent
                            .fetch_add(1, Ordering::Relaxed);
                        vec![best.id, second.id]
                    } else {
                        vec![best.id]
                    }
                } else if !sorted.is_empty() {
                    vec![sorted[0].id]
                } else {
                    vec![]
                }
            }
            PacketImportance::Normal | PacketImportance::Low => {
                if !sorted.is_empty() {
                    self.stats
                        .packets_sent_primary
                        .fetch_add(1, Ordering::Relaxed);
                    vec![sorted[0].id]
                } else {
                    vec![]
                }
            }
        }
    }

    pub fn should_failover(&self) -> Option<u32> {
        let paths = match self.paths.read() {
            Ok(p) => p,
            Err(_) => return None,
        };

        let primary = paths.values().find(|p| p.is_primary)?;
        let backup = paths.values().find(|p| !p.is_primary)?;

        if primary.consecutive_failures >= 3
            || (primary.loss_rate > backup.loss_rate + 0.1 && primary.rtt_ms > backup.rtt_ms * 1.5)
        {
            self.stats.failovers.fetch_add(1, Ordering::Relaxed);
            Some(backup.id)
        } else {
            None
        }
    }

    pub fn get_path_count(&self) -> usize {
        self.paths.read().map(|p| p.len()).unwrap_or(0)
    }
}
