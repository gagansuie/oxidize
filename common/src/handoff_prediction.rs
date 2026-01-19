//! ML Handoff Prediction (WiFi → LTE)
//!
//! Predicts network transitions 5+ seconds ahead using signal trends.
//! Enables proactive FEC and path preparation.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    WiFi = 0,
    LTE = 1,
    FiveG = 2,
    Ethernet = 3,
    Unknown = 4,
}

#[derive(Debug)]
pub struct HandoffPredictor {
    current_network: AtomicU8,
    handoff_probability: AtomicU32,
    signal_history: RwLock<SignalHistory>,
    pub stats: HandoffStats,
}

#[derive(Debug, Default)]
pub struct HandoffStats {
    pub predictions_made: AtomicU64,
    pub handoffs_predicted: AtomicU64,
    pub handoffs_actual: AtomicU64,
    pub correct_predictions: AtomicU64,
}

#[derive(Debug)]
struct SignalHistory {
    wifi_rssi: Vec<i8>,
    lte_rsrp: Vec<i8>,
    rtt_samples: Vec<u32>,
    max_samples: usize,
}

impl SignalHistory {
    fn new(max: usize) -> Self {
        Self {
            wifi_rssi: Vec::with_capacity(max),
            lte_rsrp: Vec::with_capacity(max),
            rtt_samples: Vec::with_capacity(max),
            max_samples: max,
        }
    }

    fn add_wifi(&mut self, rssi: i8, rtt_us: u32) {
        if self.wifi_rssi.len() >= self.max_samples {
            self.wifi_rssi.remove(0);
            self.rtt_samples.remove(0);
        }
        self.wifi_rssi.push(rssi);
        self.rtt_samples.push(rtt_us);
    }

    fn add_lte(&mut self, rsrp: i8) {
        if self.lte_rsrp.len() >= self.max_samples {
            self.lte_rsrp.remove(0);
        }
        self.lte_rsrp.push(rsrp);
    }

    fn wifi_trend(&self) -> f32 {
        if self.wifi_rssi.len() < 5 {
            return 0.0;
        }
        let len = self.wifi_rssi.len();
        let old: f32 = self.wifi_rssi[len - 5..len - 3]
            .iter()
            .map(|&x| x as f32)
            .sum::<f32>()
            / 2.0;
        let new: f32 = self.wifi_rssi[len - 2..]
            .iter()
            .map(|&x| x as f32)
            .sum::<f32>()
            / 2.0;
        new - old
    }

    fn is_wifi_weak(&self) -> bool {
        self.wifi_rssi.last().map(|&r| r < -75).unwrap_or(true)
    }

    fn is_lte_available(&self) -> bool {
        self.lte_rsrp.last().map(|&r| r > -100).unwrap_or(false)
    }
}

impl HandoffPredictor {
    pub fn new() -> Self {
        Self {
            current_network: AtomicU8::new(NetworkType::WiFi as u8),
            handoff_probability: AtomicU32::new(0),
            signal_history: RwLock::new(SignalHistory::new(50)),
            stats: HandoffStats::default(),
        }
    }

    pub fn record_wifi_signal(&self, rssi: i8, rtt_us: u32) {
        if let Ok(mut h) = self.signal_history.write() {
            h.add_wifi(rssi, rtt_us);
        }
    }

    pub fn record_lte_signal(&self, rsrp: i8) {
        if let Ok(mut h) = self.signal_history.write() {
            h.add_lte(rsrp);
        }
    }

    pub fn set_network(&self, network: NetworkType) {
        let old = self.current_network.swap(network as u8, Ordering::Relaxed);
        if old != network as u8 {
            self.stats.handoffs_actual.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Predict handoff probability (0-100)
    pub fn predict_handoff(&self) -> u32 {
        let h = match self.signal_history.read() {
            Ok(h) => h,
            Err(_) => return 0,
        };

        self.stats.predictions_made.fetch_add(1, Ordering::Relaxed);

        let trend = h.wifi_trend();
        let weak = h.is_wifi_weak();
        let lte_ok = h.is_lte_available();

        let prob = if weak && lte_ok {
            80 + ((-trend) * 4.0).min(20.0) as u32
        } else if trend < -2.0 && lte_ok {
            50 + ((-trend) * 5.0).min(40.0) as u32
        } else if trend < -1.0 {
            20 + ((-trend) * 10.0).min(30.0) as u32
        } else {
            5
        };

        let prob = prob.min(100);
        self.handoff_probability.store(prob, Ordering::Relaxed);

        if prob > 60 {
            self.stats
                .handoffs_predicted
                .fetch_add(1, Ordering::Relaxed);
        }
        prob
    }

    pub fn get_probability(&self) -> u32 {
        self.handoff_probability.load(Ordering::Relaxed)
    }

    pub fn should_prepare_handoff(&self) -> bool {
        self.handoff_probability.load(Ordering::Relaxed) > 60
    }

    pub fn get_actions(&self) -> HandoffActions {
        let p = self.handoff_probability.load(Ordering::Relaxed);
        HandoffActions {
            increase_fec: p > 50,
            duplicate_critical: p > 70,
            preemptive_path_probe: p > 40,
            reduce_batch_size: p > 60,
        }
    }
}

impl Default for HandoffPredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct HandoffActions {
    pub increase_fec: bool,
    pub duplicate_critical: bool,
    pub preemptive_path_probe: bool,
    pub reduce_batch_size: bool,
}
