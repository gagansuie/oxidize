//! ECN (Explicit Congestion Notification) Support
//!
//! Implements RFC 9000 Section 13.4 for QUIC ECN.
//! Provides explicit congestion signals from the network for better congestion control.
//!
//! # ECN Codepoints
//! - Not-ECT (00): Not ECN-capable
//! - ECT(0) (10): ECN-capable transport
//! - ECT(1) (01): ECN-capable transport (alternative)
//! - CE (11): Congestion Experienced

use std::sync::atomic::{AtomicU64, Ordering};

/// ECN codepoints (2-bit field in IP header)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EcnCodepoint {
    /// Not ECN-Capable Transport
    NotEct = 0b00,
    /// ECN-Capable Transport (0)
    Ect0 = 0b10,
    /// ECN-Capable Transport (1)
    Ect1 = 0b01,
    /// Congestion Experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Parse from IP header TOS/Traffic Class field
    #[inline]
    pub fn from_tos(tos: u8) -> Self {
        match tos & 0b11 {
            0b00 => EcnCodepoint::NotEct,
            0b10 => EcnCodepoint::Ect0,
            0b01 => EcnCodepoint::Ect1,
            0b11 => EcnCodepoint::Ce,
            _ => unreachable!(),
        }
    }

    /// Convert to TOS bits
    #[inline]
    pub fn to_tos(self) -> u8 {
        self as u8
    }

    /// Check if this indicates congestion
    #[inline]
    pub fn is_congestion(self) -> bool {
        self == EcnCodepoint::Ce
    }

    /// Check if ECN-capable
    #[inline]
    pub fn is_ecn_capable(self) -> bool {
        matches!(
            self,
            EcnCodepoint::Ect0 | EcnCodepoint::Ect1 | EcnCodepoint::Ce
        )
    }
}

/// ECN counts for QUIC ACK frames
#[derive(Debug, Clone, Copy, Default)]
pub struct EcnCounts {
    /// Packets received with ECT(0)
    pub ect0: u64,
    /// Packets received with ECT(1)
    pub ect1: u64,
    /// Packets received with CE (congestion)
    pub ce: u64,
}

impl EcnCounts {
    /// Update counts from received packet
    #[inline]
    pub fn record(&mut self, ecn: EcnCodepoint) {
        match ecn {
            EcnCodepoint::Ect0 => self.ect0 += 1,
            EcnCodepoint::Ect1 => self.ect1 += 1,
            EcnCodepoint::Ce => self.ce += 1,
            EcnCodepoint::NotEct => {}
        }
    }

    /// Check if any congestion was reported
    #[inline]
    pub fn has_congestion(&self) -> bool {
        self.ce > 0
    }

    /// Get total ECN-capable packets
    #[inline]
    pub fn total_ecn(&self) -> u64 {
        self.ect0 + self.ect1 + self.ce
    }
}

/// ECN validation state machine (RFC 9000 Section 13.4.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnValidationState {
    /// ECN not yet tested
    Unknown,
    /// Testing ECN capability
    Testing,
    /// ECN validated and working
    Capable,
    /// ECN failed validation
    Failed,
}

/// ECN controller for a QUIC connection
pub struct EcnController {
    /// Current validation state
    state: EcnValidationState,
    /// ECN counts sent by peer
    peer_counts: EcnCounts,
    /// ECN counts we've recorded locally
    local_counts: EcnCounts,
    /// Packets sent with ECT during testing
    testing_packets: u64,
    /// CE marks received (for congestion response)
    ce_marks_received: AtomicU64,
    /// Statistics
    pub stats: EcnStats,
}

#[derive(Default)]
pub struct EcnStats {
    pub packets_sent_ect0: AtomicU64,
    pub packets_sent_ect1: AtomicU64,
    pub packets_received_ce: AtomicU64,
    pub congestion_responses: AtomicU64,
    pub validation_failures: AtomicU64,
}

impl EcnController {
    pub fn new() -> Self {
        Self {
            state: EcnValidationState::Unknown,
            peer_counts: EcnCounts::default(),
            local_counts: EcnCounts::default(),
            testing_packets: 0,
            ce_marks_received: AtomicU64::new(0),
            stats: EcnStats::default(),
        }
    }

    /// Get ECN codepoint to use for outgoing packets
    #[inline]
    pub fn outgoing_ecn(&self) -> EcnCodepoint {
        match self.state {
            EcnValidationState::Unknown | EcnValidationState::Testing => EcnCodepoint::Ect0,
            EcnValidationState::Capable => EcnCodepoint::Ect0,
            EcnValidationState::Failed => EcnCodepoint::NotEct,
        }
    }

    /// Record that we sent a packet with ECN
    pub fn on_packet_sent(&mut self, ecn: EcnCodepoint) {
        if ecn == EcnCodepoint::Ect0 {
            self.stats.packets_sent_ect0.fetch_add(1, Ordering::Relaxed);
            if self.state == EcnValidationState::Unknown {
                self.state = EcnValidationState::Testing;
                self.testing_packets = 1;
            } else if self.state == EcnValidationState::Testing {
                self.testing_packets += 1;
            }
        }
    }

    /// Process ECN counts received in ACK frame
    pub fn on_ack_ecn(&mut self, counts: EcnCounts) -> EcnResponse {
        let prev_ce = self.peer_counts.ce;
        self.peer_counts = counts;

        // Check for new CE marks (congestion signal)
        let new_ce = counts.ce.saturating_sub(prev_ce);
        if new_ce > 0 {
            self.ce_marks_received.fetch_add(new_ce, Ordering::Relaxed);
            self.stats
                .packets_received_ce
                .fetch_add(new_ce, Ordering::Relaxed);
            self.stats
                .congestion_responses
                .fetch_add(1, Ordering::Relaxed);
            return EcnResponse::Congestion { ce_count: new_ce };
        }

        // Validate ECN if in testing state
        if self.state == EcnValidationState::Testing {
            let total_reported = counts.ect0 + counts.ect1 + counts.ce;
            if total_reported >= self.testing_packets {
                // ECN is working
                self.state = EcnValidationState::Capable;
                return EcnResponse::Validated;
            }
        }

        EcnResponse::None
    }

    /// Record incoming packet ECN
    #[inline]
    pub fn on_packet_received(&mut self, ecn: EcnCodepoint) {
        self.local_counts.record(ecn);
    }

    /// Get local ECN counts for ACK frame
    #[inline]
    pub fn local_counts(&self) -> EcnCounts {
        self.local_counts
    }

    /// Check if ECN is enabled
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.state == EcnValidationState::Capable || self.state == EcnValidationState::Testing
    }

    /// Mark ECN as failed (e.g., path doesn't support ECN)
    pub fn mark_failed(&mut self) {
        self.state = EcnValidationState::Failed;
        self.stats
            .validation_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get current validation state
    #[inline]
    pub fn state(&self) -> EcnValidationState {
        self.state
    }

    /// Get total CE marks received
    #[inline]
    pub fn ce_marks(&self) -> u64 {
        self.ce_marks_received.load(Ordering::Relaxed)
    }
}

impl Default for EcnController {
    fn default() -> Self {
        Self::new()
    }
}

/// Response to ECN processing
#[derive(Debug, Clone, Copy)]
pub enum EcnResponse {
    /// No action needed
    None,
    /// ECN validated successfully
    Validated,
    /// Congestion detected
    Congestion { ce_count: u64 },
}

/// ECN-aware congestion response
/// Implements DCTCP-style ECN response
pub struct EcnCongestionResponse {
    /// Alpha parameter (EWMA of CE ratio)
    alpha: f64,
    /// Gain for alpha update
    g: f64,
    /// Bytes sent since last CE
    bytes_since_ce: u64,
    /// CE bytes in current window
    ce_bytes: u64,
}

impl EcnCongestionResponse {
    pub fn new() -> Self {
        Self {
            alpha: 0.0,
            g: 0.0625, // 1/16, standard DCTCP gain
            bytes_since_ce: 0,
            ce_bytes: 0,
        }
    }

    /// Update on packet sent
    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_since_ce += bytes;
    }

    /// Update on CE mark received
    pub fn on_ce_received(&mut self, bytes: u64) {
        self.ce_bytes += bytes;
    }

    /// Update alpha at end of RTT
    pub fn end_of_rtt(&mut self) {
        if self.bytes_since_ce > 0 {
            let f = self.ce_bytes as f64 / self.bytes_since_ce as f64;
            self.alpha = (1.0 - self.g) * self.alpha + self.g * f;
        }
        self.bytes_since_ce = 0;
        self.ce_bytes = 0;
    }

    /// Get CWND reduction factor (0.0 to 1.0)
    /// Returns how much to multiply CWND by on congestion
    #[inline]
    pub fn cwnd_reduction_factor(&self) -> f64 {
        1.0 - self.alpha / 2.0
    }

    /// Get current alpha value
    #[inline]
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

impl Default for EcnCongestionResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecn_codepoint() {
        assert_eq!(EcnCodepoint::from_tos(0b00), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_tos(0b10), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_tos(0b01), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_tos(0b11), EcnCodepoint::Ce);
    }

    #[test]
    fn test_ecn_controller() {
        let mut ctrl = EcnController::new();

        // Initially unknown
        assert_eq!(ctrl.state(), EcnValidationState::Unknown);

        // After sending with ECT, should be testing
        ctrl.on_packet_sent(EcnCodepoint::Ect0);
        assert_eq!(ctrl.state(), EcnValidationState::Testing);
    }

    #[test]
    fn test_ecn_congestion_response() {
        let mut resp = EcnCongestionResponse::new();

        // Initially no reduction
        assert!((resp.cwnd_reduction_factor() - 1.0).abs() < 0.001);

        // Simulate 50% CE marks
        resp.on_packet_sent(1000);
        resp.on_ce_received(500);
        resp.end_of_rtt();

        // Should have some reduction now
        assert!(resp.cwnd_reduction_factor() < 1.0);
    }
}
