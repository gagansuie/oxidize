//! HTTP/3 Priority Scheduler
//!
//! Implements smart stream scheduling for QUIC/HTTP3 connections.
//! Prioritizes real-time traffic (gaming, VoIP) over bulk transfers.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Stream priority levels (HTTP/3 urgency)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Priority {
    /// Highest - real-time gaming/VoIP
    Realtime = 0,
    /// High - interactive (mouse clicks, keypresses)
    Interactive = 1,
    /// Normal - web browsing
    #[default]
    Normal = 2,
    /// Low - prefetch, background
    Background = 3,
    /// Lowest - bulk transfers
    Bulk = 4,
}

impl From<u8> for Priority {
    fn from(urgency: u8) -> Self {
        match urgency {
            0 => Priority::Realtime,
            1 => Priority::Interactive,
            2 => Priority::Normal,
            3 => Priority::Background,
            _ => Priority::Bulk,
        }
    }
}

/// Stream scheduling entry
#[derive(Debug, Clone)]
pub struct StreamEntry {
    /// Stream ID
    pub stream_id: u64,
    /// Priority level
    pub priority: Priority,
    /// Whether this stream should be incremental (can yield to others)
    pub incremental: bool,
    /// Bytes pending to send
    pub pending_bytes: usize,
    /// Deadline (for real-time streams)
    pub deadline_ms: Option<u64>,
    /// Creation timestamp (for fairness)
    pub created_at: u64,
}

impl PartialEq for StreamEntry {
    fn eq(&self, other: &Self) -> bool {
        self.stream_id == other.stream_id
    }
}

impl Eq for StreamEntry {}

impl PartialOrd for StreamEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StreamEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority (lower number) comes first
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {
                // Same priority: check deadlines
                match (self.deadline_ms, other.deadline_ms) {
                    (Some(a), Some(b)) => b.cmp(&a), // Earlier deadline first (reversed for max-heap)
                    (Some(_), None) => Ordering::Greater,
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => {
                        // FIFO for same priority without deadline
                        other.created_at.cmp(&self.created_at)
                    }
                }
            }
            other => other.reverse(), // Reverse for max-heap behavior
        }
    }
}

/// Priority-based stream scheduler
pub struct PriorityScheduler {
    /// Priority queue of streams
    queue: BinaryHeap<StreamEntry>,
    /// Maximum streams to track
    max_streams: usize,
    /// Bytes allocated per priority level in current round
    bytes_per_priority: [usize; 5],
    /// Weight multipliers for each priority
    weights: [usize; 5],
    /// Current scheduling round
    round: u64,
}

impl PriorityScheduler {
    pub fn new(max_streams: usize) -> Self {
        PriorityScheduler {
            queue: BinaryHeap::with_capacity(max_streams),
            max_streams,
            bytes_per_priority: [0; 5],
            weights: [16, 8, 4, 2, 1], // Realtime gets 16x, bulk gets 1x
            round: 0,
        }
    }

    /// Add or update a stream
    pub fn add_stream(&mut self, entry: StreamEntry) {
        if self.queue.len() >= self.max_streams {
            // Remove lowest priority stream
            let entries: Vec<_> = self.queue.drain().collect();
            let mut entries = entries;
            entries.sort_by(|a, b| b.priority.cmp(&a.priority));
            entries.pop(); // Remove lowest
            for e in entries {
                self.queue.push(e);
            }
        }
        self.queue.push(entry);
    }

    /// Remove a stream
    pub fn remove_stream(&mut self, stream_id: u64) {
        let entries: Vec<_> = self
            .queue
            .drain()
            .filter(|e| e.stream_id != stream_id)
            .collect();
        for e in entries {
            self.queue.push(e);
        }
    }

    /// Get next stream to send on
    pub fn next_stream(&mut self) -> Option<StreamEntry> {
        self.queue.pop()
    }

    /// Peek at next stream without removing
    pub fn peek(&self) -> Option<&StreamEntry> {
        self.queue.peek()
    }

    /// Get number of pending streams
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Check if scheduler has pending work
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Calculate bytes to allocate for a stream based on weighted fair queuing
    pub fn bytes_for_stream(&self, entry: &StreamEntry, available: usize) -> usize {
        let weight = self.weights[entry.priority as usize];
        let total_weight: usize = self.weights.iter().sum();

        // Weighted share, but cap at pending bytes
        let share = available * weight / total_weight;
        share.min(entry.pending_bytes)
    }

    /// Start a new scheduling round
    pub fn new_round(&mut self) {
        self.round += 1;
        self.bytes_per_priority = [0; 5];
    }

    /// Get statistics
    pub fn stats(&self) -> SchedulerStats {
        let mut by_priority = [0usize; 5];
        for entry in self.queue.iter() {
            by_priority[entry.priority as usize] += 1;
        }

        SchedulerStats {
            total_streams: self.queue.len(),
            by_priority,
            round: self.round,
        }
    }
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub total_streams: usize,
    pub by_priority: [usize; 5],
    pub round: u64,
}

/// Traffic classifier for automatic priority assignment
pub struct TrafficClassifier;

impl TrafficClassifier {
    /// Classify traffic based on port and protocol
    pub fn classify(dst_port: u16, protocol: &str) -> Priority {
        // Gaming ports
        if matches!(dst_port,
            3074 | // Xbox Live
            3478..=3480 | // PlayStation
            27015..=27030 | // Steam/Valve
            5060..=5061 | // SIP (VoIP)
            7777..=7800 | // Common game servers
            9000..=9010   // Various games
        ) {
            return Priority::Realtime;
        }

        // VoIP/RTC
        if matches!(dst_port,
            5004 | // RTP
            5060..=5061 | // SIP
            10000..=20000 // RTP range
        ) {
            return Priority::Realtime;
        }

        // Interactive web
        if matches!(dst_port, 80 | 443 | 8080 | 8443) {
            if protocol == "QUIC" || protocol == "HTTP/3" {
                return Priority::Interactive;
            }
            return Priority::Normal;
        }

        // DNS
        if dst_port == 53 {
            return Priority::Interactive;
        }

        // Email, FTP, etc.
        if matches!(dst_port, 25 | 110 | 143 | 993 | 995 | 21 | 22) {
            return Priority::Background;
        }

        // Bulk transfer ports
        if matches!(dst_port, 6881..=6889 | 51413) {
            // BitTorrent
            return Priority::Bulk;
        }

        Priority::Normal
    }

    /// Classify based on packet characteristics
    pub fn classify_packet(packet_size: usize, is_retransmit: bool) -> Priority {
        // Small packets are usually interactive
        if packet_size < 100 {
            return Priority::Interactive;
        }

        // Retransmits are high priority (recovery)
        if is_retransmit {
            return Priority::Interactive;
        }

        // Large packets are usually bulk
        if packet_size > 1200 {
            return Priority::Background;
        }

        Priority::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        let realtime = StreamEntry {
            stream_id: 1,
            priority: Priority::Realtime,
            incremental: false,
            pending_bytes: 100,
            deadline_ms: None,
            created_at: 0,
        };

        let bulk = StreamEntry {
            stream_id: 2,
            priority: Priority::Bulk,
            incremental: true,
            pending_bytes: 10000,
            deadline_ms: None,
            created_at: 0,
        };

        // Realtime should be "greater" (come first in max-heap)
        assert!(realtime > bulk);
    }

    #[test]
    fn test_scheduler() {
        let mut scheduler = PriorityScheduler::new(100);

        scheduler.add_stream(StreamEntry {
            stream_id: 1,
            priority: Priority::Bulk,
            incremental: true,
            pending_bytes: 10000,
            deadline_ms: None,
            created_at: 0,
        });

        scheduler.add_stream(StreamEntry {
            stream_id: 2,
            priority: Priority::Realtime,
            incremental: false,
            pending_bytes: 100,
            deadline_ms: Some(10),
            created_at: 1,
        });

        // Realtime should come first
        let next = scheduler.next_stream().unwrap();
        assert_eq!(next.stream_id, 2);
        assert_eq!(next.priority, Priority::Realtime);
    }

    #[test]
    fn test_traffic_classifier() {
        assert_eq!(TrafficClassifier::classify(3074, "UDP"), Priority::Realtime);
        assert_eq!(
            TrafficClassifier::classify(443, "QUIC"),
            Priority::Interactive
        );
        assert_eq!(TrafficClassifier::classify(6881, "TCP"), Priority::Bulk);
    }
}
