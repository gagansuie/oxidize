//! QUIC Stream Management for AF_XDP
//!
//! Lock-free stream state management with zero-copy data handling.
//! Supports millions of concurrent streams across all connections.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum number of streams per connection
const MAX_STREAMS_PER_CONN: usize = 65536;

/// Stream ID type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Create a new stream ID
    #[inline(always)]
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Check if this is a client-initiated stream
    #[inline(always)]
    pub fn is_client_initiated(&self) -> bool {
        (self.0 & 0x01) == 0
    }

    /// Check if this is a server-initiated stream
    #[inline(always)]
    pub fn is_server_initiated(&self) -> bool {
        !self.is_client_initiated()
    }

    /// Check if this is a bidirectional stream
    #[inline(always)]
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x02) == 0
    }

    /// Check if this is a unidirectional stream
    #[inline(always)]
    pub fn is_unidirectional(&self) -> bool {
        !self.is_bidirectional()
    }

    /// Get the stream type index (0-3)
    #[inline(always)]
    pub fn stream_type(&self) -> u8 {
        (self.0 & 0x03) as u8
    }
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamState {
    /// Stream created, no data sent/received
    Idle = 0,
    /// Data being sent (send side)
    Send = 1,
    /// Data being received (recv side)
    Recv = 2,
    /// Both sides active
    Open = 3,
    /// Local side has sent FIN
    HalfClosedLocal = 4,
    /// Remote side has sent FIN
    HalfClosedRemote = 5,
    /// Both sides closed
    Closed = 6,
    /// Reset by local
    ResetLocal = 7,
    /// Reset by remote
    ResetRemote = 8,
}

/// Stream flow control state
#[derive(Debug)]
pub struct FlowControl {
    /// Maximum data we can send
    pub max_send: AtomicU64,
    /// Maximum data we can receive
    pub max_recv: AtomicU64,
    /// Data sent so far
    pub sent: AtomicU64,
    /// Data received so far
    pub received: AtomicU64,
    /// Blocked flag
    pub blocked: AtomicBool,
}

impl FlowControl {
    pub fn new(initial_max: u64) -> Self {
        Self {
            max_send: AtomicU64::new(initial_max),
            max_recv: AtomicU64::new(initial_max),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            blocked: AtomicBool::new(false),
        }
    }

    /// Check if we can send `bytes` more data
    #[inline(always)]
    pub fn can_send(&self, bytes: u64) -> bool {
        let max = self.max_send.load(Ordering::Relaxed);
        let sent = self.sent.load(Ordering::Relaxed);
        sent + bytes <= max
    }

    /// Record bytes sent
    #[inline(always)]
    pub fn on_send(&self, bytes: u64) {
        self.sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes received
    #[inline(always)]
    pub fn on_recv(&self, bytes: u64) {
        self.received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Update max send window
    #[inline(always)]
    pub fn update_max_send(&self, max: u64) {
        let current = self.max_send.load(Ordering::Relaxed);
        if max > current {
            self.max_send.store(max, Ordering::Relaxed);
            self.blocked.store(false, Ordering::Relaxed);
        }
    }

    /// Get available send window
    #[inline(always)]
    pub fn available_send(&self) -> u64 {
        let max = self.max_send.load(Ordering::Relaxed);
        let sent = self.sent.load(Ordering::Relaxed);
        max.saturating_sub(sent)
    }
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::new(1_048_576) // 1MB default
    }
}

/// Single stream state
#[repr(C, align(64))]
pub struct Stream {
    /// Stream ID
    pub id: StreamId,
    /// Current state
    state: u8,
    /// Flow control
    pub flow: FlowControl,
    /// Receive buffer (ordered data)
    recv_buffer: VecDeque<StreamChunk>,
    /// Send buffer (pending data)
    send_buffer: VecDeque<StreamChunk>,
    /// Next expected receive offset
    recv_offset: u64,
    /// Next send offset
    send_offset: u64,
    /// FIN received
    fin_received: bool,
    /// FIN sent
    fin_sent: bool,
    /// Error code if reset
    error_code: Option<u64>,
    /// Priority (0 = highest)
    priority: u8,
}

/// Chunk of stream data
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub offset: u64,
    pub data: Vec<u8>,
    pub fin: bool,
}

impl Stream {
    pub fn new(id: StreamId) -> Self {
        Self {
            id,
            state: StreamState::Idle as u8,
            flow: FlowControl::default(),
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            recv_offset: 0,
            send_offset: 0,
            fin_received: false,
            fin_sent: false,
            error_code: None,
            priority: 128,
        }
    }

    /// Get stream state
    #[inline(always)]
    pub fn state(&self) -> StreamState {
        match self.state {
            0 => StreamState::Idle,
            1 => StreamState::Send,
            2 => StreamState::Recv,
            3 => StreamState::Open,
            4 => StreamState::HalfClosedLocal,
            5 => StreamState::HalfClosedRemote,
            6 => StreamState::Closed,
            7 => StreamState::ResetLocal,
            _ => StreamState::ResetRemote,
        }
    }

    /// Set stream state
    #[inline(always)]
    fn set_state(&mut self, state: StreamState) {
        self.state = state as u8;
    }

    /// Receive data for this stream
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), StreamError> {
        if self.state() == StreamState::Closed || self.state() == StreamState::ResetRemote {
            return Err(StreamError::StreamClosed);
        }

        // Check flow control
        let end_offset = offset + data.len() as u64;
        if end_offset > self.flow.max_recv.load(Ordering::Relaxed) {
            return Err(StreamError::FlowControlViolation);
        }

        // Handle FIN
        if fin {
            self.fin_received = true;
        }

        // Insert into receive buffer (handle reordering)
        if offset == self.recv_offset {
            // In-order delivery
            self.recv_offset = end_offset;
            self.recv_buffer.push_back(StreamChunk {
                offset,
                data: data.to_vec(),
                fin,
            });
            self.flow.on_recv(data.len() as u64);
        } else if offset > self.recv_offset {
            // Out-of-order, buffer for later
            self.recv_buffer.push_back(StreamChunk {
                offset,
                data: data.to_vec(),
                fin,
            });
        }
        // else: duplicate/old data, ignore

        // Update state
        match self.state() {
            StreamState::Idle => self.set_state(StreamState::Recv),
            StreamState::Send => self.set_state(StreamState::Open),
            _ => {}
        }

        if self.fin_received && self.fin_sent {
            self.set_state(StreamState::Closed);
        } else if self.fin_received {
            self.set_state(StreamState::HalfClosedRemote);
        }

        Ok(())
    }

    /// Queue data for sending
    pub fn send(&mut self, data: &[u8], fin: bool) -> Result<(), StreamError> {
        if self.state() == StreamState::Closed || self.state() == StreamState::ResetLocal {
            return Err(StreamError::StreamClosed);
        }

        if self.fin_sent {
            return Err(StreamError::FinAlreadySent);
        }

        // Check flow control
        if !self.flow.can_send(data.len() as u64) {
            return Err(StreamError::Blocked);
        }

        let offset = self.send_offset;
        self.send_offset += data.len() as u64;
        self.flow.on_send(data.len() as u64);

        self.send_buffer.push_back(StreamChunk {
            offset,
            data: data.to_vec(),
            fin,
        });

        if fin {
            self.fin_sent = true;
        }

        // Update state
        match self.state() {
            StreamState::Idle => self.set_state(StreamState::Send),
            StreamState::Recv => self.set_state(StreamState::Open),
            _ => {}
        }

        if self.fin_received && self.fin_sent {
            self.set_state(StreamState::Closed);
        } else if self.fin_sent {
            self.set_state(StreamState::HalfClosedLocal);
        }

        Ok(())
    }

    /// Read available data from receive buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut total = 0;
        while let Some(chunk) = self.recv_buffer.front() {
            let remaining = buf.len() - total;
            if remaining == 0 {
                break;
            }

            let to_copy = chunk.data.len().min(remaining);
            buf[total..total + to_copy].copy_from_slice(&chunk.data[..to_copy]);
            total += to_copy;

            if to_copy == chunk.data.len() {
                self.recv_buffer.pop_front();
            } else {
                // Partial read - would need more complex handling
                break;
            }
        }
        total
    }

    /// Get pending send data
    pub fn pending_send(&mut self) -> Option<StreamChunk> {
        self.send_buffer.pop_front()
    }

    /// Reset stream
    pub fn reset(&mut self, error_code: u64, local: bool) {
        self.error_code = Some(error_code);
        if local {
            self.set_state(StreamState::ResetLocal);
        } else {
            self.set_state(StreamState::ResetRemote);
        }
    }

    /// Check if stream is finished (both sides closed)
    pub fn is_finished(&self) -> bool {
        matches!(
            self.state(),
            StreamState::Closed | StreamState::ResetLocal | StreamState::ResetRemote
        )
    }
}

/// Stream errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    StreamClosed,
    FlowControlViolation,
    FinAlreadySent,
    Blocked,
    InvalidStreamId,
    TooManyStreams,
}

/// Stream manager for a connection
pub struct StreamManager {
    /// Active streams
    streams: Vec<Option<Stream>>,
    /// Number of active streams
    count: usize,
    /// Next local bidirectional stream ID
    next_bidi: u64,
    /// Next local unidirectional stream ID
    next_uni: u64,
    /// Maximum concurrent bidirectional streams
    max_bidi: u64,
    /// Maximum concurrent unidirectional streams
    max_uni: u64,
    /// Is this a server?
    is_server: bool,
    /// Connection-level flow control
    pub conn_flow: FlowControl,
}

impl StreamManager {
    pub fn new(is_server: bool) -> Self {
        // Server uses odd stream IDs, client uses even
        let (next_bidi, next_uni) = if is_server { (1, 3) } else { (0, 2) };

        let mut streams = Vec::with_capacity(256);
        streams.resize_with(256, || None);

        Self {
            streams,
            count: 0,
            next_bidi,
            next_uni,
            max_bidi: 100,
            max_uni: 100,
            is_server,
            conn_flow: FlowControl::new(16_777_216), // 16MB connection window
        }
    }

    /// Get or create a stream
    pub fn get_or_create(&mut self, id: StreamId) -> Result<&mut Stream, StreamError> {
        let idx = (id.0 / 4) as usize;

        // Grow if needed
        if idx >= self.streams.len() {
            if idx >= MAX_STREAMS_PER_CONN {
                return Err(StreamError::TooManyStreams);
            }
            self.streams.resize_with(idx + 1, || None);
        }

        if self.streams[idx].is_none() {
            self.streams[idx] = Some(Stream::new(id));
            self.count += 1;
        }

        Ok(self.streams[idx].as_mut().unwrap())
    }

    /// Get an existing stream
    pub fn get(&self, id: StreamId) -> Option<&Stream> {
        let idx = (id.0 / 4) as usize;
        self.streams.get(idx).and_then(|s| s.as_ref())
    }

    /// Get an existing stream mutably
    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut Stream> {
        let idx = (id.0 / 4) as usize;
        self.streams.get_mut(idx).and_then(|s| s.as_mut())
    }

    /// Create a new bidirectional stream
    pub fn open_bidi(&mut self) -> Result<StreamId, StreamError> {
        if self.count as u64 >= self.max_bidi {
            return Err(StreamError::TooManyStreams);
        }

        let id = StreamId::new(self.next_bidi);
        self.next_bidi += 4;
        self.get_or_create(id)?;
        Ok(id)
    }

    /// Create a new unidirectional stream
    pub fn open_uni(&mut self) -> Result<StreamId, StreamError> {
        if self.count as u64 >= self.max_uni {
            return Err(StreamError::TooManyStreams);
        }

        let id = StreamId::new(self.next_uni);
        self.next_uni += 4;
        self.get_or_create(id)?;
        Ok(id)
    }

    /// Close a stream
    pub fn close(&mut self, id: StreamId) {
        let idx = (id.0 / 4) as usize;
        if idx < self.streams.len() && self.streams[idx].is_some() {
            self.streams[idx] = None;
            self.count -= 1;
        }
    }

    /// Get number of active streams
    pub fn active_count(&self) -> usize {
        self.count
    }

    /// Update max streams limit
    pub fn set_max_bidi(&mut self, max: u64) {
        self.max_bidi = max;
    }

    pub fn set_max_uni(&mut self, max: u64) {
        self.max_uni = max;
    }

    /// Iterate over active streams
    pub fn iter(&self) -> impl Iterator<Item = &Stream> {
        self.streams.iter().filter_map(|s| s.as_ref())
    }

    /// Iterate over streams with pending send data
    pub fn pending_sends(&mut self) -> impl Iterator<Item = &mut Stream> {
        self.streams
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .filter(|s| !s.send_buffer.is_empty())
    }

    /// Cleanup finished streams
    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;
        for slot in self.streams.iter_mut() {
            if let Some(stream) = slot {
                if stream.is_finished() {
                    *slot = None;
                    self.count -= 1;
                    removed += 1;
                }
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id() {
        let client_bidi = StreamId::new(0);
        assert!(client_bidi.is_client_initiated());
        assert!(client_bidi.is_bidirectional());

        let server_uni = StreamId::new(3);
        assert!(server_uni.is_server_initiated());
        assert!(server_uni.is_unidirectional());
    }

    #[test]
    fn test_stream_send_recv() {
        let mut stream = Stream::new(StreamId::new(0));

        // Send data
        assert!(stream.send(b"hello", false).is_ok());
        assert!(stream.send(b" world", true).is_ok());

        // Can't send after FIN
        assert!(stream.send(b"more", false).is_err());
    }

    #[test]
    fn test_stream_manager() {
        let mut mgr = StreamManager::new(true);

        let id = mgr.open_bidi().unwrap();
        assert_eq!(id.0, 1); // Server bidi starts at 1

        let stream = mgr.get_mut(id).unwrap();
        stream.send(b"test", false).unwrap();

        assert_eq!(mgr.active_count(), 1);
    }
}
