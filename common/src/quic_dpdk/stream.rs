//! QUIC Stream Multiplexing
//!
//! High-performance stream management for QUIC with zero-copy data transfer.
//! Supports bidirectional and unidirectional streams as per RFC 9000.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};

/// Stream ID type
pub type StreamId = u64;

/// Stream type (client/server, bidirectional/unidirectional)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    ClientBidi,
    ServerBidi,
    ClientUni,
    ServerUni,
}

impl StreamType {
    /// Get stream type from stream ID
    pub fn from_id(id: StreamId) -> Self {
        match id & 0x03 {
            0x00 => StreamType::ClientBidi,
            0x01 => StreamType::ServerBidi,
            0x02 => StreamType::ClientUni,
            0x03 => StreamType::ServerUni,
            _ => unreachable!(),
        }
    }

    /// Check if this is a client-initiated stream
    pub fn is_client_initiated(&self) -> bool {
        matches!(self, StreamType::ClientBidi | StreamType::ClientUni)
    }

    /// Check if this is bidirectional
    pub fn is_bidirectional(&self) -> bool {
        matches!(self, StreamType::ClientBidi | StreamType::ServerBidi)
    }
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Ready to send/receive
    Open,
    /// Local side finished sending
    HalfClosedLocal,
    /// Remote side finished sending
    HalfClosedRemote,
    /// Both sides finished
    Closed,
    /// Reset by local
    ResetLocal,
    /// Reset by remote
    ResetRemote,
}

/// A single QUIC stream
pub struct QuicStream {
    /// Stream ID
    pub id: StreamId,
    /// Stream type
    pub stream_type: StreamType,
    /// Current state
    pub state: StreamState,
    /// Receive buffer (ordered by offset)
    recv_buffer: BTreeMap<u64, Vec<u8>>,
    /// Next expected receive offset
    recv_offset: u64,
    /// Send buffer
    send_buffer: VecDeque<u8>,
    /// Next send offset
    send_offset: u64,
    /// Maximum data we can send (flow control)
    max_send_data: u64,
    /// Maximum data peer can send (flow control)
    max_recv_data: u64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// FIN received
    fin_received: bool,
    /// FIN sent
    fin_sent: bool,
}

impl QuicStream {
    pub fn new(id: StreamId, initial_max_data: u64) -> Self {
        Self {
            id,
            stream_type: StreamType::from_id(id),
            state: StreamState::Open,
            recv_buffer: BTreeMap::new(),
            recv_offset: 0,
            send_buffer: VecDeque::new(),
            send_offset: 0,
            max_send_data: initial_max_data,
            max_recv_data: initial_max_data,
            bytes_sent: 0,
            bytes_received: 0,
            fin_received: false,
            fin_sent: false,
        }
    }

    /// Write data to send buffer
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.state == StreamState::Closed
            || self.state == StreamState::HalfClosedLocal
            || self.state == StreamState::ResetLocal
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream closed for writing",
            ));
        }

        // Check flow control
        let available = self.max_send_data.saturating_sub(self.bytes_sent);
        let to_write = data.len().min(available as usize);

        if to_write == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Flow control limit",
            ));
        }

        self.send_buffer.extend(&data[..to_write]);
        Ok(to_write)
    }

    /// Read data from receive buffer
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.state == StreamState::Closed || self.state == StreamState::ResetRemote {
            return Ok(0); // EOF
        }

        // Read contiguous data from recv_buffer
        let mut total_read = 0;
        while total_read < buf.len() {
            if let Some(data) = self.recv_buffer.remove(&self.recv_offset) {
                let to_copy = data.len().min(buf.len() - total_read);
                buf[total_read..total_read + to_copy].copy_from_slice(&data[..to_copy]);
                total_read += to_copy;
                self.recv_offset += to_copy as u64;

                // Put back remaining data if any
                if to_copy < data.len() {
                    self.recv_buffer
                        .insert(self.recv_offset, data[to_copy..].to_vec());
                }
            } else {
                break;
            }
        }

        if total_read == 0 && !self.fin_received {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "No data available",
            ));
        }

        Ok(total_read)
    }

    /// Receive data from a STREAM frame
    pub fn receive_data(&mut self, offset: u64, data: &[u8], fin: bool) -> io::Result<()> {
        if self.state == StreamState::Closed || self.state == StreamState::ResetRemote {
            return Ok(());
        }

        // Check if data exceeds flow control limit
        let end_offset = offset + data.len() as u64;
        if end_offset > self.max_recv_data {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Flow control violation",
            ));
        }

        // Store data (may be out of order)
        if offset >= self.recv_offset {
            self.recv_buffer.insert(offset, data.to_vec());
        }

        self.bytes_received = self.bytes_received.max(end_offset);

        if fin {
            self.fin_received = true;
            if self.fin_sent {
                self.state = StreamState::Closed;
            } else {
                self.state = StreamState::HalfClosedRemote;
            }
        }

        Ok(())
    }

    /// Get data to send in a STREAM frame
    pub fn get_send_data(&mut self, max_len: usize) -> Option<(u64, Vec<u8>, bool)> {
        if self.send_buffer.is_empty() && !self.fin_sent {
            return None;
        }

        let available = self.max_send_data.saturating_sub(self.bytes_sent);
        let to_send = max_len.min(available as usize).min(self.send_buffer.len());

        if to_send == 0 && !self.fin_sent && self.send_buffer.is_empty() {
            return None;
        }

        let offset = self.send_offset;
        let data: Vec<u8> = self.send_buffer.drain(..to_send).collect();
        self.send_offset += data.len() as u64;
        self.bytes_sent += data.len() as u64;

        let fin = self.send_buffer.is_empty() && self.fin_sent;

        Some((offset, data, fin))
    }

    /// Mark stream for FIN
    pub fn finish(&mut self) {
        if self.state == StreamState::Open {
            self.fin_sent = true;
            if self.fin_received {
                self.state = StreamState::Closed;
            } else {
                self.state = StreamState::HalfClosedLocal;
            }
        }
    }

    /// Reset the stream
    pub fn reset(&mut self, _error_code: u64) {
        self.state = StreamState::ResetLocal;
        self.send_buffer.clear();
    }

    /// Update max send data (flow control update from peer)
    pub fn update_max_send_data(&mut self, max_data: u64) {
        self.max_send_data = self.max_send_data.max(max_data);
    }

    /// Check if stream has data to send
    pub fn has_pending_data(&self) -> bool {
        !self.send_buffer.is_empty() || (self.fin_sent && self.state != StreamState::Closed)
    }

    /// Check if stream is finished
    pub fn is_finished(&self) -> bool {
        self.state == StreamState::Closed
            || self.state == StreamState::ResetLocal
            || self.state == StreamState::ResetRemote
    }
}

/// Stream manager for a connection
pub struct StreamManager {
    /// All streams
    streams: RwLock<BTreeMap<StreamId, Mutex<QuicStream>>>,
    /// Next client bidirectional stream ID
    next_client_bidi: AtomicU64,
    /// Next client unidirectional stream ID
    next_client_uni: AtomicU64,
    /// Next server bidirectional stream ID
    next_server_bidi: AtomicU64,
    /// Next server unidirectional stream ID
    next_server_uni: AtomicU64,
    /// Is this the server side?
    is_server: bool,
    /// Maximum concurrent bidirectional streams
    max_bidi_streams: u64,
    /// Maximum concurrent unidirectional streams
    max_uni_streams: u64,
    /// Initial max stream data
    initial_max_stream_data: u64,
}

impl StreamManager {
    pub fn new(is_server: bool, max_bidi: u64, max_uni: u64, initial_max_data: u64) -> Self {
        Self {
            streams: RwLock::new(BTreeMap::new()),
            next_client_bidi: AtomicU64::new(0),
            next_client_uni: AtomicU64::new(2),
            next_server_bidi: AtomicU64::new(1),
            next_server_uni: AtomicU64::new(3),
            is_server,
            max_bidi_streams: max_bidi,
            max_uni_streams: max_uni,
            initial_max_stream_data: initial_max_data,
        }
    }

    /// Open a new bidirectional stream
    pub fn open_bidi(&self) -> io::Result<StreamId> {
        let id = if self.is_server {
            self.next_server_bidi.fetch_add(4, Ordering::SeqCst)
        } else {
            self.next_client_bidi.fetch_add(4, Ordering::SeqCst)
        };

        self.create_stream(id)?;
        Ok(id)
    }

    /// Open a new unidirectional stream
    pub fn open_uni(&self) -> io::Result<StreamId> {
        let id = if self.is_server {
            self.next_server_uni.fetch_add(4, Ordering::SeqCst)
        } else {
            self.next_client_uni.fetch_add(4, Ordering::SeqCst)
        };

        self.create_stream(id)?;
        Ok(id)
    }

    /// Create a stream
    fn create_stream(&self, id: StreamId) -> io::Result<()> {
        let stream = QuicStream::new(id, self.initial_max_stream_data);
        let mut streams = self.streams.write();
        streams.insert(id, Mutex::new(stream));
        Ok(())
    }

    /// Get or create a stream (for receiving data on new stream)
    pub fn get_or_create(&self, id: StreamId) -> io::Result<()> {
        {
            let streams = self.streams.read();
            if streams.contains_key(&id) {
                return Ok(());
            }
        }
        self.create_stream(id)
    }

    /// Write to a stream
    pub fn write(&self, id: StreamId, data: &[u8]) -> io::Result<usize> {
        let streams = self.streams.read();
        match streams.get(&id) {
            Some(stream) => {
                let mut guard = stream.lock();
                guard.write(data)
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Stream not found")),
        }
    }

    /// Read from a stream
    pub fn read(&self, id: StreamId, buf: &mut [u8]) -> io::Result<usize> {
        let streams = self.streams.read();
        match streams.get(&id) {
            Some(stream) => {
                let mut guard = stream.lock();
                guard.read(buf)
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Stream not found")),
        }
    }

    /// Receive data for a stream
    pub fn receive_stream_data(
        &self,
        id: StreamId,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> io::Result<()> {
        self.get_or_create(id)?;
        let streams = self.streams.read();
        match streams.get(&id) {
            Some(stream) => {
                let mut guard = stream.lock();
                guard.receive_data(offset, data, fin)
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Stream not found")),
        }
    }

    /// Get streams with pending data to send
    pub fn get_sendable_streams(&self) -> Vec<StreamId> {
        let streams = self.streams.read();
        streams
            .iter()
            .filter(|(_, s)| s.lock().has_pending_data())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get send data for a stream
    pub fn get_stream_send_data(
        &self,
        id: StreamId,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>, bool)> {
        let streams = self.streams.read();
        let stream = streams.get(&id)?;
        let mut guard = stream.lock();
        guard.get_send_data(max_len)
    }

    /// Close a stream
    pub fn close_stream(&self, id: StreamId) {
        let streams = self.streams.read();
        if let Some(stream) = streams.get(&id) {
            stream.lock().finish();
        }
    }

    /// Reset a stream
    pub fn reset_stream(&self, id: StreamId, error_code: u64) {
        let streams = self.streams.read();
        if let Some(stream) = streams.get(&id) {
            stream.lock().reset(error_code);
        }
    }

    /// Get number of active streams
    pub fn active_stream_count(&self) -> usize {
        let streams = self.streams.read();
        streams.values().filter(|s| !s.lock().is_finished()).count()
    }

    /// Cleanup finished streams
    pub fn cleanup_finished(&self) {
        let mut streams = self.streams.write();
        streams.retain(|_, s| !s.lock().is_finished());
    }
}

/// Stream frame for wire format
#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub stream_id: StreamId,
    pub offset: u64,
    pub data: Vec<u8>,
    pub fin: bool,
}

impl StreamFrame {
    /// Encode stream frame to bytes
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // Frame type (0x08-0x0f depending on flags)
        let mut frame_type = 0x08u8;
        if self.offset > 0 {
            frame_type |= 0x04; // OFF bit
        }
        if !self.data.is_empty() {
            frame_type |= 0x02; // LEN bit
        }
        if self.fin {
            frame_type |= 0x01; // FIN bit
        }
        buf.push(frame_type);

        // Stream ID (varint)
        encode_varint(self.stream_id, buf);

        // Offset (varint, if present)
        if self.offset > 0 {
            encode_varint(self.offset, buf);
        }

        // Length (varint, if present)
        if !self.data.is_empty() {
            encode_varint(self.data.len() as u64, buf);
        }

        // Data
        buf.extend_from_slice(&self.data);
    }

    /// Decode stream frame from bytes
    pub fn decode(data: &[u8]) -> io::Result<(Self, usize)> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Empty frame"));
        }

        let frame_type = data[0];
        if !(0x08..=0x0f).contains(&frame_type) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not a STREAM frame",
            ));
        }

        let has_offset = frame_type & 0x04 != 0;
        let has_length = frame_type & 0x02 != 0;
        let fin = frame_type & 0x01 != 0;

        let mut pos = 1;

        // Stream ID
        let (stream_id, len) = decode_varint(&data[pos..])?;
        pos += len;

        // Offset
        let offset = if has_offset {
            let (off, len) = decode_varint(&data[pos..])?;
            pos += len;
            off
        } else {
            0
        };

        // Length and data
        let frame_data = if has_length {
            let (data_len, len) = decode_varint(&data[pos..])?;
            pos += len;
            let end = pos + data_len as usize;
            if end > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated frame",
                ));
            }
            let d = data[pos..end].to_vec();
            pos = end;
            d
        } else {
            // Data extends to end of packet
            data[pos..].to_vec()
        };

        Ok((
            StreamFrame {
                stream_id,
                offset,
                data: frame_data,
                fin,
            },
            pos,
        ))
    }
}

/// Encode QUIC varint
fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    if value < 0x40 {
        buf.push(value as u8);
    } else if value < 0x4000 {
        buf.extend_from_slice(&((value as u16 | 0x4000).to_be_bytes()));
    } else if value < 0x40000000 {
        buf.extend_from_slice(&((value as u32 | 0x80000000).to_be_bytes()));
    } else {
        buf.extend_from_slice(&((value | 0xc000000000000000).to_be_bytes()));
    }
}

/// Decode QUIC varint
fn decode_varint(data: &[u8]) -> io::Result<(u64, usize)> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Empty varint"));
    }

    let first = data[0];
    let len = 1 << (first >> 6);

    if data.len() < len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Truncated varint",
        ));
    }

    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let v = u16::from_be_bytes([data[0], data[1]]);
            (v & 0x3fff) as u64
        }
        4 => {
            let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            (v & 0x3fffffff) as u64
        }
        8 => {
            let v = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            v & 0x3fffffffffffffff
        }
        _ => unreachable!(),
    };

    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_write_read() {
        let mut stream = QuicStream::new(0, 1024);

        let data = b"Hello, QUIC!";
        let written = stream.write(data).unwrap();
        assert_eq!(written, data.len());

        // Simulate receiving the data back
        stream.receive_data(0, data, false).unwrap();

        let mut buf = [0u8; 32];
        let read = stream.read(&mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }

    #[test]
    fn test_stream_frame_encode_decode() {
        let frame = StreamFrame {
            stream_id: 4,
            offset: 100,
            data: b"test data".to_vec(),
            fin: true,
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf);

        let (decoded, _) = StreamFrame::decode(&buf).unwrap();
        assert_eq!(decoded.stream_id, frame.stream_id);
        assert_eq!(decoded.offset, frame.offset);
        assert_eq!(decoded.data, frame.data);
        assert_eq!(decoded.fin, frame.fin);
    }
}
