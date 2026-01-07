use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

/// Binary wire format constants
/// Header: [len:4][type:1][flags:1][conn_id:8][seq:8] = 22 bytes
const HEADER_SIZE: usize = 22;
const FLAG_COMPRESSED: u8 = 0x01;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Connect = 0,
    ConnectAck = 1,
    Data = 2,
    DataAck = 3,
    Ping = 4,
    Pong = 5,
    Disconnect = 6,
}

impl MessageType {
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Connect),
            1 => Some(Self::ConnectAck),
            2 => Some(Self::Data),
            3 => Some(Self::DataAck),
            4 => Some(Self::Ping),
            5 => Some(Self::Pong),
            6 => Some(Self::Disconnect),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMessage {
    pub msg_type: MessageType,
    pub connection_id: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub compressed: bool,
}

impl RelayMessage {
    pub fn new(msg_type: MessageType, connection_id: u64, sequence: u64, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            connection_id,
            sequence,
            payload,
            compressed: false,
        }
    }

    pub fn connect(connection_id: u64) -> Self {
        Self::new(MessageType::Connect, connection_id, 0, vec![])
    }

    pub fn connect_ack(connection_id: u64) -> Self {
        Self::new(MessageType::ConnectAck, connection_id, 0, vec![])
    }

    pub fn data(connection_id: u64, sequence: u64, payload: Vec<u8>) -> Self {
        Self::new(MessageType::Data, connection_id, sequence, payload)
    }

    pub fn data_ack(connection_id: u64, sequence: u64) -> Self {
        Self::new(MessageType::DataAck, connection_id, sequence, vec![])
    }

    pub fn ping(connection_id: u64) -> Self {
        Self::new(MessageType::Ping, connection_id, 0, vec![])
    }

    pub fn pong(connection_id: u64) -> Self {
        Self::new(MessageType::Pong, connection_id, 0, vec![])
    }

    pub fn disconnect(connection_id: u64) -> Self {
        Self::new(MessageType::Disconnect, connection_id, 0, vec![])
    }

    /// Encode message to binary format (zero-copy where possible)
    /// Format: [total_len:4][type:1][flags:1][conn_id:8][seq:8][payload:N]
    #[inline]
    pub fn encode(&self) -> Result<Bytes> {
        let payload_len = self.payload.len();
        let total_len = HEADER_SIZE - 4 + payload_len; // exclude length field itself

        let mut buf = BytesMut::with_capacity(HEADER_SIZE + payload_len);

        // Length prefix (total bytes after this field)
        buf.put_u32(total_len as u32);
        // Message type
        buf.put_u8(self.msg_type as u8);
        // Flags
        let flags = if self.compressed { FLAG_COMPRESSED } else { 0 };
        buf.put_u8(flags);
        // Connection ID
        buf.put_u64(self.connection_id);
        // Sequence number
        buf.put_u64(self.sequence);
        // Payload
        buf.put_slice(&self.payload);

        Ok(buf.freeze())
    }

    /// Encode into a pre-allocated buffer (zero-copy)
    #[inline]
    pub fn encode_into(&self, buf: &mut BytesMut) {
        let payload_len = self.payload.len();
        let total_len = HEADER_SIZE - 4 + payload_len;

        buf.reserve(HEADER_SIZE + payload_len);
        buf.put_u32(total_len as u32);
        buf.put_u8(self.msg_type as u8);
        buf.put_u8(if self.compressed { FLAG_COMPRESSED } else { 0 });
        buf.put_u64(self.connection_id);
        buf.put_u64(self.sequence);
        buf.put_slice(&self.payload);
    }

    /// Decode message from binary format
    #[inline]
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.remaining() < 4 {
            return Err(anyhow!("Insufficient data for length"));
        }
        let len = data.get_u32() as usize;
        if data.remaining() < len {
            return Err(anyhow!("Insufficient data for message"));
        }

        // Minimum header after length: type(1) + flags(1) + conn_id(8) + seq(8) = 18
        if len < 18 {
            return Err(anyhow!("Message too short"));
        }

        let msg_type_byte = data.get_u8();
        let msg_type = MessageType::from_u8(msg_type_byte)
            .ok_or_else(|| anyhow!("Invalid message type: {}", msg_type_byte))?;

        let flags = data.get_u8();
        let compressed = (flags & FLAG_COMPRESSED) != 0;

        let connection_id = data.get_u64();
        let sequence = data.get_u64();

        let payload_len = len - 18;
        let payload = if payload_len > 0 {
            data.split_to(payload_len).to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            msg_type,
            connection_id,
            sequence,
            payload,
            compressed,
        })
    }

    /// Decode without copying payload (returns Bytes slice)
    #[inline]
    pub fn decode_zero_copy(mut data: Bytes) -> Result<(Self, Bytes)> {
        if data.remaining() < 4 {
            return Err(anyhow!("Insufficient data for length"));
        }
        let len = data.get_u32() as usize;
        if data.remaining() < len {
            return Err(anyhow!("Insufficient data for message"));
        }

        if len < 18 {
            return Err(anyhow!("Message too short"));
        }

        let msg_type_byte = data.get_u8();
        let msg_type = MessageType::from_u8(msg_type_byte)
            .ok_or_else(|| anyhow!("Invalid message type: {}", msg_type_byte))?;

        let flags = data.get_u8();
        let compressed = (flags & FLAG_COMPRESSED) != 0;

        let connection_id = data.get_u64();
        let sequence = data.get_u64();

        let payload_len = len - 18;
        let payload_bytes = if payload_len > 0 {
            data.split_to(payload_len)
        } else {
            Bytes::new()
        };

        let msg = Self {
            msg_type,
            connection_id,
            sequence,
            payload: Vec::new(), // Empty, use payload_bytes instead
            compressed,
        };

        Ok((msg, payload_bytes))
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: u64,
    pub destination: String,
    pub port: u16,
    pub created_at: std::time::Instant,
}

impl ConnectionInfo {
    pub fn new(id: u64, destination: String, port: u16) -> Self {
        Self {
            id,
            destination,
            port,
            created_at: std::time::Instant::now(),
        }
    }
}

/// Stream framer for handling partial reads and multiple messages per buffer.
/// Critical for correct QUIC stream handling where reads may be fragmented.
#[derive(Debug)]
pub struct MessageFramer {
    buffer: BytesMut,
}

impl Default for MessageFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageFramer {
    /// Create a new framer with default capacity
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(65536),
        }
    }

    /// Create a framer with specified initial capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Append new data to the internal buffer
    #[inline]
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to decode the next complete message from the buffer.
    /// Returns None if more data is needed.
    #[inline]
    pub fn try_decode(&mut self) -> Result<Option<RelayMessage>> {
        if self.buffer.len() < 4 {
            return Ok(None); // Need more data for length
        }

        // Peek at length without consuming
        let len = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;

        let total_needed = 4 + len;
        if self.buffer.len() < total_needed {
            return Ok(None); // Need more data for complete message
        }

        // We have a complete message, decode it
        let msg_bytes = self.buffer.split_to(total_needed).freeze();
        RelayMessage::decode(msg_bytes).map(Some)
    }

    /// Decode all complete messages from the buffer
    #[inline]
    pub fn decode_all(&mut self) -> Vec<Result<RelayMessage>> {
        let mut messages = Vec::new();
        loop {
            match self.try_decode() {
                Ok(Some(msg)) => messages.push(Ok(msg)),
                Ok(None) => break,
                Err(e) => {
                    messages.push(Err(e));
                    break; // Stop on error
                }
            }
        }
        messages
    }

    /// Check if there's pending data in the buffer
    #[inline]
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Get the amount of pending data
    #[inline]
    pub fn pending_len(&self) -> usize {
        self.buffer.len()
    }

    /// Clear the buffer (e.g., on connection reset)
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Batch encoder for sending multiple messages efficiently
pub struct MessageBatch {
    buffer: BytesMut,
    count: usize,
}

impl Default for MessageBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageBatch {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(65536),
            count: 0,
        }
    }

    /// Add a message to the batch
    #[inline]
    pub fn push(&mut self, msg: &RelayMessage) {
        msg.encode_into(&mut self.buffer);
        self.count += 1;
    }

    /// Get the number of messages in the batch
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the batch is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Consume the batch and return the encoded bytes
    #[inline]
    pub fn finish(self) -> Bytes {
        self.buffer.freeze()
    }

    /// Get the current size in bytes
    #[inline]
    pub fn byte_len(&self) -> usize {
        self.buffer.len()
    }

    /// Clear the batch for reuse
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_roundtrip() {
        let msg = RelayMessage::data(123, 456, vec![1, 2, 3, 4, 5]);
        let encoded = msg.encode().unwrap();
        let decoded = RelayMessage::decode(encoded).unwrap();

        assert_eq!(decoded.msg_type, MessageType::Data);
        assert_eq!(decoded.connection_id, 123);
        assert_eq!(decoded.sequence, 456);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_binary_size_improvement() {
        // Compare binary vs JSON size
        let msg = RelayMessage::data(u64::MAX, u64::MAX, vec![0u8; 1400]);
        let binary = msg.encode().unwrap();

        // Binary: 22 header + 1400 payload = 1422 bytes
        assert_eq!(binary.len(), 22 + 1400);

        // JSON would be much larger due to base64 encoding of payload
        // and string representation of u64s
    }

    #[test]
    fn test_framer_partial_reads() {
        let mut framer = MessageFramer::new();

        let msg1 = RelayMessage::connect(1);
        let msg2 = RelayMessage::ping(2);
        let encoded1 = msg1.encode().unwrap();
        let encoded2 = msg2.encode().unwrap();

        // Send first message in two parts
        let (part1, part2) = encoded1.split_at(10);
        framer.extend(part1);
        assert!(framer.try_decode().unwrap().is_none());

        framer.extend(part2);
        let decoded1 = framer.try_decode().unwrap().unwrap();
        assert_eq!(decoded1.msg_type, MessageType::Connect);
        assert_eq!(decoded1.connection_id, 1);

        // Send second message all at once
        framer.extend(&encoded2);
        let decoded2 = framer.try_decode().unwrap().unwrap();
        assert_eq!(decoded2.msg_type, MessageType::Ping);
        assert_eq!(decoded2.connection_id, 2);
    }

    #[test]
    fn test_framer_multiple_messages() {
        let mut framer = MessageFramer::new();

        // Encode multiple messages into one buffer
        let mut combined = BytesMut::new();
        for i in 0..5 {
            let msg = RelayMessage::data(i, i * 10, vec![i as u8; 100]);
            msg.encode_into(&mut combined);
        }

        // Feed all at once
        framer.extend(&combined);

        // Decode all
        let messages = framer.decode_all();
        assert_eq!(messages.len(), 5);

        for (i, result) in messages.into_iter().enumerate() {
            let msg = result.unwrap();
            assert_eq!(msg.connection_id, i as u64);
            assert_eq!(msg.sequence, (i * 10) as u64);
        }
    }

    #[test]
    fn test_message_batch() {
        let mut batch = MessageBatch::new();

        batch.push(&RelayMessage::connect(1));
        batch.push(&RelayMessage::data(1, 1, vec![1, 2, 3]));
        batch.push(&RelayMessage::ping(1));

        assert_eq!(batch.len(), 3);

        let encoded = batch.finish();

        // Decode with framer
        let mut framer = MessageFramer::new();
        framer.extend(&encoded);

        let messages = framer.decode_all();
        assert_eq!(messages.len(), 3);
    }

    #[test]
    fn test_compressed_flag() {
        let mut msg = RelayMessage::data(1, 1, vec![1, 2, 3]);
        msg.compressed = true;

        let encoded = msg.encode().unwrap();
        let decoded = RelayMessage::decode(encoded).unwrap();

        assert!(decoded.compressed);
    }
}
