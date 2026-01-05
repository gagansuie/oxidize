use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageType {
    Connect,
    ConnectAck,
    Data,
    DataAck,
    Ping,
    Pong,
    Disconnect,
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

    pub fn encode(&self) -> Result<Bytes> {
        let json = serde_json::to_vec(self)?;
        let mut buf = BytesMut::with_capacity(4 + json.len());
        buf.put_u32(json.len() as u32);
        buf.put_slice(&json);
        Ok(buf.freeze())
    }

    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.remaining() < 4 {
            return Err(anyhow!("Insufficient data for length"));
        }
        let len = data.get_u32() as usize;
        if data.remaining() < len {
            return Err(anyhow!("Insufficient data for message"));
        }
        let json_data = data.split_to(len);
        let message: RelayMessage = serde_json::from_slice(&json_data)?;
        Ok(message)
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
