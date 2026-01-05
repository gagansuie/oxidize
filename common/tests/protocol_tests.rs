use oxidize_common::{MessageType, RelayMessage};

#[test]
fn test_message_encode_decode() {
    let original = RelayMessage::new(MessageType::Data, 42, 123, vec![1, 2, 3, 4, 5]);

    let encoded = original.encode().expect("Failed to encode");
    let decoded = RelayMessage::decode(encoded).expect("Failed to decode");

    assert_eq!(decoded.msg_type, original.msg_type);
    assert_eq!(decoded.connection_id, original.connection_id);
    assert_eq!(decoded.sequence, original.sequence);
    assert_eq!(decoded.payload, original.payload);
}

#[test]
fn test_connect_message() {
    let msg = RelayMessage::connect(999);
    assert_eq!(msg.msg_type, MessageType::Connect);
    assert_eq!(msg.connection_id, 999);
    assert_eq!(msg.sequence, 0);
    assert!(msg.payload.is_empty());
}

#[test]
fn test_data_ack_message() {
    let msg = RelayMessage::data_ack(100, 50);
    assert_eq!(msg.msg_type, MessageType::DataAck);
    assert_eq!(msg.connection_id, 100);
    assert_eq!(msg.sequence, 50);
}

#[test]
fn test_message_roundtrip() {
    let messages = vec![
        RelayMessage::connect(1),
        RelayMessage::connect_ack(1),
        RelayMessage::data(2, 10, vec![0xDE, 0xAD, 0xBE, 0xEF]),
        RelayMessage::data_ack(2, 10),
        RelayMessage::ping(3),
        RelayMessage::pong(3),
        RelayMessage::disconnect(4),
    ];

    for original in messages {
        let encoded = original.encode().unwrap();
        let decoded = RelayMessage::decode(encoded).unwrap();
        assert_eq!(decoded.msg_type, original.msg_type);
        assert_eq!(decoded.connection_id, original.connection_id);
    }
}
