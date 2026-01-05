use oxidize_common::{MessageType, RelayMessage};

#[tokio::test]
async fn test_message_encoding() {
    let msg = RelayMessage::connect(123);
    let encoded = msg.encode().expect("Encoding failed");

    assert!(!encoded.is_empty());

    let decoded = RelayMessage::decode(encoded).expect("Decoding failed");
    assert_eq!(decoded.msg_type, MessageType::Connect);
    assert_eq!(decoded.connection_id, 123);
}

#[tokio::test]
async fn test_data_message_with_payload() {
    let payload = vec![1, 2, 3, 4, 5];
    let msg = RelayMessage::data(42, 10, payload.clone());

    let encoded = msg.encode().unwrap();
    let decoded = RelayMessage::decode(encoded).unwrap();

    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.sequence, 10);
}

#[test]
fn test_config_defaults() {
    use relay_server::config::Config;

    let config = Config::default();
    assert_eq!(config.max_connections, 10000);
    assert_eq!(config.enable_compression, true);
    assert_eq!(config.rate_limit_per_ip, 100);
}
