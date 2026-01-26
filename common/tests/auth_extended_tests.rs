//! Extended tests for auth module

use oxidize_common::auth::{
    generate_api_credentials, generate_app_keypair, AuthError, AuthPayload, ClientAuthConfig,
    ServerAuthConfig,
};

// ============================================================================
// Key Generation Tests
// ============================================================================

#[test]
fn test_generate_app_keypair_format() {
    let (private_hex, public_hex) = generate_app_keypair();

    // Both should be 64 hex chars (32 bytes)
    assert_eq!(private_hex.len(), 64);
    assert_eq!(public_hex.len(), 64);

    // Should be valid hex
    assert!(hex::decode(&private_hex).is_ok());
    assert!(hex::decode(&public_hex).is_ok());
}

#[test]
fn test_generate_app_keypair_unique() {
    let (private1, public1) = generate_app_keypair();
    let (private2, public2) = generate_app_keypair();

    // Each call should generate unique keys
    assert_ne!(private1, private2);
    assert_ne!(public1, public2);
}

#[test]
fn test_generate_api_credentials_format() {
    let (api_key, api_secret) = generate_api_credentials();

    assert_eq!(api_key.len(), 64);
    assert_eq!(api_secret.len(), 64);

    assert!(hex::decode(&api_key).is_ok());
    assert!(hex::decode(&api_secret).is_ok());
}

#[test]
fn test_generate_api_credentials_unique() {
    let (key1, secret1) = generate_api_credentials();
    let (key2, secret2) = generate_api_credentials();

    assert_ne!(key1, key2);
    assert_ne!(secret1, secret2);
}

// ============================================================================
// ServerAuthConfig Tests
// ============================================================================

#[test]
fn test_server_auth_config_new() {
    let (_, public_hex) = generate_app_keypair();
    let (_, api_secret) = generate_api_credentials();

    let config = ServerAuthConfig::new(&public_hex, &api_secret);
    assert!(config.is_ok());

    let config = config.unwrap();
    assert!(config.require_api_key);
    assert_eq!(config.max_timestamp_age_secs, 300);
}

#[test]
fn test_server_auth_config_invalid_public_key() {
    let (_, api_secret) = generate_api_credentials();

    // Too short
    let result = ServerAuthConfig::new("abcd", &api_secret);
    assert!(matches!(result, Err(AuthError::MalformedData)));

    // Not valid hex
    let result = ServerAuthConfig::new(&"zz".repeat(32), &api_secret);
    assert!(matches!(result, Err(AuthError::MalformedData)));
}

#[test]
fn test_server_auth_config_invalid_api_secret() {
    let (_, public_hex) = generate_app_keypair();

    // Too short
    let result = ServerAuthConfig::new(&public_hex, "abcd");
    assert!(matches!(result, Err(AuthError::MalformedData)));
}

#[test]
fn test_server_auth_config_from_bytes() {
    let (_, public_hex) = generate_app_keypair();
    let (_, api_secret_hex) = generate_api_credentials();

    let public_bytes: [u8; 32] = hex::decode(&public_hex).unwrap().try_into().unwrap();
    let api_secret: [u8; 32] = hex::decode(&api_secret_hex).unwrap().try_into().unwrap();

    let config = ServerAuthConfig::from_bytes(public_bytes, api_secret);
    assert!(config.is_ok());
}

// ============================================================================
// ClientAuthConfig Tests
// ============================================================================

#[test]
fn test_client_auth_config_new() {
    let (private_hex, _) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();

    let config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret);
    assert!(config.is_ok());
}

#[test]
fn test_client_auth_config_invalid_signing_key() {
    let (api_key, api_secret) = generate_api_credentials();

    // Too short
    let result = ClientAuthConfig::new("abcd", &api_key, &api_secret);
    assert!(matches!(result, Err(AuthError::MalformedData)));
}

#[test]
fn test_client_auth_config_from_bytes() {
    let (private_hex, _) = generate_app_keypair();
    let (api_key_hex, api_secret_hex) = generate_api_credentials();

    let signing_key: [u8; 32] = hex::decode(&private_hex).unwrap().try_into().unwrap();
    let api_key: [u8; 32] = hex::decode(&api_key_hex).unwrap().try_into().unwrap();
    let api_secret: [u8; 32] = hex::decode(&api_secret_hex).unwrap().try_into().unwrap();

    let config = ClientAuthConfig::from_bytes(signing_key, api_key, api_secret);
    // from_bytes doesn't return Result
    assert_eq!(config.api_key, api_key);
}

// ============================================================================
// AuthPayload Tests
// ============================================================================

#[test]
fn test_auth_payload_encoded_size() {
    assert_eq!(AuthPayload::ENCODED_SIZE, 168);
}

#[test]
fn test_auth_payload_create() {
    let (private_hex, _) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();

    let client_config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret).unwrap();
    let client_id = [42u8; 32];

    let payload = AuthPayload::create(client_id, &client_config);
    assert_eq!(payload.client_id, client_id);
    assert!(payload.timestamp > 0);
}

#[test]
fn test_auth_payload_encode_decode() {
    let (private_hex, _) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();

    let client_config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret).unwrap();
    let client_id = [123u8; 32];

    let payload = AuthPayload::create(client_id, &client_config);

    // Encode
    let mut buf = [0u8; 256];
    let len = payload.encode(&mut buf);
    assert_eq!(len, AuthPayload::ENCODED_SIZE);

    // Decode
    let decoded = AuthPayload::decode(&buf[..len]).unwrap();
    assert_eq!(decoded.client_id, client_id);
    assert_eq!(decoded.timestamp, payload.timestamp);
    assert_eq!(decoded.api_key, payload.api_key);
}

#[test]
fn test_auth_payload_encode_buffer_too_small() {
    let (private_hex, _) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();

    let client_config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret).unwrap();
    let payload = AuthPayload::create([0u8; 32], &client_config);

    // Buffer too small
    let mut small_buf = [0u8; 50];
    let len = payload.encode(&mut small_buf);
    assert_eq!(len, 0);
}

#[test]
fn test_auth_payload_decode_buffer_too_small() {
    let small_buf = [0u8; 50];
    let result = AuthPayload::decode(&small_buf);
    assert!(result.is_none());
}

#[test]
fn test_auth_payload_verify_success() {
    let (private_hex, public_hex) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();

    let client_config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret).unwrap();
    let server_config = ServerAuthConfig::new(&public_hex, &api_secret).unwrap();

    let payload = AuthPayload::create([1u8; 32], &client_config);
    let result = payload.verify(&server_config);
    assert!(result.is_ok());
}

#[test]
fn test_auth_payload_verify_wrong_public_key() {
    let (private_hex, _) = generate_app_keypair();
    let (_, wrong_public) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();

    let client_config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret).unwrap();
    let server_config = ServerAuthConfig::new(&wrong_public, &api_secret).unwrap();

    let payload = AuthPayload::create([1u8; 32], &client_config);
    let result = payload.verify(&server_config);
    assert_eq!(result, Err(AuthError::InvalidAppSignature));
}

#[test]
fn test_auth_payload_verify_wrong_api_secret() {
    let (private_hex, public_hex) = generate_app_keypair();
    let (api_key, api_secret) = generate_api_credentials();
    let (_, wrong_secret) = generate_api_credentials();

    let client_config = ClientAuthConfig::new(&private_hex, &api_key, &api_secret).unwrap();
    let server_config = ServerAuthConfig::new(&public_hex, &wrong_secret).unwrap();

    let payload = AuthPayload::create([1u8; 32], &client_config);
    let result = payload.verify(&server_config);
    assert_eq!(result, Err(AuthError::InvalidApiSignature));
}

// ============================================================================
// AuthError Tests
// ============================================================================

#[test]
fn test_auth_error_display() {
    assert_eq!(
        format!("{}", AuthError::InvalidAppSignature),
        "Invalid app signature"
    );
    assert_eq!(format!("{}", AuthError::InvalidApiKey), "Invalid API key");
    assert_eq!(
        format!("{}", AuthError::InvalidApiSignature),
        "Invalid API signature"
    );
    assert_eq!(
        format!("{}", AuthError::TimestampExpired),
        "Timestamp expired"
    );
    assert_eq!(
        format!("{}", AuthError::TimestampInFuture),
        "Timestamp in future"
    );
    assert_eq!(
        format!("{}", AuthError::MalformedData),
        "Malformed authentication data"
    );
    assert_eq!(format!("{}", AuthError::ApiKeyRevoked), "API key revoked");
    assert_eq!(format!("{}", AuthError::ApiKeyExpired), "API key expired");
    assert_eq!(
        format!("{}", AuthError::RateLimitExceeded),
        "Rate limit exceeded"
    );
}

#[test]
fn test_auth_error_eq() {
    assert_eq!(
        AuthError::InvalidAppSignature,
        AuthError::InvalidAppSignature
    );
    assert_ne!(AuthError::InvalidAppSignature, AuthError::InvalidApiKey);
}
