//! Authentication Module
//!
//! Provides two-layer authentication for Oxidize relay servers:
//! 1. **App Signature** - Ed25519 signature proving traffic is from authorized builds
//! 2. **API Key** - Per-user/device authentication for access control
//!
//! # Open Source Deployment Model
//! This is an open source project - deployers generate their own keys:
//!
//! 1. Run `cargo run --package oxidize-common --example keygen` to generate keys
//! 2. Set `OXIDIZE_APP_SIGNING_KEY` env var when building clients
//! 3. Configure server with the public key and API secret
//! 4. Issue API keys to users from your backend
//!
//! **No secrets are committed to the repository.**

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Authentication error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// App signature verification failed
    InvalidAppSignature,
    /// API key not found or invalid
    InvalidApiKey,
    /// API key signature (HMAC) verification failed
    InvalidApiSignature,
    /// Timestamp too old (replay attack prevention)
    TimestampExpired,
    /// Timestamp in the future
    TimestampInFuture,
    /// Malformed authentication data
    MalformedData,
    /// API key has been revoked
    ApiKeyRevoked,
    /// API key expired
    ApiKeyExpired,
    /// Rate limit exceeded for this API key
    RateLimitExceeded,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidAppSignature => write!(f, "Invalid app signature"),
            AuthError::InvalidApiKey => write!(f, "Invalid API key"),
            AuthError::InvalidApiSignature => write!(f, "Invalid API signature"),
            AuthError::TimestampExpired => write!(f, "Timestamp expired"),
            AuthError::TimestampInFuture => write!(f, "Timestamp in future"),
            AuthError::MalformedData => write!(f, "Malformed authentication data"),
            AuthError::ApiKeyRevoked => write!(f, "API key revoked"),
            AuthError::ApiKeyExpired => write!(f, "API key expired"),
            AuthError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Server-side authentication configuration
#[derive(Clone)]
pub struct ServerAuthConfig {
    /// Ed25519 public key for verifying app signatures (32 bytes)
    pub app_public_key: VerifyingKey,
    /// Secret key for validating API key HMACs (32 bytes)
    pub api_secret: [u8; 32],
    /// Maximum timestamp age in seconds (replay protection)
    pub max_timestamp_age_secs: u64,
    /// Whether to require API key (can be disabled for testing)
    pub require_api_key: bool,
}

impl ServerAuthConfig {
    /// Create from hex-encoded public key and API secret
    pub fn new(app_public_key_hex: &str, api_secret_hex: &str) -> Result<Self, AuthError> {
        let pk_bytes = hex::decode(app_public_key_hex).map_err(|_| AuthError::MalformedData)?;
        if pk_bytes.len() != 32 {
            return Err(AuthError::MalformedData);
        }

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&pk_bytes);
        let app_public_key =
            VerifyingKey::from_bytes(&pk_array).map_err(|_| AuthError::MalformedData)?;

        let secret_bytes = hex::decode(api_secret_hex).map_err(|_| AuthError::MalformedData)?;
        if secret_bytes.len() != 32 {
            return Err(AuthError::MalformedData);
        }

        let mut api_secret = [0u8; 32];
        api_secret.copy_from_slice(&secret_bytes);

        Ok(Self {
            app_public_key,
            api_secret,
            max_timestamp_age_secs: 300, // 5 minutes
            require_api_key: true,
        })
    }

    /// Create from raw bytes
    pub fn from_bytes(app_public_key: [u8; 32], api_secret: [u8; 32]) -> Result<Self, AuthError> {
        let app_public_key =
            VerifyingKey::from_bytes(&app_public_key).map_err(|_| AuthError::MalformedData)?;

        Ok(Self {
            app_public_key,
            api_secret,
            max_timestamp_age_secs: 300,
            require_api_key: true,
        })
    }

    /// Load from environment variables
    ///
    /// Environment variables:
    /// - `OXIDIZE_APP_PUBLIC_KEY` - hex-encoded Ed25519 public key (required)
    /// - `OXIDIZE_API_SECRET` - hex-encoded API secret for HMAC validation (required)
    ///
    /// Returns None if any required env var is missing or invalid.
    pub fn from_env() -> Option<Self> {
        let app_public_key = std::env::var("OXIDIZE_APP_PUBLIC_KEY").ok()?;
        let api_secret = std::env::var("OXIDIZE_API_SECRET").ok()?;

        Self::new(&app_public_key, &api_secret).ok()
    }
}

/// Client-side authentication configuration
#[derive(Clone)]
pub struct ClientAuthConfig {
    /// Ed25519 signing key for app signature (loaded from env/config at runtime)
    pub app_signing_key: SigningKey,
    /// User's API key (32 bytes, issued by backend)
    pub api_key: [u8; 32],
    /// API secret for generating HMAC (derived from API key issuance)
    pub api_secret: [u8; 32],
}

impl ClientAuthConfig {
    /// Create from hex-encoded keys
    pub fn new(
        app_signing_key_hex: &str,
        api_key_hex: &str,
        api_secret_hex: &str,
    ) -> Result<Self, AuthError> {
        let sk_bytes = hex::decode(app_signing_key_hex).map_err(|_| AuthError::MalformedData)?;
        if sk_bytes.len() != 32 {
            return Err(AuthError::MalformedData);
        }

        let mut sk_array = [0u8; 32];
        sk_array.copy_from_slice(&sk_bytes);
        let app_signing_key = SigningKey::from_bytes(&sk_array);

        let api_key_bytes = hex::decode(api_key_hex).map_err(|_| AuthError::MalformedData)?;
        if api_key_bytes.len() != 32 {
            return Err(AuthError::MalformedData);
        }

        let mut api_key = [0u8; 32];
        api_key.copy_from_slice(&api_key_bytes);

        let secret_bytes = hex::decode(api_secret_hex).map_err(|_| AuthError::MalformedData)?;
        if secret_bytes.len() != 32 {
            return Err(AuthError::MalformedData);
        }

        let mut api_secret = [0u8; 32];
        api_secret.copy_from_slice(&secret_bytes);

        Ok(Self {
            app_signing_key,
            api_key,
            api_secret,
        })
    }

    /// Create from raw bytes
    pub fn from_bytes(app_signing_key: [u8; 32], api_key: [u8; 32], api_secret: [u8; 32]) -> Self {
        Self {
            app_signing_key: SigningKey::from_bytes(&app_signing_key),
            api_key,
            api_secret,
        }
    }

    /// Load from environment variables
    ///
    /// Environment variables:
    /// - `OXIDIZE_APP_SIGNING_KEY` - hex-encoded Ed25519 private key (required)
    /// - `OXIDIZE_API_KEY` - hex-encoded user API key (required)
    /// - `OXIDIZE_API_SECRET` - hex-encoded user API secret (required)
    ///
    /// Returns None if any required env var is missing or invalid.
    pub fn from_env() -> Option<Self> {
        let app_key = std::env::var("OXIDIZE_APP_SIGNING_KEY").ok()?;
        let api_key = std::env::var("OXIDIZE_API_KEY").ok()?;
        let api_secret = std::env::var("OXIDIZE_API_SECRET").ok()?;

        Self::new(&app_key, &api_key, &api_secret).ok()
    }
}

/// Authentication payload included in handshake
#[derive(Debug, Clone)]
pub struct AuthPayload {
    /// Client ID (32 bytes)
    pub client_id: [u8; 32],
    /// Unix timestamp (seconds)
    pub timestamp: u64,
    /// Ed25519 signature of (client_id || timestamp) - proves official app
    pub app_signature: [u8; 64],
    /// API key (32 bytes) - identifies user/subscription
    pub api_key: [u8; 32],
    /// HMAC-SHA256 of (client_id || timestamp || api_key) - proves API key ownership
    pub api_signature: [u8; 32],
}

impl AuthPayload {
    /// Total encoded size: 32 + 8 + 64 + 32 + 32 = 168 bytes
    pub const ENCODED_SIZE: usize = 168;

    /// Create and sign a new auth payload
    pub fn create(client_id: [u8; 32], config: &ClientAuthConfig) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign (client_id || timestamp) with app signing key
        let mut sign_data = Vec::with_capacity(40);
        sign_data.extend_from_slice(&client_id);
        sign_data.extend_from_slice(&timestamp.to_le_bytes());

        let signature = config.app_signing_key.sign(&sign_data);
        let app_signature: [u8; 64] = signature.to_bytes();

        // HMAC (client_id || timestamp || api_key) with api_secret
        let mut mac =
            HmacSha256::new_from_slice(&config.api_secret).expect("HMAC can take key of any size");
        mac.update(&client_id);
        mac.update(&timestamp.to_le_bytes());
        mac.update(&config.api_key);
        let api_signature: [u8; 32] = mac.finalize().into_bytes().into();

        Self {
            client_id,
            timestamp,
            app_signature,
            api_key: config.api_key,
            api_signature,
        }
    }

    /// Encode auth payload to bytes
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::ENCODED_SIZE {
            return 0;
        }

        buf[0..32].copy_from_slice(&self.client_id);
        buf[32..40].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[40..104].copy_from_slice(&self.app_signature);
        buf[104..136].copy_from_slice(&self.api_key);
        buf[136..168].copy_from_slice(&self.api_signature);

        Self::ENCODED_SIZE
    }

    /// Decode auth payload from bytes
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::ENCODED_SIZE {
            return None;
        }

        let mut client_id = [0u8; 32];
        client_id.copy_from_slice(&buf[0..32]);

        let timestamp = u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
        ]);

        let mut app_signature = [0u8; 64];
        app_signature.copy_from_slice(&buf[40..104]);

        let mut api_key = [0u8; 32];
        api_key.copy_from_slice(&buf[104..136]);

        let mut api_signature = [0u8; 32];
        api_signature.copy_from_slice(&buf[136..168]);

        Some(Self {
            client_id,
            timestamp,
            app_signature,
            api_key,
            api_signature,
        })
    }

    /// Verify the auth payload (server-side)
    pub fn verify(&self, config: &ServerAuthConfig) -> Result<(), AuthError> {
        // 1. Check timestamp freshness (replay protection)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.timestamp > now + 60 {
            return Err(AuthError::TimestampInFuture);
        }

        if now.saturating_sub(self.timestamp) > config.max_timestamp_age_secs {
            return Err(AuthError::TimestampExpired);
        }

        // 2. Verify app signature (proves official app)
        let mut sign_data = Vec::with_capacity(40);
        sign_data.extend_from_slice(&self.client_id);
        sign_data.extend_from_slice(&self.timestamp.to_le_bytes());

        let signature = Signature::from_bytes(&self.app_signature);

        config
            .app_public_key
            .verify(&sign_data, &signature)
            .map_err(|_| AuthError::InvalidAppSignature)?;

        // 3. Verify API key signature (proves API key ownership)
        if config.require_api_key {
            let mut mac = HmacSha256::new_from_slice(&config.api_secret)
                .expect("HMAC can take key of any size");
            mac.update(&self.client_id);
            mac.update(&self.timestamp.to_le_bytes());
            mac.update(&self.api_key);

            mac.verify_slice(&self.api_signature)
                .map_err(|_| AuthError::InvalidApiSignature)?;
        }

        Ok(())
    }
}

/// Generate a new Ed25519 keypair for app signing
/// Returns (private_key_hex, public_key_hex)
pub fn generate_app_keypair() -> (String, String) {
    use rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());

    (private_hex, public_hex)
}

/// Generate a new API key and secret pair
/// Returns (api_key_hex, api_secret_hex)
pub fn generate_api_credentials() -> (String, String) {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    let mut api_key = [0u8; 32];
    let mut api_secret = [0u8; 32];

    rng.fill_bytes(&mut api_key);
    rng.fill_bytes(&mut api_secret);

    (hex::encode(api_key), hex::encode(api_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (private_hex, public_hex) = generate_app_keypair();
        assert_eq!(private_hex.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(public_hex.len(), 64);
    }

    #[test]
    fn test_auth_roundtrip() {
        // Generate keys
        let (app_private, app_public) = generate_app_keypair();
        let (api_key, api_secret) = generate_api_credentials();

        // Create client config
        let client_config = ClientAuthConfig::new(&app_private, &api_key, &api_secret).unwrap();

        // Create server config
        let server_config = ServerAuthConfig::new(&app_public, &api_secret).unwrap();

        // Create auth payload
        let client_id = [42u8; 32];
        let payload = AuthPayload::create(client_id, &client_config);

        // Encode/decode
        let mut buf = [0u8; 256];
        let len = payload.encode(&mut buf);
        assert_eq!(len, AuthPayload::ENCODED_SIZE);

        let decoded = AuthPayload::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.client_id, client_id);

        // Verify
        decoded.verify(&server_config).unwrap();
    }

    #[test]
    fn test_invalid_app_signature() {
        let (app_private, _) = generate_app_keypair();
        let (_, wrong_public) = generate_app_keypair(); // Different keypair
        let (api_key, api_secret) = generate_api_credentials();

        let client_config = ClientAuthConfig::new(&app_private, &api_key, &api_secret).unwrap();
        let server_config = ServerAuthConfig::new(&wrong_public, &api_secret).unwrap();

        let payload = AuthPayload::create([1u8; 32], &client_config);

        assert_eq!(
            payload.verify(&server_config),
            Err(AuthError::InvalidAppSignature)
        );
    }

    #[test]
    fn test_invalid_api_signature() {
        let (app_private, app_public) = generate_app_keypair();
        let (api_key, api_secret) = generate_api_credentials();
        let (_, wrong_secret) = generate_api_credentials(); // Different secret

        let client_config = ClientAuthConfig::new(&app_private, &api_key, &api_secret).unwrap();
        let server_config = ServerAuthConfig::new(&app_public, &wrong_secret).unwrap();

        let payload = AuthPayload::create([1u8; 32], &client_config);

        assert_eq!(
            payload.verify(&server_config),
            Err(AuthError::InvalidApiSignature)
        );
    }
}
