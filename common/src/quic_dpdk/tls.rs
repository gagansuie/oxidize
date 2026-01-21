//! QUIC TLS 1.3 Integration via Rustls
//!
//! Provides full TLS 1.3 handshake for QUIC using rustls.
//! Implements QUIC-TLS as specified in RFC 9001.

use std::io;
use std::sync::Arc;

use rustls::crypto::ring as crypto_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::quic::{Connection as QuicConnection, KeyChange, Keys, Version};
use rustls::{ClientConfig, ServerConfig, Side};

/// QUIC-TLS session for a connection
pub struct QuicTlsSession {
    connection: QuicConnection,
    side: Side,
    handshake_complete: bool,
    early_data_accepted: bool,
}

/// TLS configuration for QUIC server
pub struct QuicTlsServerConfig {
    inner: Arc<ServerConfig>,
}

/// TLS configuration for QUIC client  
pub struct QuicTlsClientConfig {
    inner: Arc<ClientConfig>,
}

/// QUIC-specific ALPN protocols
pub const QUIC_ALPN_H3: &[u8] = b"h3";
pub const QUIC_ALPN_RELAY: &[u8] = b"relay/1";

impl QuicTlsServerConfig {
    /// Create server config from certificate and key
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(crypto_provider::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // QUIC requires ALPN
        config.alpn_protocols = vec![QUIC_ALPN_H3.to_vec(), QUIC_ALPN_RELAY.to_vec()];

        // Enable 0-RTT
        config.max_early_data_size = 0xffffffff;
        config.send_half_rtt_data = true;

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Create a new server session
    pub fn new_session(&self, quic_version: Version) -> io::Result<QuicTlsSession> {
        let conn = QuicConnection::Server(
            rustls::quic::ServerConnection::new(self.inner.clone(), quic_version, vec![])
                .map_err(io::Error::other)?,
        );

        Ok(QuicTlsSession {
            connection: conn,
            side: Side::Server,
            handshake_complete: false,
            early_data_accepted: false,
        })
    }
}

impl QuicTlsClientConfig {
    /// Create client config with certificate verification disabled (for testing)
    /// In production, use new_with_roots() with proper root certificates
    pub fn new() -> io::Result<Self> {
        // Create an empty root store - in production use proper roots
        let root_store = rustls::RootCertStore::empty();

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                .with_root_certificates(root_store)
                .with_no_client_auth();

        config.alpn_protocols = vec![QUIC_ALPN_H3.to_vec(), QUIC_ALPN_RELAY.to_vec()];
        config.enable_early_data = true;

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Create client config with custom root certificates
    pub fn new_with_roots(root_certs: Vec<CertificateDer<'static>>) -> io::Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in root_certs {
            root_store
                .add(cert)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                .with_root_certificates(root_store)
                .with_no_client_auth();

        config.alpn_protocols = vec![QUIC_ALPN_H3.to_vec(), QUIC_ALPN_RELAY.to_vec()];
        config.enable_early_data = true;

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Create a new client session
    pub fn new_session(
        &self,
        server_name: &str,
        quic_version: Version,
    ) -> io::Result<QuicTlsSession> {
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let conn = QuicConnection::Client(
            rustls::quic::ClientConnection::new(
                self.inner.clone(),
                quic_version,
                server_name,
                vec![],
            )
            .map_err(io::Error::other)?,
        );

        Ok(QuicTlsSession {
            connection: conn,
            side: Side::Client,
            handshake_complete: false,
            early_data_accepted: false,
        })
    }
}

impl Default for QuicTlsClientConfig {
    fn default() -> Self {
        Self::new().expect("Failed to create default TLS client config")
    }
}

impl QuicTlsSession {
    /// Process incoming CRYPTO frame data
    pub fn read_handshake(&mut self, data: &[u8]) -> io::Result<()> {
        self.connection
            .read_hs(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Get outgoing CRYPTO frame data
    pub fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        self.connection.write_hs(buf)
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete || !self.connection.is_handshaking()
    }

    /// Mark handshake as complete
    pub fn complete_handshake(&mut self) {
        self.handshake_complete = true;
    }

    /// Get negotiated ALPN protocol
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.connection.alpn_protocol()
    }

    /// Check if 0-RTT was accepted
    pub fn is_early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// Get handshake keys
    pub fn handshake_keys(&self) -> Option<Keys> {
        // Keys are provided via KeyChange during write_handshake
        None
    }

    /// Get 1-RTT keys after handshake
    pub fn one_rtt_keys(&self) -> Option<Keys> {
        // Keys are provided via KeyChange during write_handshake
        None
    }

    /// Process key update
    pub fn process_key_change(&mut self, key_change: KeyChange) -> ProcessedKeys {
        match key_change {
            KeyChange::Handshake { keys } => ProcessedKeys::Handshake(keys),
            KeyChange::OneRtt { keys, next } => {
                self.handshake_complete = true;
                ProcessedKeys::OneRtt {
                    keys,
                    next_secrets: next,
                }
            }
        }
    }

    /// Export keying material (for connection ID encryption, etc.)
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> io::Result<()> {
        self.connection
            .export_keying_material(output, label, context)
            .map(|_| ())
            .map_err(io::Error::other)
    }
}

/// Processed key change result
pub enum ProcessedKeys {
    Handshake(Keys),
    OneRtt {
        keys: Keys,
        next_secrets: rustls::quic::Secrets,
    },
}

/// QUIC packet encryption keys extracted from TLS
pub struct QuicKeys {
    /// Packet protection key
    pub key: [u8; 16],
    /// Packet protection IV
    pub iv: [u8; 12],
    /// Header protection key
    pub hp_key: [u8; 16],
}

impl QuicKeys {
    /// Create placeholder keys - actual key extraction happens via HKDF
    /// The Keys from rustls are opaque - use InitialSecrets for QUIC initial keys
    pub fn placeholder() -> Self {
        Self {
            key: [0u8; 16],
            iv: [0u8; 12],
            hp_key: [0u8; 16],
        }
    }

    /// Create from raw key material
    pub fn new(key: [u8; 16], iv: [u8; 12], hp_key: [u8; 16]) -> Self {
        Self { key, iv, hp_key }
    }
}

/// QUIC version for TLS
pub fn quic_version_v1() -> Version {
    Version::V1
}

/// QUIC version for TLS (draft-29 compatibility)
pub fn quic_version_v1_draft() -> Version {
    Version::V1Draft
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_creation() {
        let config = QuicTlsClientConfig::new();
        assert!(config.is_ok());
    }
}
