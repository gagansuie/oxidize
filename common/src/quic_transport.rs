//! QUIC Transport Layer
//!
//! Provides QUIC-based transport as a fallback for restrictive networks where UDP is blocked.
//! Uses QUIC datagrams for efficient packet tunneling with TLS encryption.

use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// QUIC client configuration
#[derive(Clone)]
pub struct QuicClientConfig {
    /// Server address (default port 51822 for QUIC fallback)
    pub server_addr: SocketAddr,
    /// Server name for TLS verification
    pub server_name: String,
    /// Enable 0-RTT for faster reconnection
    pub enable_0rtt: bool,
    /// Keep-alive interval (seconds)
    pub keepalive_interval: u64,
}

impl Default for QuicClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:51822".parse().unwrap(),
            server_name: "localhost".to_string(),
            enable_0rtt: true,
            keepalive_interval: 25,
        }
    }
}

/// QUIC server configuration
pub struct QuicServerConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// TLS certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// TLS private key
    pub private_key: PrivateKeyDer<'static>,
    /// Enable 0-RTT
    pub enable_0rtt: bool,
}

/// QUIC client for tunneling
pub struct QuicClient {
    config: QuicClientConfig,
    endpoint: Endpoint,
    connection: Option<quinn::Connection>,
    tx: mpsc::Sender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
}

impl QuicClient {
    /// Create a new QUIC client
    pub async fn new(config: QuicClientConfig) -> Result<Self> {
        let client_config = Self::create_client_config()?;

        let bind_addr: SocketAddr = if config.server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        let (tx, rx) = mpsc::channel(4096);

        info!("QUIC client created for {}", config.server_addr);

        Ok(Self {
            config,
            endpoint,
            connection: None,
            tx,
            rx,
        })
    }

    /// Connect to the QUIC server
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to QUIC server: {}", self.config.server_addr);

        let connection = self
            .endpoint
            .connect(self.config.server_addr, &self.config.server_name)?
            .await
            .context("QUIC connection failed")?;

        info!(
            "✅ QUIC connection established (RTT: {:?})",
            connection.rtt()
        );

        // Start datagram receiver task
        self.start_datagram_receiver(connection.clone()).await?;

        self.connection = Some(connection);
        Ok(())
    }

    /// Send a packet through the QUIC tunnel (as datagram)
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let connection = self
            .connection
            .as_ref()
            .context("Not connected to QUIC server")?;

        connection
            .send_datagram(Bytes::copy_from_slice(data))
            .context("Failed to send QUIC datagram")?;

        Ok(())
    }

    /// Receive a packet from the QUIC tunnel
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }

    /// Start datagram receiver task
    async fn start_datagram_receiver(&self, connection: quinn::Connection) -> Result<()> {
        let tx = self.tx.clone();

        tokio::spawn(async move {
            loop {
                match connection.read_datagram().await {
                    Ok(data) => {
                        if tx.send(data).await.is_err() {
                            debug!("QUIC receiver: channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("QUIC datagram receive error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Create client config that accepts self-signed certs (for dev)
    fn create_client_config() -> Result<ClientConfig> {
        // Create crypto config that skips certificate verification (dev only)
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        Ok(config)
    }

    /// Get connection statistics
    pub fn stats(&self) -> Option<quinn::ConnectionStats> {
        self.connection.as_ref().map(|c| c.stats())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }
}

/// QUIC server for accepting tunnel connections
pub struct QuicServer {
    #[allow(dead_code)]
    config: QuicServerConfig,
    endpoint: Endpoint,
}

impl QuicServer {
    /// Create a new QUIC server
    pub async fn new(config: QuicServerConfig) -> Result<Self> {
        let server_config = Self::create_server_config(&config)?;
        let endpoint = Endpoint::server(server_config, config.listen_addr)?;

        info!("QUIC server listening on {}", config.listen_addr);

        Ok(Self { config, endpoint })
    }

    /// Accept incoming QUIC connections
    pub async fn accept(&self) -> Option<QuicServerConnection> {
        let connecting = self.endpoint.accept().await?;

        match connecting.await {
            Ok(connection) => {
                info!(
                    "QUIC connection accepted from {}",
                    connection.remote_address()
                );
                Some(QuicServerConnection { connection })
            }
            Err(e) => {
                warn!("QUIC connection failed: {}", e);
                None
            }
        }
    }

    /// Create server config
    fn create_server_config(config: &QuicServerConfig) -> Result<ServerConfig> {
        let crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(config.cert_chain.clone(), config.private_key.clone_key())?;

        let server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));

        Ok(server_config)
    }
}

/// Server-side QUIC connection
pub struct QuicServerConnection {
    connection: quinn::Connection,
}

impl QuicServerConnection {
    /// Receive a datagram
    pub async fn recv_datagram(&self) -> Result<Bytes> {
        self.connection
            .read_datagram()
            .await
            .context("Failed to receive datagram")
    }

    /// Send a datagram
    pub fn send_datagram(&self, data: Bytes) -> Result<()> {
        self.connection
            .send_datagram(data)
            .context("Failed to send datagram")
    }

    /// Get remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Get connection stats
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }
}

/// Skip certificate verification (for development/self-signed certs)
/// WARNING: Do not use in production without proper cert verification!
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Generate self-signed certificate for testing
pub fn generate_self_signed_cert(
    domains: Vec<String>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(domains)?;
    let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_der = CertificateDer::from(cert.cert);
    Ok((vec![cert_der], key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config() {
        let config = QuicClientConfig::default();
        assert!(config.enable_0rtt);
        assert_eq!(config.keepalive_interval, 25);
    }

    #[test]
    fn test_self_signed_cert() {
        let result = generate_self_signed_cert(vec!["localhost".to_string()]);
        assert!(result.is_ok());
    }
}
