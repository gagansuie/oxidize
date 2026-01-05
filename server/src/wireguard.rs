use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use boringtun::noise::{Tunn, TunnResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Peer connection state
struct PeerState {
    tunnel: Tunn,
    last_activity: Instant,
    endpoint: SocketAddr,
}

/// WireGuard protocol handler for mobile client compatibility
pub struct WireGuardServer {
    socket: Arc<UdpSocket>,
    private_key: [u8; 32],
    peers: Arc<RwLock<HashMap<[u8; 32], PeerState>>>,
}

impl WireGuardServer {
    /// Create new WireGuard server
    pub async fn new(listen_addr: SocketAddr, private_key: [u8; 32]) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind WireGuard socket")?;

        info!("WireGuard server listening on {}", listen_addr);

        Ok(Self {
            socket: Arc::new(socket),
            private_key,
            peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Run WireGuard server
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        // Spawn cleanup task
        let peers_clone = Arc::clone(&self.peers);
        tokio::spawn(async move {
            Self::cleanup_stale_peers(peers_clone).await;
        });

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    let packet = &buf[..len];
                    if let Err(e) = self.handle_packet(packet, peer_addr).await {
                        error!("Error handling WireGuard packet from {}: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    error!("Error receiving WireGuard packet: {}", e);
                }
            }
        }
    }

    async fn handle_packet(&self, packet: &[u8], peer_addr: SocketAddr) -> Result<()> {
        debug!(
            "Received WireGuard packet from {}, {} bytes",
            peer_addr,
            packet.len()
        );

        // Try to parse as handshake initiation
        if let Some(peer_key) = Self::extract_peer_public_key(packet) {
            // Create or get existing tunnel
            let mut peers = self.peers.write().await;

            if !peers.contains_key(&peer_key) {
                info!("New WireGuard peer connecting: {:?}", peer_addr);

                // Create new tunnel for this peer
                match Tunn::new(
                    self.private_key.into(),
                    peer_key.into(),
                    None,
                    Some(120),
                    0,
                    None,
                ) {
                    Ok(tunnel) => {
                        peers.insert(
                            peer_key,
                            PeerState {
                                tunnel,
                                last_activity: Instant::now(),
                                endpoint: peer_addr,
                            },
                        );
                        info!("Created tunnel for new peer");
                    }
                    Err(e) => {
                        error!("Failed to create tunnel: {:?}", e);
                        return Ok(());
                    }
                }
            }

            if let Some(peer_state) = peers.get_mut(&peer_key) {
                peer_state.last_activity = Instant::now();
                peer_state.endpoint = peer_addr;

                // Process packet through tunnel
                let mut response_buf = vec![0u8; 65536];
                match peer_state
                    .tunnel
                    .decapsulate(None, packet, &mut response_buf)
                {
                    TunnResult::Done => {
                        debug!("Handshake completed");
                    }
                    TunnResult::Err(e) => {
                        warn!("Tunnel error: {:?}", e);
                    }
                    TunnResult::WriteToNetwork(data) => {
                        // Send response
                        if let Err(e) = self.socket.send_to(data, peer_addr).await {
                            error!("Failed to send response: {}", e);
                        } else {
                            debug!("Sent {} bytes to peer", data.len());
                        }
                    }
                    TunnResult::WriteToTunnelV4(data, addr) => {
                        debug!("Received IPv4 packet: {} bytes to {}", data.len(), addr);
                        // TODO: Forward to destination through relay
                        // For now, just acknowledge receipt
                    }
                    TunnResult::WriteToTunnelV6(data, addr) => {
                        debug!("Received IPv6 packet: {} bytes to {}", data.len(), addr);
                        // TODO: Forward to destination through relay
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract peer public key from handshake packet
    fn extract_peer_public_key(packet: &[u8]) -> Option<[u8; 32]> {
        // WireGuard handshake initiation is 148 bytes
        // Public key starts at offset 8
        if packet.len() >= 148 && packet[0] == 1 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&packet[8..40]);
            Some(key)
        } else {
            None
        }
    }

    /// Cleanup stale peer connections
    async fn cleanup_stale_peers(peers: Arc<RwLock<HashMap<[u8; 32], PeerState>>>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let mut peers_lock = peers.write().await;
            let stale_timeout = Duration::from_secs(300); // 5 minutes

            peers_lock.retain(|_, peer| {
                let is_active = peer.last_activity.elapsed() < stale_timeout;
                if !is_active {
                    info!("Removing stale peer from {:?}", peer.endpoint);
                }
                is_active
            });
        }
    }
}

/// Generate WireGuard configuration for client
pub fn generate_client_config(
    server_endpoint: &str,
    server_public_key: &str,
    client_private_key: Option<&str>,
) -> Result<String> {
    // Generate client keys if not provided
    let client_private = if let Some(key) = client_private_key {
        key.to_string()
    } else {
        generate_keypair()?.0
    };

    let config = format!(
        r#"[Interface]
PrivateKey = {}
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = {}
Endpoint = {}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#,
        client_private, server_public_key, server_endpoint
    );

    Ok(config)
}

/// Generate WireGuard keypair
fn generate_keypair() -> Result<(String, String)> {
    use boringtun::x25519;

    let private_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
    let public_key = x25519::PublicKey::from(&private_key);

    let private_b64 = general_purpose::STANDARD.encode(private_key.to_bytes());
    let public_b64 = general_purpose::STANDARD.encode(public_key.as_bytes());

    Ok((private_b64, public_b64))
}

/// Derive public key from private key
fn derive_public_key(private_key_b64: &str) -> Result<String> {
    use boringtun::x25519;

    let private_bytes = general_purpose::STANDARD
        .decode(private_key_b64)
        .context("Invalid private key base64")?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&private_bytes);

    let private_key = x25519::StaticSecret::from(key_bytes);
    let public_key = x25519::PublicKey::from(&private_key);

    Ok(general_purpose::STANDARD.encode(public_key.as_bytes()))
}

/// Generate server keypair and return config
pub fn generate_server_config() -> Result<(String, String, [u8; 32])> {
    let (private_b64, public_b64) = generate_keypair()?;

    let private_bytes = general_purpose::STANDARD.decode(&private_b64)?;
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&private_bytes);

    info!("Generated WireGuard server keys");
    info!("Public key: {}", public_b64);

    Ok((private_b64, public_b64, private_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (private, public) = generate_keypair().unwrap();
        assert_eq!(private.len(), 44); // Base64 of 32 bytes
        assert_eq!(public.len(), 44);
    }

    #[test]
    fn test_derive_public_key() {
        let (private, expected_public) = generate_keypair().unwrap();
        let derived_public = derive_public_key(&private).unwrap();
        assert_eq!(derived_public, expected_public);
    }

    #[test]
    fn test_client_config_generation() {
        let config =
            generate_client_config("relay.example.com:51820", "SERVER_PUBLIC_KEY_HERE", None)
                .unwrap();

        assert!(config.contains("[Interface]"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("relay.example.com:51820"));
    }
}
