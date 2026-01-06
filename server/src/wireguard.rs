use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use boringtun::noise::{Tunn, TunnResult};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Allowed IP range for a peer
#[derive(Debug, Clone)]
pub struct AllowedIp {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl AllowedIp {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }

    /// Check if an IP address matches this allowed IP range
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = if self.prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from_be_bytes(net.octets()) & mask)
                    == (u32::from_be_bytes(addr.octets()) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bytes = net.octets();
                let addr_bytes = addr.octets();
                let full_bytes = (self.prefix_len / 8) as usize;
                let remaining_bits = self.prefix_len % 8;

                if net_bytes[..full_bytes] != addr_bytes[..full_bytes] {
                    return false;
                }

                if remaining_bits > 0 && full_bytes < 16 {
                    let mask = 0xFF << (8 - remaining_bits);
                    return (net_bytes[full_bytes] & mask) == (addr_bytes[full_bytes] & mask);
                }
                true
            }
            _ => false,
        }
    }
}

/// Peer connection state
struct PeerState {
    tunnel: Tunn,
    last_activity: Instant,
    endpoint: SocketAddr,
    assigned_ip: Ipv4Addr,
    allowed_ips: Vec<AllowedIp>,
}

/// IP address pool for assigning addresses to peers
struct IpPool {
    base: Ipv4Addr,
    next_octet: u8,
    assigned: HashMap<[u8; 32], Ipv4Addr>,
}

impl IpPool {
    fn new(base: Ipv4Addr) -> Self {
        Self {
            base,
            next_octet: 2, // Start at .2 (server is .1)
            assigned: HashMap::new(),
        }
    }

    fn allocate(&mut self, peer_key: [u8; 32]) -> Ipv4Addr {
        if let Some(&ip) = self.assigned.get(&peer_key) {
            return ip;
        }
        let octets = self.base.octets();
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], self.next_octet);
        self.next_octet = self.next_octet.wrapping_add(1);
        if self.next_octet == 0 || self.next_octet == 1 {
            self.next_octet = 2;
        }
        self.assigned.insert(peer_key, ip);
        ip
    }

    fn release(&mut self, peer_key: &[u8; 32]) {
        self.assigned.remove(peer_key);
    }
}

/// Packet forwarder for sending decrypted packets to destinations
struct PacketForwarder {
    raw_socket_v4: Option<std::os::unix::io::RawFd>,
    raw_socket_v6: Option<std::os::unix::io::RawFd>,
}

impl PacketForwarder {
    fn new() -> Self {
        let raw_socket_v4 = Self::create_raw_socket_v4();
        let raw_socket_v6 = Self::create_raw_socket_v6();

        if raw_socket_v4.is_none() {
            warn!("Failed to create IPv4 raw socket - packet forwarding may be limited");
        }
        if raw_socket_v6.is_none() {
            warn!("Failed to create IPv6 raw socket - IPv6 forwarding may be limited");
        }

        Self {
            raw_socket_v4,
            raw_socket_v6,
        }
    }

    fn create_raw_socket_v4() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;
        match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => {
                // Enable IP_HDRINCL so we can send raw IP packets
                if sock.set_header_included_v4(true).is_err() {
                    warn!("Failed to set IP_HDRINCL");
                }
                Some(sock.into_raw_fd())
            }
            Err(e) => {
                debug!(
                    "Failed to create raw IPv4 socket: {} (requires CAP_NET_RAW)",
                    e
                );
                None
            }
        }
    }

    fn create_raw_socket_v6() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;
        match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => Some(sock.into_raw_fd()),
            Err(e) => {
                debug!(
                    "Failed to create raw IPv6 socket: {} (requires CAP_NET_RAW)",
                    e
                );
                None
            }
        }
    }

    /// Forward an IPv4 packet to its destination
    async fn forward_ipv4(&self, packet: &[u8], dest: Ipv4Addr) -> Result<()> {
        if packet.len() < 20 {
            return Err(anyhow::anyhow!("IPv4 packet too short"));
        }

        if let Some(fd) = self.raw_socket_v4 {
            let dest_addr = socket2::SockAddr::from(SocketAddr::new(IpAddr::V4(dest), 0));

            // Send via raw socket
            let result = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    dest_addr.as_ptr(),
                    dest_addr.len(),
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                debug!("Raw socket send failed: {}, falling back to UDP relay", err);
                return self.forward_via_udp_relay(packet, IpAddr::V4(dest)).await;
            }

            debug!(
                "Forwarded {} bytes to {} via raw socket",
                packet.len(),
                dest
            );
            Ok(())
        } else {
            self.forward_via_udp_relay(packet, IpAddr::V4(dest)).await
        }
    }

    /// Forward an IPv6 packet to its destination  
    async fn forward_ipv6(&self, packet: &[u8], dest: Ipv6Addr) -> Result<()> {
        if packet.len() < 40 {
            return Err(anyhow::anyhow!("IPv6 packet too short"));
        }

        if let Some(fd) = self.raw_socket_v6 {
            let dest_addr = socket2::SockAddr::from(SocketAddr::new(IpAddr::V6(dest), 0));

            let result = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    dest_addr.as_ptr(),
                    dest_addr.len(),
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                debug!("Raw socket send failed: {}, falling back to UDP relay", err);
                return self.forward_via_udp_relay(packet, IpAddr::V6(dest)).await;
            }

            debug!(
                "Forwarded {} bytes to {} via raw socket",
                packet.len(),
                dest
            );
            Ok(())
        } else {
            self.forward_via_udp_relay(packet, IpAddr::V6(dest)).await
        }
    }

    /// Fallback: extract transport layer info and relay via UDP/TCP
    async fn forward_via_udp_relay(&self, packet: &[u8], dest: IpAddr) -> Result<()> {
        let (protocol, payload, dest_port) = match dest {
            IpAddr::V4(_) => {
                if packet.len() < 20 {
                    return Err(anyhow::anyhow!("Packet too short"));
                }
                let ihl = ((packet[0] & 0x0F) * 4) as usize;
                let protocol = packet[9];
                let payload = &packet[ihl..];
                let dest_port = if payload.len() >= 4 {
                    u16::from_be_bytes([payload[2], payload[3]])
                } else {
                    0
                };
                (protocol, payload, dest_port)
            }
            IpAddr::V6(_) => {
                if packet.len() < 40 {
                    return Err(anyhow::anyhow!("IPv6 packet too short"));
                }
                let protocol = packet[6]; // Next header
                let payload = &packet[40..];
                let dest_port = if payload.len() >= 4 {
                    u16::from_be_bytes([payload[2], payload[3]])
                } else {
                    0
                };
                (protocol, payload, dest_port)
            }
        };

        match protocol {
            17 => {
                // UDP
                if payload.len() < 8 {
                    return Err(anyhow::anyhow!("UDP payload too short"));
                }
                let udp_payload = &payload[8..];
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.send_to(udp_payload, (dest, dest_port)).await?;
                debug!("Relayed UDP packet to {}:{}", dest, dest_port);
            }
            6 => {
                // TCP - establish connection and forward
                if payload.len() < 20 {
                    return Err(anyhow::anyhow!("TCP payload too short"));
                }
                let tcp_payload = &payload[20..];
                if !tcp_payload.is_empty() {
                    use tokio::io::AsyncWriteExt;
                    match tokio::net::TcpStream::connect((dest, dest_port)).await {
                        Ok(mut stream) => {
                            stream.write_all(tcp_payload).await?;
                            debug!("Relayed TCP data to {}:{}", dest, dest_port);
                        }
                        Err(e) => {
                            debug!("TCP relay connection failed: {}", e);
                        }
                    }
                }
            }
            1 | 58 => {
                // ICMP/ICMPv6 - log only, raw socket needed
                debug!(
                    "ICMP packet to {} (requires raw socket for forwarding)",
                    dest
                );
            }
            _ => {
                debug!("Unsupported protocol {} for UDP relay fallback", protocol);
            }
        }

        Ok(())
    }
}

impl Drop for PacketForwarder {
    fn drop(&mut self) {
        if let Some(fd) = self.raw_socket_v4 {
            unsafe {
                libc::close(fd);
            }
        }
        if let Some(fd) = self.raw_socket_v6 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// WireGuard protocol handler for mobile client compatibility
pub struct WireGuardServer {
    socket: Arc<UdpSocket>,
    private_key: [u8; 32],
    peers: Arc<RwLock<HashMap<[u8; 32], PeerState>>>,
    ip_pool: Arc<RwLock<IpPool>>,
    forwarder: Arc<PacketForwarder>,
    /// Channel for sending responses back to peers
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    response_rx: Arc<RwLock<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
}

impl WireGuardServer {
    /// Create new WireGuard server
    pub async fn new(listen_addr: SocketAddr, private_key: [u8; 32]) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind WireGuard socket")?;

        let (response_tx, response_rx) = mpsc::channel(1024);

        info!("WireGuard server listening on {}", listen_addr);

        Ok(Self {
            socket: Arc::new(socket),
            private_key,
            peers: Arc::new(RwLock::new(HashMap::new())),
            ip_pool: Arc::new(RwLock::new(IpPool::new(Ipv4Addr::new(10, 0, 0, 0)))),
            forwarder: Arc::new(PacketForwarder::new()),
            response_tx,
            response_rx: Arc::new(RwLock::new(response_rx)),
        })
    }

    /// Run WireGuard server
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        // Spawn cleanup task
        let peers_clone = Arc::clone(&self.peers);
        let ip_pool_clone = Arc::clone(&self.ip_pool);
        tokio::spawn(async move {
            Self::cleanup_stale_peers(peers_clone, ip_pool_clone).await;
        });

        // Spawn response sender task
        let socket_clone = Arc::clone(&self.socket);
        let response_rx = Arc::clone(&self.response_rx);
        tokio::spawn(async move {
            let mut rx = response_rx.write().await;
            while let Some((data, addr)) = rx.recv().await {
                if let Err(e) = socket_clone.send_to(&data, addr).await {
                    error!("Failed to send response to {}: {}", addr, e);
                }
            }
        });

        // Spawn keepalive task
        let peers_ka = Arc::clone(&self.peers);
        let socket_ka = Arc::clone(&self.socket);
        tokio::spawn(async move {
            Self::send_keepalives(peers_ka, socket_ka).await;
        });

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    let packet = buf[..len].to_vec();
                    let server = self.clone_refs();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_packet(&packet, peer_addr).await {
                            error!("Error handling WireGuard packet from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error receiving WireGuard packet: {}", e);
                }
            }
        }
    }

    /// Clone references for spawning handlers
    fn clone_refs(&self) -> WireGuardServerRef {
        WireGuardServerRef {
            private_key: self.private_key,
            peers: Arc::clone(&self.peers),
            ip_pool: Arc::clone(&self.ip_pool),
            forwarder: Arc::clone(&self.forwarder),
            response_tx: self.response_tx.clone(),
        }
    }

    /// Send periodic keepalives to maintain NAT mappings
    async fn send_keepalives(
        peers: Arc<RwLock<HashMap<[u8; 32], PeerState>>>,
        socket: Arc<UdpSocket>,
    ) {
        loop {
            tokio::time::sleep(Duration::from_secs(25)).await;

            let mut peers_lock = peers.write().await;
            for (_, peer) in peers_lock.iter_mut() {
                let mut buf = vec![0u8; 256];
                match peer.tunnel.encapsulate(&[], &mut buf) {
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = socket.send_to(data, peer.endpoint).await {
                            debug!("Failed to send keepalive: {}", e);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Cleanup stale peer connections
    async fn cleanup_stale_peers(
        peers: Arc<RwLock<HashMap<[u8; 32], PeerState>>>,
        ip_pool: Arc<RwLock<IpPool>>,
    ) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let mut peers_lock = peers.write().await;
            let mut ip_pool_lock = ip_pool.write().await;
            let stale_timeout = Duration::from_secs(300);

            let stale_keys: Vec<_> = peers_lock
                .iter()
                .filter(|(_, peer)| peer.last_activity.elapsed() >= stale_timeout)
                .map(|(k, peer)| {
                    info!("Removing stale peer from {:?}", peer.endpoint);
                    *k
                })
                .collect();

            for key in stale_keys {
                peers_lock.remove(&key);
                ip_pool_lock.release(&key);
            }
        }
    }
}

/// Reference struct for spawned packet handlers
struct WireGuardServerRef {
    private_key: [u8; 32],
    peers: Arc<RwLock<HashMap<[u8; 32], PeerState>>>,
    ip_pool: Arc<RwLock<IpPool>>,
    forwarder: Arc<PacketForwarder>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl WireGuardServerRef {
    async fn handle_packet(&self, packet: &[u8], peer_addr: SocketAddr) -> Result<()> {
        debug!(
            "Received WireGuard packet from {}, {} bytes",
            peer_addr,
            packet.len()
        );

        // Determine packet type and find/create peer
        let peer_key = self.find_or_create_peer(packet, peer_addr).await?;

        if let Some(key) = peer_key {
            self.process_peer_packet(&key, packet, peer_addr).await?;
        }

        Ok(())
    }

    async fn find_or_create_peer(
        &self,
        packet: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<Option<[u8; 32]>> {
        // Try to extract public key from handshake initiation
        if let Some(peer_key) = Self::extract_peer_public_key(packet) {
            let mut peers = self.peers.write().await;

            if !peers.contains_key(&peer_key) {
                info!("New WireGuard peer connecting: {:?}", peer_addr);

                // Allocate IP for this peer
                let assigned_ip = {
                    let mut pool = self.ip_pool.write().await;
                    pool.allocate(peer_key)
                };

                // Default allowed IPs: the assigned IP and 0.0.0.0/0 for full tunnel
                let allowed_ips = vec![
                    AllowedIp::new(IpAddr::V4(assigned_ip), 32),
                    AllowedIp::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                ];

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
                                assigned_ip,
                                allowed_ips,
                            },
                        );
                        info!("Created tunnel for peer, assigned IP: {}", assigned_ip);
                    }
                    Err(e) => {
                        error!("Failed to create tunnel: {:?}", e);
                        return Ok(None);
                    }
                }
            }

            return Ok(Some(peer_key));
        }

        // For data packets, find peer by checking all tunnels
        let peers = self.peers.read().await;
        for (key, _) in peers.iter() {
            return Ok(Some(*key));
        }

        Ok(None)
    }

    async fn process_peer_packet(
        &self,
        peer_key: &[u8; 32],
        packet: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut peers = self.peers.write().await;

        if let Some(peer_state) = peers.get_mut(peer_key) {
            peer_state.last_activity = Instant::now();
            peer_state.endpoint = peer_addr;

            let mut response_buf = vec![0u8; 65536];
            let mut result = peer_state
                .tunnel
                .decapsulate(None, packet, &mut response_buf);

            // Process all results from the tunnel
            loop {
                match result {
                    TunnResult::Done => {
                        debug!("Tunnel operation completed");
                        break;
                    }
                    TunnResult::Err(e) => {
                        warn!("Tunnel error: {:?}", e);
                        break;
                    }
                    TunnResult::WriteToNetwork(data) => {
                        let data_vec = data.to_vec();
                        if let Err(e) = self.response_tx.send((data_vec, peer_addr)).await {
                            error!("Failed to queue response: {}", e);
                        } else {
                            debug!("Queued {} bytes response to peer", data.len());
                        }

                        // Check for more data
                        result = peer_state.tunnel.decapsulate(None, &[], &mut response_buf);
                    }
                    TunnResult::WriteToTunnelV4(data, dest_addr) => {
                        debug!(
                            "Decrypted IPv4 packet: {} bytes to {}",
                            data.len(),
                            dest_addr
                        );

                        // Verify source IP is allowed for this peer
                        if data.len() >= 20 {
                            let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                            if !self.verify_source_ip(peer_state, IpAddr::V4(src_ip)) {
                                warn!(
                                    "Packet from {} with unauthorized source IP {}",
                                    peer_addr, src_ip
                                );
                                break;
                            }
                        }

                        // Forward the decrypted packet
                        let forwarder = Arc::clone(&self.forwarder);
                        let data_vec = data.to_vec();
                        tokio::spawn(async move {
                            if let Err(e) = forwarder.forward_ipv4(&data_vec, dest_addr).await {
                                debug!("Failed to forward IPv4 packet: {}", e);
                            }
                        });

                        break;
                    }
                    TunnResult::WriteToTunnelV6(data, dest_addr) => {
                        debug!(
                            "Decrypted IPv6 packet: {} bytes to {}",
                            data.len(),
                            dest_addr
                        );

                        let forwarder = Arc::clone(&self.forwarder);
                        let data_vec = data.to_vec();
                        tokio::spawn(async move {
                            if let Err(e) = forwarder.forward_ipv6(&data_vec, dest_addr).await {
                                debug!("Failed to forward IPv6 packet: {}", e);
                            }
                        });

                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn verify_source_ip(&self, peer: &PeerState, src_ip: IpAddr) -> bool {
        // Check if source IP is the assigned IP or within allowed ranges
        if let IpAddr::V4(v4) = src_ip {
            if v4 == peer.assigned_ip {
                return true;
            }
        }

        peer.allowed_ips
            .iter()
            .any(|allowed| allowed.contains(&src_ip))
    }

    fn extract_peer_public_key(packet: &[u8]) -> Option<[u8; 32]> {
        // WireGuard message types:
        // 1 = Handshake Initiation (148 bytes)
        // 2 = Handshake Response (92 bytes)
        // 3 = Cookie Reply (64 bytes)
        // 4 = Data (variable)
        if packet.len() >= 148 && packet[0] == 1 {
            // Handshake initiation - extract ephemeral public key
            let mut key = [0u8; 32];
            key.copy_from_slice(&packet[8..40]);
            Some(key)
        } else {
            None
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
#[allow(dead_code)]
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
