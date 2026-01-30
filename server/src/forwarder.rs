//! Packet Forwarder
//!
//! Handles forwarding decoded packets to their destinations AND receiving responses.
//! Supports UDP, TCP, and ICMP traffic tunneled through QUIC (IPv4 and IPv6).

use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Tracks a forwarded packet's original source for response routing
#[derive(Clone, Debug)]
struct PacketMapping {
    conn_id: u64,
    /// Original source IP from the client's packet (v4 or v6)
    src_ip: IpAddr,
    /// Original source port from the client's packet
    src_port: u16,
}

/// ICMP echo tracking for response routing
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct IcmpKey {
    conn_id: u64,
    /// ICMP identifier
    id: u16,
    /// ICMP sequence number
    seq: u16,
    /// Destination IP we sent to
    dst_ip: IpAddr,
}

/// TCP connection key for connection pooling
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct TcpConnKey {
    conn_id: u64,
    src_port: u16,
    dst_addr: SocketAddr,
}

/// TCP connection state for proper sequence/ack tracking
#[derive(Debug)]
#[allow(dead_code)]
struct TcpState {
    /// Our sequence number (server -> client direction)
    our_seq: AtomicU64,
    /// Expected ack from client (tracks what client has received)
    their_ack: AtomicU64,
    /// Client's sequence number we've seen
    their_seq: AtomicU64,
    /// Our ack to client (what we've received from client)
    our_ack: AtomicU64,
    /// Source IP for response building
    src_ip: IpAddr,
}

impl TcpState {
    fn new(src_ip: IpAddr, initial_client_seq: u32) -> Self {
        // Generate random initial sequence number for security
        let our_initial_seq = rand::random::<u32>() as u64;
        Self {
            our_seq: AtomicU64::new(our_initial_seq),
            their_ack: AtomicU64::new(our_initial_seq),
            their_seq: AtomicU64::new(initial_client_seq as u64),
            our_ack: AtomicU64::new(initial_client_seq.wrapping_add(1) as u64),
            src_ip,
        }
    }

    /// Get current seq and advance by payload length
    fn advance_seq(&self, payload_len: usize) -> u32 {
        let seq = self.our_seq.fetch_add(payload_len as u64, Ordering::SeqCst);
        seq as u32
    }

    /// Get current ack number
    fn get_ack(&self) -> u32 {
        self.our_ack.load(Ordering::SeqCst) as u32
    }

    /// Update ack based on received client data
    #[allow(dead_code)]
    fn update_ack(&self, client_seq: u32, payload_len: usize) {
        let new_ack = client_seq.wrapping_add(payload_len as u32) as u64;
        self.our_ack.fetch_max(new_ack, Ordering::SeqCst);
    }
}

/// Shared packet forwarder for all connections
pub struct SharedForwarder {
    /// Outbound UDP socket for forwarding (IPv4)
    socket_v4: Arc<UdpSocket>,
    /// Outbound UDP socket for forwarding (IPv6)
    socket_v6: Arc<UdpSocket>,
    /// Raw ICMP socket for ping IPv4 (requires CAP_NET_RAW or ping_group_range)
    icmp_socket: Option<Arc<std::net::UdpSocket>>,
    /// Raw ICMPv6 socket for ping IPv6 (requires CAP_NET_RAW or ping_group_range)
    icmp6_socket: Option<Arc<std::net::UdpSocket>>,
    /// Response channels per connection ID
    response_channels: Arc<RwLock<HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Mapping from (dst_ip, dst_port) to connection for response routing
    /// Key: destination address we forwarded TO
    /// Value: connection info to route responses back
    packet_mappings: Arc<RwLock<HashMap<SocketAddr, PacketMapping>>>,
    /// Active TCP connections (conn_id + src_port + dst -> TcpStream write half)
    tcp_connections: Arc<RwLock<HashMap<TcpConnKey, mpsc::Sender<Vec<u8>>>>>,
    /// TCP state tracking for proper seq/ack numbers
    tcp_states: Arc<RwLock<HashMap<TcpConnKey, Arc<TcpState>>>>,
    /// ICMP echo mappings for response routing
    icmp_mappings: Arc<RwLock<HashMap<IcmpKey, PacketMapping>>>,
    /// Statistics
    stats: Arc<ForwarderStats>,
}

#[derive(Debug, Default)]
pub struct ForwarderStats {
    pub packets_forwarded: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_forwarded: AtomicU64,
    pub bytes_received: AtomicU64,
    pub forward_errors: AtomicU64,
}

impl SharedForwarder {
    /// Create a new shared forwarder with response listener
    pub async fn new() -> Result<Arc<Self>> {
        // Bind to any available port for outbound traffic (IPv4)
        let socket_v4 = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr_v4 = socket_v4.local_addr()?;
        info!("Forwarder IPv4 bound to {}", local_addr_v4);

        // Bind IPv6 socket
        let socket_v6 = UdpSocket::bind("[::]:0").await?;
        let local_addr_v6 = socket_v6.local_addr()?;
        info!("Forwarder IPv6 bound to {}", local_addr_v6);

        // Try to create raw ICMP sockets (requires CAP_NET_RAW or ping_group_range)
        let icmp_socket = Self::create_icmp_socket();
        let icmp6_socket = Self::create_icmp6_socket();

        match (&icmp_socket, &icmp6_socket) {
            (Some(_), Some(_)) => info!("ICMP sockets created (IPv4 + IPv6)"),
            (Some(_), None) => info!("ICMP socket created (IPv4 only, IPv6 needs CAP_NET_RAW)"),
            (None, Some(_)) => {
                info!("ICMP socket created (IPv6 only, IPv4 needs ping_group_range)")
            }
            (None, None) => warn!("ICMP socket creation failed - ping will not work"),
        }

        let forwarder = Arc::new(Self {
            socket_v4: Arc::new(socket_v4),
            socket_v6: Arc::new(socket_v6),
            icmp_socket,
            icmp6_socket,
            response_channels: Arc::new(RwLock::new(HashMap::new())),
            packet_mappings: Arc::new(RwLock::new(HashMap::new())),
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
            tcp_states: Arc::new(RwLock::new(HashMap::new())),
            icmp_mappings: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(ForwarderStats::default()),
        });

        // Start response listener tasks for both IPv4 and IPv6
        let forwarder_v4 = forwarder.clone();
        tokio::spawn(async move {
            forwarder_v4.response_listener_v4().await;
        });

        let forwarder_v6 = forwarder.clone();
        tokio::spawn(async move {
            forwarder_v6.response_listener_v6().await;
        });

        // Start ICMP response listeners
        if forwarder.icmp_socket.is_some() {
            let forwarder_icmp = forwarder.clone();
            tokio::spawn(async move {
                forwarder_icmp.icmp_response_listener_v4().await;
            });
        }
        if forwarder.icmp6_socket.is_some() {
            let forwarder_icmp6 = forwarder.clone();
            tokio::spawn(async move {
                forwarder_icmp6.icmp_response_listener_v6().await;
            });
        }

        Ok(forwarder)
    }

    /// Try to create a raw ICMP socket for IPv4
    fn create_icmp_socket() -> Option<Arc<std::net::UdpSocket>> {
        // On Linux, we can use SOCK_DGRAM with IPPROTO_ICMP for unprivileged ICMP
        // This requires kernel >= 3.0 and net.ipv4.ping_group_range sysctl
        use std::os::unix::io::FromRawFd;

        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
            if fd >= 0 {
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                Some(Arc::new(std::net::UdpSocket::from_raw_fd(fd)))
            } else {
                None
            }
        }
    }

    /// Try to create a raw ICMPv6 socket
    fn create_icmp6_socket() -> Option<Arc<std::net::UdpSocket>> {
        // On Linux, SOCK_DGRAM with IPPROTO_ICMPV6 for unprivileged ICMPv6
        // Requires net.ipv6.ping_group_range sysctl (or CAP_NET_RAW)
        use std::os::unix::io::FromRawFd;

        unsafe {
            let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6);
            if fd >= 0 {
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                // Allow sending to any IPv6 address
                let opt: libc::c_int = 0;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                Some(Arc::new(std::net::UdpSocket::from_raw_fd(fd)))
            } else {
                None
            }
        }
    }

    /// Background task that receives IPv4 UDP responses and routes them to clients
    async fn response_listener_v4(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        info!("IPv4 response listener started");
        let mut response_count: u64 = 0;
        let mut last_log = std::time::Instant::now();

        loop {
            match self.socket_v4.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    response_count += 1;
                    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    if last_log.elapsed().as_secs() >= 10 {
                        info!(
                            "📥 Forwarder received {} IPv4 responses total",
                            response_count
                        );
                        last_log = std::time::Instant::now();
                    }

                    self.route_udp_response(src_addr, &buf[..len]).await;
                }
                Err(e) => {
                    warn!("IPv4 response recv error: {}", e);
                }
            }
        }
    }

    /// Background task that receives IPv6 UDP responses and routes them to clients
    async fn response_listener_v6(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        info!("IPv6 response listener started");

        loop {
            match self.socket_v6.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    self.route_udp_response(src_addr, &buf[..len]).await;
                }
                Err(e) => {
                    warn!("IPv6 response recv error: {}", e);
                }
            }
        }
    }

    /// Route a UDP response back to the appropriate client
    async fn route_udp_response(&self, src_addr: SocketAddr, payload: &[u8]) {
        let mapping = {
            let mappings = self.packet_mappings.read().await;
            mappings.get(&src_addr).cloned()
        };

        if let Some(mapping) = mapping {
            let response_packet =
                self.build_udp_response_packet(src_addr, mapping.src_ip, mapping.src_port, payload);

            let channels = self.response_channels.read().await;
            if let Some(tx) = channels.get(&mapping.conn_id) {
                if let Err(e) = tx.try_send(response_packet) {
                    debug!("Failed to send response to conn {}: {}", mapping.conn_id, e);
                }
            }
        }
    }

    /// Background task that receives ICMP Echo Reply (IPv4) and routes to clients
    async fn icmp_response_listener_v4(self: Arc<Self>) {
        let icmp_socket = match &self.icmp_socket {
            Some(s) => s.clone(),
            None => return,
        };

        info!("ICMP IPv4 response listener started");
        let mut buf = vec![0u8; 65536];

        loop {
            // Use try_clone and set_nonblocking for async compatibility
            match icmp_socket.recv_from(&mut buf) {
                Ok((len, src_addr)) => {
                    if len < 8 {
                        continue;
                    }
                    // ICMP Echo Reply: type=0, code=0
                    let icmp_type = buf[0];
                    if icmp_type != 0 {
                        continue;
                    }
                    let id = u16::from_be_bytes([buf[4], buf[5]]);
                    let seq = u16::from_be_bytes([buf[6], buf[7]]);

                    self.route_icmp_response(src_addr.ip(), id, seq, &buf[..len])
                        .await;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Background task that receives ICMPv6 Echo Reply and routes to clients
    async fn icmp_response_listener_v6(self: Arc<Self>) {
        let icmp6_socket = match &self.icmp6_socket {
            Some(s) => s.clone(),
            None => return,
        };

        info!("ICMPv6 response listener started");
        let mut buf = vec![0u8; 65536];

        loop {
            match icmp6_socket.recv_from(&mut buf) {
                Ok((len, src_addr)) => {
                    if len < 8 {
                        continue;
                    }
                    // ICMPv6 Echo Reply: type=129
                    let icmp_type = buf[0];
                    if icmp_type != 129 {
                        continue;
                    }
                    let id = u16::from_be_bytes([buf[4], buf[5]]);
                    let seq = u16::from_be_bytes([buf[6], buf[7]]);

                    self.route_icmp_response(src_addr.ip(), id, seq, &buf[..len])
                        .await;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Route an ICMP Echo Reply back to the client
    async fn route_icmp_response(&self, src_ip: IpAddr, id: u16, seq: u16, icmp_data: &[u8]) {
        // Find matching request by iterating mappings (id+seq+dst_ip)
        let mapping = {
            let mappings = self.icmp_mappings.read().await;
            mappings
                .iter()
                .find(|(k, _)| k.id == id && k.seq == seq && k.dst_ip == src_ip)
                .map(|(k, v)| (k.clone(), v.clone()))
        };

        if let Some((key, mapping)) = mapping {
            // Build ICMP response packet
            let response_packet =
                self.build_icmp_response_packet(src_ip, mapping.src_ip, icmp_data);

            let channels = self.response_channels.read().await;
            if let Some(tx) = channels.get(&mapping.conn_id) {
                if tx.try_send(response_packet).is_ok() {
                    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        "ICMP: Routed reply from {} to conn {}",
                        src_ip, mapping.conn_id
                    );
                }
            }

            // Remove used mapping
            let mut mappings = self.icmp_mappings.write().await;
            mappings.remove(&key);
        }
    }

    /// Build an ICMP response packet (IP header + ICMP data)
    fn build_icmp_response_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        icmp_data: &[u8],
    ) -> Vec<u8> {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.build_icmp_response_v4(src, dst, icmp_data),
            (IpAddr::V6(src), IpAddr::V6(dst)) => self.build_icmp_response_v6(src, dst, icmp_data),
            _ => Vec::new(),
        }
    }

    /// Build IPv4 ICMP response packet
    fn build_icmp_response_v4(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        icmp_data: &[u8],
    ) -> Vec<u8> {
        let ip_len = 20 + icmp_data.len();
        let mut packet = vec![0u8; ip_len];

        // IP Header
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&[0x40, 0x00]);
        packet[8] = 64;
        packet[9] = 1; // ICMP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        let checksum = self.ip_checksum(&packet[0..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        // ICMP data
        packet[20..].copy_from_slice(icmp_data);

        packet
    }

    /// Build IPv6 ICMPv6 response packet
    fn build_icmp_response_v6(
        &self,
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        icmp_data: &[u8],
    ) -> Vec<u8> {
        let ip_len = 40 + icmp_data.len();
        let mut packet = vec![0u8; ip_len];

        // IPv6 Header
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(icmp_data.len() as u16).to_be_bytes());
        packet[6] = 58; // ICMPv6
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src_ip.octets());
        packet[24..40].copy_from_slice(&dst_ip.octets());

        // ICMPv6 data
        packet[40..].copy_from_slice(icmp_data);

        packet
    }

    /// Build an IP+UDP packet from response data (supports IPv4 and IPv6)
    fn build_udp_response_packet(
        &self,
        src_addr: SocketAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        match (src_addr.ip(), dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                self.build_ipv4_udp_packet(src_ip, src_addr.port(), dst_ip, dst_port, payload)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                self.build_ipv6_udp_packet(src_ip, src_addr.port(), dst_ip, dst_port, payload)
            }
            _ => Vec::new(), // Mismatched IP versions
        }
    }

    /// Build an IPv4+UDP packet
    fn build_ipv4_udp_packet(
        &self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut packet = vec![0u8; ip_len];

        // IP Header (20 bytes, no options)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00; // DSCP/ECN
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&[0x00, 0x00]); // ID
        packet[6..8].copy_from_slice(&[0x40, 0x00]); // Flags (DF), Fragment offset
        packet[8] = 64; // TTL
        packet[9] = 17; // Protocol: UDP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // Calculate IP header checksum
        let checksum = self.ip_checksum(&packet[0..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        // UDP Header (8 bytes)
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // Checksum placeholder (0) - will be calculated below
        packet[26..28].copy_from_slice(&[0x00, 0x00]);

        // Payload
        packet[28..].copy_from_slice(payload);

        // Calculate UDP checksum over UDP header + payload
        let udp_checksum = Self::udp_checksum_v4(src_ip, dst_ip, &packet[20..]);
        packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());

        packet
    }

    /// Build an IPv6+UDP packet
    fn build_ipv6_udp_packet(
        &self,
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_len = 40 + udp_len; // IPv6 header is 40 bytes
        let mut packet = vec![0u8; ip_len];

        // IPv6 Header (40 bytes)
        packet[0] = 0x60; // Version 6
                          // Traffic class and flow label = 0
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // Payload length
        packet[6] = 17; // Next header: UDP
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&src_ip.octets());
        packet[24..40].copy_from_slice(&dst_ip.octets());

        // UDP Header (8 bytes)
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // Checksum placeholder (0) - will be calculated below
        packet[46..48].copy_from_slice(&[0x00, 0x00]);

        // Payload
        packet[48..].copy_from_slice(payload);

        // Calculate UDP checksum over UDP header + payload (mandatory for IPv6)
        let udp_checksum = Self::udp_checksum_v6(src_ip, dst_ip, &packet[40..]);
        packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());

        packet
    }

    /// Calculate IP header checksum
    fn ip_checksum(&self, header: &[u8]) -> u16 {
        Self::checksum_oneshot(header)
    }

    /// One-shot checksum calculation
    fn checksum_oneshot(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..data.len()).step_by(2) {
            let word = if i + 1 < data.len() {
                ((data[i] as u32) << 8) | (data[i + 1] as u32)
            } else {
                (data[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Calculate TCP checksum for IPv4
    fn tcp_checksum_v4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        sum = sum.wrapping_add(((src[0] as u32) << 8) | (src[1] as u32));
        sum = sum.wrapping_add(((src[2] as u32) << 8) | (src[3] as u32));
        sum = sum.wrapping_add(((dst[0] as u32) << 8) | (dst[1] as u32));
        sum = sum.wrapping_add(((dst[2] as u32) << 8) | (dst[3] as u32));
        sum = sum.wrapping_add(6); // Protocol: TCP
        sum = sum.wrapping_add(tcp_segment.len() as u32);

        // TCP segment
        for i in (0..tcp_segment.len()).step_by(2) {
            let word = if i + 1 < tcp_segment.len() {
                ((tcp_segment[i] as u32) << 8) | (tcp_segment[i + 1] as u32)
            } else {
                (tcp_segment[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Calculate TCP checksum for IPv6
    fn tcp_checksum_v6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header for IPv6
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        for i in (0..16).step_by(2) {
            sum = sum.wrapping_add(((src[i] as u32) << 8) | (src[i + 1] as u32));
            sum = sum.wrapping_add(((dst[i] as u32) << 8) | (dst[i + 1] as u32));
        }
        let len = tcp_segment.len() as u32;
        sum = sum.wrapping_add(len >> 16);
        sum = sum.wrapping_add(len & 0xFFFF);
        sum = sum.wrapping_add(6); // Next header: TCP

        // TCP segment
        for i in (0..tcp_segment.len()).step_by(2) {
            let word = if i + 1 < tcp_segment.len() {
                ((tcp_segment[i] as u32) << 8) | (tcp_segment[i + 1] as u32)
            } else {
                (tcp_segment[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Calculate UDP checksum for IPv4
    fn udp_checksum_v4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        sum = sum.wrapping_add(((src[0] as u32) << 8) | (src[1] as u32));
        sum = sum.wrapping_add(((src[2] as u32) << 8) | (src[3] as u32));
        sum = sum.wrapping_add(((dst[0] as u32) << 8) | (dst[1] as u32));
        sum = sum.wrapping_add(((dst[2] as u32) << 8) | (dst[3] as u32));
        sum = sum.wrapping_add(17); // Protocol: UDP
        sum = sum.wrapping_add(udp_segment.len() as u32);

        // UDP segment
        for i in (0..udp_segment.len()).step_by(2) {
            let word = if i + 1 < udp_segment.len() {
                ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32)
            } else {
                (udp_segment[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let result = !(sum as u16);
        if result == 0 {
            0xFFFF
        } else {
            result
        }
    }

    /// Calculate UDP checksum for IPv6 (mandatory)
    fn udp_checksum_v6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, udp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header for IPv6
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        for i in (0..16).step_by(2) {
            sum = sum.wrapping_add(((src[i] as u32) << 8) | (src[i + 1] as u32));
            sum = sum.wrapping_add(((dst[i] as u32) << 8) | (dst[i + 1] as u32));
        }
        let len = udp_segment.len() as u32;
        sum = sum.wrapping_add(len >> 16);
        sum = sum.wrapping_add(len & 0xFFFF);
        sum = sum.wrapping_add(17); // Next header: UDP

        // UDP segment
        for i in (0..udp_segment.len()).step_by(2) {
            let word = if i + 1 < udp_segment.len() {
                ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32)
            } else {
                (udp_segment[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let result = !(sum as u16);
        if result == 0 {
            0xFFFF
        } else {
            result
        }
    }

    /// Register a connection and return a receiver for responses
    pub async fn register_connection(&self, conn_id: u64) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(1024);
        self.response_channels.write().await.insert(conn_id, tx);
        rx
    }

    /// Unregister a connection
    pub async fn unregister_connection(&self, conn_id: u64) {
        self.response_channels.write().await.remove(&conn_id);
    }

    /// Forward a packet to its destination and store mapping for responses
    /// Supports UDP (17), TCP (6), ICMP (1), and ICMPv6 (58) for both IPv4 and IPv6
    pub async fn forward(&self, conn_id: u64, packet: Vec<u8>) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        let version = (packet[0] >> 4) & 0x0F;
        match version {
            4 => self.forward_ipv4(conn_id, packet).await,
            6 => self.forward_ipv6(conn_id, packet).await,
            _ => Ok(()), // Unknown IP version
        }
    }

    /// Forward an IPv4 packet
    async fn forward_ipv4(&self, conn_id: u64, packet: Vec<u8>) -> Result<()> {
        if packet.len() < 20 {
            return Ok(());
        }

        let protocol = packet[9];
        let ip_header_len = ((packet[0] & 0x0F) * 4) as usize;
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let dst_ip_v4 = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst_ip = IpAddr::V4(dst_ip_v4);

        match protocol {
            17 => {
                self.forward_udp(conn_id, &packet, ip_header_len, src_ip, dst_ip, true)
                    .await
            }
            6 => {
                self.forward_tcp(conn_id, &packet, ip_header_len, src_ip, dst_ip)
                    .await
            }
            1 => {
                self.forward_icmp_v4(conn_id, &packet, ip_header_len, src_ip, dst_ip_v4)
                    .await
            }
            _ => Ok(()),
        }
    }

    /// Forward an IPv6 packet
    async fn forward_ipv6(&self, conn_id: u64, packet: Vec<u8>) -> Result<()> {
        if packet.len() < 40 {
            return Ok(());
        }

        let next_header = packet[6];
        let ip_header_len = 40; // Fixed for IPv6 (extension headers not handled yet)

        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&packet[8..24]);
        dst_bytes.copy_from_slice(&packet[24..40]);

        let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

        match next_header {
            17 => {
                self.forward_udp(conn_id, &packet, ip_header_len, src_ip, dst_ip, false)
                    .await
            }
            6 => {
                self.forward_tcp(conn_id, &packet, ip_header_len, src_ip, dst_ip)
                    .await
            }
            58 => {
                self.forward_icmp_v6(
                    conn_id,
                    &packet,
                    ip_header_len,
                    src_ip,
                    Ipv6Addr::from(dst_bytes),
                )
                .await
            }
            _ => Ok(()),
        }
    }

    /// Forward UDP packet (works for both IPv4 and IPv6)
    async fn forward_udp(
        &self,
        conn_id: u64,
        packet: &[u8],
        ip_header_len: usize,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        is_v4: bool,
    ) -> Result<()> {
        if packet.len() < ip_header_len + 8 {
            return Ok(());
        }

        let src_port = u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
        let dst_port = u16::from_be_bytes([packet[ip_header_len + 2], packet[ip_header_len + 3]]);
        let dst_addr = SocketAddr::new(dst_ip, dst_port);

        // Store mapping for response routing
        {
            let mut mappings = self.packet_mappings.write().await;
            mappings.insert(
                dst_addr,
                PacketMapping {
                    conn_id,
                    src_ip,
                    src_port,
                },
            );
        }

        // Forward the UDP payload
        let payload_offset = ip_header_len + 8;
        if packet.len() > payload_offset {
            let payload = &packet[payload_offset..];
            let socket = if is_v4 {
                &self.socket_v4
            } else {
                &self.socket_v6
            };

            match socket.send_to(payload, dst_addr).await {
                Ok(n) => {
                    let count = self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_forwarded
                        .fetch_add(n as u64, Ordering::Relaxed);
                    #[allow(clippy::manual_is_multiple_of)]
                    if count % 1000 == 0 {
                        info!(
                            "📤 Forwarded {} UDP packets (latest: {} bytes to {})",
                            count, n, dst_addr
                        );
                    }
                }
                Err(e) => {
                    self.stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                    warn!("UDP forward error to {}: {}", dst_addr, e);
                }
            }
        }
        Ok(())
    }

    /// Forward TCP packet (works for both IPv4 and IPv6)
    async fn forward_tcp(
        &self,
        conn_id: u64,
        packet: &[u8],
        ip_header_len: usize,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Result<()> {
        if packet.len() < ip_header_len + 20 {
            return Ok(());
        }

        let src_port = u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
        let dst_port = u16::from_be_bytes([packet[ip_header_len + 2], packet[ip_header_len + 3]]);
        let dst_addr = SocketAddr::new(dst_ip, dst_port);

        let tcp_header_len = ((packet[ip_header_len + 12] >> 4) * 4) as usize;
        let payload_offset = ip_header_len + tcp_header_len;

        let flags = packet[ip_header_len + 13];
        let syn = (flags & 0x02) != 0;
        let fin = (flags & 0x01) != 0;
        let rst = (flags & 0x04) != 0;

        let key = TcpConnKey {
            conn_id,
            src_port,
            dst_addr,
        };

        if syn && (flags & 0x10) == 0 {
            self.establish_tcp_connection(conn_id, src_ip, src_port, dst_addr)
                .await;
        } else if fin || rst {
            let mut conns = self.tcp_connections.write().await;
            conns.remove(&key);
            debug!(
                "TCP: Connection closed {}:{} -> {}",
                src_ip, src_port, dst_addr
            );
        } else if packet.len() > payload_offset {
            let payload = packet[payload_offset..].to_vec();
            if !payload.is_empty() {
                let conns = self.tcp_connections.read().await;
                if let Some(tx) = conns.get(&key) {
                    if tx.try_send(payload).is_ok() {
                        self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                        self.stats
                            .bytes_forwarded
                            .fetch_add((packet.len() - payload_offset) as u64, Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(())
    }

    /// Forward ICMP Echo Request (ping) for IPv4
    async fn forward_icmp_v4(
        &self,
        conn_id: u64,
        packet: &[u8],
        ip_header_len: usize,
        src_ip: IpAddr,
        dst_ip: Ipv4Addr,
    ) -> Result<()> {
        if packet.len() < ip_header_len + 8 {
            return Ok(());
        }

        let icmp_type = packet[ip_header_len];
        if icmp_type != 8 {
            return Ok(()); // Only handle Echo Request
        }

        let id = u16::from_be_bytes([packet[ip_header_len + 4], packet[ip_header_len + 5]]);
        let seq = u16::from_be_bytes([packet[ip_header_len + 6], packet[ip_header_len + 7]]);

        // Store mapping for response
        let key = IcmpKey {
            conn_id,
            id,
            seq,
            dst_ip: IpAddr::V4(dst_ip),
        };
        {
            let mut mappings = self.icmp_mappings.write().await;
            mappings.insert(
                key,
                PacketMapping {
                    conn_id,
                    src_ip,
                    src_port: 0,
                },
            );
        }

        // Try to send ICMP via raw socket
        if let Some(ref icmp_socket) = self.icmp_socket {
            let icmp_data = &packet[ip_header_len..];
            let dst_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(dst_ip), 0);
            if icmp_socket.send_to(icmp_data, dst_addr).is_ok() {
                self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                debug!("ICMP: Sent ping to {}", dst_ip);
            }
        } else {
            debug!("ICMP: No raw socket available, ping not forwarded");
        }
        Ok(())
    }

    /// Forward ICMPv6 Echo Request (ping) for IPv6
    async fn forward_icmp_v6(
        &self,
        conn_id: u64,
        packet: &[u8],
        ip_header_len: usize,
        src_ip: IpAddr,
        dst_ip: Ipv6Addr,
    ) -> Result<()> {
        if packet.len() < ip_header_len + 8 {
            return Ok(());
        }

        let icmp_type = packet[ip_header_len];
        if icmp_type != 128 {
            return Ok(()); // Only handle Echo Request (128 for ICMPv6)
        }

        let id = u16::from_be_bytes([packet[ip_header_len + 4], packet[ip_header_len + 5]]);
        let seq = u16::from_be_bytes([packet[ip_header_len + 6], packet[ip_header_len + 7]]);

        // Store mapping for response
        let key = IcmpKey {
            conn_id,
            id,
            seq,
            dst_ip: IpAddr::V6(dst_ip),
        };
        {
            let mut mappings = self.icmp_mappings.write().await;
            mappings.insert(
                key,
                PacketMapping {
                    conn_id,
                    src_ip,
                    src_port: 0,
                },
            );
        }

        // Try to send ICMPv6 via raw socket
        if let Some(ref icmp6_socket) = self.icmp6_socket {
            let icmp_data = &packet[ip_header_len..];
            let dst_addr = std::net::SocketAddr::new(std::net::IpAddr::V6(dst_ip), 0);
            if icmp6_socket.send_to(icmp_data, dst_addr).is_ok() {
                self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                debug!("ICMPv6: Sent ping to {}", dst_ip);
            }
        } else {
            debug!("ICMPv6: No raw socket available, ping not forwarded");
        }
        Ok(())
    }

    /// Establish a TCP connection to destination and set up bidirectional proxy
    async fn establish_tcp_connection(
        &self,
        conn_id: u64,
        src_ip: IpAddr,
        src_port: u16,
        dst_addr: SocketAddr,
    ) {
        let key = TcpConnKey {
            conn_id,
            src_port,
            dst_addr,
        };

        // Check if connection already exists
        {
            let conns = self.tcp_connections.read().await;
            if conns.contains_key(&key) {
                return;
            }
        }

        // Connect to destination
        let stream = match TcpStream::connect(dst_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("TCP connect to {} failed: {}", dst_addr, e);
                return;
            }
        };

        info!("TCP: Connected to {} for {}:{}", dst_addr, src_ip, src_port);

        let (mut read_half, mut write_half) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        // Create TCP state for tracking seq/ack
        // Initial client seq is 0 since we're establishing a new connection
        let tcp_state = Arc::new(TcpState::new(src_ip, 0));

        // Store the write channel and TCP state
        {
            let mut conns = self.tcp_connections.write().await;
            conns.insert(key.clone(), tx);
        }
        {
            let mut states = self.tcp_states.write().await;
            states.insert(key.clone(), tcp_state.clone());
        }

        // Spawn task to write data to TCP connection
        let tcp_conns = self.tcp_connections.clone();
        let tcp_states = self.tcp_states.clone();
        let key_clone = key.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if write_half.write_all(&data).await.is_err() {
                    break;
                }
            }
            // Cleanup on disconnect
            let mut conns = tcp_conns.write().await;
            conns.remove(&key_clone);
            drop(conns);
            let mut states = tcp_states.write().await;
            states.remove(&key_clone);
        });

        // Spawn task to read responses and send back to client
        let response_channels = self.response_channels.clone();
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        // Use TCP state to get proper seq/ack numbers
                        let seq = tcp_state.advance_seq(n);
                        let ack = tcp_state.get_ack();
                        // PSH+ACK flags (0x18) for data packets
                        let flags = 0x18;
                        let response = Self::build_tcp_response_with_state(
                            dst_addr,
                            src_ip,
                            src_port,
                            seq,
                            ack,
                            flags,
                            &buf[..n],
                        );
                        let channels = response_channels.read().await;
                        if let Some(tx) = channels.get(&conn_id) {
                            let _ = tx.try_send(response);
                            stats.packets_received.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    /// Build a TCP response packet with proper seq/ack (supports IPv4 and IPv6)
    fn build_tcp_response_with_state(
        src_addr: SocketAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        match (src_addr.ip(), dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => Self::build_tcp_response_v4(
                src_ip,
                src_addr.port(),
                dst_ip,
                dst_port,
                seq,
                ack,
                flags,
                payload,
            ),
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => Self::build_tcp_response_v6(
                src_ip,
                src_addr.port(),
                dst_ip,
                dst_port,
                seq,
                ack,
                flags,
                payload,
            ),
            _ => Vec::new(),
        }
    }

    /// Build an IPv4 TCP response packet with proper seq/ack/flags and checksums
    #[allow(clippy::too_many_arguments)]
    fn build_tcp_response_v4(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_header_len = 20;
        let ip_len = 20 + tcp_header_len + payload.len();
        let mut packet = vec![0u8; ip_len];

        // IP Header (20 bytes)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00; // DSCP/ECN
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes()); // Total length
                                                                      // packet[4..6] - Identification (0)
        packet[6..8].copy_from_slice(&[0x40, 0x00]); // Flags: Don't Fragment
        packet[8] = 64; // TTL
        packet[9] = 6; // Protocol: TCP
                       // packet[10..12] - Header checksum (calculated below)
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // Calculate IP header checksum
        let ip_checksum = Self::checksum_oneshot(&packet[0..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // TCP Header (20 bytes at offset 20)
        packet[20..22].copy_from_slice(&src_port.to_be_bytes()); // Source port
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes()); // Dest port
        packet[24..28].copy_from_slice(&seq.to_be_bytes()); // Sequence number
        packet[28..32].copy_from_slice(&ack.to_be_bytes()); // Acknowledgment number
        packet[32] = 0x50; // Data offset: 5 (20 bytes)
        packet[33] = flags; // TCP flags
        packet[34..36].copy_from_slice(&(65535u16).to_be_bytes()); // Window size
                                                                   // packet[36..38] - Checksum (calculated below)
                                                                   // packet[38..40] - Urgent pointer (0)

        // Payload
        if !payload.is_empty() {
            packet[40..40 + payload.len()].copy_from_slice(payload);
        }

        // Calculate TCP checksum over TCP header + payload
        let tcp_checksum = Self::tcp_checksum_v4(src_ip, dst_ip, &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

    /// Build an IPv6 TCP response packet with proper seq/ack/flags and checksums
    #[allow(clippy::too_many_arguments)]
    fn build_tcp_response_v6(
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_header_len = 20;
        let tcp_payload_len = tcp_header_len + payload.len();
        let ip_len = 40 + tcp_payload_len;
        let mut packet = vec![0u8; ip_len];

        // IPv6 Header (40 bytes)
        packet[0] = 0x60; // Version 6
                          // packet[1..4] - Traffic class + Flow label (0)
        packet[4..6].copy_from_slice(&(tcp_payload_len as u16).to_be_bytes()); // Payload length
        packet[6] = 6; // Next header: TCP
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&src_ip.octets());
        packet[24..40].copy_from_slice(&dst_ip.octets());

        // TCP Header (20 bytes at offset 40)
        packet[40..42].copy_from_slice(&src_port.to_be_bytes()); // Source port
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes()); // Dest port
        packet[44..48].copy_from_slice(&seq.to_be_bytes()); // Sequence number
        packet[48..52].copy_from_slice(&ack.to_be_bytes()); // Acknowledgment number
        packet[52] = 0x50; // Data offset: 5 (20 bytes)
        packet[53] = flags; // TCP flags
        packet[54..56].copy_from_slice(&(65535u16).to_be_bytes()); // Window size
                                                                   // packet[56..58] - Checksum (calculated below)
                                                                   // packet[58..60] - Urgent pointer (0)

        // Payload
        if !payload.is_empty() {
            packet[60..60 + payload.len()].copy_from_slice(payload);
        }

        // Calculate TCP checksum over TCP header + payload
        let tcp_checksum = Self::tcp_checksum_v6(src_ip, dst_ip, &packet[40..]);
        packet[56..58].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

    /// Get forwarder statistics
    pub fn stats(&self) -> &ForwarderStats {
        &self.stats
    }
}

// Type alias for backward compatibility
pub type SharedTunForwarder = SharedForwarder;
