//! Cross-platform UDP socket abstraction with DPDK PMD backend
//!
//! Provides a unified interface for packet I/O across platforms:
//! - Linux: Standard UDP sockets (or DPDK PMD when enabled)
//! - macOS/Windows: Standard UDP sockets
//!
//! Performance targets with DPDK:
//! - Throughput: 100+ Gbps (line rate on 100GbE)
//! - Latency: <300ns per-packet (P99)
//! - PPS: 148+ Mpps (line rate for 64-byte packets)

use std::io::{self, Result};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
use super::dpdk_bindings::*;

/// Cross-platform UDP socket for QUIC packet I/O
pub struct QuicSocket {
    inner: SocketInner,
    local_addr: SocketAddr,
    stats: SocketStats,
}

/// Socket I/O statistics
#[derive(Default)]
pub struct SocketStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

enum SocketInner {
    /// Standard UDP socket (cross-platform)
    Std(std::net::UdpSocket),
    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    /// DPDK PMD-based socket (Linux only with DPDK feature)
    Dpdk(DpdkPmdSocket),
}

/// DPDK Poll-Mode Driver socket for 100+ Gbps performance
#[cfg(all(target_os = "linux", feature = "dpdk"))]
pub struct DpdkPmdSocket {
    /// DPDK port ID
    port_id: u16,
    /// Queue ID for this socket
    queue_id: u16,
    /// Memory pool for packet buffers
    mempool: *mut rte_mempool,
    /// Receive burst buffer
    rx_burst: Vec<*mut rte_mbuf>,
    /// Transmit burst buffer  
    tx_burst: Vec<*mut rte_mbuf>,
    /// Burst size for batch processing
    burst_size: usize,
    /// Local MAC address
    local_mac: [u8; 6],
    /// Local IP address
    local_ip: u32,
    /// Local port
    local_port: u16,
}

#[cfg(all(target_os = "linux", feature = "dpdk"))]
impl DpdkPmdSocket {
    /// Create a new DPDK PMD socket
    pub fn new(
        port_id: u16,
        queue_id: u16,
        mempool: *mut rte_mempool,
        local_addr: SocketAddr,
    ) -> Result<Self> {
        let burst_size = 64; // Optimal for most NICs

        // Get MAC address
        let mut mac_addr = rte_ether_addr { addr_bytes: [0; 6] };
        unsafe {
            if rte_eth_macaddr_get(port_id, &mut mac_addr) != 0 {
                return Err(io::Error::other("Failed to get MAC address"));
            }
        }

        let local_ip = match local_addr.ip() {
            std::net::IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 not supported yet",
                ))
            }
        };

        Ok(Self {
            port_id,
            queue_id,
            mempool,
            rx_burst: vec![std::ptr::null_mut(); burst_size],
            tx_burst: Vec::with_capacity(burst_size),
            burst_size,
            local_mac: mac_addr.addr_bytes,
            local_ip,
            local_port: local_addr.port(),
        })
    }

    /// Receive a burst of packets (high-performance path)
    pub fn recv_burst(&mut self, packets: &mut [DpdkPacket]) -> usize {
        let nb_rx = unsafe {
            rte_eth_rx_burst(
                self.port_id,
                self.queue_id,
                self.rx_burst.as_mut_ptr(),
                self.burst_size as u16,
            )
        };

        let mut count = 0;
        for i in 0..nb_rx as usize {
            let mbuf = self.rx_burst[i];
            if mbuf.is_null() {
                continue;
            }

            // Parse packet and extract UDP payload
            if let Some(pkt) = Self::parse_udp_packet(mbuf) {
                if count < packets.len() {
                    packets[count] = pkt;
                    count += 1;
                }
            }

            // Free mbuf
            unsafe {
                rte_pktmbuf_free(mbuf);
            }
        }

        count
    }

    /// Send a burst of packets (high-performance path)
    pub fn send_burst(&mut self, packets: &[DpdkPacket]) -> usize {
        self.tx_burst.clear();

        for pkt in packets {
            if let Some(mbuf) = self.build_udp_packet(pkt) {
                self.tx_burst.push(mbuf);
            }
        }

        if self.tx_burst.is_empty() {
            return 0;
        }

        let nb_tx = unsafe {
            rte_eth_tx_burst(
                self.port_id,
                self.queue_id,
                self.tx_burst.as_mut_ptr(),
                self.tx_burst.len() as u16,
            )
        };

        // Free unsent mbufs
        for i in nb_tx as usize..self.tx_burst.len() {
            unsafe {
                rte_pktmbuf_free(self.tx_burst[i]);
            }
        }

        nb_tx as usize
    }

    /// Parse incoming UDP packet from mbuf
    fn parse_udp_packet(mbuf: *mut rte_mbuf) -> Option<DpdkPacket> {
        unsafe {
            let data = rte_pktmbuf_mtod(mbuf) as *const u8;
            let data_len = (*mbuf).data_len as usize;

            if data_len < 42 {
                // Ethernet + IP + UDP headers
                return None;
            }

            // Skip Ethernet header (14 bytes)
            let ip_hdr = data.add(14);

            // Check IP version and protocol (UDP = 17)
            let version_ihl = *ip_hdr;
            if (version_ihl >> 4) != 4 {
                return None; // Not IPv4
            }
            let ihl = ((version_ihl & 0x0f) * 4) as usize;
            let protocol = *ip_hdr.add(9);
            if protocol != 17 {
                return None; // Not UDP
            }

            // Extract IP addresses
            let src_ip = u32::from_be_bytes([
                *ip_hdr.add(12),
                *ip_hdr.add(13),
                *ip_hdr.add(14),
                *ip_hdr.add(15),
            ]);
            let dst_ip = u32::from_be_bytes([
                *ip_hdr.add(16),
                *ip_hdr.add(17),
                *ip_hdr.add(18),
                *ip_hdr.add(19),
            ]);

            // UDP header
            let udp_hdr = ip_hdr.add(ihl);
            let src_port = u16::from_be_bytes([*udp_hdr, *udp_hdr.add(1)]);
            let dst_port = u16::from_be_bytes([*udp_hdr.add(2), *udp_hdr.add(3)]);
            let udp_len = u16::from_be_bytes([*udp_hdr.add(4), *udp_hdr.add(5)]) as usize;

            // UDP payload
            let payload_start = 14 + ihl + 8;
            let payload_len = udp_len.saturating_sub(8);

            if payload_start + payload_len > data_len {
                return None;
            }

            let payload = std::slice::from_raw_parts(data.add(payload_start), payload_len);

            Some(DpdkPacket {
                data: payload.to_vec(),
                src_addr: SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(src_ip.to_be_bytes())),
                    src_port,
                ),
                dst_addr: SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(dst_ip.to_be_bytes())),
                    dst_port,
                ),
            })
        }
    }

    /// Build outgoing UDP packet in mbuf
    fn build_udp_packet(&self, pkt: &DpdkPacket) -> Option<*mut rte_mbuf> {
        unsafe {
            let mbuf = rte_pktmbuf_alloc(self.mempool);
            if mbuf.is_null() {
                return None;
            }

            let total_len = 14 + 20 + 8 + pkt.data.len(); // Eth + IP + UDP + payload
            let data = rte_pktmbuf_mtod(mbuf) as *mut u8;

            // Ethernet header
            let dst_mac = Self::get_dst_mac(&pkt.dst_addr); // Would need ARP resolution
            std::ptr::copy_nonoverlapping(dst_mac.as_ptr(), data, 6);
            std::ptr::copy_nonoverlapping(self.local_mac.as_ptr(), data.add(6), 6);
            *data.add(12) = 0x08; // EtherType: IPv4
            *data.add(13) = 0x00;

            // IP header
            let ip_hdr = data.add(14);
            *ip_hdr = 0x45; // Version + IHL
            *ip_hdr.add(1) = 0x00; // DSCP + ECN
            let ip_len = (20 + 8 + pkt.data.len()) as u16;
            *ip_hdr.add(2) = (ip_len >> 8) as u8;
            *ip_hdr.add(3) = ip_len as u8;
            // ID, flags, fragment offset
            *ip_hdr.add(4) = 0;
            *ip_hdr.add(5) = 0;
            *ip_hdr.add(6) = 0x40; // Don't fragment
            *ip_hdr.add(7) = 0;
            *ip_hdr.add(8) = 64; // TTL
            *ip_hdr.add(9) = 17; // Protocol: UDP
                                 // Checksum (calculated later or offloaded)
            *ip_hdr.add(10) = 0;
            *ip_hdr.add(11) = 0;
            // Source IP
            let src_ip = self.local_ip.to_be_bytes();
            std::ptr::copy_nonoverlapping(src_ip.as_ptr(), ip_hdr.add(12), 4);
            // Destination IP
            let dst_ip = match pkt.dst_addr.ip() {
                std::net::IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()),
                _ => return None,
            };
            let dst_ip_bytes = dst_ip.to_be_bytes();
            std::ptr::copy_nonoverlapping(dst_ip_bytes.as_ptr(), ip_hdr.add(16), 4);

            // UDP header
            let udp_hdr = ip_hdr.add(20);
            let src_port = self.local_port.to_be_bytes();
            let dst_port = pkt.dst_addr.port().to_be_bytes();
            *udp_hdr = src_port[0];
            *udp_hdr.add(1) = src_port[1];
            *udp_hdr.add(2) = dst_port[0];
            *udp_hdr.add(3) = dst_port[1];
            let udp_len = (8 + pkt.data.len()) as u16;
            *udp_hdr.add(4) = (udp_len >> 8) as u8;
            *udp_hdr.add(5) = udp_len as u8;
            // Checksum (optional for UDP over IPv4)
            *udp_hdr.add(6) = 0;
            *udp_hdr.add(7) = 0;

            // Payload
            std::ptr::copy_nonoverlapping(pkt.data.as_ptr(), udp_hdr.add(8), pkt.data.len());

            // Set packet length
            (*mbuf).data_len = total_len as u16;
            (*mbuf).pkt_len = total_len as u32;

            // Enable TX offloads
            (*mbuf).ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;

            Some(mbuf)
        }
    }

    fn get_dst_mac(_addr: &SocketAddr) -> [u8; 6] {
        // In production, this would use ARP cache or be set via flow rules
        // For now, use broadcast (gateway will handle it)
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }
}

/// DPDK packet representation
#[cfg(all(target_os = "linux", feature = "dpdk"))]
#[derive(Clone)]
pub struct DpdkPacket {
    pub data: Vec<u8>,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

impl QuicSocket {
    /// Create a new UDP socket bound to the given address
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        // Set socket options for high performance
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();

            // Increase receive buffer size
            unsafe {
                let bufsize: libc::c_int = 16 * 1024 * 1024; // 16MB
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &bufsize as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &bufsize as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        let local_addr = socket.local_addr()?;

        Ok(Self {
            inner: SocketInner::Std(socket),
            local_addr,
            stats: SocketStats::default(),
        })
    }

    /// Create a DPDK PMD-backed socket (Linux only with DPDK feature)
    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    pub fn bind_dpdk(
        addr: SocketAddr,
        port_id: u16,
        queue_id: u16,
        mempool: *mut rte_mempool,
    ) -> Result<Self> {
        let dpdk_socket = DpdkPmdSocket::new(port_id, queue_id, mempool, addr)?;
        Ok(Self {
            inner: SocketInner::Dpdk(dpdk_socket),
            local_addr: addr,
            stats: SocketStats::default(),
        })
    }

    /// Get socket statistics
    pub fn stats(&self) -> &SocketStats {
        &self.stats
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Receive packets into buffer, returns (bytes_read, source_addr)
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match &self.inner {
            SocketInner::Std(socket) => socket.recv_from(buf),
            #[cfg(all(target_os = "linux", feature = "dpdk"))]
            SocketInner::Dpdk(_dpdk) => {
                // DPDK receive path - implemented in runtime
                Err(io::Error::new(io::ErrorKind::WouldBlock, "use batch recv"))
            }
        }
    }

    /// Send packet to destination
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        match &self.inner {
            SocketInner::Std(socket) => socket.send_to(buf, addr),
            #[cfg(all(target_os = "linux", feature = "dpdk"))]
            SocketInner::Dpdk(_dpdk) => {
                // DPDK send path - implemented in runtime
                Err(io::Error::new(io::ErrorKind::WouldBlock, "use batch send"))
            }
        }
    }

    /// Try to receive without blocking
    pub fn try_recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.recv_from(buf)
    }

    /// Poll for readability (for async integration)
    #[cfg(unix)]
    pub fn poll_readable(&self) -> Result<bool> {
        match &self.inner {
            SocketInner::Std(socket) => {
                use std::os::unix::io::AsRawFd;
                let fd = socket.as_raw_fd();

                let mut pollfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };

                let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }

                Ok(pollfd.revents & libc::POLLIN != 0)
            }
            #[cfg(all(target_os = "linux", feature = "dpdk"))]
            SocketInner::Dpdk(_) => Ok(true), // DPDK is always poll-ready
        }
    }

    #[cfg(not(unix))]
    pub fn poll_readable(&self) -> Result<bool> {
        // On Windows, use select or IOCP
        Ok(true)
    }
}

// SAFETY: QuicSocket is Send+Sync because:
// - For Std variant: std::net::UdpSocket is Send+Sync
// - For Dpdk variant: DPDK queues are designed for single-threaded access per queue,
//   but the socket itself can be safely sent between threads. The raw pointers point
//   to DPDK-managed memory that outlives the socket.
unsafe impl Send for QuicSocket {}
unsafe impl Sync for QuicSocket {}

/// Async wrapper for QuicSocket using tokio
pub struct AsyncQuicSocket {
    inner: Arc<QuicSocket>,
}

// SAFETY: AsyncQuicSocket is Send+Sync because QuicSocket is Send+Sync
unsafe impl Send for AsyncQuicSocket {}
unsafe impl Sync for AsyncQuicSocket {}

impl AsyncQuicSocket {
    pub fn new(socket: QuicSocket) -> Self {
        Self {
            inner: Arc::new(socket),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    /// Async receive
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        loop {
            match self.inner.try_recv_from(buf) {
                Ok(result) => return Ok(result),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Yield to other tasks
                    tokio::task::yield_now().await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Async send
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.inner.send_to(buf, addr)
    }

    /// Get reference to inner socket
    pub fn socket(&self) -> &QuicSocket {
        &self.inner
    }
}

/// Batch packet buffer for high-performance I/O
pub struct PacketBatch {
    /// Packet data buffers
    pub packets: Vec<Vec<u8>>,
    /// Source addresses
    pub addrs: Vec<SocketAddr>,
    /// Number of valid packets
    pub count: usize,
}

impl PacketBatch {
    pub fn new(capacity: usize) -> Self {
        Self {
            packets: (0..capacity).map(|_| vec![0u8; 1500]).collect(),
            addrs: vec![SocketAddr::from(([0, 0, 0, 0], 0)); capacity],
            count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.count
    }
}
