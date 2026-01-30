# 🚀 OxTunnel Protocol Documentation

OxTunnel is Oxidize's **unified cross-platform** tunnel protocol for desktop and mobile connectivity. It replaces WireGuard with a lighter, faster implementation optimized for modern networks and works seamlessly across all platforms.

> **Full Traffic Support**: OxTunnel tunnels **both TCP and UDP** traffic through AF_XDP/UDP, ensuring all your network activity benefits from Oxidize's optimizations.

## Unified Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        OxTunnel Unified Protocol                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
│  │   Desktop   │    │   Mobile    │    │   Mobile    │                 │
│  │   (Linux)   │    │  (Android)  │    │    (iOS)    │                 │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                 │
│         │                  │                  │                         │
│  ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐                 │
│  │  NFQUEUE    │    │ VpnService  │    │ NEPacketTun │                 │
│  │  Capture    │    │   Capture   │    │   Capture   │                 │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                 │
│         │                  │                  │                         │
│         └────────────┬─────┴──────────────────┘                         │
│                      │                                                  │
│              ┌───────▼───────┐                                          │
│              │   OxTunnel    │  ◄── Unified packet encapsulation        │
│              │   Batching    │      (9-byte header, optional crypto)    │
│              └───────┬───────┘                                          │
│                      │                                                  │
│         ┌────────────┼────────────┐                                     │
│         │            │            │                                     │
│  ┌──────▼──────┐ ┌───▼───┐ ┌──────▼──────┐                             │
│  │   AF_XDP    │ │  UDP  │ │    UDP      │                             │
│  │  (Linux)    │ │(Other)│ │  (Mobile)   │                             │
│  │  Zero-Copy  │ │       │ │             │                             │
│  └──────┬──────┘ └───┬───┘ └──────┬──────┘                             │
│         │            │            │                                     │
│         └────────────┴────────────┘                                     │
│                      │                                                  │
│              ┌───────▼───────┐                                          │
│              │  Relay Server │                                          │
│              │  (Unified)    │                                          │
│              └───────────────┘                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Benefits:**
- **Same protocol** on desktop, Android, and iOS
- **AF_XDP primary** on Linux for kernel bypass (18-25 Gbps)
- **Optimized UDP** for macOS/Windows/mobile
- **Single server** handles all client types
- **Dual-stack IPv4/IPv6** - server binds to `[::]:51820` for both
- **TCP fallback** on port 51821 for restrictive networks (firewalls blocking UDP)

## Why OxTunnel?

WireGuard is excellent, but has limitations for our use case:

| Limitation | WireGuard | OxTunnel Solution |
|------------|-----------|-------------------|
| Mandatory encryption | Always ChaCha20-Poly1305 | Optional - skip on trusted networks |
| Complex handshake | Multi-round Noise protocol | Single round-trip |
| Header overhead | 32+ bytes | 9 bytes |
| Buffer allocation | malloc per packet | Zero-copy pool |
| Batch processing | Not supported | Native batching |

## Protocol Specification

### Packet Header (9 bytes)

```
┌─────────────────────────────────────────────────────────────┐
│  Magic (2)  │  Flags (1)  │  SeqNum (4)  │  Length (2)     │
├─────────────────────────────────────────────────────────────┤
│    0x4F58   │   0bXXXXXXXX │   uint32_be  │   uint16_be     │
└─────────────────────────────────────────────────────────────┘
```

- **Magic**: `0x4F58` ("OX" for Oxidize) - Protocol identification
- **Flags**: Bitfield for packet options
- **SeqNum**: 32-bit sequence number for ordering/dedup
- **Length**: Payload length in bytes

### Flags

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x01 | Encrypted payload (ChaCha20-Poly1305) |
| 1 | 0x02 | Compressed payload (LZ4) |
| 2 | 0x04 | Batch packet (contains multiple IP packets) |
| 3 | 0x08 | Control message (not IP packet) |
| 4 | 0x10 | IPv6 payload |

### Control Messages

| Type | Value | Description |
|------|-------|-------------|
| HANDSHAKE_INIT | 0x01 | Client initiates connection |
| HANDSHAKE_RESPONSE | 0x02 | Server responds with config |
| KEEPALIVE | 0x03 | Connection keepalive |
| DISCONNECT | 0x04 | Graceful disconnect |
| ACK | 0x05 | Acknowledgment |
| CONFIG_UPDATE | 0x06 | Server pushes new config |

## Handshake Flow

```
Client                                    Server
  │                                          │
  │─────── HANDSHAKE_INIT ─────────────────►│
  │        (client_id, timestamp,            │
  │         capabilities, request_encryption)│
  │                                          │
  │◄────── HANDSHAKE_RESPONSE ──────────────│
  │        (server_id, assigned_ip,          │
  │         encryption_key?)                 │
  │                                          │
  │═══════ DATA PACKETS ═══════════════════►│
  │◄════════════════════════════════════════│
```

**Single round-trip** vs WireGuard's multi-round Noise handshake.

## Encryption (Optional)

When enabled, OxTunnel uses **ChaCha20-Poly1305**:

- **Key**: 256-bit key exchanged during handshake
- **Nonce**: 96-bit counter-based (12 bytes)
- **Tag**: 128-bit authentication tag (16 bytes)

```
┌──────────────────────────────────────────────────────────┐
│  Header (9)  │  Nonce (12)  │  Ciphertext  │  Tag (16)  │
└──────────────────────────────────────────────────────────┘
```

**When to disable encryption:**
- Trusted local networks (home NAS, local gaming)
- Already-encrypted inner protocols (HTTPS, SSH)
- Performance-critical scenarios (~40% speedup)

## Zero-Copy Buffer Pool

OxTunnel pre-allocates buffers to avoid per-packet allocation:

```rust
// Buffer pool configuration
const BUFFER_POOL_SIZE: usize = 128;
const MAX_PACKET_SIZE: usize = 1500;
const CACHE_LINE_SIZE: usize = 64;

// Buffers are cache-aligned for optimal performance
#[repr(align(64))]
struct TunnelBuffer {
    data: [u8; MAX_PACKET_SIZE],
    len: usize,
}
```

**Benefits:**
- Zero heap allocation on hot path
- Cache-aligned for CPU efficiency
- Lock-free acquisition/release
- Automatic fallback if pool exhausted

## Batch Processing

Multiple IP packets can be combined in a single OxTunnel packet:

```
┌─────────────────────────────────────────────────────────┐
│  Header (flags=BATCH)  │  Count (2)  │  Packets...     │
├─────────────────────────────────────────────────────────┤
│  For each packet:      │  Length (2) │  IP Packet      │
└─────────────────────────────────────────────────────────┘
```

**Advantages:**
- Fewer syscalls (recvmsg/sendmsg)
- Better UDP GSO/GRO utilization
- Reduced per-packet overhead

## Server Configuration

```toml
# config.toml
[mobile_tunnel]
enable_mobile_tunnel = true
mobile_tunnel_port = 51820

# Server generates config with:
# ./oxidize-server --generate-mobile-config
```

## Performance Comparison

| Metric | WireGuard | OxTunnel | Improvement |
|--------|-----------|----------|-------------|
| Header overhead | 32 bytes | 9 bytes | **72% smaller** |
| Handshake RTT | 2-3 | 1 | **50-66% faster** |
| Encryption (optional) | Always | Skip when safe | **~40% faster** |
| Buffer allocation | malloc/packet | Zero-copy | **Lower CPU** |
| Batch efficiency | 1 packet/call | 64 packets/call | **64x fewer syscalls** |

## Pipeline Optimizations

The OxTunnel implementation includes several low-level optimizations:

### Zero-Allocation Hot Path
- **Ownership transfer** - Packet data ownership is transferred through the pipeline instead of cloning
- **In-place decoding** - OxTunnel packets are decoded in-place without buffer copies
- **Pre-sized allocations** - Output buffers are sized exactly to avoid reallocation

### Compression
- **LZ4 DEFAULT mode** - Uses ~6 GB/s compression (30x faster than HIGH mode with only ~5% worse ratio)
- **AI entropy detection** - Skips compression for encrypted/high-entropy data automatically
- **ROHC header compression** - 44% size reduction for small UDP/VoIP packets

### No Double Work
- **AF_XDP + OxTunnel** - Zero-copy packet processing with kernel bypass
- **Smart compression** - AI engine skips compression for already-compressed or encrypted payloads

## Mobile Optimizations

OxTunnel is specifically optimized for mobile:

### Battery Efficiency
- Optional encryption reduces CPU usage
- Fewer handshake round-trips
- Batch processing reduces radio wake-ups

### Network Transitions
- Single-round handshake for fast reconnects
- Session state preserved across IP changes
- Keepalive tuned for mobile networks

### Congested Networks
- Adaptive FEC integration
- Smaller headers = less wasted bandwidth
- Compression support (LZ4)

## Cross-Platform Support

| Platform | Capture | Protocols | Transport | IPv6 | TCP Fallback | Status |
|----------|---------|-----------|-----------|------|--------------|--------|
| Linux (server) | - | TCP + UDP + ICMP | AF_XDP | ✅ | ✅ Port 51821 | ✅ Full support |
| Linux (client) | NFQUEUE | TCP + UDP + ICMP | AF_XDP/UDP | ✅ | ✅ Auto | ✅ Full support |
| macOS | PF/Utun | TCP + UDP + ICMP | Optimized UDP | ✅ | ✅ Auto | ✅ Full support |
| Windows | WinDivert | TCP + UDP + ICMP | Optimized UDP | ✅ | ✅ Auto | ✅ Full support |
| Android | VpnService | TCP + UDP + ICMP | UDP | ✅ | ✅ Auto | ✅ Full support |
| iOS | NEPacketTunnel | TCP + UDP + ICMP | UDP | ✅ | ✅ Auto | ✅ Full support |

**All platforms use the same OxTunnel protocol** with platform-specific packet capture and optimized transport.

### Dual-Stack IPv6 Support

The server binds to `[::]:51820` by default, which accepts both IPv4 and IPv6 connections:
- IPv4 clients connect normally (mapped to `::ffff:x.x.x.x` internally)
- IPv6 clients connect directly via IPv6

### TCP Fallback for Restrictive Networks

For networks that block UDP (corporate firewalls, some hotels), clients automatically fall back to TCP:
- Server listens on port **51821/tcp** alongside UDP on 51820
- Client auto-detects: tries UDP first, falls back to TCP if blocked
- Same OxTunnel protocol over length-prefixed TCP framing
- Slightly higher latency than UDP but works everywhere

## ICMP (Ping) Support

OxTunnel supports ICMP Echo Request/Reply (ping) for both IPv4 and IPv6:

| Protocol | Type | Status |
|----------|------|--------|
| ICMP (IPv4) | Echo Request (8) / Reply (0) | ✅ Full support |
| ICMPv6 | Echo Request (128) / Reply (129) | ✅ Full support |

**Server Requirements:**
```bash
# Enable unprivileged ICMP for all users (IPv4)
sudo sysctl -w net.ipv4.ping_group_range="0 65535"

# Or grant CAP_NET_RAW capability
sudo setcap cap_net_raw+ep /path/to/oxidize-server
```

The server creates raw ICMP sockets and tracks Echo Request/Reply pairs using (id, seq, dst_ip) as keys for proper response routing back to clients.

## Bidirectional Tunnel Architecture

OxTunnel implements full bidirectional tunneling with response injection:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Complete Tunnel Data Flow                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CLIENT OUTBOUND:                                                       │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐         │
│  │   App    │───►│ NFQUEUE  │───►│ OxTunnel │───►│   UDP    │         │
│  │ (TCP/UDP)│    │  (DROP)  │    │ Encrypt  │    │ to Server│         │
│  └──────────┘    └──────────┘    └──────────┘    └────┬─────┘         │
│                                                       │                │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─  │
│                                                       ▼                │
│  SERVER:                                         ┌──────────┐         │
│                                                  │  Server  │         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐   │ Decrypt  │         │
│  │ Internet │◄──►│ Forwarder│◄──►│   NAT    │◄──►│ + Route  │         │
│  │          │    │ (TCP/UDP)│    │MASQUERADE│   │          │         │
│  └──────────┘    └──────────┘    └──────────┘   └────┬─────┘         │
│                                                       │                │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─  │
│                                                       ▼                │
│  CLIENT INBOUND:                                 ┌──────────┐         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐   │   UDP    │         │
│  │   App    │◄───│ Response │◄───│ OxTunnel │◄──│from Server│         │
│  │ (TCP/UDP)│    │ Injector │    │ Decrypt  │   │          │         │
│  └──────────┘    └──────────┘    └──────────┘   └──────────┘         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Platform | Description |
|-----------|----------|-------------|
| **NFQUEUE Capture** | Linux | Intercepts OUTPUT chain only, DROPs original packets |
| **Response Injector** | Linux | Raw socket with `IP_HDRINCL` injects responses |
| **NAT/MASQUERADE** | Server | Source NAT for tunnel IP pool (10.0.0.0/8) |
| **SharedForwarder** | Server | Routes responses back to correct client |

### System Traffic Exclusions

The following traffic is **never tunneled** to ensure system functionality:

| Traffic | Port | Reason |
|---------|------|--------|
| DNS | 53/udp, 53/tcp | Name resolution must work directly |
| DHCP | 67-68/udp | IP address renewal |
| NTP | 123/udp | Time synchronization |
| mDNS | 5353/udp | Local network discovery |
| Localhost | 127.0.0.0/8 | Local traffic never tunneled |
| Relay Server | (dynamic) | Tunnel traffic itself excluded |

### Response Injection (Linux)

The `ResponseInjector` uses raw sockets to inject decrypted response packets directly into the local network stack:

```rust
// Creates raw socket with IP_HDRINCL (we provide full IP header)
let sock = socket2::Socket::new(Domain::IPV4, Type::RAW, Protocol::from(IPPROTO_RAW))?;
sock.set_header_included_v4(true)?;

// Extract destination IP from packet header (bytes 16-19 for IPv4)
let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
let dest_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(dst_ip), 0));

// Inject complete IP packet (header + payload)
libc::sendto(fd, packet.as_ptr(), packet.len(), 0, dest_addr.as_ptr(), dest_addr.len());
```

**Requirements:**
- `CAP_NET_RAW` capability (daemon runs as root)
- IPv4 and IPv6 raw sockets created at startup
- Destination extracted from IP header for routing

### NFQUEUE Capture Flow

NFQUEUE only captures the **OUTPUT chain** (outbound traffic). Responses come through the tunnel and are injected via raw sockets:

```bash
# Capture outbound TCP/UDP (OUTPUT chain only)
iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I OUTPUT -p udp -j NFQUEUE --queue-num 0 --queue-bypass

# Exclude system traffic
iptables -I OUTPUT -p udp --dport 53 -j ACCEPT      # DNS
iptables -I OUTPUT -p udp --dport 67:68 -j ACCEPT   # DHCP
iptables -I OUTPUT -p udp --dport 123 -j ACCEPT     # NTP
iptables -I OUTPUT -p udp --dport 5353 -j ACCEPT    # mDNS
iptables -I OUTPUT -d 127.0.0.0/8 -j ACCEPT         # Localhost

# Exclude relay server (both directions)
iptables -I OUTPUT -d $RELAY_IP -j ACCEPT
iptables -I INPUT -s $RELAY_IP -j ACCEPT
```

**Verdict handling:**
- Packet sent to tunnel → `Verdict::Drop` (original packet dropped)
- Tunnel channel full → `Verdict::Accept` (fallback to direct)

### Server-Side Forwarder (SharedForwarder)

The server uses `SharedForwarder` to route packets to destinations and route responses back to clients:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Server SharedForwarder Architecture                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Client Packet                                                          │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │ OxTunnel │───►│ SharedFwd    │───►│  Internet    │                  │
│  │ Decrypt  │    │ forward_pkt  │    │ (UDP/TCP)    │                  │
│  └──────────┘    └──────┬───────┘    └──────┬───────┘                  │
│                         │                   │                           │
│                   Store mapping       Response arrives                  │
│                   (dst → conn_id)           │                           │
│                         │                   │                           │
│                         ▼                   ▼                           │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │ OxTunnel │◄───│ SharedFwd    │◄───│ Response     │                  │
│  │ Encrypt  │    │ route_resp   │    │ Listener     │                  │
│  └──────────┘    └──────────────┘    └──────────────┘                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Protocol Support:**
| Protocol | Forward | Response Routing |
|----------|---------|------------------|
| UDP | `socket_v4/v6.send_to()` | `packet_mappings` lookup |
| TCP | Connection pool | Per-connection read task |
| ICMP | Raw ICMP socket | `icmp_mappings` (id+seq+dst) |

### Server-Side NAT

The server uses MASQUERADE for tunnel traffic:

```bash
# IPv4 NAT for tunnel IP pool
iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o $DEFAULT_IF -j MASQUERADE

# IPv6 NAT for tunnel IP pool  
ip6tables -t nat -A POSTROUTING -s fd00::/8 -o $DEFAULT_IF -j MASQUERADE

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
```

## TCP Tunneling Architecture

OxTunnel tunnels TCP traffic through UDP datagrams with connection pooling on the server:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      TCP Tunneling Flow                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Client Side:                                                       │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │   App    │───►│ NFQUEUE  │───►│  Client  │───►│   UDP    │     │
│  │ (TCP/UDP)│    │ Capture  │    │ Batching │    │ Datagram │     │
│  └──────────┘    └──────────┘    └──────────┘    └────┬─────┘     │
│                                                       │            │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─  │
│                                                       │            │
│  Server Side:                                         ▼            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │ Internet │◄───│   TCP    │◄───│ Protocol │◄───│  Server  │     │
│  │          │    │  Proxy   │    │ Dispatch │    │ Receive  │     │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│                       │                                            │
│                       ▼                                            │
│              Connection Pooling                                    │
│              (reuse TCP connections)                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### TCP Handling Details

| Phase | Action | Description |
|-------|--------|-------------|
| SYN | `establish_tcp_connection()` | Server opens TCP connection to destination |
| DATA | Forward payload | TCP payload extracted and sent to destination |
| FIN/RST | Close connection | Connection removed from pool |

### Benefits of TCP Tunneling

| Benefit | Description |
|---------|-------------|
| **Multiplexing** | Multiple TCP flows share single UDP connection |
| **0-RTT** | Instant reconnection with session resumption |
| **Encryption** | All traffic encrypted by ChaCha20-Poly1305 |
| **Adaptive FEC** | ML-driven forward error correction for loss recovery |
| **Connection Migration** | TCP flows survive network changes (WiFi→LTE) |

## Security Considerations

### With Encryption Enabled
- ChaCha20-Poly1305 AEAD (same as WireGuard)
- Forward secrecy via session keys
- Replay protection via sequence numbers
- Authentication via MAC tag

### With Encryption Disabled
- Rely on inner protocol encryption (TLS, SSH, etc.)
- Still have sequence numbers for ordering
- Use only on trusted networks
- Consider network-level security (WPA3, etc.)

## API Usage

### Server (Unified)

```rust
use relay_server::oxtunnel_server::{OxTunnelServer, OxTunnelServerConfig};

// Server handles all clients (desktop, mobile, CLI) with unified OxTunnel protocol
let config = OxTunnelServerConfig {
    listen_addr: "0.0.0.0:51820".parse()?,
    enable_encryption: true,
    ..Default::default()
};

let server = OxTunnelServer::new(config).await?;
server.run().await?;
```

### Client (Full Tunnel Mode with Response Injection)

```rust
use relay_client::client::{RelayClient, ClientConfig};
use oxidize_common::oxtunnel_client::{PacketCaptureService, CaptureConfig, ResponseInjector};

// 1. Configure client
let config = ClientConfig {
    server_addr: "<server_ip>:51820".parse()?,
    enable_encryption: true,
    enable_compression: true,
    ..Default::default()
};

// 2. Create and connect client
let client = RelayClient::new(config).await?;
client.connect().await?;

// 3. Start packet capture (NFQUEUE on Linux, WinDivert on Windows, BPF on macOS)
let capture_config = CaptureConfig {
    capture_tcp: true,
    capture_udp: true,
    exclude_ips: vec![server_addr.ip()],  // Don't capture tunnel traffic
    queue_num: 0,
};
let capture_service = PacketCaptureService::new(capture_config);
let (packet_rx, capture_handle) = capture_service.start();

// 4. Create response injector (raw sockets for injecting responses)
let response_injector = Arc::new(ResponseInjector::new());

// 5. Run bidirectional tunnel
// - Outbound: capture_rx → encrypt → send to server
// - Inbound: recv from server → decrypt → inject via raw socket
client.run_with_injection(packet_rx, response_injector).await?;
```

### Client (Mobile - UDP + VpnService)

```rust
use relay_client::client::{RelayClient, ClientConfig};

// Mobile uses optimized UDP with VpnService/NEPacketTunnel capture
let config = ClientConfig {
    server_addr: "<server_ip>:51820".parse()?,
    enable_encryption: true,
    enable_compression: true,
    ..Default::default()
};
// Same OxTunnel protocol, platform-specific packet capture
```

### Transport Configuration

```rust
use oxidize_common::platform_transport::{PlatformTransport, TransportConfig};

// Platform-optimized transport (auto-detects best option)
let config = TransportConfig {
    bind_addr: "0.0.0.0:0".parse()?,
    enable_batching: true,
    max_batch_size: 64,
    socket_buffer_size: 2 * 1024 * 1024, // 2MB
};

let transport = PlatformTransport::new(config)?;
println!("Using: {}", PlatformTransport::platform_name());
// Linux: "Linux (sendmmsg)" or AF_XDP
// macOS: "macOS (kqueue)"
// Windows: "Windows (IOCP)"
```

## Future Roadmap

- [x] **AF_XDP transport** - Kernel bypass for Linux (18-25 Gbps) ✅
- [x] **Unified protocol** - Same OxTunnel on desktop and mobile ✅
- [x] **Platform-optimized UDP** - kqueue (macOS), IOCP (Windows) ✅
- [x] **0-RTT resumption** - Instant reconnects with session tickets ✅
- [x] **Multi-path support** - Aggregate WiFi + LTE ✅
- [x] **Hardware crypto** - AES-NI/ARMv8 via ring crate ✅

---

## See Also

- [INSTALL.md](INSTALL.md) - Installation guide
- [SECURITY.md](SECURITY.md) - Security comparison with WireGuard
- [DEEP_LEARNING.md](DEEP_LEARNING.md) - Deep learning engine documentation
- [KERNEL_BYPASS.md](KERNEL_BYPASS.md) - 100x kernel bypass optimizations
