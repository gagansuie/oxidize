# 🚀 OxTunnel Protocol Documentation

OxTunnel is Oxidize's **unified cross-platform** tunnel protocol for desktop and mobile connectivity. It replaces WireGuard with a lighter, faster implementation optimized for modern networks and works seamlessly across all platforms.

> **Full Traffic Support**: OxTunnel tunnels **both TCP and UDP** traffic through QUIC, ensuring all your network activity benefits from Oxidize's optimizations.

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
│  │    QUIC     │ │  UDP  │ │    QUIC     │                             │
│  │  Datagrams  │ │Fallback│ │  Datagrams  │                             │
│  │  (Primary)  │ │       │ │  (Primary)  │                             │
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
- **QUIC primary** for all platforms (encrypted, multiplexed, 0-RTT)
- **UDP fallback** for networks that block QUIC
- **Single server** handles all client types

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
- **QUIC + OxTunnel** - When using QUIC transport (primary), OxTunnel encryption is disabled since QUIC already encrypts
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

| Platform | Capture | Protocols | Transport | Status |
|----------|---------|-----------|-----------|--------|
| Linux (server) | - | TCP + UDP + ICMP | QUIC/UDP | ✅ Full support |
| Linux (client) | NFQUEUE | TCP + UDP + ICMP | QUIC | ✅ Full support |
| macOS | PF/Utun | TCP + UDP + ICMP | QUIC | ✅ Full support |
| Windows | WinDivert | TCP + UDP + ICMP | QUIC | ✅ Full support |
| Android | VpnService | TCP + UDP + ICMP | QUIC/UDP | ✅ Full support |
| iOS | NEPacketTunnel | TCP + UDP + ICMP | QUIC/UDP | ✅ Full support |

**All platforms use the same OxTunnel protocol** with platform-specific packet capture and unified QUIC transport.

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

## TCP over QUIC Architecture

OxTunnel tunnels TCP traffic through QUIC datagrams with connection pooling on the server:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      TCP Tunneling Flow                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Client Side:                                                       │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │   App    │───►│ NFQUEUE  │───►│  Client  │───►│   QUIC   │     │
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

### Benefits of TCP over QUIC

| Benefit | Description |
|---------|-------------|
| **Multiplexing** | Multiple TCP flows share single QUIC connection |
| **0-RTT** | Instant reconnection with session resumption |
| **Encryption** | All traffic encrypted by QUIC TLS 1.3 |
| **Loss Recovery** | QUIC's superior loss recovery benefits TCP traffic |
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

### Client (Desktop - QUIC + NFQUEUE)

```rust
use oxidize_common::unified_transport::{UnifiedTransportConfig, TransportType};

// Desktop uses QUIC transport with NFQUEUE packet capture
let config = UnifiedTransportConfig::desktop("<server_ip>:4433".parse()?);
// Packets captured via NFQUEUE are batched and sent over QUIC datagrams
```

### Client (Mobile - QUIC + VpnService)

```rust
use oxidize_common::unified_transport::{UnifiedTransportConfig, TransportType};

// Mobile uses same QUIC transport with VpnService/NEPacketTunnel capture
let config = UnifiedTransportConfig::mobile("<server_ip>:4433".parse()?);
// Same OxTunnel protocol, platform-specific packet capture
```

### Transport Configuration

```rust
use oxidize_common::unified_transport::{UnifiedTransportConfig, TransportType};

// QUIC (primary - encrypted, multiplexed)
let quic_config = UnifiedTransportConfig {
    transport: TransportType::Quic,
    enable_oxtunnel_encryption: false,  // QUIC already encrypts
    enable_batching: true,
    max_batch_size: 64,
    ..Default::default()
};

// UDP fallback (when QUIC is blocked)
let udp_config = UnifiedTransportConfig {
    transport: TransportType::Udp,
    enable_oxtunnel_encryption: true,   // Need encryption without QUIC
    enable_batching: true,
    max_batch_size: 32,
    ..Default::default()
};
```

## Future Roadmap

- [x] **QUIC transport** - Unified QUIC for all platforms ✅
- [x] **Unified protocol** - Same OxTunnel on desktop and mobile ✅
- [x] **AF_XDP acceleration** - Kernel bypass for 10-25 Gbps (bare metal) ✅
- [x] **0-RTT resumption** - Instant reconnects with session tickets + anti-replay protection ✅
- [x] **Multi-path support** - Aggregate WiFi + LTE ✅
- [x] **Hardware crypto** - AES-NI/ARMv8 via ring crate ✅

---

## See Also

- [INSTALL.md](INSTALL.md) - Installation guide
- [SECURITY.md](SECURITY.md) - Security comparison with WireGuard
- [DEEP_LEARNING.md](DEEP_LEARNING.md) - Deep learning engine documentation
- [KERNEL_BYPASS.md](KERNEL_BYPASS.md) - 100x kernel bypass optimizations
