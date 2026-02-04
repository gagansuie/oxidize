# TUN + QUIC/MASQUE Implementation

## Architecture Overview

Full-coverage network acceleration with UDP → QUIC → TCP fallback, **AF_XDP/FLASH required on Linux servers**, and a userspace fast path on TUN-only clients.

### Transport Stack
```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
├─────────────────────────────────────────────────────────┤
│              TUN/Tunnel APIs (Full Coverage)           │
│  • Linux client: TUN + userspace fast path              │
│  • macOS: utun (TUN-only)                               │
│  • Windows: Wintun (TUN-only)                           │
│  • Android/iOS: VpnService/NetworkExtension             │
├─────────────────────────────────────────────────────────┤
│                  OxTunnel Protocol                      │
│  • Encryption, Compression, Batching                    │
│  • IPv4/IPv6, TCP/UDP/ICMP support                     │
├─────────────────────────────────────────────────────────┤
│              Transport Layer (Auto-Fallback)            │
│  Primary: UDP (port 51820)                             │
│  Fallback: QUIC/MASQUE (port 51822)                    │
│  Last resort: TCP (port 51821, full-duplex)            │
├─────────────────────────────────────────────────────────┤
│                   Physical Network                       │
└─────────────────────────────────────────────────────────┘
```

## Implementation Status

### Core Components (v3 migration in progress)

#### 1. TUN Device Management (`common/src/tun_device.rs`)
- **Linux**: TUN device (no client kernel bypass)
  - Creates `oxtun0` device with `tun-tap` crate
  - Configures IP address (server-assigned from pool)
  - Sets up routing via `ip route`
  - `unsafe impl Send/Sync` for thread-safe Mutex access
- **macOS**: utun device support
  - Auto-assigned utun number by kernel
  - ifconfig-based configuration
- **Windows**: Wintun adapter support
  - Native Wintun session management
  - netsh-based IP configuration
- **Android/iOS**: Platform tunnel integration
  - VpnService (Android) / NetworkExtension (iOS) for TUN access
  - Accepts pre-created TUN file descriptors

#### 2. QUIC Transport Layer (`common/src/quic_transport.rs`)
- **Pure QUIC Datagrams**: Simple, fast fallback transport
  - 0-RTT support for instant reconnection
  - QUIC datagrams for low-latency tunneling
  - Self-signed cert generation for testing
  - `SkipServerVerification` for dev environments
- **QUIC Server**: Accept incoming QUIC connections
  - TLS certificate management (rcgen)
  - Datagram receive/send
  - Connection statistics

#### 3. PacketCaptureService TUN Mode (`common/src/oxtunnel_client.rs`)
- **CaptureConfig**: Includes TUN device config, TCP/UDP/ICMP flags
- **TUN capture**: Full TCP/UDP/ICMP coverage for all client platforms
- **Userspace fast path**: batching + SIMD + buffer pools (kernel bypass is server-side)

#### 4. ResponseInjector TUN Mode (`common/src/oxtunnel_client.rs`)
- **TUN device injection**: `with_tun_device()` constructor
- **inject_to_tun()**: Write packets directly to TUN
- **Bidirectional tunnel**: Both capture and injection through same TUN
- **TUN-only**: No legacy injection paths in v3

#### 5. Daemon Integration (`daemon/src/main.rs`)
- **TUN mode default**: Creates `oxtun0` on connect
- **Shared TUN device**: Between capture and injection
- **TCP capture enabled**: `capture_tcp: true`
- **ICMP capture enabled**: `capture_icmp: true`
- **Route setup**: Default route through TUN

#### 6. Server QUIC Support (`server/src/oxtunnel_server.rs`)
- **QUIC listener**: Port 51822 (configurable)
- **run_quic_fallback()**: Handles QUIC datagram connections
- **Same packet handler**: Uses existing handler for UDP/TCP/QUIC
- **Rate limiting**: Applies to QUIC connections

#### 7. Dependencies
```toml
# QUIC transport (fallback)
quinn = "0.11"
rustls = { version = "0.23", features = ["ring"] }
rustls-native-certs = "0.8"
rcgen = "0.13"

# TUN devices
tun-tap = "0.1"  # Linux, macOS
wintun = "0.4"   # Windows
```

### 📋 Future Enhancements

#### Auto-Fallback Logic
- Detect UDP:51820 blocking and auto-switch to QUIC:51822
- Connection quality monitoring for transport selection
- Seamless reconnection on transport change

#### Production TLS
- Let's Encrypt integration for QUIC certs
- Certificate rotation and renewal
- Client cert verification option

## Key Design Decisions

### 1. TUN as Default
**Rationale**: Full TCP/UDP/ICMP coverage, kernel handles TCP state
**Trade-off**: Slightly higher overhead than raw kernel bypass, offset by userspace fast path

### 2. Kernel Bypass Strategy
**Rationale**: AF_XDP/FLASH provides maximum throughput on Linux servers and is required for relay nodes.
**Implementation**: Server uses AF_XDP/FLASH (no UDP fallback); clients use TUN/tunnel APIs only.
**Fallback**: Client transport fallback remains UDP → QUIC → TCP.

### 3. QUIC as Fallback (not Primary)
**Rationale**: UDP is faster and simpler; QUIC for restrictive networks only
**Auto-detection**: Try UDP first, fall back to QUIC if connection fails

### 4. MASQUE for Standards Compliance
**Rationale**: IETF standard for tunneling over HTTP/3
**Implementation**: CONNECT-IP for full IP tunneling, CONNECT-UDP for UDP-only
**Trade-off**: More complex than simple QUIC datagrams, but future-proof

## Performance Characteristics

### Expected Throughput
- **TUN + UDP + FLASH**: 10-25 Gbps (server-side AF_XDP)
- **TUN + userspace fast path**: 1-5 Gbps (desktop/mobile baseline)
- **TUN + QUIC**: 500 Mbps - 2 Gbps (TLS overhead)

### Latency
- **TUN + UDP + FLASH**: <1ms (kernel bypass)
- **TUN + UDP**: 1-3ms (standard kernel)
- **TUN + QUIC**: 2-5ms (TLS handshake + crypto)

## Platform-Specific Notes

### Linux
- Requires `CAP_NET_ADMIN` for TUN device creation
- AF_XDP/FLASH requires Linux 5.4+ and XDP-capable NIC (server-side)
- iptables rules no longer needed (TUN handles routing)
- Linux clients use TUN + userspace fast path (no client kernel bypass)

### macOS
- Requires root for utun device creation
- utun number auto-assigned by kernel
- Uses ifconfig for IP configuration
- TUN + userspace fast path only (no client kernel bypass)

### Windows
- Requires Administrator for Wintun adapter
- Wintun DLL must be present
- Uses netsh for IP configuration
- TUN + userspace fast path only (no client kernel bypass)

### Android/iOS
- TUN fd provided by VpnService/NetworkExtension
- Routing managed by OS tunnel API
- No root required (uses OS tunnel framework)
- TUN + userspace fast path only (no client kernel bypass)

## Next Steps

1. **Complete PacketCaptureService TUN mode** (current task)
2. **Validate ResponseInjector TUN writes across platforms**
3. **Integrate TUN into daemon**
4. **Add QUIC transport to client**
5. **Add QUIC listener to server**
6. **Test full stack end-to-end**
7. **Performance benchmarks**
8. **Documentation and deployment guides**

## Migration Path (OxTunnel v3)

1. Standardize on TUN/tunnel APIs for all clients (full TCP/UDP/ICMP coverage)
2. Remove remaining legacy capture references and scripts
3. Enforce transport fallback order: UDP → QUIC → TCP (full-duplex)
4. Keep server AF_XDP/FLASH; clients remain TUN-only

## References

- IETF MASQUE: https://datatracker.ietf.org/wg/masque/
- AF_XDP: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
- Quinn QUIC: https://github.com/quinn-rs/quinn
- Wintun: https://www.wintun.net/
