<div align="center">

# Oxidize

### Open Source Deep Learning Driven Network Acceleration

**Neural networks predict packet loss before it happens, optimize routing in real-time, and accelerate your network automatically.**

> 🔥 **~0.1µs** per-packet processing • **44%** header compression • **Zero-copy** packet pipeline • **Pure Rust**

[![CI](https://github.com/gagansuie/oxidize/actions/workflows/ci.yml/badge.svg)](https://github.com/gagansuie/oxidize/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/github/downloads/gagansuie/oxidize/total?logo=github&label=downloads)](https://github.com/gagansuie/oxidize/releases)
[![codecov](https://codecov.io/gh/gagansuie/oxidize/graph/badge.svg)](https://codecov.io/gh/gagansuie/oxidize)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

[Website](https://oxd.sh) · [Download](https://oxd.sh/download) · [Documentation](docs/) · [Speed Test](#speed-test)

</div>

---

## The Problem

Your ISP's routing is suboptimal:
- **Congested peering points** → packet loss
- **Cost-optimized routes** → unnecessary latency (+50-200ms)
- **No QoS guarantees** → inconsistent performance

## The Solution

```
❌ Direct (Your ISP):     You → Congested ISP routes → Destination     (120ms, 2% loss)
✅ Via Oxidize:           You → OxTunnel → Premium edge → Destination   (80ms, 0% loss)
```

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│   Your Device   │ OxTunnel│  Relay Server   │
│  oxidize-client │ ──────► │  oxidize-server │ ──────► Internet
└─────────────────┘  (UDP)  └─────────────────┘
        ↑                           ↑
   TCP + UDP                   TCP + UDP
   captured                    forwarded
```

- **Full traffic tunneling** — ALL TCP and UDP traffic flows through the relay
- **Dedicated infrastructure** — no peer-to-peer, no bandwidth sharing with strangers
- **Smart routing** — gaming tunneled, streaming bypassed for zero latency

## Perfect For

| 🎮 Gamers | 📱 Mobile Users | 🏢 Remote Workers | 🚀 Bad ISPs |
|-----------|-----------------|-------------------|-------------|
| Reduce jitter & packet loss | Better than carrier routing | VPN alternative, better perf | Bypass congestion |

## Features

### 🚀 Core Performance
- **OxTunnel Protocol** - Custom UDP protocol with ChaCha20-Poly1305 encryption, LZ4 compression, adaptive FEC
- **Smart Routing** - Bypass congested ISP routes with optimized paths
- **Adaptive FEC** - Dynamic Reed-Solomon redundancy based on packet loss rate
- **Multi-path Support** - WiFi + LTE bandwidth aggregation and seamless failover

### ⚡ High-Performance Pipeline (100x Optimization)
- **Kernel Bypass** - AF_XDP/XDP for bare metal (10-25 Gbps, no dedicated CPU cores)
- **Zero-Copy I/O** - Direct packet access via AF_XDP UMEM
- **UDP GSO/GRO Batching** - 64 packets per syscall, 5-10x throughput
- **Zero-Copy Buffers** - Buffer pooling eliminates allocation overhead
- **Ring Buffers** - Lock-free packet queuing
- **Connection Pooling** - Session reuse, 10x handshake reduction
- **SIMD Acceleration** - AVX-512/AVX2/NEON optimized operations (2x faster with AVX-512)
- **Lock-Free Streams** - No mutex contention on hot path
- **ACK Batching** - Configurable batching reduces round-trips
- **Latency Instrumentation** - Built-in µs-level timing for optimization
- **LZ4 Compression** - ~80 MB/s single-thread, scales with parallel compression
- **Zero-Allocation Hot Path** - Ownership transfer instead of cloning in packet pipeline

### 📱 OxTunnel Protocol (Unified Cross-Platform)
Custom high-performance tunnel protocol replacing WireGuard with **unified architecture** for all platforms:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OxTunnel Protocol (TCP + UDP)                    │
├─────────────────────────────────────────────────────────────────────┤
│  Linux:   App → NFQUEUE → OxTunnel → AF_XDP/UDP → Server           │
│  macOS:   App → PF/Utun → OxTunnel → UDP Datagrams → Server        │
│  Windows: App → WinDivert → OxTunnel → UDP Datagrams → Server      │
│  Android: App → VpnService → OxTunnel → UDP Datagrams → Server     │
│  iOS:     App → NEPacketTunnel → OxTunnel → UDP Datagrams → Server │
└─────────────────────────────────────────────────────────────────────┘
    Server: AF_XDP/FLASH zero-copy (18-25 Gbps) on Linux bare metal
```

- **Same protocol everywhere** - All platforms use identical OxTunnel encapsulation over UDP
- **Platform-specific capture** - NFQUEUE (Linux), PF (macOS), WinDivert (Windows), VpnService (Android)
- **AF_XDP/FLASH Server** - Kernel bypass on Linux bare metal, 18-25 Gbps zero-copy throughput
- **0-RTT reconnection** - Instant session resumption via cached keys
- **V2 Variable Headers** - 2-7 byte headers (avg 4B) with varint encoding, 55% smaller than V1
- **64 packets/batch** - Reduces syscalls by 64x
- **Zero-copy buffer pools** - 128 pre-allocated buffers, no heap allocation per packet

| Feature | WireGuard | OxTunnel |
|---------|-----------|----------|
| Header size | 32+ bytes | **4 bytes avg** (V2) |
| Encryption | Double (WG + TLS) | Single (ChaCha20-Poly1305) |
| Handshake | Multi-round Noise | Single round-trip |
| Buffer allocation | Per-packet malloc | Zero-copy pool |
| Batch processing | No | 64 packets/batch |
| Packet capture | TUN device | NFQUEUE/PF/WinDivert |
| Transport | UDP only | OxTunnel (UDP + AF_XDP kernel bypass) |
| Cross-platform | Separate implementations | Unified protocol |

### 🎭 MASQUE-Inspired Architecture
Inspired by [Cloudflare's MASQUE/WARP](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/):
- **UDP Datagrams** - Real-time traffic (gaming/VoIP) bypasses stream ordering, eliminating head-of-line blocking
- **0-RTT Session Resumption** - Instant reconnects via cached session tickets
- **Connection Migration** - Seamless WiFi ↔ cellular transitions without reconnecting
- **Dual-Path Architecture** - Streams for reliable traffic, datagrams for latency-sensitive traffic
- **Smart Traffic Detection** - Auto-detects gaming/VoIP ports for optimal routing

### 🧠 Smart Traffic Management
- **Adaptive ML Congestion Control** - Online learning with continuous improvement
  - Lookup tables generated from trained ML model (<100ns decisions)
  - Live ML inference for edge cases (~1µs)
  - Automatic table refresh (hourly) from real traffic observations
  - No restart needed - model improves continuously
- **ECN (Explicit Congestion Notification)** - RFC 9000 compliant
  - DCTCP-style congestion response
  - Better signals than loss-based detection
- **Multipath UDP** - Aggregate bandwidth across paths
  - Adaptive path selection (RTT + loss + bandwidth scoring)
  - Seamless failover on path failure
  - Round-robin, weighted, or lowest-RTT scheduling
- **Deep Packet Inspection** - Identifies Discord, Zoom, Valorant, Fortnite by protocol patterns
- **Application Fingerprinting** - Detect apps on non-standard ports (Discord on 443, etc.)
- **Traffic Classification** - Auto-detects gaming/streaming/VoIP for optimal handling
- **Smart Split-Tunneling** - Gaming tunneled for optimization, streaming bypassed for clean IP
- **Edge Caching** - LRU cache for static content at relay points


### 🧠 Deep Learning Engine
Adaptive online learning with <10µs inference:

| Model | Latency | Purpose |
|-------|---------|---------|
| Loss Predictor | <10µs | Predicts packet loss 50-100ms ahead |
| Congestion Control | <1µs | PPO-based CWND optimization |
| Path Selector | <1µs | UCB1 bandit for best path selection |
| FEC Decision | <100ns | Optimal redundancy ratio |

See [DEEP_LEARNING.md](docs/DEEP_LEARNING.md) and [ADVANCED_ML.md](docs/ADVANCED_ML.md) for details.

**Auto-detected:** Gaming ports (Xbox, PlayStation, Steam, VoIP) use UDP datagrams. Streaming services (Netflix, Disney+, etc.) are bypassed for your residential IP.

### 📦 Compression
- **LZ4** - Multi-threaded, ~80 MB/s (single), ~4 GB/s (parallel)
- **ROHC Headers** - 44% size reduction (UDP/TCP/IP/RTP profiles)
- **Smart Detection** - Skips already-compressed data (TLS, media, archives)

### 🔒 Security
- **TLS 1.3** with Let's Encrypt
- **Per-IP rate limiting** with auto-blocking
- **DDoS protection** via iptables + application-level limits

### 🌐 Infrastructure
- **Connection migration** - Seamless WiFi ↔ LTE handoff
- **BBR congestion control** - Optimal for lossy links
- **Prometheus metrics** - Real-time observability

## Speed Test

```bash
oxidize-client --server SERVER_IP:51820 --speedtest
oxidize-client --server SERVER_IP:51820 --speedtest --json  # For scripting
```

## Quick Start

### One-Click Client Install

```bash
# Install with server address (required)
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- <server_ip>:51820
```

The installer handles everything: downloads binary, configures service, and starts automatically.

> **Review the script:** [install.sh](install.sh)

### Build from Source

```bash
# Build
cargo build --release

# Run server (on your relay server)
./target/release/oxidize-server --listen 0.0.0.0:51820

# Run client (server address required)
./target/release/oxidize-client --server <server_ip>:51820

# Run speed test
./target/release/oxidize-client --speedtest
```

### Server Deployment (AF_XDP)

For maximum performance on bare metal Linux servers:

```bash
# 1. Setup system for AF_XDP (configures NIC, huge pages, sysctl)
sudo ./scripts/xdp-setup.sh eth0 51820

# 2. Run server (AF_XDP is automatic on Linux)
sudo ./target/release/oxidize-server --listen 0.0.0.0:51820
```

AF_XDP provides 10-25 Gbps throughput with <0.2µs latency. Requires:
- Linux 5.4+ kernel
- Root privileges
- XDP-capable NIC (Intel i40e/ixgbe, Mellanox mlx5, etc.)

## Configuration

```toml
# config.toml
max_connections = 10000
enable_compression = true
congestion_algorithm = "adaptive_ml"  # or "cubic", "gaming"
rate_limit_per_ip = 100
```


## Performance

| Scenario | Improvement |
|----------|-------------|
| Mobile networks | +30-50% (packet loss handling) |
| Congested ISPs | +40-60% (better routing) |
| Gaming | +20-40% (stable latency) |

**Won't help:** Already-optimal fiber, video streaming, local traffic.

## Monitoring

```bash
curl http://localhost:9090/metrics
```

## Apps

### Desktop
Modern GUI built with Tauri. Requires daemon for full traffic tunneling.

**macOS:** Right-click → Open to bypass Gatekeeper, or `xattr -cr /Applications/Oxidize.app`

### Mobile (Coming Soon)
Same OxTunnel protocol. Uses native VPN APIs (VpnService/NEPacketTunnel).

```bash
cd app && npx tauri android build   # Android
cd app && npx tauri ios build       # iOS
```

## Daemon

OxTunnel captures TCP+UDP via NFQUEUE and tunnels over encrypted UDP datagrams.

```bash
sudo systemctl status oxidize-daemon   # Check status
sudo systemctl restart oxidize-daemon  # Restart
sudo journalctl -u oxidize-daemon -f   # View logs
```

## Documentation

- [OXTUNNEL.md](docs/OXTUNNEL.md) - Protocol specification
- [DEEP_LEARNING.md](docs/DEEP_LEARNING.md) - ML engine details
- [SECURITY.md](docs/SECURITY.md) - Security & DDoS protection
- [Deployment guides](docs/) - Vultr, Latitude.sh setup

## Development

```bash
cargo test --all           # Run tests
cargo bench --package oxidize-common  # Benchmarks
```

## Uninstall

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/scripts/uninstall.sh | sudo bash

# Windows (PowerShell as Admin)
irm https://raw.githubusercontent.com/gagansuie/oxidize/main/scripts/uninstall-windows.ps1 | iex
```

## License

MIT OR Apache-2.0

---

<div align="center">
<sub>Built with 🦀 by <a href="https://github.com/gagansuie">gagansuie</a></sub>
</div>
