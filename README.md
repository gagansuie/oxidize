# oxidize

Enterprise-grade network backbone for everyone. Built in Rust using QUIC protocol.

## Why Oxidize?

Your ISP's routing is suboptimal. We fix that.

**The Problem:**
- Consumer ISPs use congested peering points
- Last-mile connections have packet loss
- Poor routing adds 50-200ms of unnecessary latency

**The Solution:**
Route your traffic through enterprise-grade backbone infrastructure with premium peering.

## How It Works

```
❌ Direct (Your ISP):
You → Congested ISP routes → Destination
(120ms, 2% packet loss)

✅ Via Oxidize:
You → QUIC tunnel → Fly.io edge → Premium peering → Destination
(80ms, 0% packet loss)
```

## Architecture

Oxidize uses a simple **client-server model**:

```
┌─────────────────┐         ┌─────────────────┐
│   Your Device   │  QUIC   │  Relay Server   │
│                 │ ──────► │    (Fly.io)     │ ──────► Internet
│  oxidize-client │         │  oxidize-server │
└─────────────────┘         └─────────────────┘
```

**Key Points:**
- **Client** connects to a **centralized relay server** you control
- **No peer-to-peer** - your traffic only goes through your relay
- **No bandwidth sharing** - each user has their own connection
- **Smart Routing** - Gaming tunneled for optimization, streaming bypasses for zero latency

## Key Features

### 🚀 Core Performance
- **QUIC Protocol** - 0-RTT resumption, stream multiplexing, fast loss recovery
- **Enterprise Routing** - Premium backbone peering vs congested ISP routes
- **Adaptive FEC** - Dynamic Reed-Solomon redundancy based on packet loss rate
- **Multi-path Support** - WiFi + LTE bandwidth aggregation and seamless failover

### ⚡ High-Performance Pipeline (100x Optimization)
- **io_uring Ready** - 10-20x syscall reduction on Linux
- **UDP GSO/GRO Batching** - 64 packets per syscall, 5-10x throughput
- **Zero-Copy Buffers** - Buffer pooling eliminates allocation overhead
- **Ring Buffers** - Lock-free packet queuing
- **Connection Pooling** - QUIC connection reuse, 10x handshake reduction
- **SIMD Acceleration** - AVX2/NEON optimized operations

### 🧠 Smart Traffic Management
- **BBRv3 Congestion Control** - Adaptive bandwidth probing with gaming mode
- **HTTP/3 Priority Scheduler** - Real-time traffic prioritization
- **Traffic Classification** - Auto-detects gaming/streaming/VoIP for optimal handling
- **Smart Routing** - Gaming through tunnel, streaming bypasses for zero latency
- **Edge Caching** - LRU cache for static content at relay points

### 📦 Compression (Pure Rust, Enabled by Default)
- **ROHC Header Compression** - 44% size reduction for UDP/IP headers
  - UDP, TCP, IP, RTP, ESP, IPv6 profiles
  - State machine compression (IR → FO → SO)
  - W-LSB delta encoding for sequence numbers
  - **Enabled by default** - no configuration needed
- **LZ4 Payload Compression** - Fast compression for bandwidth-constrained uplinks
- **SIMD-Accelerated** - AVX2/NEON when available
- **Intelligent Selection** - Automatically chooses best compression per packet

**ROHC Performance Impact:**
| Traffic Type | Without ROHC | With ROHC | Savings |
|--------------|--------------|-----------|--------|
| UDP Gaming (64B) | 62% header overhead | 3% | **59%** |
| VoIP RTP (160B) | 25% header overhead | 1% | **24%** |
| SSH keystrokes (80B) | 75% header overhead | 10% | **65%** |

### 🔒 Security & DDoS Protection
- **TLS 1.3** - Real certificate support with Let's Encrypt
- **Per-IP Rate Limiting** - Connection, PPS, and bandwidth limits
- **Auto-blocking** - Automatic IP blocking after violations
- **QUIC Security** - Stateless retry, address validation, anti-amplification
- **Connection Multiplexing** - Thousands of concurrent flows

### 🌐 Infrastructure & Resilience
- **Connection Migration** - Seamless WiFi ↔ LTE handoff
- **Multi-Server Ready** - Relay mesh for scaling when needed
- **Predictive Prefetching** - DNS and connection pre-warming
- **Health Monitoring** - Automatic failover on relay issues

### 📊 Observability
- **Prometheus Metrics** - Latency, throughput, compression ratios
- **Speed Test** - Built-in benchmarking with JSON output

## Perfect For

- 🎮 **Gamers** - Reduce jitter and packet loss
- 📱 **Mobile users** - Better than your carrier's routing
- 🏢 **Remote workers** - VPN alternative with better performance
- 🌐 **API developers** - Faster API calls through compression
- 🚀 **Anyone with a crappy ISP** - Bypass congestion and poor peering

## Speed Test

Test your connection improvement before committing:

```bash
# Human-readable results
oxidize-client --server SERVER_IP:4433 --speedtest

# JSON output for scripting
oxidize-client --server SERVER_IP:4433 --speedtest --json
```

Sample output:
```
╔════════════════════════════════════════════════════════════════╗
║              Oxidize Speed Test Results                        ║
╠════════════════════════════════════════════════════════════════╣
║                      Direct      Via Relay      Improvement    ║
╠════════════════════════════════════════════════════════════════╣
║  Latency (ms):        45.2          38.1           +15.7%      ║
║  Download (Mbps):     85.2          92.4           +8.5%       ║
║  Upload (Mbps):       42.1          48.7           +15.7%      ║
║  Jitter (ms):         12.3           4.2           +65.9%      ║
╚════════════════════════════════════════════════════════════════╝

✨ Summary: Oxidize provides 16% better latency, 8% better download speed
```

## Quick Start

### One-Click Client Install

```bash
# Install and auto-start (prompts for server address)
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash

# Or specify server directly
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- oxd.sh:4433
```

The installer handles everything: downloads binary, configures service, and starts automatically.

> **Review the script:** [install.sh](install.sh)

### Build from Source

```bash
# Build
cargo build --release

# Run server (on your Fly.io/cloud instance)
./target/release/oxidize-server --listen 0.0.0.0:4433

# Run client (on your device)
./target/release/oxidize-client --server oxd.sh:4433

# Run speed test to verify improvement
./target/release/oxidize-client --server oxd.sh:4433 --speedtest
```

## Why This Works

**Network Quality Difference:**
```
Consumer ISP Routing:
- Congested peering points
- Cost-optimized (cheapest) routes
- No QoS guarantees
- Variable packet loss

Fly.io Edge Network:
- Premium peering with major networks
- Low-latency global edge locations
- Simple scaling to multiple regions
- Enterprise SLAs
```

**Protocol Advantages:**
```
TCP (Direct):
- Head-of-line blocking
- Slow congestion recovery
- 3-RTT connection setup

QUIC (Oxidize):
- Stream multiplexing
- Fast loss recovery
- 0-RTT resumption
```

## Configuration

Create `config.toml`:

```toml
max_connections = 10000
enable_compression = true
enable_tcp_acceleration = true
rate_limit_per_ip = 100

# ROHC header compression (enabled by default)
enable_rohc = true
rohc_max_size = 1400

# Congestion control (bbr, bbr_v2, bbr_v3, cubic, gaming)
congestion_algorithm = "bbr_v3"

# Priority scheduling
enable_priority_scheduler = true
```


## Real-World Performance

**When Oxidize Helps:**
- Mobile networks: +30-50% improvement (packet loss handling)
- Congested ISPs: +40-60% improvement (better routing)
- Gaming: +20-40% improvement (stable latency)
- API-heavy apps: +50-70% improvement (compression + multiplexing)

**When It Won't:**
- Already-optimal fiber connections
- Video streaming (already compressed)
- Local network traffic

**Honest benchmarks, no marketing BS.**

## Production Features

- ✅ Real TLS certificate support
- ✅ Per-IP rate limiting
- ✅ Prometheus metrics
- ✅ ROHC header compression (pure Rust, enabled by default)
- ✅ Forward error correction (adaptive FEC)
- ✅ Multi-path QUIC (WiFi + LTE aggregation)
- ✅ BBRv3 congestion control with gaming mode
- ✅ HTTP/3 priority scheduling
- ✅ Connection pooling
- ✅ Edge caching
- ✅ SIMD acceleration (AVX2/NEON)
- ✅ Connection migration (network handoff)
- ✅ Relay mesh (multi-server ready)
- ✅ Predictive prefetching
- ✅ DDoS protection & auto-blocking
- ✅ Comprehensive test suite (70+ tests)
- ✅ Fly.io deployment (~$5/mo)
- ✅ One-click client installer
- ✅ Smart traffic classification
- ✅ Zero external dependencies

## Monitoring

```bash
# Metrics endpoint
curl http://localhost:9090/metrics
```

## Deployment

See [DEPLOY.md](docs/DEPLOY.md) for production deployment guide.

## Documentation

- [INSTALL.md](docs/INSTALL.md) - Desktop & mobile installation guide
- [TUN.md](docs/TUN.md) - Full system tunneling (VPN-like mode)
- [STREAMING.md](docs/STREAMING.md) - Streaming service compatibility (Netflix, etc.)
- [SECURITY.md](docs/SECURITY.md) - Security hardening & DDoS protection
- [DEPLOY.md](docs/DEPLOY.md) - Server deployment guide (Fly.io)

## Testing

```bash
cargo test --all
```

## Benchmarks

```bash
# Run performance benchmarks
cargo bench --package oxidize-common
```

**Sample Results:**
```
╔════════════════════════════════════════════════════════════════╗
║                     KEY TAKEAWAYS                              ║
╠════════════════════════════════════════════════════════════════╣
║ LZ4 Throughput:      ~82 MB/s (handles 1 Gbps+)                ║
║ FEC Throughput:      ~4321 MB/s (never a bottleneck)           ║
║ Adaptive FEC:        64ns overhead (undetectable)              ║
║ Buffer Pool:         100% hit rate (zero allocs)               ║
║ Batch Efficiency:    2.6x speedup (fewer syscalls)             ║
║ Multipath Select:    9M ops/sec                                ║
║ E2E Pipeline:        0.7µs per packet                          ║
║ ROHC Compression:    44% size reduction                        ║
║ Sustained Load:      3M+ ops/sec (no degradation)              ║
╚════════════════════════════════════════════════════════════════╝
```

## CI/CD

[![CI](https://github.com/gagansuie/oxidize/actions/workflows/ci.yml/badge.svg)](https://github.com/gagansuie/oxidize/actions/workflows/ci.yml)
[![Release](https://github.com/gagansuie/oxidize/actions/workflows/release.yml/badge.svg)](https://github.com/gagansuie/oxidize/actions/workflows/release.yml)

Automatic builds for Linux, macOS, and Windows on every release tag.

## License

MIT OR Apache-2.0
