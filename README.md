# oxidize

High-performance network relay built in Rust using QUIC protocol.

## Features

- **QUIC Protocol** - Fast, reliable transport with 0-RTT
- **TCP Acceleration** - Immediate ACK for reduced latency
- **LZ4 Compression** - Intelligent payload compression
- **Packet Prioritization** - Smart QoS routing
- **Prometheus Metrics** - Built-in monitoring

## Quick Start

### Download Pre-built Binaries

Get the latest release from [GitHub Releases](https://github.com/YOUR_USERNAME/oxidize/releases)

Or see [DOWNLOADS.md](DOWNLOADS.md) for installation instructions.

### Build from Source

```bash
# Build
cargo build --release

# Run server
./target/release/oxidize-server --listen 0.0.0.0:4433

# Run client
./target/release/oxidize-client --server SERVER_IP:4433
```

## Configuration

Create `config.toml`:

```toml
max_connections = 10000
enable_compression = true
enable_tcp_acceleration = true
rate_limit_per_ip = 100
```

## Production Features

- ✅ Real TLS certificate support
- ✅ Per-IP rate limiting
- ✅ Prometheus metrics
- ✅ Comprehensive test suite
- ✅ Oracle Cloud deployment

## Monitoring

```bash
# Metrics endpoint
curl http://localhost:9090/metrics
```

## Deployment

See [DEPLOY_ORACLE.md](DEPLOY_ORACLE.md) for production deployment guide.

## Testing

```bash
cargo test --all
```

## CI/CD

[![CI](https://github.com/YOUR_USERNAME/oxidize/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/oxidize/actions/workflows/ci.yml)
[![Release](https://github.com/YOUR_USERNAME/oxidize/actions/workflows/release.yml/badge.svg)](https://github.com/YOUR_USERNAME/oxidize/actions/workflows/release.yml)

Automatic builds for Linux, macOS, and Windows on every release tag.

## License

MIT OR Apache-2.0
