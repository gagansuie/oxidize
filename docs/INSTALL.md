# Install Oxidize

Complete setup guide for **desktop** and **mobile** devices.

## Desktop (Linux, macOS, Windows)

### One-Click Install (Linux/macOS)

```bash
# Install and auto-start
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- relay.oxd.sh:4433
```

### Manual Install

#### Linux (x86_64)
```bash
# Get latest version
VERSION=$(curl -s https://api.github.com/repos/gagansuie/oxidize/releases/latest | grep tag_name | cut -d'"' -f4)
wget https://github.com/gagansuie/oxidize/releases/download/$VERSION/oxidize-client-$VERSION-x86_64-unknown-linux-musl.tar.gz
tar xzf oxidize-client-$VERSION-x86_64-unknown-linux-musl.tar.gz
sudo mv oxidize-client /usr/local/bin/
```

#### Linux (ARM64)
```bash
# ARM64 Linux: build from source (no prebuilt binary available)
git clone https://github.com/gagansuie/oxidize.git && cd oxidize
cargo build --release --package relay-client
sudo cp target/release/oxidize-client /usr/local/bin/
```

#### macOS (Intel)
```bash
VERSION=$(curl -s https://api.github.com/repos/gagansuie/oxidize/releases/latest | grep tag_name | cut -d'"' -f4)
curl -L -o oxidize.tar.gz https://github.com/gagansuie/oxidize/releases/download/$VERSION/oxidize-client-$VERSION-x86_64-apple-darwin.tar.gz
tar xzf oxidize.tar.gz
sudo mv oxidize-client /usr/local/bin/
```

#### macOS (Apple Silicon)
```bash
VERSION=$(curl -s https://api.github.com/repos/gagansuie/oxidize/releases/latest | grep tag_name | cut -d'"' -f4)
curl -L -o oxidize.tar.gz https://github.com/gagansuie/oxidize/releases/download/$VERSION/oxidize-client-$VERSION-aarch64-apple-darwin.tar.gz
tar xzf oxidize.tar.gz
sudo mv oxidize-client /usr/local/bin/
```

#### Windows
```powershell
# Download from GitHub Releases
# https://github.com/gagansuie/oxidize/releases/latest
# Extract oxidize-client-{version}-x86_64-pc-windows-msvc.zip and run oxidize-client.exe
```

### Connect

```bash
# Test your connection
oxidize-client --server relay.oxd.sh:4433 --speedtest

# Run with daemon (routes all UDP traffic via NFQUEUE)
sudo oxidize-client --server relay.oxd.sh:4433
```

---

## Mobile (iOS & Android)

Native mobile apps using the **unified OxTunnel Protocol** are in development.

### Unified OxTunnel Architecture

All platforms (desktop, Android, iOS) use the **same OxTunnel protocol** over **QUIC transport**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Unified OxTunnel Protocol                    │
├─────────────────────────────────────────────────────────────────┤
│  Desktop (NFQUEUE) ──┐                                          │
│                      ├── OxTunnel ──► QUIC Datagrams ──► Server │
│  Mobile (VpnService) ┘                                          │
└─────────────────────────────────────────────────────────────────┘
```

| Feature | WireGuard | OxTunnel |
|---------|-----------|----------|
| Header size | 32+ bytes | 9 bytes |
| Encryption | Always on | Optional (QUIC encrypts) |
| Handshake | Multi-round Noise | Single round-trip |
| Buffer allocation | Per-packet | Zero-copy pool |
| Batch processing | No | 64 packets/batch |
| Transport | UDP only | QUIC + UDP fallback |
| Cross-platform | Separate implementations | **Unified protocol** |

**Benefits:**
- **Same protocol everywhere** - Desktop and mobile use identical OxTunnel encapsulation
- **QUIC primary** - Encrypted, multiplexed transport for all platforms
- **Lower battery usage** - QUIC encryption eliminates double-encryption overhead
- **Faster reconnects** - Single-round handshake + QUIC 0-RTT
- **Better on congested networks** - 64 packets/batch, adaptive FEC
- **Single server** - Handles desktop and mobile clients with same codebase

---

## Platform Support

| Platform | Capture Method | Transport | Status |
|----------|----------------|-----------|--------|
| Linux x86_64 | NFQUEUE | QUIC | ✅ Full support |
| Linux ARM64 | NFQUEUE | QUIC | ✅ Full support |
| macOS Intel | PF/Utun | QUIC | ✅ Full support |
| macOS Apple Silicon | PF/Utun | QUIC | ✅ Full support |
| Windows | WinDivert | QUIC | ✅ Full support |
| Android | VpnService | QUIC/UDP | ✅ Full support |
| iOS | NEPacketTunnel | QUIC/UDP | ✅ Full support |

**All platforms use the unified OxTunnel protocol** with platform-specific packet capture.

---

## Build from Source

```bash
git clone https://github.com/gagansuie/oxidize.git
cd oxidize
cargo build --release

# Binaries in target/release/
./target/release/oxidize-client --help
```

---

## Troubleshooting

### Desktop

| Problem | Solution |
|---------|----------|
| Permission denied | Run with `sudo` |
| Can't connect | Check firewall allows UDP 4433 |
| NFQUEUE not working | Run daemon as root, check iptables |

### Mobile

Mobile apps are coming soon.

---

## Verify Installation

```bash
# Desktop
oxidize-client --version
oxidize-client --server relay.oxd.sh:4433 --speedtest

# Mobile apps coming soon
```

---

## Uninstall

```bash
# Run the installer with uninstall argument
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- uninstall
```

This will:
- Stop and disable the Oxidize service
- Remove the binary from `/usr/local/bin/`
- Remove configuration from `/etc/oxidize/`
- Clean up service files

---

## Daemon Management

The Oxidize daemon enables **NFQUEUE + OxTunnel** for automatic traffic optimization using the unified protocol.

### How NFQUEUE + OxTunnel Works

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   App UDP    │───►│   NFQUEUE    │───►│   OxTunnel   │───►│    QUIC      │───► Server
│   Traffic    │    │   Capture    │    │   Batching   │    │  Datagrams   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

1. **NFQUEUE capture** - All UDP traffic captured at kernel level via iptables
2. **OxTunnel batching** - Up to 64 packets batched with 9-byte OxTunnel header
3. **QUIC transport** - Batched packets sent as QUIC datagrams (encrypted, multiplexed)
4. **Server decoding** - Server decodes OxTunnel batches and forwards individual packets
5. **Response routing** - Responses injected back via raw sockets

### Daemon Commands

```bash
# Check daemon status
sudo systemctl status oxidize-daemon

# Start daemon
sudo systemctl start oxidize-daemon

# Stop daemon
sudo systemctl stop oxidize-daemon

# Restart daemon
sudo systemctl restart oxidize-daemon

# View daemon logs
sudo journalctl -u oxidize-daemon -f

# Enable auto-start on boot
sudo systemctl enable oxidize-daemon

# Disable auto-start
sudo systemctl disable oxidize-daemon
```

### Manual Daemon Control

```bash
# Build daemon
cargo build --release -p oxidize-daemon

# Run daemon directly (for debugging)
sudo ./target/release/oxidize-daemon

# Check if daemon is running
ls -la /var/run/oxidize/daemon.sock
```

### Verify NFQUEUE Rules

```bash
# Check if NFQUEUE rules are active
sudo iptables -L OUTPUT -n | grep -E 'NFQUEUE|4433'

# You should see:
# ACCEPT udp -- 0.0.0.0/0 0.0.0.0/0 udp dpt:4433
# NFQUEUE udp -- 0.0.0.0/0 0.0.0.0/0 ! owner UID match 0 NFQUEUE num 0 bypass
```

---

## Next Steps

- [Deploy Server](DEPLOY.md) - Set up your relay server on Fly.io
- [Security Guide](SECURITY.md) - Harden your setup
