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

**Coming Soon** — Native mobile apps for iOS and Android are currently in development.

---

## Platform Support

| Platform | Method | Status |
|----------|--------|--------|
| Linux x86_64 | Native client | ✅ |
| Linux ARM64 | Native client | ✅ |
| macOS Intel | Native client | ✅ |
| macOS Apple Silicon | Native client | ✅ |
| Windows | Native client | ✅ |
| iOS | Native app | 🚧 Coming Soon |
| Android | Native app | 🚧 Coming Soon |

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

The Oxidize daemon enables **NFQUEUE packet capture** for automatic traffic optimization.

### How NFQUEUE Works

1. **Auto-connect on start** - App automatically connects to fastest server
2. **iptables rules** - All UDP traffic sent to NFQUEUE for userspace processing
3. **Pure userspace** - No kernel modules required, packets processed in daemon
4. **QUIC relay** - Packets forwarded through encrypted QUIC tunnel
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
