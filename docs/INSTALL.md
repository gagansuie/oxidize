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

# Run with TUN (routes all traffic)
sudo oxidize-client --server relay.oxd.sh:4433
```

---

## Mobile (iOS & Android)

Mobile devices use the **WireGuard** app (no custom app needed).

### Step 1: Install WireGuard App

- **iOS**: [App Store](https://apps.apple.com/us/app/wireguard/id1441195209)
- **Android**: [Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android)

### Step 2: Enable WireGuard on Server

Add to your server's `config.toml`:

```toml
enable_wireguard = true
wireguard_port = 51820
wireguard_private_key = "YOUR_KEY"
```

Generate keys:
```bash
./oxidize-server --generate-wg-config --wg-endpoint relay.oxd.sh:51820
```

Open firewall:
```bash
sudo iptables -I INPUT -p udp --dport 51820 -j ACCEPT
```

### Step 3: Scan QR Code

Generate QR on server:
```bash
sudo apt install qrencode
./oxidize-server --generate-wg-config --wg-endpoint relay.oxd.sh:51820 | tail -n +10 | qrencode -t ansiutf8
```

On mobile:
1. Open WireGuard app
2. Tap **+** → **Create from QR code**
3. Scan → Save → Connect

### Manual Mobile Config

If QR doesn't work, create config manually:

```conf
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = relay.oxd.sh:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

---

## Platform Support

| Platform | Method | Status |
|----------|--------|--------|
| Linux x86_64 | Native client | ✅ |
| Linux ARM64 | Native client | ✅ |
| macOS Intel | Native client | ✅ |
| macOS Apple Silicon | Native client | ✅ |
| Windows | Native client | ✅ |
| iOS | WireGuard app | ✅ |
| Android | WireGuard app | ✅ |

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
| TUN not working | Install `iproute2` (Linux) |

### Mobile

| Problem | Solution |
|---------|----------|
| Connection timeout | Check firewall allows UDP 51820 |
| No internet after connect | Enable IP forwarding: `sudo sysctl -w net.ipv4.ip_forward=1` |
| Handshake fails | Regenerate WireGuard keys |

---

## Verify Installation

```bash
# Desktop
oxidize-client --version
oxidize-client --server relay.oxd.sh:4433 --speedtest

# Mobile
# Check WireGuard app shows "Active" status
# Visit https://ifconfig.me - should show server IP
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

The Oxidize daemon enables **TPROXY (Transparent Proxy)** for automatic traffic optimization.

### How TPROXY Works

1. **Auto-connect on start** - App automatically connects to fastest server
2. **iptables rules** - All UDP traffic marked for interception
3. **Zero-copy forwarding** - Kernel-to-kernel packet transfer via splice()
4. **QUIC relay** - Packets forwarded through encrypted QUIC tunnel
5. **Response routing** - Responses sent back to original clients

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

### Verify TPROXY Rules

```bash
# Check if TPROXY chain exists
sudo iptables -t mangle -L OXIDIZE_TPROXY -n

# Check policy routing
ip rule show | grep fwmark
ip route show table 100
```

---

## Next Steps

- [Deploy Server](DEPLOY.md) - Set up your relay server on Fly.io
- [Security Guide](SECURITY.md) - Harden your setup
