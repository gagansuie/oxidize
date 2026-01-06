# Install Oxidize

Complete setup guide for **desktop** and **mobile** devices.

## Desktop (Linux, macOS, Windows)

### One-Click Install (Linux/macOS)

```bash
# Install and auto-start
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- YOUR_SERVER:4433
```

### Manual Install

#### Linux (x86_64)
```bash
wget https://github.com/gagansuie/oxidize/releases/latest/download/oxidize-client-linux-x86_64.tar.gz
tar xzf oxidize-client-linux-x86_64.tar.gz
sudo mv oxidize-client /usr/local/bin/
```

#### Linux (ARM64)
```bash
wget https://github.com/gagansuie/oxidize/releases/latest/download/oxidize-client-linux-arm64.tar.gz
tar xzf oxidize-client-linux-arm64.tar.gz
sudo mv oxidize-client /usr/local/bin/
```

#### macOS
```bash
curl -L -o oxidize.tar.gz https://github.com/gagansuie/oxidize/releases/latest/download/oxidize-client-macos.tar.gz
tar xzf oxidize.tar.gz
sudo mv oxidize-client /usr/local/bin/
```

#### Windows
1. Download [oxidize-client-windows.zip](https://github.com/gagansuie/oxidize/releases/latest)
2. Extract and run `oxidize-client.exe`

### Connect

```bash
# Test your connection
oxidize-client --server YOUR_SERVER:4433 --speedtest

# Run with TUN (routes all traffic)
sudo oxidize-client --server YOUR_SERVER:4433
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
./oxidize-server --generate-wg-config --wg-endpoint YOUR_SERVER_IP:51820
```

Open firewall:
```bash
sudo iptables -I INPUT -p udp --dport 51820 -j ACCEPT
```

### Step 3: Scan QR Code

Generate QR on server:
```bash
sudo apt install qrencode
./oxidize-server --generate-wg-config --wg-endpoint YOUR_IP:51820 | tail -n +10 | qrencode -t ansiutf8
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
Endpoint = YOUR_SERVER_IP:51820
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
oxidize-client --server YOUR_SERVER:4433 --speedtest

# Mobile
# Check WireGuard app shows "Active" status
# Visit https://ifconfig.me - should show server IP
```

---

## Next Steps

- [Deploy Server](DEPLOY_ORACLE.md) - Set up your relay server
- [Security Guide](SECURITY.md) - Harden your setup
- [Streaming Guide](STREAMING.md) - Netflix/streaming compatibility
