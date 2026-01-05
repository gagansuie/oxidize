# Mobile Device Setup Guide

Connect to Oxidize from your iOS or Android device using the official WireGuard app.

## Why WireGuard?

Oxidize supports the WireGuard protocol for mobile devices because:
- **No custom app needed** - Use the official WireGuard app (trusted, open-source)
- **Works on iOS and Android** - Available in App Store and Play Store
- **Full VPN functionality** - Routes all device traffic through Oxidize
- **Easy setup** - Just scan a QR code

## Prerequisites

1. **Server Setup**: Oxidize server running with WireGuard enabled
2. **WireGuard App**: Install from [App Store](https://apps.apple.com/us/app/wireguard/id1441195209) (iOS) or [Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android) (Android)

## Server Configuration

### Step 1: Generate WireGuard Keys

On your server, run:

```bash
./oxidize-server --generate-wg-config --wg-endpoint YOUR_SERVER_IP:51820
```

This will output:
- Server private key
- Server public key  
- Sample client configuration

### Step 2: Update Server Config

Add to your `config.toml`:

```toml
# WireGuard settings for mobile clients
enable_wireguard = true
wireguard_port = 51820
wireguard_private_key = "YOUR_GENERATED_PRIVATE_KEY"
```

### Step 3: Open Firewall Port

```bash
# Allow WireGuard traffic
sudo ufw allow 51820/udp

# Or with iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

### Step 4: Restart Server

```bash
./oxidize-server --listen 0.0.0.0:4433 --config config.toml
```

You should see:
```
WireGuard server listening on 0.0.0.0:51820
```

## Client Setup (Mobile)

### Option 1: QR Code (Easiest)

1. **Generate QR code on server:**

```bash
# Install qrencode if needed
sudo apt install qrencode  # Debian/Ubuntu
brew install qrencode      # macOS

# Generate QR code
./oxidize-server --generate-wg-config --wg-endpoint YOUR_IP:51820 | \
  tail -n +10 | qrencode -t ansiutf8
```

2. **Scan on mobile device:**
   - Open WireGuard app
   - Tap **+** → **Create from QR code**
   - Scan the QR code
   - Name it "Oxidize"
   - Tap **Save**

### Option 2: Manual Config

1. **Copy the client config from server output:**

```conf
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY_HERE
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

2. **On mobile device:**
   - Open WireGuard app
   - Tap **+** → **Create from file or archive**
   - Or tap **+** → **Create from scratch**
   - Paste the configuration
   - Name it "Oxidize"
   - Tap **Save**

## Connect

1. Open WireGuard app
2. Toggle the switch next to "Oxidize"
3. Approve VPN connection (first time only)
4. ✅ Connected!

## Verify Connection

### On Mobile Device

1. Check WireGuard app shows:
   - Status: **Active**
   - Transfer: Data flowing
   - Latest handshake: Recent timestamp

2. Check your IP changed:
   - Visit https://ifconfig.me
   - Should show your server's IP

### On Server

Check logs for:
```
New WireGuard peer connecting
Created tunnel for new peer
```

## Troubleshooting

### Connection Times Out

**Problem:** Can't establish connection

**Solutions:**
- Verify firewall allows UDP 51820
- Check server IP is correct in config
- Ensure server is running with WireGuard enabled
- Try from different network (some block VPN ports)

### No Internet After Connecting

**Problem:** Connected but no traffic flows

**Solutions:**
- Check server has internet access
- Verify IP forwarding enabled on server:
  ```bash
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sysctl -w net.ipv6.conf.all.forwarding=1
  ```
- Check NAT rules:
  ```bash
  sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  ```

### Frequent Disconnects

**Problem:** Connection drops often

**Solutions:**
- Increase `PersistentKeepalive` to 30 seconds
- Check mobile data/WiFi stability
- Verify server has stable internet

### Handshake Fails

**Problem:** "Unable to establish handshake"

**Solutions:**
- Regenerate keys on both sides
- Check server private key matches public key
- Verify no firewall blocking UDP 51820
- Ensure server and client keys don't match (they should be different)

## Advanced Configuration

### Split Tunneling (Route Only Some Traffic)

Change `AllowedIPs` in client config:

```conf
# Only route specific networks through VPN
AllowedIPs = 192.168.1.0/24, 10.0.0.0/8

# Or specific services
AllowedIPs = 1.1.1.1/32  # Only DNS
```

### Multiple Clients

Generate unique config for each device:

```bash
# Generate with different private key for each device
./oxidize-server --generate-wg-config --wg-endpoint YOUR_IP:51820
```

Each client should have:
- Unique private key
- Unique IP address (10.0.0.2, 10.0.0.3, etc.)
- Same server public key

### Custom DNS

```conf
[Interface]
PrivateKey = ...
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8  # Multiple DNS servers
```

## Performance Tips

1. **Use UDP**: WireGuard is UDP-only (faster than TCP VPNs)
2. **Keepalive**: Set to 25 seconds for mobile (prevents NAT timeout)
3. **Location**: Choose server closest to you for best latency
4. **Battery**: WireGuard is very efficient, minimal battery impact

## Security Notes

⚠️ **Keep Private Keys Secret**
- Never share your private key
- Don't commit keys to git
- Regenerate if compromised

✅ **Best Practices**
- Use strong server authentication
- Regularly rotate keys (monthly)
- Monitor active connections
- Use firewall rules to limit access

## Benefits Over Standard VPN

**With Oxidize + WireGuard:**
- **Faster**: Enterprise backbone routing
- **Reliable**: Automatic reconnection
- **Modern**: WireGuard protocol (faster than OpenVPN)
- **Efficient**: Lower battery drain than traditional VPNs
- **Simple**: No complex configuration files

## Common Questions

**Q: Does this use my mobile data?**
A: Yes, but can reduce overall usage via compression.

**Q: Will this drain my battery?**
A: WireGuard is very efficient. Battery impact is minimal.

**Q: Can I use on public WiFi?**
A: Yes! This is perfect for securing public WiFi connections.

**Q: What about IPv6?**
A: Fully supported. Add IPv6 address in config if needed.

**Q: Can I use on desktop too?**
A: Yes! WireGuard clients available for macOS, Windows, Linux.

## Next Steps

- [Deploy to Oracle Cloud](DEPLOY_ORACLE.md)
- [Monitor with Prometheus](../README.md#monitoring)
- [Optimize Performance](../README.md#performance)

## Need Help?

- Check server logs: `journalctl -u oxidize-server -f`
- Test connectivity: `ping 10.0.0.1` (from mobile)
- Join our community: [GitHub Discussions](https://github.com/YOUR_USERNAME/oxidize/discussions)
