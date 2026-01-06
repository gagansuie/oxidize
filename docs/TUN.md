# TUN Interface Guide

Oxidize supports full system traffic tunneling via a TUN (network tunnel) interface. This allows all system traffic to be routed through the Oxidize relay, similar to a VPN.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Applications                         │
│              (Browser, Games, Services)                      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Kernel Network Stack                       │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐│
│  │  eth0    │    │  wlan0   │    │      oxidize0          ││
│  │(physical)│    │(physical)│    │   (TUN interface)      ││
│  └──────────┘    └──────────┘    └────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Oxidize Client                            │
│  • Reads packets from TUN                                    │
│  • Compresses with LZ4/ROHC                                 │
│  • Encrypts with QUIC/TLS 1.3                               │
│  • Sends to relay server                                    │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ (QUIC over UDP)
┌─────────────────────────────────────────────────────────────┐
│                    Oxidize Relay Server                      │
│  • Decrypts traffic                                         │
│  • Forwards to destination                                  │
│  • Returns responses                                        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
                      Internet
```

## Quick Start

### 1. Install (One-Time Setup)

```bash
# Download and install
curl -fsSL https://raw.githubusercontent.com/oxidize-network/oxidize/main/install.sh | sudo bash

# Or build from source
cargo build --release --package relay-client
sudo cp target/release/oxidize-client /usr/local/bin/
```

### 2. Run with TUN (Full System Tunnel)

```bash
# Requires root/sudo for TUN creation
sudo oxidize-client --server your-server.com:4433
```

### 3. Run without TUN (Application Proxy)

```bash
# No root required
oxidize-client --server your-server.com:4433 --no-tun
```

## How It Works

### Routing Strategy

Oxidize uses **split routing** to capture all traffic without breaking the connection to the relay server:

| Route | Destination | Purpose |
|-------|-------------|---------|
| `0.0.0.0/1` | oxidize0 | Captures 0.x.x.x - 127.x.x.x |
| `128.0.0.0/1` | oxidize0 | Captures 128.x.x.x - 255.x.x.x |
| relay-server-ip | original gateway | Prevents routing loop |

This approach covers the entire IPv4 address space while avoiding the default route.

### DNS Leak Prevention

Oxidize automatically configures DNS to prevent leaks:

```
Linux:   Uses resolvconf or modifies /etc/resolv.conf
macOS:   Uses networksetup to set DNS servers
Windows: Uses netsh to configure DNS
```

Default DNS servers: `1.1.1.1`, `8.8.8.8` (configurable)

### Cleanup

On exit (including Ctrl+C), Oxidize:
1. Removes added routes
2. Restores original DNS configuration
3. Destroys TUN interface

## Configuration

### Client Config (`/etc/oxidize/client.toml`)

```toml
# TUN interface settings
tun_mtu = 1400

# Enable compression (recommended)
enable_compression = true
compression_threshold = 512

# Connection settings
buffer_size = 65536
max_packet_queue = 10000
reconnect_interval = 5
keepalive_interval = 30
```

### TUN-Specific Options

| Option | Default | Description |
|--------|---------|-------------|
| `tun_mtu` | 1400 | MTU size (should be < path MTU - QUIC overhead) |
| `max_packet_queue` | 10000 | Max packets to queue before dropping |

## Platform Support

### Linux

**Requirements:**
- Root privileges (`sudo`)
- `iproute2` package
- Optional: `resolvconf` for DNS

**TUN Device:** `/dev/net/tun` (created automatically)

```bash
# Check if TUN is available
ls -la /dev/net/tun
```

### macOS

**Requirements:**
- Root privileges (`sudo`)
- No additional packages needed

**TUN Device:** `utun0` (created via system call)

### Windows

**Requirements:**
- Administrator privileges
- Wintun driver (bundled or install separately)

**TUN Device:** Created via Wintun API

## Systemd Service

For persistent tunneling, use the systemd service:

```bash
# Edit server address
sudo nano /etc/oxidize/oxidize.env

# Start service
sudo systemctl start oxidize
sudo systemctl enable oxidize  # Start on boot

# Check status
sudo systemctl status oxidize
journalctl -u oxidize -f  # View logs
```

## Troubleshooting

### Permission Denied

```
Error: Root/administrator privileges required for TUN mode.
```

**Solution:** Run with `sudo` or use `--no-tun` for proxy mode.

### TUN Creation Failed

```
Error: Failed to create TUN device
```

**Solutions:**
- Linux: Ensure `/dev/net/tun` exists: `sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200`
- Check kernel module: `lsmod | grep tun` (load with `sudo modprobe tun`)

### Routing Loop / No Connectivity

```
Error: Connection timed out
```

**Solution:** Ensure the relay server IP is correctly bypassed:
```bash
ip route show | grep <server-ip>  # Should show via original gateway
```

### DNS Leaks

**Test:** Use https://dnsleaktest.com while connected

**Solutions:**
- Verify DNS is set: `cat /etc/resolv.conf`
- Manually set DNS: `echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf`

### High Latency

**Possible causes:**
- MTU too large (fragmentation)
- Compression overhead on small packets

**Solutions:**
- Reduce MTU: `tun_mtu = 1280`
- Adjust compression threshold: `compression_threshold = 1024`

## Performance Tips

1. **MTU Tuning**: Set `tun_mtu` below path MTU minus QUIC overhead (~100 bytes)

2. **Compression**: Enable for text/HTTP traffic, may hurt encrypted/compressed data

3. **Buffer Sizing**: Increase `max_packet_queue` for high-throughput scenarios

4. **Keepalive**: Adjust `keepalive_interval` based on NAT timeout (usually 30-60s)

## Security Considerations

- **Root Access**: TUN mode requires root. The client drops privileges after setup where possible.
- **DNS**: Configure trusted DNS servers in config to prevent DNS-based attacks.
- **Kill Switch**: If the tunnel dies, traffic is blocked (routes point to non-existent interface).

## Comparison: TUN vs Proxy Mode

| Feature | TUN Mode | Proxy Mode |
|---------|----------|------------|
| Traffic captured | All system traffic | Only configured apps |
| Root required | Yes | No |
| DNS protection | Automatic | Manual |
| Performance | Slightly lower | Higher |
| Setup complexity | One-time | Per-app |

## API Reference

### TunHandler

```rust
use oxidize_client::tun_handler::{TunHandler, TunConfig};

// Create handler
let mut handler = TunHandler::new(config)?
    .with_server_ip(server_addr.ip());

// Setup TUN and routing
let device = handler.setup().await?;

// Run packet capture loop
handler.run(tx).await?;

// Cleanup (automatic on drop, but can call manually)
handler.cleanup()?;
```

### TunConfig

```rust
pub struct TunConfig {
    pub name: String,           // "oxidize0"
    pub address: (u8,u8,u8,u8), // (10, 200, 200, 1)
    pub netmask: (u8,u8,u8,u8), // (255, 255, 255, 0)
    pub mtu: usize,             // 1400
    pub dns_servers: Vec<String>, // ["1.1.1.1", "8.8.8.8"]
}
```
