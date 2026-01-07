# Deploy Oxidize Relay Server

Deploy your Oxidize relay server to **Fly.io** for global, low-latency performance.

## Cost

| Plan | Specs | Price |
|------|-------|-------|
| **Starter** | 1 shared CPU, 1GB RAM | ~$5/mo |
| **Performance** | 1 dedicated CPU, 2GB RAM | ~$15/mo |

## Quick Deploy

### 1. Install Fly CLI

```bash
curl -L https://fly.io/install.sh | sh
```

### 2. Login

```bash
fly auth login
```

### 3. Deploy

```bash
cd oxidize
fly launch --no-deploy  # First time: creates app
fly deploy              # Deploy the server
```

### 4. Get Your Server Address

```bash
fly status
```

Your server address will be: `oxd.sh:4433`

## Connect Clients

```bash
# Linux/macOS
sudo oxidize-client --server oxd.sh:4433

# Or use the install script
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- oxd.sh:4433
```

## Scaling

### Add More Regions

```bash
# Deploy to multiple regions for lower latency
fly regions add lax sea iad  # LA, Seattle, Virginia
fly scale count 3            # One instance per region
```

### Scale Up

```bash
# More resources
fly scale vm shared-cpu-2x --memory 2048
```

## Monitoring

```bash
# View logs
fly logs

# SSH into the server
fly ssh console

# Check metrics
fly status
```

## Custom Domain

Oxidize uses `oxd.sh` as the official relay server.

To use your own domain:
```bash
fly certs add yourdomain.com
```

Then add DNS records (Cloudflare example):
| Type | Name | Value | Proxy |
|------|------|-------|-------|
| A | @ | YOUR_FLY_IPV4 | DNS only |
| AAAA | @ | YOUR_FLY_IPV6 | DNS only |

**Important:** Disable Cloudflare proxy (gray cloud) - QUIC/UDP requires direct connection.

## Environment Variables

```bash
fly secrets set RUST_LOG=debug  # Enable debug logging
```

## Performance Tuning

Performance optimizations are **always enabled** (zero-copy buffers, lock-free streams, ACK batching). Tune these settings for your use case:

### Gaming / Low-Latency
```toml
enable_tcp_acceleration = true
enable_compression = false      # Skip compression for lowest latency
```

### High-Throughput / API Traffic
```toml
enable_compression = true
compression_threshold = 256     # Compress smaller payloads
```

### Mobile Networks (High Loss)
```toml
enable_rohc = true              # Header compression saves bandwidth
# FEC auto-adjusts based on loss rate
```

### Latency Monitoring

Check server latency metrics:
```bash
fly ssh console
curl http://localhost:9090/metrics | grep latency
```

Target values:
- Process Latency: < 1µs
- Encode/Decode: < 0.5µs
- Forward Latency: depends on destination

## Regions

| Code | Location |
|------|----------|
| `ord` | Chicago |
| `iad` | Virginia |
| `lax` | Los Angeles |
| `sea` | Seattle |
| `ams` | Amsterdam |
| `lhr` | London |
| `nrt` | Tokyo |
| `syd` | Sydney |

See all: `fly platform regions`
