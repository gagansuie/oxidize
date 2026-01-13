# Deploy Oxidize Relay Server

Deploy your Oxidize relay server for low-latency gaming and VoIP.

## Fly.io (Recommended)

Low-latency edge deployment with anycast routing. Perfect for gaming and VoIP.

| Feature | Value |
|---------|-------|
| **Latency** | 5-15ms (multi-region) |
| **Throughput** | 1 Gbps per VM |
| **Price** | $5-15/mo per region |
| **Regions** | 30+ worldwide |

## Quick Deploy

```bash
# 1. Install Fly CLI
curl -L https://fly.io/install.sh | sh

# 2. Login
fly auth login

# 3. Deploy
cd oxidize
fly launch --no-deploy  # First time only
fly deploy

# 4. Scale to multiple regions for lowest latency
fly scale count 3 --region iad,ord,lax
```

### Recommended Regions

| Region | Location | Coverage |
|--------|----------|----------|
| `iad` | Ashburn, VA | East Coast |
| `ord` | Chicago | Central |
| `lax` | Los Angeles | West Coast |
| `dfw` | Dallas | South |
| `sea` | Seattle | Northwest |

### What Works on Fly.io

| Optimization | Status |
|--------------|--------|
| BBRv3 congestion control | ✅ |
| ROHC header compression | ✅ |
| Native LZ4 compression | ✅ |
| SIMD FEC | ✅ |
| io_uring | ✅ |
| Parallel compression | ✅ |
| DPDK kernel bypass | ❌ (bare metal only) |
| AF_XDP | ❌ (bare metal only) |

## Connect Clients

```bash
# Linux/macOS
sudo oxidize-client --server YOUR_SERVER_IP:4433

# Or use the install script
curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash -s -- YOUR_SERVER_IP:4433
```

## Configuration

Edit your server config:

```toml
# Server settings
max_connections = 50000
enable_compression = true
enable_rohc = true
rate_limit_per_ip = 1000

# High-performance settings
congestion_algorithm = "bbr_v3"
enable_priority_scheduler = true
```

## Performance Tuning

### Gaming / Low-Latency
```toml
congestion_algorithm = "bbr_v3"
enable_compression = false      # Skip for lowest latency
```

### High-Throughput
```toml
enable_compression = true
enable_rohc = true              # 60% header compression
compression_threshold = 256
```

### Mobile Networks (High Loss)
```toml
enable_rohc = true
# FEC auto-adjusts based on loss rate
```

## Achieving <5ms Latency

For the lowest possible latency:

### 1. Deploy Near Users
```bash
# More regions = lower latency for more users
fly scale count 6 --region iad,ord,lax,dfw,sea,mia
```

### 2. Latency Budget
| Component | Target |
|-----------|--------|
| Network (user → edge) | <2ms |
| Server processing | <0.5ms |
| Serialization | <0.1ms |
| **Total** | **<5ms** |

### 3. What Affects Latency
| Factor | Impact | Solution |
|--------|--------|----------|
| Physical distance | +1ms per 100km | More edge regions |
| Compression | +0.05ms | LZ4 is fine (fast) |
| QUIC streams | +0.5ms ordering | Use datagrams for gaming |
| Packet size | Minimal | Small packets are fast |

### 4. Reality Check
| User Location | Nearest Edge | Expected Latency |
|---------------|--------------|------------------|
| Same city | iad/ord/lax | **2-5ms** ✅ |
| Same region | ~500km | 5-10ms |
| Cross-country | ~3000km | 20-40ms |

**<5ms is achievable** for users within ~200km of an edge node.

---

## Vultr Bare Metal (Coming Soon)

For maximum performance, deploy on Vultr bare metal with DPDK kernel bypass.

| Feature | Fly.io (Cloud) | Vultr Bare Metal |
|---------|----------------|------------------|
| **Throughput** | 1 Gbps | **40+ Gbps per core** |
| **Latency** | 5-15ms | **<5µs per packet** |
| **Kernel** | Standard | **Complete bypass (DPDK)** |
| **PPS** | ~100K | **20+ Mpps per core** |
| **Price** | $5-15/mo | ~$120/mo |

### Why DPDK for Bare Metal?

| Technology | Throughput | Best For |
|------------|------------|----------|
| Standard kernel | 1-2 Gbps | Cloud VMs |
| eBPF/XDP | 10-25 Gbps | Cloud with XDP support |
| **DPDK** | **40+ Gbps** | **Bare metal (Vultr)** |

### DPDK Requirements

```bash
# Vultr bare metal setup (coming soon)
# 1. Enable hugepages
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 2. Bind NIC to VFIO
modprobe vfio-pci
dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

# 3. Run with DPDK feature
cargo build --release --features dpdk
./target/release/oxidize-server --dpdk-pci 0000:01:00.0
```

### DPDK Roadmap

| Phase | Status |
|-------|--------|
| DPDK module scaffolding | ✅ Complete |
| DpdkConfig struct | ✅ Complete |
| Feature flag (`--features dpdk`) | ✅ Complete |
| DpdkRuntime with full feature integration | ✅ Complete |
| io_uring bypass when DPDK enabled | ✅ Complete |
| dpdk-rs FFI bindings | 🚧 Pending (waiting for stable crate) |
| Vultr deployment scripts | 🚧 Pending |

### DPDK Feature Integration

When DPDK is enabled, all Oxidize features run on top:

```
┌─────────────────────────────────────────────────────┐
│  BBRv3 + ROHC + LZ4 + FEC + Deep Learning (ML)     │  ← All features enabled
├─────────────────────────────────────────────────────┤
│  DPDK Runtime (kernel bypass, 40+ Gbps)            │  ← Replaces io_uring
└─────────────────────────────────────────────────────┘
```

Build with DPDK:
```bash
cargo build --release --features dpdk
```

---

## Scaling

Scale to multiple regions for lowest latency:

```bash
# Add more regions
fly scale count 5 --region iad,ord,lax,dfw,sea

# Check status
fly status
```

## Monitoring

```bash
# Check Fly.io logs
fly logs

# Check metrics
fly ssh console -C "curl http://localhost:9090/metrics"
```

## Troubleshooting

```bash
# SSH into instance
fly ssh console

# Check service status
fly status

# Restart
fly apps restart
```
