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
| Kernel bypass mode | ❌ (bare metal only) |

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

For maximum performance, deploy on Vultr bare metal with kernel bypass mode.

| Feature | Fly.io (Cloud) | Vultr Bare Metal |
|---------|----------------|------------------|
| **Throughput** | 1 Gbps | **40+ Gbps per core** |
| **Latency** | 5-15ms | **<5µs per packet** |
| **Kernel** | Standard | **Complete bypass** |
| **PPS** | ~100K | **20+ Mpps per core** |
| **Price** | $5-15/mo | ~$120/mo |

### Why Kernel Bypass for Bare Metal?

| Technology | Throughput | Best For |
|------------|------------|----------|
| Standard kernel | 1-2 Gbps | Cloud VMs |
| io_uring | 5-10 Gbps | Linux 5.1+ |
| **Kernel Bypass** | **100+ Gbps** | **Bare metal (Vultr)** |

### Kernel Bypass Requirements

```bash
# Vultr bare metal setup (coming soon)
# 1. Enable hugepages
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 2. Bind NIC to VFIO
modprobe vfio-pci
dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

# 3. Run with kernel-bypass feature
cargo build --release --features kernel-bypass
./target/release/oxidize-server --bypass-pci 0000:01:00.0
```

### Kernel Bypass Roadmap

| Phase | Status |
|-------|--------|
| Kernel bypass module | ✅ Complete |
| BypassConfig struct | ✅ Complete |
| Feature flag (`--features kernel-bypass`) | ✅ Complete |
| UltraDpdkRuntime with full feature integration | ✅ Complete |
| io_uring bypass when kernel-bypass enabled | ✅ Complete |
| Lock-free SPSC rings | ✅ Complete |
| SIMD packet parsing | ✅ Complete |
| CPU pinning & NUMA awareness | ✅ Complete |
| Vultr deployment scripts | 🚧 Pending |

### Kernel Bypass Feature Integration

When kernel bypass is enabled, all Oxidize features run on top:

```
┌─────────────────────────────────────────────────────┐
│  BBRv3 + ROHC + LZ4 + FEC + Deep Learning (ML)     │  ← All features enabled
├─────────────────────────────────────────────────────┤
│  Ultra Kernel Bypass Runtime (100x optimized)      │  ← Custom implementation
├─────────────────────────────────────────────────────┤
│  Poll-Mode Driver (kernel bypass, 100+ Gbps)       │  ← Replaces io_uring
└─────────────────────────────────────────────────────┘
```

### Kernel Bypass Optimizations (100x Performance)

| Layer | Optimization | Benefit |
|-------|--------------|---------|
| **Hardware** | RSS, Flow Director, Checksum Offload | NIC handles distribution |
| **Memory** | 1GB Huge Pages, NUMA-aware, Memory Pools | Zero TLB misses |
| **CPU** | Core Pinning, SIMD Parsing, Prefetching | No cache misses |
| **Data Structures** | Lock-free SPSC Rings, Batch Processing | No contention |
| **Security** | Constant-time Crypto, Packet Validation | Timing attack resistant |

Build with kernel bypass:
```bash
cargo build --release --features kernel-bypass
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
