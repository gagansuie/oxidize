# 🚀 Kernel Bypass Mode (AF_XDP)

Oxidize includes AF_XDP kernel bypass for bare metal deployments.

> **Status**: ✅ Fully implemented with automatic detection

## Overview

| Technology | Throughput | Latency | Requirements |
|------------|------------|---------|-------------|
| **AF_XDP** | 10-40 Gbps | 1-2 µs | Linux kernel 4.18+, root/CAP_NET_RAW |

## How It Works

### Standard Networking (Cloud)

```
Application → System Call → Kernel Network Stack → Driver → NIC
                  ↓
            Context Switch      ← 1000+ CPU cycles
            Memory Copy         ← Data copied multiple times
            Interrupt Handling  ← CPU interrupted per packet
            Protocol Processing ← Kernel overhead
```

**Every packet = ~5-10 system calls, memory copies, and interrupts**

### Kernel Bypass (Bare Metal)

```
Application → User-space Driver (PMD) → NIC
                     ↓
              Direct Memory Access    ← Zero copies
              No System Calls         ← Zero kernel involvement
              No Interrupts           ← Poll-mode (busy wait)
              Zero-Copy Buffers       ← Pre-allocated pools
```

**Every packet = direct memory read/write, zero kernel involvement**

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                      100x Kernel Bypass Architecture                   │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 1: Hardware Acceleration                                        │
│  ├── RSS (Receive Side Scaling) - Multi-queue distribution            │
│  ├── Flow Director - Hardware flow classification                     │
│  ├── Checksum Offload - NIC computes checksums                        │
│  └── TSO/GSO - Segmentation offload                                   │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Memory Optimization                                          │
│  ├── 1GB Huge Pages - Minimal TLB misses                              │
│  ├── NUMA-Aware Allocation - Memory close to CPU                      │
│  ├── Memory Pools - Zero-allocation hot path                          │
│  └── Cache-Line Alignment - No false sharing                          │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 3: CPU Optimization                                             │
│  ├── CPU Pinning - Dedicated cores per queue                          │
│  ├── SIMD Parsing - AVX2/AVX-512 packet parsing                       │
│  ├── Prefetching - Prefetch next packet during processing             │
│  ├── Branch Prediction - likely/unlikely hints                        │
│  └── Busy Polling - No context switches                               │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 4: Data Structure Optimization                                  │
│  ├── Lock-Free Rings - SPSC/MPMC without locks                        │
│  ├── Batch Processing - 32-64 packets per burst                       │
│  ├── Doorbell Coalescing - Reduce PCIe transactions                   │
│  └── Zero-Copy Path - No memcpy in hot path                           │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 5: Security Hardening                                           │
│  ├── Constant-Time Crypto - No timing side channels                   │
│  ├── Packet Validation - Strict header validation                     │
│  ├── Rate Limiting - Per-flow and global limits                       │
│  └── Memory Isolation - Separate pools per security domain            │
└────────────────────────────────────────────────────────────────────────┘
```

## Performance

| Metric | AF_XDP |
|--------|--------|
| **Throughput** | 10-40 Gbps |
| **Latency** | 1-2 µs |
| **Packets/sec** | 1-5M pps |
| **CPU per packet** | ~100 cycles |
| **System calls** | 1 per batch |
| **NIC binding** | No (uses kernel driver) |
| **SSH access** | Yes |

## Key Components

### 1. Lock-Free SPSC Ring Buffer

Single-producer single-consumer ring for zero-contention packet queuing:

```rust
use oxidize_common::kernel_bypass::{SpscRing, PacketBuffer};

// Create ring with 16K slots
let ring: SpscRing<PacketBuffer> = SpscRing::new(16384);

// Producer side (RX thread)
ring.push(packet);

// Consumer side (processing thread)
if let Some(pkt) = ring.pop() {
    process(pkt);
}
```

### 2. Memory Pool (Zero Allocation)

Pre-allocated packet buffers eliminate malloc in hot path:

```rust
use oxidize_common::kernel_bypass::{PacketPool, PacketBuffer};

// Create pool with 256K buffers
let pool = PacketPool::new(262144, 0);

// Allocate from pool (O(1), no malloc)
let buf = pool.alloc().unwrap();
buf.set_data(&packet_data);

// Return to pool (O(1), no free)
pool.free(buf);
```

### 3. CPU Pinning

Each worker thread is pinned to a dedicated CPU core:

```rust
use oxidize_common::kernel_bypass::BypassWorker;

let worker = BypassWorker::new(core_id, queue_id, pool);
worker.pin_to_core()?; // Uses sched_setaffinity

worker.run(|packet| {
    // Process packet on dedicated core
    // No cache invalidation from other threads
    true
});
```

### 4. SIMD Packet Parsing

AVX2/AVX-512 accelerated header parsing with prefetching:

```rust
use oxidize_common::kernel_bypass::SimdPacketParser;

// Parse with prefetch of next packet
let parsed = SimdPacketParser::parse_fast(&packet_data);
if let Some(info) = parsed {
    println!("UDP: {}:{} -> {}:{}", 
        info.src_addr, info.dst_addr, info.is_quic);
}

// Batch parsing with automatic prefetch
let mut results = Vec::new();
SimdPacketParser::parse_batch(&packets, &mut results);
```

### 5. Security Hardening

Constant-time operations prevent timing attacks:

```rust
use oxidize_common::kernel_bypass::security;

// Constant-time comparison (prevents timing attacks)
let valid = security::constant_time_compare(&expected, &actual);

// Packet validation (prevents malformed packet attacks)
match security::validate_packet(&data) {
    ValidationResult::Valid => process(data),
    ValidationResult::TooShort => drop(),
    ValidationResult::InvalidEthertype => drop(),
    // ...
}

// Rate limiting (token bucket)
let limiter = security::RateLimiter::new(10_000_000, 1_000_000);
if limiter.allow() {
    process(packet);
}
```

## Configuration

### UltraConfig (100x Mode)

```rust
use oxidize_common::kernel_bypass::{BypassConfig, UnifiedBypass};

// Maximum throughput configuration
let config = BypassConfig::max_throughput();

// Or balanced security + performance
let config = UltraConfig::secure();

// Custom configuration
let config = UltraConfig {
    workers: 8,                    // 8 CPU cores
    pool_size: 1_048_576,          // 1M packet buffers
    numa_aware: true,              // NUMA-aware allocation
    huge_1gb: true,                // Use 1GB huge pages
    quic_port: 4433,               // QUIC port
    rate_limit: 10_000_000,        // 10M pps limit
    security_validation: true,     // Enable packet validation
};

let bypass = UnifiedBypass::new(Some(config))?;
bypass.start();
```

## Deployment

### Requirements (Vultr Bare Metal)

1. **Hugepages** - 2MB or 1GB huge pages for zero TLB misses
2. **VFIO Driver** - For userspace NIC access
3. **Dedicated NICs** - At least one NIC for kernel bypass

### Setup

```bash
# 1. Enable hugepages (add to /etc/default/grub)
GRUB_CMDLINE_LINUX="default_hugepagesz=2M hugepagesz=2M hugepages=1024"
sudo update-grub && sudo reboot

# 2. Load VFIO driver
sudo modprobe vfio-pci

# 3. Bind NIC to VFIO (find PCI address with lspci)
echo "0000:01:00.0" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind

# 4. Build server (AF_XDP is always enabled on Linux)
cargo build --release -p relay-server

# 5. Run server
sudo ./target/release/oxidize-server --listen 0.0.0.0:4433
```

## Bare Metal Provider Comparison

For AF_XDP kernel bypass, you need bare metal. Here's how the top providers compare:

### Vultr vs OVHcloud

| Factor | Vultr | OVHcloud | Winner |
|--------|-------|----------|--------|
| **Entry Price** | ~$120/mo | ~$62/mo (Rise) | **OVHcloud** |
| **Network Speed** | 10-25 Gbps standard | 1-10 Gbps | **Vultr** |
| **Bandwidth** | 5-25 TB included | **Unlimited** (excl. APAC) | **OVHcloud** |
| **Global Locations** | 32 cities, 19 countries | ~30 DCs (US, EU, APAC) | **Vultr** |
| **DDoS Protection** | Basic included | Robust included | **OVHcloud** |
| **Provisioning** | Instant (minutes) | Minutes-hours | **Vultr** |
| **NICs** | Intel (i350, x520, x710) | Intel/Mellanox on Scale+ | Tie |

### Recommendation

| Priority | Choose | Why |
|----------|--------|-----|
| **Best Performance** | Vultr | 25 Gbps NICs, AMD EPYC, faster provisioning |
| **Budget/Pre-Profit** | OVHcloud | 50% cheaper, unlimited bandwidth, startup credits |
| **Global Scale** | Vultr | More edge locations worldwide |
| **Heavy Egress** | OVHcloud | Unlimited bandwidth saves on data transfer |

### Vultr Bare Metal Options

| Config | Price | Specs | Use Case |
|--------|-------|-------|----------|
| AMD EPYC 4245P | ~$185/mo | 6c/12t, 32GB, **25 Gbps** | Entry |
| AMD EPYC 4345P | ~$250/mo | 8c/16t, 128GB, **25 Gbps** | Production |
| AMD EPYC 7443P | ~$350/mo | 24c/48t, 256GB, **25 Gbps** | High-traffic |

### OVHcloud Options

| Config | Price | Specs | Use Case |
|--------|-------|-------|----------|
| Rise-1 | ~$62/mo | 4c, 32GB, 1 Gbps | Testing/Dev |
| Advance-1 | ~$93/mo | 8c, 64GB, 1-5 Gbps | Small production |
| Scale-a3 | ~$513/mo | 32c, 256GB, 10 Gbps | Enterprise |

### Startup Programs (Free Credits)

If pre-profit, apply for startup credits to avoid infrastructure costs:

| Program | Credits | Best For |
|---------|---------|----------|
| **OVHcloud Startup** | Up to $12,000 | Networking projects |
| **Microsoft Founders Hub** | $1,000-$5,000 | Quick approval |
| **Equinix Metal Startup** | Varies | Premium bare metal |

### Hardware Requirements Checklist

Before choosing a provider, verify:

- [ ] **VT-d / IOMMU** - Recommended for best performance
- [ ] **Compatible NICs** - Most Intel/Mellanox NICs work with AF_XDP
- [ ] **Hugepages Support** - 2MB or 1GB huge pages in BIOS
- [ ] **No Hypervisor Layer** - True bare metal, not "dedicated" VMs

### Phased Deployment Strategy

```
Phase 1 (0-500 users):     Single Vultr node ($120/mo)
                           └── vbm-4c-32gb with 10 Gbps NIC

Phase 2 (500-2000 users):  Upgrade to larger plan ($185-350/mo)
                           └── vbm-6c-32gb or vbm-8c-128gb

Phase 3 (2000+ users):     Multi-region deployment
                           └── Add WEST/EU servers via CI/CD matrix
```

## Feature Integration

All Oxidize features work on top of kernel bypass:

```
┌─────────────────────────────────────────────────────┐
│  ROHC + LZ4 + FEC + Deep Learning (ML)             │  ← All features enabled
├─────────────────────────────────────────────────────┤
│  Ultra Kernel Bypass Runtime (100x optimized)      │  ← Custom implementation
├─────────────────────────────────────────────────────┤
│  Poll-Mode Driver (kernel bypass, 100+ Gbps)       │  ← Direct NIC access
└─────────────────────────────────────────────────────┘
```

## When To Use

| Use Case | Recommended Mode | Technology |
|----------|------------------|-----------|
| Small VPN (<500 users) | Single Vultr node | AF_XDP |
| Gaming/Low Latency | Bare metal Vultr | AF_XDP |
| High-traffic CDN | Bare metal Vultr | AF_XDP |
| Enterprise (2000+ users) | Multi-node Vultr | AF_XDP |

## Monitoring

```rust
// Get runtime statistics
let stats = runtime.stats_summary();
println!("{}", stats);
// Output: "Ultra Bypass: RX 85.2 Gbps (12.3M pps), TX 82.1 Gbps (11.9M pps), 8 workers"

// Per-worker stats
for stat in runtime.worker_stats() {
    println!("{}", stat);
}

// Pool stats (allocations, frees, failures)
for (allocs, frees, failures) in runtime.pool_stats() {
    println!("Pool: {} allocs, {} frees, {} failures", allocs, frees, failures);
}
```

---

## See Also

- [OXTUNNEL.md](OXTUNNEL.md) - OxTunnel protocol specification
- [SECURITY.md](SECURITY.md) - Security hardening
