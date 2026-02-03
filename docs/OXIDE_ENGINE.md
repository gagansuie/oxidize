# OXIDE Engine - Oxidize eXtreme I/O Data Engine

## Overview

OXIDE is the **server-side** ultra-high-performance I/O engine that powers Linux relay nodes via AF_XDP/FLASH (~100ns latency, 10-25 Gbps throughput). Client apps are TUN-only and do **not** use OXIDE kernel bypass.

## Current Scope
- **Linux relay servers**: AF_XDP/FLASH (required)
- **Clients (all platforms)**: TUN/tunnel APIs + userspace fast path (no kernel bypass)
- **Cross-platform OXIDE prototypes below are legacy/experimental and not wired into clients**

## Performance Targets

| Role | Technology | Notes |
|------|------------|-------|
| Linux relay server | AF_XDP/FLASH | ~100ns, 10-25 Gbps (required) |
| Clients (all platforms) | TUN/tunnel APIs + userspace fast path | No kernel bypass (see TUN_QUIC_IMPLEMENTATION.md) |

## Architecture

> Note: The unified cross-platform diagram below reflects the original OXIDE concept. In production, only the Linux AF_XDP/FLASH server backend is active.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OXIDE Unified API                                    │
│                    OxideEngine::recv_batch() / send_batch()                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                       Zero-Copy Packet Ring                                  │
│              Memory-mapped shared buffer (no memcpy in hot path)            │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────────────┤
│   Linux     │   macOS     │  Windows    │  Android    │       iOS           │
│  AF_XDP     │  IOKit +    │  Wintun +   │  NDK +      │  NetworkExt +       │
│  FLASH      │  UMEM       │  UMEM       │  UMEM       │  UMEM               │
│  ~100ns     │  ~100ns     │  ~100ns     │  ~150ns     │  ~150ns             │
└─────────────┴─────────────┴─────────────┴─────────────┴─────────────────────┘
```

## Key Techniques

### 1. UMEM-Style Shared Memory
Single contiguous memory region shared between kernel/driver and userspace:
- Pre-allocated at startup (no runtime allocation)
- Memory-mapped for zero-copy access
- Page-faulted upfront to avoid TLB misses

```rust
// Allocate UMEM
let umem_size = frame_count * frame_size;
let umem = mmap(NULL, umem_size, PROT_READ | PROT_WRITE, 
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// Pre-fault all pages
for i in (0..umem_size).step_by(4096) {
    *umem.add(i) = 0;
}
```

### 2. Producer-Consumer Rings
Lock-free ring buffers for packet exchange:
- Cache-line aligned (64 bytes) to prevent false sharing
- Atomic operations only on indices
- Power-of-2 sizes for fast modulo via bitmask

```rust
#[repr(C, align(64))]
pub struct OxideRing {
    producer: AtomicU32,    // Cache line 1
    _pad1: [u8; 60],
    consumer: AtomicU32,    // Cache line 2
    _pad2: [u8; 60],
    mask: u32,              // Cache line 3
    size: u32,
}
```

### 3. Batch Operations
Process 64+ packets per "syscall":
- Amortizes syscall overhead across many packets
- Reduces context switches
- Enables SIMD processing

```rust
// Batch receive - up to 64 packets at once
let count = engine.recv_batch(&mut packets[..64]);

// Batch send
let sent = engine.send_batch(&packets_to_send);
```

### 4. Busy-Polling
No sleep, no context switch in hot path:
- Spin on ring indices
- Optional timeout for power management
- Falls back to event-based when idle

```rust
fn poll(&mut self, timeout_us: u32) -> usize {
    // Pure busy-poll when timeout is 0
    if timeout_us == 0 {
        loop {
            if self.rx_ring.available() > 0 {
                return 1;
            }
            std::hint::spin_loop();
        }
    }
    // ...
}
```

### 5. Cache-Line Alignment
Prevent false sharing between producer and consumer:
- All hot data structures are 64-byte aligned
- Separate cache lines for producer/consumer indices
- Descriptors are exactly 64 bytes

```rust
#[repr(C, align(64))]
pub struct OxideDescriptor {
    addr: u64,          // 8 bytes
    len: u32,           // 4 bytes
    flags: u32,         // 4 bytes
    timestamp_ns: u64,  // 8 bytes
    _pad: [u64; 5],     // 40 bytes = 64 total
}
```

### 6. Nanosecond Timestamps
Platform-specific high-resolution timing:

| Platform | Source | Resolution |
|----------|--------|------------|
| Linux | `clock_gettime(CLOCK_MONOTONIC)` | ~1ns |
| macOS | `mach_absolute_time()` | ~1ns |
| Windows | `QueryPerformanceCounter` | ~100ns |
| Android | `clock_gettime(CLOCK_MONOTONIC)` | ~1ns |
| iOS | `mach_absolute_time()` | ~1ns |

## Platform-Specific Implementations

### Linux: AF_XDP/FLASH (relay servers only, required)
Already optimal - OXIDE wraps FLASH for unified API:
- Zero-copy via XDP UMEM
- Kernel bypass - no syscalls in hot path
- Multi-queue support for NIC scaling

### macOS: IOKit + UMEM (legacy prototype)
Achieves near-AF_XDP performance:
- Memory-mapped packet buffers
- kqueue for efficient event notification
- Direct utun I/O with non-blocking mode
- `mach_absolute_time()` for nanosecond timestamps

### Windows: Wintun + UMEM (legacy prototype)
Wintun already provides ring buffers:
- `MAX_RING_CAPACITY` for maximum throughput
- Non-blocking packet receive/send
- Memory-mapped packet pool
- QPC-based nanosecond timing

### Android: NDK + UMEM (legacy prototype)
Optimized VpnService I/O:
- Memory-mapped shared buffer
- Non-blocking fd operations
- Pre-allocated packet buffers
- Native `clock_gettime` for timing

### iOS: NetworkExtension + UMEM (legacy prototype)
Optimized packet tunnel I/O:
- Memory-mapped dispatch
- Non-blocking utun operations
- Pre-faulted memory pages
- `mach_absolute_time()` for timing

## Usage

```rust
use oxidize_common::oxide_engine::{create_oxide_engine, OxideConfig, OxidePacket};

// Create engine with default config
let config = OxideConfig {
    interface: "oxtun0".to_string(),
    ring_size: 4096,
    frame_size: 2048,
    busy_poll: true,
    zero_copy: true,
    batch_size: 64,
    ..Default::default()
};

let mut engine = create_oxide_engine(config);
engine.init()?;

// Hot path - batch receive
let mut packets = [None; 64];
loop {
    let count = engine.recv_batch(&mut packets);
    if count > 0 {
        // Process packets...
        for packet in packets[..count].iter().flatten() {
            process(packet.data);
        }
    }
    
    // Batch send
    let to_send: Vec<&[u8]> = prepare_packets();
    engine.send_batch(&to_send);
}
```

## Performance Comparison

> Note: Only Linux relay servers use OXIDE today; other platform comparisons are historical targets.

### Before OXIDE (standard I/O)
| Platform | Latency | Throughput |
|----------|---------|------------|
| Linux relay server (AF_XDP) | ~100ns | 10-25 Gbps |
| macOS | ~1µs | 1-5 Gbps |
| Windows | ~1µs | 1-5 Gbps |
| Android | ~2µs | 500 Mbps |
| iOS | ~2µs | 500 Mbps |

### After OXIDE (unified architecture)
| Platform | Latency | Throughput | Improvement |
|----------|---------|------------|-------------|
| Linux relay server | ~100ns | 10-25 Gbps | - |
| macOS | ~100ns | 5-15 Gbps | **10x** |
| Windows | ~100ns | 5-15 Gbps | **10x** |
| Android | ~150ns | 1-5 Gbps | **13x** |
| iOS | ~150ns | 1-5 Gbps | **13x** |

## Why This Works

### The Secret: Memory Layout
Traditional I/O copies packets through multiple buffers:
```
NIC → Kernel buffer → User buffer → Application
        ^copy          ^copy
```

OXIDE eliminates copies:
```
NIC → Shared UMEM → Application
        ^zero-copy
```

### The Math
- Traditional syscall: ~1µs overhead
- OXIDE ring operation: ~10ns (atomic load/store)
- **100x improvement** just from avoiding syscalls

### Cache Efficiency
- 64-byte alignment = one cache line per descriptor
- No false sharing between producer/consumer
- Prefetch-friendly sequential access

## Advanced Optimizations (Implemented)

### 1. SIMD Batch Processing (AVX-512/NEON)

Parallel packet processing using vector instructions:

```rust
use oxidize_common::oxide_simd::{SimdBatchProcessor, SimdCapability};

let processor = SimdBatchProcessor::new();
println!("SIMD: {:?}, {} packets parallel", 
    processor.capability(), 
    processor.capability().parallel_packets());

// Batch checksum calculation
let checksums = processor.batch_ipv4_checksum(&headers);

// SIMD-accelerated copy
processor.batch_copy(&sources, &mut destinations);
```

| Instruction Set | Vector Width | Parallel Packets |
|-----------------|--------------|------------------|
| AVX-512 | 64 bytes | 16 |
| AVX2 | 32 bytes | 8 |
| SSE4.2 | 16 bytes | 4 |
| NEON (ARM) | 16 bytes | 4 |

### 2. Huge Pages (2MB)

Reduce TLB misses by 512x:

```rust
use oxidize_common::oxide_memory::{HugePageAllocator, HugePageSize};

let allocator = HugePageAllocator::new(HugePageSize::Size2MB);
let umem = allocator.alloc(16 * 1024 * 1024); // 16MB with 2MB pages

// Only 8 TLB entries needed vs 4096 with 4KB pages
```

### 3. CPU Pinning

Dedicate cores to OXIDE processing:

```rust
use oxidize_common::oxide_memory::CpuPinning;

let mut pinning = CpuPinning::new();
pinning.pin_to_core(7)?;  // Pin to core 7
pinning.set_realtime_priority()?;  // SCHED_FIFO priority 99
```

### 4. NUMA Awareness

Allocate memory on correct NUMA node:

```rust
use oxidize_common::oxide_memory::NumaAllocator;

let allocator = NumaAllocator::default();  // Auto-detect current node
let umem = allocator.alloc_local(16 * 1024 * 1024);  // Allocate on local node

println!("NUMA nodes: {}, current: {}", 
    NumaAllocator::num_nodes(), 
    NumaAllocator::current_node());
```

## Protocol Coverage

OXIDE captures ALL IP traffic at Layer 3:

| Protocol | Supported | Notes |
|----------|-----------|-------|
| **TCP** | ✅ | HTTP, HTTPS, SSH, etc. |
| **UDP** | ✅ | DNS, gaming, VoIP, QUIC |
| **ICMP** | ✅ | ping, traceroute |
| **IPv4** | ✅ | Full support |
| **IPv6** | ✅ | Full support |
| **SCTP** | ✅ | Any IP protocol |

The TUN device operates at the IP layer, so **all protocols above IP are automatically tunneled**.

## Files

- `common/src/oxide_engine.rs` - Unified OXIDE engine implementation
- `common/src/oxide_simd.rs` - SIMD batch processing (AVX-512/NEON)
- `common/src/oxide_memory.rs` - Huge pages, CPU pinning, NUMA
- `common/src/af_xdp/` - Linux AF_XDP/FLASH backend
  - `af_xdp/flash.rs` - Multi-queue AF_XDP socket
  - `af_xdp/utils.rs` - High-perf utilities (SpscRing, PacketBuffer, security)
- `common/src/tun_device.rs` - TUN device integration
- `common/src/handoff_prediction.rs` - WiFi→LTE handoff prediction
- `common/src/mptcp_redundancy.rs` - Multipath packet duplication

## Configuration

```rust
let config = OxideConfig {
    // Core settings
    ring_size: 4096,
    frame_size: 2048,
    busy_poll: true,
    zero_copy: true,
    batch_size: 64,
    interface: "oxtun0".to_string(),
    
    // Advanced optimizations
    enable_simd: true,       // AVX-512/NEON
    enable_huge_pages: true, // 2MB pages
    pin_to_core: Some(7),    // Pin to core 7
    enable_numa: true,       // NUMA-aware
    numa_node: None,         // Auto-detect
    ..Default::default()
};
```
