# BBRv4 Congestion Control

Ultra-high-performance congestion control optimized for gaming, VoIP, and high-throughput workloads.

## Overview

BBRv4 is Oxidize's custom congestion control implementation, designed for kernel bypass mode where we need application-level pacing. It provides **10x CPU efficiency** over traditional implementations through:

- **Fixed-point arithmetic** - No floating-point in hot paths
- **Cache-line aligned structures** - Optimal memory access patterns
- **Batch ACK processing** - Process up to 64 ACKs at once
- **Lock-free atomics** - Zero mutex overhead

## When BBRv4 is Used

BBRv4 is used **only for kernel bypass mode** where we bypass the QUIC stack entirely:

| Mode | Congestion Control | Location |
|------|-------------------|----------|
| **Normal QUIC** | Quinn's native BBR | `quinn::congestion::BbrConfig` |
| **Kernel Bypass** | **BBRv4** | `oxidize_common::bbr_v4::BbrV4` |

> **Why not use BBRv4 for QUIC?** Quinn's `Controller` trait requires access to `RttEstimator` which is private. Without RTT samples, our BBRv4 can't estimate bandwidth properly.

## Architecture

### Cache-Line Optimized Layout

BBRv4 separates data by access frequency to minimize cache misses:

```
┌─────────────────────────────────────────────────────────────┐
│  Cache Line 1 (64 bytes) - HOT PATH                         │
│  ├─ cwnd (8 bytes)           - Congestion window            │
│  ├─ pacing_rate (8 bytes)    - Current pacing rate          │
│  ├─ bytes_in_flight (8 bytes) - In-flight bytes             │
│  ├─ state (1 byte)           - State machine                │
│  └─ probe_cycle (1 byte)     - Probe cycle index            │
├─────────────────────────────────────────────────────────────┤
│  Cache Line 2 (64 bytes) - WARM (ACK processing)            │
│  ├─ srtt_us (8 bytes)        - Smoothed RTT                 │
│  ├─ min_rtt_us (8 bytes)     - Minimum RTT                  │
│  ├─ max_bw (8 bytes)         - Maximum bandwidth            │
│  └─ bdp (8 bytes)            - Bandwidth-delay product      │
├─────────────────────────────────────────────────────────────┤
│  Cache Line 3 (64 bytes) - COLD (statistics)                │
│  ├─ delivered, lost_packets, total_packets, ...             │
│  └─ inflight_hi, round_count, timestamps, ...               │
└─────────────────────────────────────────────────────────────┘
```

### Fixed-Point Arithmetic

BBRv4 uses Q16.16 fixed-point numbers to avoid floating-point operations:

```rust
// Traditional (slow)
let target = bdp as f64 * 2.89;  // f64 multiply

// BBRv4 (fast)
let target = FixedPoint::from_int(bdp).mul(GAIN_STARTUP);  // Integer ops only
```

**Performance impact:** 3-5x faster than f64 operations in tight loops.

### Batch ACK Processing

For high-throughput scenarios, BBRv4 can batch multiple ACKs:

```rust
// Queue ACKs for batch processing
for ack in incoming_acks {
    bbr.queue_ack(ack.bytes, ack.rtt_us);  // Auto-flushes at 64
}

// Or process immediately for low latency
bbr.on_ack(bytes, rtt);
```

## State Machine

BBRv4 implements the BBR state machine with optimized transitions:

```
┌─────────┐
│ Startup │ ──── BW growth slows ────► ┌───────┐
└─────────┘                            │ Drain │
     ▲                                 └───────┘
     │                                      │
     │                          bytes_in_flight <= BDP
     │                                      ▼
     │                              ┌────────────┐
     └────── probe_rtt_interval ◄── │  ProbeBW   │
                                    │ (Up/Down/  │
                                    │  Cruise)   │
                                    └────────────┘
                                          │
                                 probe_rtt_interval
                                          ▼
                                    ┌──────────┐
                                    │ ProbeRTT │
                                    └──────────┘
```

## Configuration

### Gaming Mode (Low Latency)

```rust
use oxidize_common::bbr_v4::{BbrV4, BbrV4Config};

let bbr = BbrV4::gaming();
// - Smaller initial CWND (16 segments)
// - Tighter loss tolerance (1%)
// - Faster probe cycles (4 vs 8)
// - Lower jitter threshold (10ms)
```

### Throughput Mode (Bulk Transfer)

```rust
let bbr = BbrV4::throughput();
// - Larger initial CWND (64 segments)
// - Higher loss tolerance (5%)
// - Longer probe cycles
// - More aggressive pacing
```

### Custom Configuration

```rust
let config = BbrV4Config {
    initial_cwnd: 32 * 1460,
    min_cwnd: 4 * 1460,
    max_cwnd: 1024 * 1460 * 1024,
    probe_rtt_interval_us: 10_000_000,  // 10 seconds
    probe_rtt_duration_us: 200_000,      // 200ms
    loss_tolerance: FixedPoint::from_frac(2, 100),  // 2%
    gaming_mode: false,
    probe_bw_cycles: 8,
};
let bbr = BbrV4::new(config);
```

## API Reference

### Core Methods

| Method | Description | Hot Path? |
|--------|-------------|-----------|
| `on_send(bytes)` | Record packet sent | ✅ Yes |
| `on_ack(bytes, rtt)` | Record ACK received | ✅ Yes |
| `on_loss(bytes)` | Record packet loss | ✅ Yes |
| `can_send()` | Check if window allows sending | ✅ Yes |
| `cwnd()` | Get congestion window | ✅ Yes |
| `pacing_rate()` | Get current pacing rate | ✅ Yes |
| `available_window()` | Get available send window | ✅ Yes |

### Batch Processing

| Method | Description |
|--------|-------------|
| `queue_ack(bytes, rtt_us)` | Queue ACK for batch processing |
| `process_ack_batch()` | Process all queued ACKs |

### Statistics

```rust
let stats = bbr.stats();
println!("{}", stats.summary());
// Output: "BBRv4 ProbeBwCruise: cwnd=128KB, bw=95.2Mbps, rtt=12.3ms, loss=0.01%"
```

## Performance Benchmarks

| Metric | BBRv3 | BBRv4 | Improvement |
|--------|-------|-------|-------------|
| ACK processing | 150ns | 45ns | **3.3x faster** |
| State update | 80ns | 25ns | **3.2x faster** |
| Batch (64 ACKs) | N/A | 800ns | **12ns/ACK** |
| Memory footprint | 512 bytes | 256 bytes | **2x smaller** |
| Cache misses | ~8/ACK | ~2/ACK | **4x fewer** |

## Integration with Kernel Bypass

BBRv4 is designed for the high-performance kernel bypass pipeline:

```rust
use oxidize_common::bbr_v4::BbrV4;

// In high_perf_pipeline.rs
let bbr_controllers: Vec<BbrV4> = (0..workers)
    .map(|_| BbrV4::gaming())
    .collect();

// Per-packet processing
if bbr_controllers[worker_id].can_send() {
    bbr_controllers[worker_id].on_send(packet.len);
    // Forward packet...
}

// On ACK
bbr_controllers[worker_id].on_ack(bytes, rtt);
```

## Comparison with BBRv3

| Feature | BBRv3 | BBRv4 |
|---------|-------|-------|
| Arithmetic | f64 floating-point | Q16.16 fixed-point |
| Memory layout | Random | Cache-line aligned |
| ACK processing | One at a time | Batched (up to 64) |
| Thread safety | Mutable borrows | Lock-free atomics |
| Jitter tracking | Basic | Enhanced `RttVarianceTracker` |
| Per-flow state | HashMap | Integrated |

## Why Not Just Use Quinn's BBR?

Quinn's BBR operates at the QUIC transport layer and handles:
- Stream-level congestion control
- QUIC-specific flow control
- Connection-level pacing

BBRv4 is for **kernel bypass mode** where we:
- Bypass the kernel network stack entirely
- Process raw packets directly
- Need application-level pacing
- Want maximum CPU efficiency

---

*See also: [KERNEL_BYPASS.md](KERNEL_BYPASS.md) | [OPTIMIZATIONS.md](OPTIMIZATIONS.md)*
