# ⚡ AF_XDP Zero-Copy Networking

AF_XDP (Address Family XDP) provides **kernel-bypass zero-copy packet I/O** for maximum throughput on Linux servers. Oxidize uses **FLASH (Fast Linked AF_XDP Sockets)** as the default networking layer on Linux, achieving **18-25 Gbps** with sub-microsecond latency.

## FLASH: Fast Linked AF_XDP Sockets

FLASH enables **multi-queue AF_XDP** for linear scaling across NIC hardware queues. Instead of a single socket bottlenecked on one queue, FLASH creates linked sockets sharing a single UMEM.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FLASH Multi-Queue Architecture                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   NIC with RSS                    FLASH Sockets                CPU Cores    │
│  ┌─────────────┐                 ┌─────────────┐              ┌─────────┐  │
│  │   Queue 0   │────────────────►│  Socket 0   │─────────────►│ Core 0  │  │
│  │   Queue 1   │────────────────►│  Socket 1   │─────────────►│ Core 1  │  │
│  │   Queue 2   │────────────────►│  Socket 2   │─────────────►│ Core 2  │  │
│  │   Queue N   │────────────────►│  Socket N   │─────────────►│ Core N  │  │
│  └─────────────┘                 └─────────────┘              └─────────┘  │
│         │                               │                                   │
│         │         ┌─────────────────────┘                                   │
│         │         │                                                         │
│         │    ┌────▼────┐                                                    │
│         └───►│  UMEM   │◄─── Shared memory region (16-64 MB)               │
│              └─────────┘                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### FLASH vs Single-Queue AF_XDP vs DPDK

| Metric | Single AF_XDP | FLASH | DPDK |
|--------|--------------|-------|------|
| **Throughput** | 10-15 Gbps | **18-25 Gbps** | 25-100 Gbps |
| **Latency** | <1µs | <1µs | <0.5µs |
| **CPU Cores** | 1 | N (per queue) | N (dedicated) |
| **Kernel bypass** | Partial | Partial | Full |
| **Complexity** | Low | Medium | High |
| **Driver changes** | None | None | Required |

### FLASH Configuration

```rust
use oxidize_common::af_xdp::{FlashSocket, XdpConfig};

let config = XdpConfig {
    interface: "eth0".to_string(),
    enable_flash: true,
    num_queues: 0,  // 0 = auto-detect from /sys/class/net/<iface>/queues/
    ..XdpConfig::high_throughput("eth0")
};

let mut flash = FlashSocket::new(config)?;
println!("FLASH ready with {} queues", flash.num_queues());

// Receive from all queues
let packets = flash.recv(128);

// Send (distributes across queues)
flash.send(&[&packet1, &packet2]);
```

### Queue Auto-Detection

FLASH automatically detects NIC queues via:
1. `/sys/class/net/<iface>/queues/rx-*` directory count
2. `ethtool -l <iface>` combined queue count
3. Fallback to single queue if detection fails

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AF_XDP Zero-Copy Pipeline                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    NIC      │    │    UMEM     │    │   AF_XDP    │    │  OxTunnel   │  │
│  │  (10 Gbps)  │───►│   Memory    │───►│   Socket    │───►│   Server    │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                  │                  │                  │          │
│         │           Zero-Copy           Ring Buffers        Processing      │
│         │          (no memcpy)         (Fill/Comp/         (<1µs per       │
│         │                               RX/TX)             packet)          │
│         │                                                                   │
│  ───────┴───────────────────────────────────────────────────────────────── │
│              Kernel Bypass: Packets go directly to userspace                │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Performance

| Metric | Standard UDP | AF_XDP | Improvement |
|--------|-------------|--------|-------------|
| Throughput | 1-3 Gbps | 10-25 Gbps | **8-10x** |
| Latency | 10-50µs | <1µs | **10-50x** |
| CPU per Gbps | High | Low | **3-5x less** |
| Memory copies | Multiple | Zero | **Eliminated** |

## Requirements

### Hardware
- **NIC**: XDP-capable driver (Intel i40e/ixgbe, Mellanox mlx5, etc.)
- **CPU**: Modern x86_64 with good memory bandwidth
- **Memory**: Sufficient for UMEM buffers (default 16MB)

### Software
- **Kernel**: Linux 5.4+ (5.10+ recommended)
- **Privileges**: Root or CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN + CAP_IPC_LOCK

### System Configuration
```bash
# Run the setup script (recommended)
sudo ./scripts/xdp-setup.sh <interface> <port>

# Or configure manually:
# 1. Enable BPF JIT
echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable

# 2. Increase memory lock limit
ulimit -l unlimited

# 3. Configure huge pages (optional, improves performance)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 4. Increase network buffer sizes
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
```

## Implementation Details

### UMEM (User Memory)
Oxidize allocates a contiguous memory region shared between kernel and userspace:

```rust
// Default configuration
const UMEM_SIZE: usize = 16 * 1024 * 1024;     // 16 MB
const FRAME_SIZE: usize = 4096;                 // 4 KB frames
const NUM_FRAMES: usize = UMEM_SIZE / FRAME_SIZE; // 4096 frames
```

### Ring Buffers
Four ring buffers coordinate packet flow:

| Ring | Direction | Element Size | Purpose |
|------|-----------|--------------|---------|
| **Fill Ring** | App → Kernel | 8 bytes (u64) | Frame addresses for RX |
| **Completion Ring** | Kernel → App | 8 bytes (u64) | Completed TX frames |
| **RX Ring** | Kernel → App | 16 bytes (XdpDesc) | Received packets |
| **TX Ring** | App → Kernel | 16 bytes (XdpDesc) | Packets to transmit |

### XdpDesc Structure
```rust
#[repr(C)]
struct XdpDesc {
    addr: u64,     // Frame address in UMEM
    len: u32,      // Packet length
    options: u32,  // Flags (checksum offload, etc.)
}
```

### Socket Binding
```rust
// Bind to specific interface and queue
let sockaddr = SockaddrXdp {
    sxdp_family: AF_XDP,
    sxdp_ifindex: interface_index,
    sxdp_queue_id: 0,
    sxdp_flags: XDP_ZEROCOPY,
    sxdp_shared_umem_fd: 0,
};
```

## Code Path

### Server Startup
```
1. detect_default_interface()  → Find primary NIC (from /proc/net/route)
2. XdpSocket::new()            → Create AF_XDP socket
3. Umem::new()                 → Allocate and register UMEM
4. map_ring() x 4              → Map fill/completion/rx/tx rings
5. bind()                      → Bind to interface:queue
6. populate_fill_ring()        → Pre-fill RX buffers
7. run_with_xdp()              → Start packet processing loop
```

### Packet Processing Loop
```rust
loop {
    // 1. Poll for packets
    socket.poll(timeout_ms);
    
    // 2. Receive batch
    let packets = socket.recv(batch_size);  // Zero-copy: just get descriptors
    
    // 3. Process packets
    for packet in packets {
        let data = umem.get_data(packet.addr, packet.len);  // Direct pointer
        process_oxtunnel_packet(data);
    }
    
    // 4. Return frames to fill ring
    socket.return_frames(&used_frames);
    
    // 5. Transmit responses
    socket.send(&responses);
}
```

## Platform Behavior

| Platform | Networking Layer | Notes |
|----------|-----------------|-------|
| **Linux (Server)** | AF_XDP | Zero-copy, mandatory, no fallback |
| **Linux (Client)** | Standard UDP | Clients don't need AF_XDP |
| **macOS** | High-perf UDP | 16MB buffers, sendmsg batching |
| **Windows** | High-perf UDP | WSASendMsg, large buffers |
| **Android/iOS** | Standard UDP | VpnService/NEPacketTunnel APIs |

**Important:** AF_XDP is a **server-side optimization**. Client applications use platform-appropriate high-performance UDP which is optimal for their use case.

## Troubleshooting

### Common Errors

#### `mmap failed: Invalid argument (EINVAL)`
**Cause:** Ring buffer size calculation mismatch.
**Solution:** Ensure ring sizes are power-of-2 and element sizes are correct:
- Fill/Completion rings: 8 bytes per element (u64)
- RX/TX rings: 16 bytes per element (XdpDesc)

#### `bind failed: Operation not permitted (EPERM)`
**Cause:** Insufficient privileges.
**Solution:** Run as root or with required capabilities:
```bash
sudo setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_ipc_lock+ep ./oxidize-server
```

#### `XDP not supported on interface`
**Cause:** NIC driver doesn't support XDP.
**Solution:** Use a supported NIC (Intel i40e/ixgbe, Mellanox mlx5, Broadcom bnxt).

#### `UMEM registration failed`
**Cause:** Memory lock limit too low.
**Solution:** 
```bash
ulimit -l unlimited
# Or in /etc/security/limits.conf:
# * soft memlock unlimited
# * hard memlock unlimited
```

### Verification

Check if AF_XDP is active in server logs:
```
INFO Binding socket to interface index 3 queue 0...
INFO Bound in zero-copy mode
INFO AF_XDP socket ready on enp1s0f1:0
INFO ✅ AF_XDP socket bound to enp1s0f1:0
INFO OxTunnel server started with AF_XDP
```

## Ansible/Terraform Deployment

The infrastructure automation includes XDP setup:

```yaml
# infrastructure/ansible/roles/xdp/tasks/main.yml
- name: Configure system for AF_XDP
  tasks:
    - Check kernel version (5.4+)
    - Install XDP/BPF dependencies
    - Enable BPF JIT compiler
    - Configure huge pages
    - Set network buffer sizes
    - Configure memory limits
    - Detect data NIC
    - Configure NIC ring buffers
```

## Systemd Service

The service template includes AF_XDP requirements:

```ini
# infrastructure/ansible/roles/oxidize/templates/oxidize.service.j2
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_IPC_LOCK
LimitMEMLOCK=infinity
LimitNOFILE=1048576
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=99
Nice=-20
```

## Benchmarks

Tested on Latitude.sh bare metal (AMD EPYC, dual 10 Gbps NICs):

| Test | Result |
|------|--------|
| Single-flow throughput | 9.8 Gbps |
| Multi-flow throughput | 18+ Gbps |
| Packets per second | 14.8 Mpps |
| Per-packet latency | 0.5-1.0 µs |
| CPU utilization @ 10 Gbps | ~40% single core |

## See Also

- [OXTUNNEL.md](OXTUNNEL.md) - OxTunnel protocol specification
- [DEEP_LEARNING.md](DEEP_LEARNING.md) - ML engine for congestion control
- [SECURITY.md](SECURITY.md) - Security architecture
- [Linux XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
