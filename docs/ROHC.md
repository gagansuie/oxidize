# ROHC (Robust Header Compression) Support

Oxidize supports ROHC (RFC 3095/6846) for compressing IP/UDP/TCP headers, significantly reducing bandwidth usage across all network traffic types.

**Pure Rust implementation** - no external dependencies required!

## What is ROHC?

ROHC compresses IP packet headers from ~40-60 bytes down to 1-4 bytes by maintaining compression context between endpoints.

## Supported Profiles

| Profile | Use Case | Header Savings |
|---------|----------|----------------|
| **UDP** | Gaming, VoIP, DNS | 40 → 1-2 bytes |
| **TCP** | Web, SSH, Database | 40-60 → 3-8 bytes |
| **IP** | ICMP, GRE tunnels | 20 → 1 byte |
| **RTP** | VoIP, Video streaming | 40 → 1-2 bytes |
| **IPv6** | Modern networks | 40 → 2-4 bytes |
| **ESP** | VPN/IPSec traffic | 20+ → 1-2 bytes |

## Performance Impact

| Traffic Type | Header Overhead | With ROHC | Savings |
|--------------|-----------------|-----------|---------|
| UDP Gaming (64 byte packets) | 62% (40/64) | 3% (2/64) | **59%** |
| VoIP RTP (160 byte packets) | 25% (40/160) | 1% (2/160) | **24%** |
| TCP Web (1400 byte packets) | 4% (60/1400) | 0.5% (8/1400) | **3.5%** |
| SSH keystrokes (80 bytes) | 75% (60/80) | 10% (8/80) | **65%** |

## Key Features

- **State machine compression** - IR → FO → SO states for progressively smaller packets
- **W-LSB encoding** - Efficient delta encoding for sequence numbers
- **SDVL encoding** - Self-describing variable length for optimal byte usage
- **CRC protection** - 3/7/8-bit CRCs for packet integrity
- **Multi-flow support** - Up to 16 concurrent compression contexts

## Building Oxidize with ROHC Support

ROHC is implemented in pure Rust - just enable the feature:

```bash
# Build with ROHC support
cargo build --release --features rohc

# Or for all crates  
cargo build --release --all-features
```

No C compiler or external libraries needed!

## Configuration

Add to your config file:

```toml
# Enable ROHC compression
enable_rohc = true

# Maximum packet size for ROHC (larger packets use LZ4 only)
rohc_max_size = 1500
```

## How It Works

1. **Outgoing packets**: Oxidize analyzes each IP packet
   - Small packets (≤ `rohc_max_size`): ROHC compresses headers
   - Large packets: LZ4 compresses payload (headers are negligible overhead)
   - Non-IP data: LZ4 compression only

2. **Compression stages**:
   ```
   Original IP Packet (100 bytes)
   └── IP Header (20 bytes) + UDP Header (8 bytes) + Payload (72 bytes)
   
   After ROHC (64 bytes)
   └── ROHC Header (4 bytes) + Payload (72 bytes)
   
   Savings: 36% bandwidth reduction
   ```

3. **Context management**: ROHC maintains per-flow compression context
   - First packets in a flow: IR (Initialization/Refresh) mode
   - Subsequent packets: FO/SO (compressed) mode
   - Context is rebuilt automatically on packet loss

## Supported Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| ROHC_PROFILE_UNCOMPRESSED | Fallback, no compression | Unknown protocols |
| ROHC_PROFILE_IP | IP-only compression | ICMP, GRE |
| ROHC_PROFILE_UDP | IP + UDP compression | Gaming, DNS |
| ROHC_PROFILE_TCP | IP + TCP compression | HTTP, SSH |
| ROHC_PROFILE_RTP | IP + UDP + RTP compression | VoIP, Video |

## Troubleshooting

### "librohc not found" error

```bash
# Ensure library is in path
sudo ldconfig
# Or add to LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### ROHC compression not activating

1. Check if feature is enabled: `cargo build --features rohc`
2. Check config: `enable_rohc = true`
3. Check packet size: Only packets ≤ `rohc_max_size` use ROHC

### High CPU usage with ROHC

ROHC adds some CPU overhead. If CPU is constrained:
- Increase `rohc_max_size` to apply ROHC to fewer packets
- Set `enable_rohc = false` and rely on LZ4 only

## Without librohc

If librohc is not available, Oxidize will:
1. Log a warning at startup
2. Fall back to LZ4 compression only
3. Continue functioning normally (just without header compression)

## References

- [RFC 3095 - RObust Header Compression (ROHC)](https://tools.ietf.org/html/rfc3095)
- [RFC 4815 - ROHC TCP Profile](https://tools.ietf.org/html/rfc4815)
- [librohc Documentation](https://rohc-lib.org/)
- [librohc GitHub](https://github.com/didier-barvaux/rohc)
