# Latitude.sh Bare Metal Deployment Guide

Quick-start guide for deploying Oxidize on Latitude.sh bare metal with **DPDK kernel bypass** for maximum performance.

## Server Specifications

| Component | Value |
|-----------|-------|
| **Provider** | Latitude.sh |
| **Location** | Chicago |
| **Plan** | m4.metal.small or f4.metal.small |
| **CPU** | AMD EPYC 4000 series (6-12 cores) |
| **RAM** | 64-96GB DDR5 |
| **Network** | 2x10Gbps NICs |
| **Bandwidth** | 20TB included |
| **Price** | $189-291/mo |

## Architecture: Dual-NIC Setup

```
┌─────────────────────────────────────────────────────────────┐
│                    Latitude.sh Server                        │
│                                                              │
│  ┌─────────────────┐              ┌─────────────────┐       │
│  │   NIC 1 (eth0)  │              │   NIC 2 (eth1)  │       │
│  │   Management    │              │   Data Plane    │       │
│  │   10Gbps        │              │   10Gbps        │       │
│  └────────┬────────┘              └────────┬────────┘       │
│           │                                │                 │
│           │                                │                 │
│  ┌────────▼────────┐              ┌────────▼────────┐       │
│  │  Linux Kernel   │              │  DPDK           │       │
│  │  SSH, API       │              │  Kernel Bypass  │       │
│  └─────────────────┘              └─────────────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Management traffic (SSH) never impacts data plane
- Full 10Gbps dedicated to QUIC relay traffic
- Zero kernel overhead on data NIC

## Quick Start

### 1. Provision Server on Latitude.sh

1. Go to [latitude.sh/dashboard](https://www.latitude.sh/dashboard/signup)
2. Select **Chicago** location
3. Choose **m4.metal.small** ($189/mo) or **f4.metal.small** ($291/mo)
4. Select **Ubuntu 22.04** or **24.04**
5. Add your SSH key
6. Deploy

### 2. Initial Server Setup

```bash
# SSH into server
ssh root@YOUR_SERVER_IP

# Clone repository
git clone https://github.com/gagansuie/oxidize.git
cd oxidize

# Run setup script (configures hugepages, IOMMU, dual NICs)
sudo ./scripts/latitude/latitude-setup.sh

# Reboot if IOMMU was configured
sudo reboot
```

### 3. Deploy Oxidize

```bash
# After reboot, SSH back in
cd oxidize

# Full deployment (build, install, configure, TLS, start)
sudo ./scripts/latitude/latitude-deploy.sh --full
```

### 4. Verify Deployment

```bash
# Check status
sudo ./scripts/latitude/latitude-deploy.sh --status

# Health check
sudo ./scripts/latitude/latitude-deploy.sh --health

# View logs
sudo ./scripts/latitude/latitude-deploy.sh --logs
```

## Configuration

Configuration file: `/etc/oxidize/server.toml`

```toml
[server]
listen_addr = "0.0.0.0:4433"
public_ip = "YOUR_PUBLIC_IP"
cert_path = "/etc/oxidize/certs/server.crt"
key_path = "/etc/oxidize/certs/server.key"

[network]
interface = "eth1"           # Data NIC for kernel bypass
kernel_bypass = "dpdk"
workers = 6                  # Match CPU cores
zero_copy = true

[performance]
hugepages = true
rx_ring_size = 4096
tx_ring_size = 4096
batch_size = 64

[quic]
max_idle_timeout_ms = 30000
max_connections = 10000
```

## NIC Configuration

The setup script automatically detects and configures dual NICs:

```bash
# View detected NICs
cat /etc/oxidize/nic-config.env

# Output:
# MGMT_NIC=eth0
# DATA_NIC=eth1
```

## Firewall Rules

The deploy script configures:

| Port | Protocol | Purpose |
|------|----------|---------|
| 22 | TCP | SSH |
| 4433 | UDP | QUIC relay |

## TLS Certificates

### Self-Signed (Development)

Generated automatically by `--tls` flag.

### Let's Encrypt (Production)

```bash
# Install certbot
apt install certbot

# Get certificate (replace with your domain)
certbot certonly --standalone -d relay.yourdomain.com

# Update config
sudo nano /etc/oxidize/server.toml
# Set:
# cert_path = "/etc/letsencrypt/live/relay.yourdomain.com/fullchain.pem"
# key_path = "/etc/letsencrypt/live/relay.yourdomain.com/privkey.pem"

# Restart
sudo systemctl restart oxidize
```

## Monitoring

### Service Status

```bash
systemctl status oxidize
```

### Logs

```bash
# Follow logs
journalctl -u oxidize -f

# Last 100 lines
journalctl -u oxidize -n 100
```

### Network Stats

```bash
# Check NIC stats
ethtool -S eth1 | grep -E 'rx_|tx_'

# Monitor bandwidth
iftop -i eth1
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u oxidize -n 50

# Verify config
cat /etc/oxidize/server.toml

# Test binary manually
/opt/oxidize/oxidize-server --config /etc/oxidize/server.toml
```

### DPDK Not Working

```bash
# Check hugepages
cat /proc/sys/vm/nr_hugepages

# Check IOMMU
dmesg | grep -i iommu

# Check NIC driver
ethtool -i eth1
```

### Port Not Listening

```bash
# Check if service is running
systemctl status oxidize

# Check port binding
ss -ulnp | grep 4433

# Check firewall
ufw status
```

## Scaling

### Vertical (Same Server)

- Upgrade to larger Latitude.sh plan
- Increase worker threads in config

### Horizontal (Multiple Servers)

Deploy additional servers in different locations:

| Location | Latency Target |
|----------|---------------|
| Chicago | US Midwest |
| Los Angeles | US West |
| Miami | US Southeast |
| Ashburn | US East |

## Cost Comparison

| Provider | Plan | Price | Bandwidth | NICs |
|----------|------|-------|-----------|------|
| Latitude.sh | m4.metal.small | $189/mo | 20TB | 2x10Gbps |
| Vultr | vbm-4c-32gb | $120/mo | 5TB | 10Gbps |
| OVHcloud | Advance-1 | $93/mo | Unlimited | 1Gbps |

**Latitude.sh advantages:**
- Dual NICs for proper DPDK architecture
- 4x more bandwidth than Vultr
- Chicago location (close to Midwest users)
- Stable bare metal (no iPXE issues like Vultr)

## GitHub Secrets (CI/CD)

For automated deployments, add these secrets:

| Secret | Description |
|--------|-------------|
| `LATITUDE_HOST` | Server IP |
| `LATITUDE_SSH_KEY` | SSH private key |

## Support

- [Latitude.sh Docs](https://www.latitude.sh/docs)
- [Latitude.sh Status](https://status.latitude.sh/)
- [Oxidize Issues](https://github.com/gagansuie/oxidize/issues)
