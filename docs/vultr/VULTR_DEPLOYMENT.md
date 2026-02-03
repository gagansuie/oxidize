# Vultr Bare Metal Deployment Guide

Quick-start guide for deploying Oxidize on Vultr bare metal with **kernel bypass** for maximum performance.

**Current Server:** `144.202.60.215` (Chicago, vbm-4c-32gb, $120/mo)

## Current Configuration

| Component | Status | Details |
|-----------|--------|---------|
| **Kernel Bypass** | ✅ AF_XDP | Required for 10-25 Gbps (no UDP fallback) |
| **Zero-Downtime** | ✅ Active | SO_REUSEPORT + graceful shutdown |
| **CI/CD** | ✅ Automated | Version bump → auto-deploy |
| **Hugepages** | ✅ Configured | 4GB (2048 x 2MB pages) |
| **IOMMU** | ✅ Enabled | intel_iommu=on iommu=pt |

## CI/CD Deployment (Automatic)

Every version bump in `Cargo.toml` triggers automatic deployment to all configured Vultr servers.

### GitHub Secrets Required

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description | Example |
|--------|-------------|---------|
| `VULTR_HOST` | Primary server IP | `144.202.60.215` |
| `VULTR_SSH_KEY` | SSH private key (full content) | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `VULTR_HOST_WEST` | (Optional) West coast server | For horizontal scaling |
| `VULTR_HOST_EU` | (Optional) EU server | For horizontal scaling |

### Generate SSH Key

```bash
# On your local machine
ssh-keygen -t ed25519 -f ~/.ssh/vultr_oxidize -N ""

# Copy public key to Vultr server
ssh-copy-id -i ~/.ssh/vultr_oxidize.pub root@YOUR_VULTR_IP

# Add private key to GitHub Secrets
cat ~/.ssh/vultr_oxidize
# Copy entire output to VULTR_SSH_PRIVATE_KEY secret
```

### First-Time Server Setup

SSH into server and run:
```bash
git clone https://github.com/gagansuie/oxidize.git /opt/oxidize
cd /opt/oxidize
./scripts/vultr-setup.sh
sudo reboot  # If IOMMU was configured
./scripts/vultr-deploy.sh
```

### Automatic Deployments

After initial setup, every version bump triggers:
1. Build server binary (optimized for x86-64-v3)
2. Upload to all configured Vultr servers
3. Zero-downtime restart with health checks
4. Auto-rollback on failure

---

## Prerequisites

- Vultr account with bare metal server provisioned
- Ubuntu 22.04/24.04 or Debian 12
- SSH access to the server

## Quick Start

### 1. Clone and Setup

```bash
# SSH into your Vultr server
ssh root@YOUR_VULTR_IP

# Clone Oxidize
git clone https://github.com/gagansuie/oxidize.git /opt/oxidize
cd /opt/oxidize

# Run initial setup (hugepages, VFIO, dependencies)
sudo ./scripts/vultr-setup.sh
```

**If IOMMU was configured, reboot:**
```bash
sudo reboot
```

### 2. Deploy Server (FLASH Required)

```bash
# Full deployment (build + install + start)
sudo ./scripts/vultr-deploy.sh
```

Server will be running on port 51820 (OxTunnel/UDP), with FLASH AF_XDP required.

### 3. Kernel Bypass

AF_XDP kernel bypass is **required** on Linux relay servers. If AF_XDP cannot initialize,
the server exits with an error. Requires Linux kernel 5.4+ with XDP support.

## Server Management

```bash
# Check status
systemctl status oxidize-server

# View logs
journalctl -u oxidize-server -f

# Restart
sudo systemctl restart oxidize-server

# Health check
curl http://localhost:9090/health

# Metrics
curl http://localhost:9090/metrics
```

## Configuration

Config file: `/etc/oxidize/server.toml`

```bash
# Edit config
sudo nano /etc/oxidize/server.toml

# Restart to apply changes
sudo systemctl restart oxidize-server
```

## TLS Certificates

### Self-Signed (Development)
```bash
sudo ./scripts/vultr-deploy.sh --tls
```

### Let's Encrypt (Production)
```bash
sudo ./scripts/vultr-deploy.sh --tls your-domain.com
```

## Firewall

The deployment script configures firewall automatically. Manual setup:

```bash
# UFW
sudo ufw allow 51820/udp
sudo ufw allow 9090/tcp

# Or iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
```

## Update Client DNS

After deployment, update your client to connect to the Vultr server:

```bash
# In client config or environment
OXIDIZE_SERVER=YOUR_VULTR_IP:51820
```

Or update relay address in the Oxidize app settings.

## Monitoring

### Prometheus Metrics
```
http://YOUR_VULTR_IP:9090/metrics
```

### Key Metrics
- `oxidize_active_connections` - Current connections
- `oxidize_bytes_rx_total` - Total bytes received
- `oxidize_bytes_tx_total` - Total bytes sent
- `oxidize_latency_us` - Packet latency in microseconds

## Troubleshooting

### Server won't start
```bash
journalctl -u oxidize-server -n 50 --no-pager
```

### Port already in use
```bash
sudo lsof -i :51820
sudo kill -9 <PID>
```

### Performance issues
```bash
# Check hugepages
cat /proc/meminfo | grep Huge

# Check CPU governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Set to performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Scripts Reference

| Script | Purpose |
|--------|---------|
| `vultr-setup.sh` | Initial bare metal setup (hugepages, VFIO, tuning) |
| `vultr-deploy.sh` | Build, install, and manage Oxidize server |

## Scaling

### Vertical Scaling (More Power)

Upgrade to a larger Vultr plan via dashboard or API:

| Plan | CPUs | RAM | Price | Use Case |
|------|------|-----|-------|----------|
| `vbm-4c-32gb` | 4 | 32GB | $120/mo | Current (1-500 users) |
| `vbm-6c-32gb` | 6 | 32GB | $185/mo | 500-2000 users |
| `vbm-8c-128gb` | 8 | 128GB | $350/mo | 2000-5000 users |
| `vbm-24c-256gb` | 24 | 256GB | $725/mo | 5000+ users |

### Horizontal Scaling (More Servers)

Add regional servers for lower latency and higher capacity:

1. **Provision new server** (same plan, different region)
2. **Run setup scripts** on new server
3. **Add GitHub secret** `VULTR_HOST_<REGION>` (e.g., `VULTR_HOST_WEST`)
4. **Update workflow matrix** in `.github/workflows/release.yml`:

```yaml
strategy:
  matrix:
    server: [PRIMARY, WEST, EU]  # Add new regions here
```

5. **Update Cloudflare** with GeoDNS or load balancer

### DNS Load Balancing (Cloudflare)

For multi-region, server discovery is handled by the `/api/servers` endpoint:

```
/api/servers returns:
  ├── relay-chi-1 (91.242.214.137) - Chicago
  ├── relay-lax-1 (x.x.x.x) - Los Angeles  
  └── relay-ams-1 (x.x.x.x) - Amsterdam
```

Configure in Cloudflare → Traffic → Load Balancing.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Vultr Bare Metal                        │
│                 Chicago (PRIMARY)                       │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐            │
│  │ Management NIC  │    │  Data NIC       │            │
│  │ (eth0 - SSH)    │    │ (eth1 - 10Gbps) │            │
│  └────────┬────────┘    └────────┬────────┘            │
│           │                      │                      │
│  ┌────────▼──────────────────────▼────────┐            │
│  │           Oxidize Server               │            │
│  │  ┌─────────────────────────────────┐   │            │
│  │  │ OxTunnel/UDP :51820             │   │            │
│  │  │ ROHC + LZ4 + FEC + ML           │   │            │
│  │  └─────────────────────────────────┘   │            │
│  │  ┌─────────────────────────────────┐   │            │
│  │  │ Metrics :9090                   │   │            │
│  │  └─────────────────────────────────┘   │            │
│  └────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
```
