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

## Quick Start (Terraform + Ansible)

Infrastructure is managed with **Terraform** (provisioning) and **Ansible** (configuration).

### 1. Add Server to Terraform

Edit `infrastructure/terraform/servers.auto.tfvars`:

```hcl
servers = [
  {
    name    = "chicago-1"
    region  = "chicago"
    site    = "chi"
    plan    = "m4-metal-small"
    os      = "ubuntu_22_04_x64_lts"
    enabled = true
  },

  # Add more servers:
  {
    name    = "chicago-2"
    region  = "chicago"
    site    = "chi"
    plan    = "m4-metal-small"
    os      = "ubuntu_22_04_x64_lts"
    enabled = true
  },

  {
    name    = "frankfurt-1"
    region  = "frankfurt"
    site    = "fra"
    plan    = "m4-metal-small"
    os      = "ubuntu_22_04_x64_lts"
    enabled = true
  },
]
```

**Site codes:** `chi` (Chicago), `nyc` (New York), `fra` (Frankfurt), `ams` (Amsterdam), `syd` (Sydney)

### 2. Add GitHub Secrets

Go to: `github.com/gagansuie/oxidize` → Settings → Secrets → Actions

| Secret | Value |
|--------|-------|
| `LATITUDE_API_KEY` | API key (from [dashboard](https://www.latitude.sh/dashboard/account/api-keys)) |
| `LATITUDE_SSH_KEY` | SSH private key (`~/.ssh/latitude_oxidize`) |
| `TF_API_TOKEN` | Terraform Cloud API token (see below) |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with DNS edit permissions (see below) |

### Cloudflare API Token (one-time)

1. Go to [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create Token → **Edit zone DNS** template
3. Zone Resources: Include → Specific zone → `oxd.sh`
4. Create Token → Copy and add as `CLOUDFLARE_API_TOKEN` secret

### Terraform Cloud Setup (one-time)

1. Create account at [app.terraform.io](https://app.terraform.io)
2. Create organization: `gagansuie`
3. Create workspace: `oxidize-infrastructure` (CLI-driven)
4. In workspace settings → General → Execution Mode: **Local**
5. Go to User Settings → Tokens → Create API token
6. Add token as `TF_API_TOKEN` secret in GitHub

### 3. Push to Main

The workflow automatically:

1. **Terraform:** Provision servers on Latitude.sh
2. **Ansible Setup:** Install DPDK, hugepages, UFW, system tuning
3. **Ansible Deploy:** Upload binary, start service, health check

### 4. Workflow Options

```bash
# Full deploy (provision + setup + deploy)
gh workflow run deploy.yml

# Just deploy binary (servers already configured)
gh workflow run deploy.yml -f action=deploy

# Run full setup on existing servers
gh workflow run deploy.yml -f action=setup

# Provision new servers only
gh workflow run deploy.yml -f action=provision

# Destroy all servers (careful!)
gh workflow run deploy.yml -f action=destroy
```

### 5. Local Development

```bash
cd infrastructure/terraform
export TF_VAR_latitude_api_key="your-api-key"
terraform init
terraform plan
terraform apply

cd ../ansible
ansible-playbook -i inventory/terraform.py playbooks/setup.yml
ansible-playbook -i inventory/terraform.py playbooks/deploy.yml
```

### 6. Check Status

```bash
ssh ubuntu@SERVER_IP

systemctl status oxidize        # Service status
journalctl -u oxidize -f        # Logs
dpdk-devbind.py --status-dev net  # DPDK NIC status
ss -ulnp | grep 4433            # Port check
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Terraform     │ ──▶ │     Ansible     │ ──▶ │    Oxidize      │
│  (Provision)    │     │   (Configure)   │     │   (Running)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
  - Create servers       - Install DPDK         - QUIC relay
  - Manage state         - Configure hugepages  - Kernel bypass
  - Output IPs           - Setup UFW            - Health checks
```

**Ansible Roles:**
- `common` - Base packages, UFW, system tuning
- `dpdk` - IOMMU, hugepages, DPDK install, NIC binding
- `oxidize` - TLS certs, config, systemd service, deployment

## Manual Deployment (Optional)

For manual setup without GitHub Actions:

```bash
ssh ubuntu@YOUR_SERVER_IP

git clone https://github.com/gagansuie/oxidize.git
cd oxidize

# Full setup + deploy
sudo ./scripts/latitude/latitude-setup.sh
sudo reboot
sudo ./scripts/dpdk/install-dpdk.sh
sudo ./scripts/dpdk/setup-hugepages.sh
sudo ./scripts/dpdk/bind-nic.sh <data_nic>
sudo ./scripts/latitude/latitude-deploy.sh --full
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

## DNS Configuration (Cloudflare)

After deployment, you need to add DNS records for your relay domain.

### Single Server

Add these records to Cloudflare for `oxd.sh`:

| Type | Name | Value | Proxy |
|------|------|-------|-------|
| A | relay | `<IPv4 from Terraform output>` | DNS only (gray cloud) |
| AAAA | relay | `<IPv6 from Terraform output>` | DNS only (gray cloud) |

**Important:** Proxy must be OFF (gray cloud) for QUIC/UDP traffic.

### Multiple Servers (Regional Subdomains)

For multi-region deployments, use regional subdomains:

| Type | Name | Value | Description |
|------|------|-------|-------------|
| A | chi.relay | `<Chicago IPv4>` | Chicago relay |
| AAAA | chi.relay | `<Chicago IPv6>` | Chicago relay |
| A | nyc.relay | `<New York IPv4>` | New York relay |
| A | fra.relay | `<Frankfurt IPv4>` | Frankfurt relay |

**Client configuration:** Clients can specify which relay to use or auto-select nearest.

### Getting Server IPs

After Terraform runs, get IPs from:

```bash
# Via Terraform
cd infrastructure/terraform
terraform output server_ips

# Via Latitude API
curl -s "https://api.latitude.sh/servers" \
  -H "Authorization: Bearer $LATITUDE_API_KEY" | \
  jq '.data[] | {hostname: .hostname, ipv4: .primary_ipv4, ipv6: .primary_ipv6}'

# Or check GitHub Actions workflow summary
```

### DNS Propagation

After adding records, verify propagation:

```bash
dig relay.oxd.sh +short
dig chi.relay.oxd.sh +short
```

## Scaling

### Vertical (Same Server)

- Upgrade to larger Latitude.sh plan
- Increase worker threads in config

### Horizontal (Multiple Servers)

Deploy additional servers in different locations:

| Location | Subdomain | Latency Target |
|----------|-----------|----------------|
| Chicago | chi.relay.oxd.sh | US Midwest |
| New York | nyc.relay.oxd.sh | US East |
| Los Angeles | lax.relay.oxd.sh | US West |
| Frankfurt | fra.relay.oxd.sh | Europe |

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
