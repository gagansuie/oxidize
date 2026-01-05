# Oracle Cloud Deployment - Quick Start (v0.0.1)

Deploy Oxidize to Oracle Cloud Free Tier in **5 commands**.

## Prerequisites

- Oracle Cloud account (free tier)
- SSH access to your Oracle VM (Ubuntu 22.04 ARM)
- 15 minutes

## One-Line Deploy

SSH into your Oracle VM and run:

```bash
# Clone and setup
git clone https://github.com/YOUR_USERNAME/oxidize.git && cd oxidize
chmod +x deploy-oracle.sh
./deploy-oracle.sh
```

The script will:
1. ✅ Update system packages
2. ✅ Install dependencies (Rust, build tools)
3. ✅ Configure firewall (QUIC, WireGuard, Prometheus)
4. ✅ Build release binaries (~10 min)
5. ✅ Create production config

## Setup Systemd Service

```bash
# Install service
sudo cp oxidize.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable oxidize
sudo systemctl start oxidize

# Check status
sudo systemctl status oxidize

# View logs
sudo journalctl -u oxidize -f
```

## Enable WireGuard (Mobile Support)

```bash
# Generate WireGuard keys
./target/release/oxidize-server --generate-wg-config --wg-endpoint $(curl -s ifconfig.me):51820

# Update production.toml with the generated keys
nano production.toml
# Set:
#   enable_wireguard = true
#   wireguard_private_key = "YOUR_GENERATED_KEY"

# Restart service
sudo systemctl restart oxidize
```

Scan the QR code with WireGuard app on mobile!

## Verify Deployment

```bash
# Check service is running
sudo systemctl status oxidize

# Check metrics
curl http://localhost:9090/metrics

# Check from outside
curl http://$(curl -s ifconfig.me):9090/metrics

# View active connections
sudo journalctl -u oxidize -f
```

## Oracle Cloud Firewall (One-Time Setup)

In Oracle Cloud Console:
1. Go to **Networking** → **Virtual Cloud Networks**
2. Click your VCN → **Security Lists** → **Default Security List**
3. Click **Add Ingress Rules**

Add:
```
UDP 4433  - Oxidize QUIC
UDP 51820 - WireGuard (mobile)
TCP 9090  - Prometheus metrics
```

## Client Connection

From your laptop/desktop:

```bash
# Download client binary from your server
scp ubuntu@YOUR_IP:/home/ubuntu/oxidize/target/release/oxidize-client .

# Connect
./oxidize-client --server YOUR_IP:4433
```

From mobile (with WireGuard):
1. Install WireGuard app
2. Scan QR code from server
3. Toggle connection on
4. ✅ Connected!

## Performance Tuning (Optional)

```bash
# Increase file limits
echo "ubuntu soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "ubuntu hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Kernel tuning
sudo tee -a /etc/sysctl.conf <<EOF
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.ip_forward = 1
EOF

sudo sysctl -p
```

## Common Commands

```bash
# Restart service
sudo systemctl restart oxidize

# Stop service
sudo systemctl stop oxidize

# Update to latest version
cd /home/ubuntu/oxidize
git pull
cargo build --release
sudo systemctl restart oxidize

# View resource usage
htop

# Check bandwidth usage
sudo apt install vnstat -y
vnstat
```

## What You're Running

**Server:**
- **Version:** v0.0.1
- **Ports:** 4433 (QUIC), 51820 (WireGuard), 9090 (metrics)
- **Resources:** 4 ARM CPUs, 24GB RAM (Oracle Free Tier)
- **Features:** BBR, FEC, Protocol Detection, WireGuard, Prometheus

**Cost:** $0/month (Oracle Always Free)

## Troubleshooting

**Service won't start:**
```bash
sudo journalctl -u oxidize -n 50
sudo netstat -tulpn | grep 4433
```

**Can't connect:**
```bash
# Check firewall
sudo iptables -L -n
# Test locally
curl http://localhost:9090/metrics
```

**High memory:**
```bash
curl http://localhost:9090/metrics | grep connections
sudo systemctl restart oxidize
```

## Next Steps

- [Mobile Setup Guide](docs/MOBILE_SETUP.md)
- [Full Deployment Guide](docs/DEPLOY_ORACLE.md)
- [Performance Monitoring](README.md#monitoring)

Your relay is now live on Oracle Cloud! 🚀
