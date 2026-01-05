# Deploy Oxidize to Oracle Cloud Free Tier

Complete guide to deploying your relay on Oracle Cloud's Always Free tier.

## What You Get (FREE Forever)

- **4 ARM CPUs** (Ampere A1)
- **24GB RAM**
- **200GB storage**
- **10TB bandwidth/month**
- **Public IPv4 address**

Perfect for running Oxidize 24/7 at no cost.

## Prerequisites

1. Oracle Cloud account (no credit card required for free tier)
2. SSH key pair
3. 15 minutes

## Step 1: Create VM Instance

### Create Instance
1. Go to Oracle Cloud Console
2. Navigate to **Compute** → **Instances**
3. Click **Create Instance**

### Configure Instance
```
Name: oxidize-relay
Image: Ubuntu 22.04 Minimal (ARM)
Shape: VM.Standard.A1.Flex
  - OCPUs: 4
  - Memory: 24GB
Network: Create new VCN (default settings)
SSH Keys: Upload your public key
```

Click **Create** and wait ~2 minutes.

## Step 2: Configure Firewall

### Oracle Cloud Security List
1. Go to **Networking** → **Virtual Cloud Networks**
2. Click your VCN → **Security Lists** → **Default Security List**
3. Click **Add Ingress Rules**

Add these rules:
```
Source CIDR: 0.0.0.0/0
IP Protocol: UDP
Destination Port: 4433
Description: Oxidize QUIC

Source CIDR: 0.0.0.0/0
IP Protocol: UDP
Destination Port: 51820
Description: WireGuard (Mobile)

Source CIDR: 0.0.0.0/0
IP Protocol: TCP
Destination Port: 9090
Description: Prometheus Metrics

Source CIDR: 0.0.0.0/0
IP Protocol: TCP
Destination Port: 22
Description: SSH (already exists)
```

### Ubuntu Firewall (iptables)
SSH into your instance:
```bash
ssh ubuntu@YOUR_PUBLIC_IP
```

Configure firewall:
```bash
# Allow QUIC traffic
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 4433 -j ACCEPT

# Allow WireGuard (mobile clients)
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 51820 -j ACCEPT

# Allow Prometheus metrics
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 9090 -j ACCEPT

# Save rules
sudo netfilter-persistent save
```

## Step 3: Install Rust & Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build tools
sudo apt install -y build-essential pkg-config libssl-dev git curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify
rustc --version
```

## Step 4: Deploy Oxidize

### Clone & Build
```bash
# Clone repo
git clone https://github.com/YOUR_USERNAME/oxidize.git
cd oxidize

# Build release
cargo build --release

# This takes ~10-15 minutes on ARM
# Binary will be in target/release/oxidize-server
```

### Create Config
```bash
cat > /home/ubuntu/oxidize/production.toml <<EOF
max_connections = 10000
enable_compression = true
compression_threshold = 512
enable_tcp_acceleration = true
enable_deduplication = true
rate_limit_per_ip = 100
rate_limit_window_secs = 60

# WireGuard for mobile clients (optional)
# Generate keys with: ./target/release/oxidize-server --generate-wg-config
enable_wireguard = false
# wireguard_port = 51820
# wireguard_private_key = "YOUR_KEY_HERE"
EOF
```

### Test Run
```bash
./target/release/oxidize-server \
  --listen 0.0.0.0:4433 \
  --config production.toml \
  --metrics-addr 0.0.0.0:9090
```

Verify it starts. Press Ctrl+C to stop.

## Step 5: Setup Systemd Service

Create service file:
```bash
sudo nano /etc/systemd/system/oxidize.service
```

Paste this:
```ini
[Unit]
Description=Oxidize Network Relay
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/oxidize
ExecStart=/home/ubuntu/oxidize/target/release/oxidize-server \
  --listen 0.0.0.0:4433 \
  --config /home/ubuntu/oxidize/production.toml \
  --metrics-addr 0.0.0.0:9090
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable & start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable oxidize
sudo systemctl start oxidize

# Check status
sudo systemctl status oxidize

# View logs
sudo journalctl -u oxidize -f
```

## Step 6: Setup Monitoring (Optional)

### Install Prometheus
```bash
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-arm64.tar.gz
tar xvf prometheus-2.45.0.linux-arm64.tar.gz
sudo mv prometheus-2.45.0.linux-arm64 /opt/prometheus
```

Create Prometheus config:
```bash
sudo nano /opt/prometheus/prometheus.yml
```

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'oxidize'
    static_configs:
      - targets: ['localhost:9090']
```

Create Prometheus service:
```bash
sudo nano /etc/systemd/system/prometheus.service
```

```ini
[Unit]
Description=Prometheus
After=network.target

[Service]
User=ubuntu
ExecStart=/opt/prometheus/prometheus \
  --config.file=/opt/prometheus/prometheus.yml \
  --storage.tsdb.path=/opt/prometheus/data \
  --web.listen-address=:9091
Restart=always

[Install]
WantedBy=multi-user.target
```

Start Prometheus:
```bash
sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus
```

Access metrics: `http://YOUR_IP:9091`

## Step 7: DNS Setup

Point your domain to the VM:
```
oxidize.yourdomain.com → YOUR_ORACLE_IP
```

Update client connections:
```bash
./oxidize-client --server oxidize.yourdomain.com:4433
```

## Maintenance Commands

```bash
# View logs
sudo journalctl -u oxidize -f

# Restart service
sudo systemctl restart oxidize

# Stop service
sudo systemctl stop oxidize

# Update binary
cd /home/ubuntu/oxidize
git pull
cargo build --release
sudo systemctl restart oxidize

# Check metrics
curl http://localhost:9090/metrics
```

## Performance Tuning

### Increase file limits
```bash
sudo nano /etc/security/limits.conf
```

Add:
```
ubuntu soft nofile 65536
ubuntu hard nofile 65536
```

### Kernel tuning
```bash
sudo nano /etc/sysctl.conf
```

Add:
```
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 65536 131072 262144
```

Apply:
```bash
sudo sysctl -p
```

## Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u oxidize -n 50

# Check if port is in use
sudo netstat -tulpn | grep 4433

# Test binary manually
cd /home/ubuntu/oxidize
./target/release/oxidize-server --listen 0.0.0.0:4433
```

### Can't connect from client
```bash
# Check firewall
sudo iptables -L -n

# Check if service is listening
sudo netstat -tulpn | grep 4433

# Test from server
curl http://localhost:9090/metrics
```

### High memory usage
```bash
# Check metrics
curl http://localhost:9090/metrics | grep oxidize_relay_connections

# Restart if needed
sudo systemctl restart oxidize
```

## Security Best Practices

1. **Keep system updated**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Use SSH keys only** (disable password auth)
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Set: PasswordAuthentication no
   sudo systemctl restart sshd
   ```

3. **Setup fail2ban**
   ```bash
   sudo apt install fail2ban -y
   sudo systemctl enable fail2ban
   ```

4. **Monitor with Prometheus alerts** (see Prometheus setup)

## Cost Monitoring

Even though it's free, monitor usage:
```bash
# Bandwidth usage
sudo vnstat

# CPU/Memory
htop

# Disk usage
df -h
```

Stay under 10TB/month bandwidth to remain free.

## Next Steps

- ✅ Setup automated backups (Oracle Cloud free)
- ✅ Configure log rotation
- ✅ Setup Grafana for visualization
- ✅ Add health checks
- ✅ Document disaster recovery

Your relay is now running 24/7 on Oracle Cloud for **$0/month**! 🎉
