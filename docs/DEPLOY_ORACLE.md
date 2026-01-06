# Deploy to Oracle Cloud (Free Tier)

Deploy your Oxidize relay server on Oracle Cloud's **Always Free** tier.

## Free Tier Specs

| Resource | Amount |
|----------|--------|
| ARM CPUs | 4 (Ampere A1) |
| RAM | 24GB |
| Storage | 200GB |
| Bandwidth | 10TB/month |
| Cost | **$0 forever** |

## Quick Deploy (Copy-Paste)

### 1. Create Oracle VM

1. [Sign up for Oracle Cloud](https://cloud.oracle.com) (no credit card required)
2. **Compute** → **Instances** → **Create Instance**
3. Configure:
   - **Name:** `oxidize-relay`
   - **Image:** Ubuntu 22.04 (ARM)
   - **Shape:** VM.Standard.A1.Flex (4 OCPU, 24GB)
   - **SSH Key:** Upload your public key
4. Click **Create** (wait ~2 min)

### 2. Open Firewall

**Oracle Console:** Networking → VCN → Security Lists → Add Ingress Rule:
```
Protocol: UDP    Port: 4433    Source: 0.0.0.0/0
```

**On the VM:**
```bash
ssh ubuntu@YOUR_PUBLIC_IP

# Open port
sudo iptables -I INPUT 6 -p udp --dport 4433 -j ACCEPT
sudo netfilter-persistent save
```

### 3. Install & Run

```bash
# Install dependencies
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Clone and build (~10 min on ARM)
git clone https://github.com/gagansuie/oxidize.git
cd oxidize
cargo build --release

# Test run
./target/release/oxidize-server --listen 0.0.0.0:4433
```

### 4. Setup Auto-Start Service

```bash
sudo tee /etc/systemd/system/oxidize.service > /dev/null <<EOF
[Unit]
Description=Oxidize Relay
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/oxidize
ExecStart=/home/ubuntu/oxidize/target/release/oxidize-server --listen 0.0.0.0:4433
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now oxidize
```

### 5. Verify

```bash
# Check status
sudo systemctl status oxidize

# View logs
sudo journalctl -u oxidize -f

# Test from your local machine
./oxidize-client --server YOUR_ORACLE_IP:4433 --speedtest
```

**Done!** Your relay is running.

---

## Performance Tuning (Optional)

```bash
# Increase file limits
echo "ubuntu soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "ubuntu hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# UDP buffer tuning
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Common Commands

```bash
sudo systemctl status oxidize    # Status
sudo systemctl restart oxidize   # Restart
sudo journalctl -u oxidize -f    # Logs

# Update
cd ~/oxidize && git pull && cargo build --release && sudo systemctl restart oxidize
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Can't connect | Check: `sudo iptables -L -n \| grep 4433` |
| Service won't start | Check: `sudo journalctl -u oxidize -n 50` |
| Port in use | Check: `sudo netstat -tulpn \| grep 4433` |

## Security Checklist

- [ ] Disable password SSH: `PasswordAuthentication no` in `/etc/ssh/sshd_config`
- [ ] Install fail2ban: `sudo apt install fail2ban -y`
- [ ] Keep updated: `sudo apt update && sudo apt upgrade -y`

---

**Your relay is now running 24/7 for $0/month** 🎉
