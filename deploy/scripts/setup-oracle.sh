#!/bin/bash
set -e

echo "🚀 Oxidize Oracle Cloud Setup Script"
echo "===================================="
echo ""

# Check if running as ubuntu user
if [ "$USER" != "ubuntu" ]; then
    echo "❌ Please run as ubuntu user"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install dependencies
echo "📦 Installing build dependencies..."
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl \
    wget \
    netfilter-persistent \
    iptables-persistent

# Install Rust
if ! command -v rustc &> /dev/null; then
    echo "🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✅ Rust already installed"
fi

# Configure firewall
echo "🔥 Configuring firewall..."
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 4433 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 9090 -j ACCEPT
sudo netfilter-persistent save

# Clone or update repo
if [ ! -d "$HOME/oxidize" ]; then
    echo "📥 Cloning Oxidize repository..."
    echo "⚠️  Update the git URL in this script first!"
    # git clone https://github.com/YOUR_USERNAME/oxidize.git $HOME/oxidize
    echo "❌ Please clone the repo manually and run this script again"
    exit 1
else
    echo "✅ Oxidize directory exists"
    cd $HOME/oxidize
    echo "📥 Pulling latest changes..."
    git pull
fi

# Build
echo "🔨 Building Oxidize (this takes ~10-15 minutes on ARM)..."
cd $HOME/oxidize
cargo build --release

# Create production config
if [ ! -f "$HOME/oxidize/production.toml" ]; then
    echo "⚙️  Creating production config..."
    cp deploy/config/production.toml $HOME/oxidize/production.toml
fi

# Setup systemd service
echo "⚙️  Setting up systemd service..."
sudo cp deploy/systemd/oxidize.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable oxidize

# Kernel tuning
echo "⚡ Applying kernel tuning..."
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF

# Oxidize network tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 65536 131072 262144
EOF
sudo sysctl -p

# File limits
echo "⚡ Increasing file limits..."
sudo tee -a /etc/security/limits.conf > /dev/null <<EOF
ubuntu soft nofile 65536
ubuntu hard nofile 65536
EOF

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit production.toml if needed: nano ~/oxidize/production.toml"
echo "2. Start service: sudo systemctl start oxidize"
echo "3. Check status: sudo systemctl status oxidize"
echo "4. View logs: sudo journalctl -u oxidize -f"
echo ""
echo "Your relay will be accessible at: $(curl -s ifconfig.me):4433"
echo "Metrics available at: http://$(curl -s ifconfig.me):9090/metrics"
