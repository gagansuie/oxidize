#!/bin/bash
set -e

echo "=================================="
echo "Oxidize v0.0.1 - Oracle Cloud Setup"
echo "=================================="
echo ""

# Check if running on Ubuntu
if [ ! -f /etc/lsb-release ]; then
    echo "Error: This script is designed for Ubuntu"
    exit 1
fi

echo "[1/6] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo ""
echo "[2/6] Installing dependencies..."
sudo apt install -y build-essential pkg-config libssl-dev git curl netfilter-persistent

echo ""
echo "[3/6] Installing Rust (if not already installed)..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "Rust already installed: $(rustc --version)"
fi

echo ""
echo "[4/6] Configuring firewall..."
# Allow QUIC
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 4433 -j ACCEPT
# Allow WireGuard
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 51820 -j ACCEPT
# Allow Prometheus
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 9090 -j ACCEPT
# Save rules
sudo netfilter-persistent save

echo ""
echo "[5/6] Building Oxidize (this takes ~10 minutes on ARM)..."
cargo build --release

echo ""
echo "[6/6] Creating production config..."
cat > production.toml <<EOF
max_connections = 10000
enable_compression = true
compression_threshold = 512
enable_tcp_acceleration = true
enable_deduplication = true
rate_limit_per_ip = 100
rate_limit_window_secs = 60

# WireGuard for mobile clients
enable_wireguard = false
# wireguard_port = 51820
# wireguard_private_key = "YOUR_KEY_HERE"
EOF

echo ""
echo "=================================="
echo "✅ Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Test the server:"
echo "   ./target/release/oxidize-server --listen 0.0.0.0:4433 --config production.toml"
echo ""
echo "2. (Optional) Enable WireGuard for mobile:"
echo "   ./target/release/oxidize-server --generate-wg-config --wg-endpoint \$(curl -s ifconfig.me):51820"
echo "   # Then update production.toml with the generated keys"
echo ""
echo "3. Install as systemd service:"
echo "   sudo cp oxidize.service /etc/systemd/system/"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl enable oxidize"
echo "   sudo systemctl start oxidize"
echo ""
echo "4. Check logs:"
echo "   sudo journalctl -u oxidize -f"
echo ""
echo "5. Access metrics:"
echo "   curl http://\$(curl -s ifconfig.me):9090/metrics"
echo ""
