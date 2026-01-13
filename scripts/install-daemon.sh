#!/bin/bash
set -e

# Oxidize Daemon Installer for Linux
# This script installs the oxidize-daemon with proper capabilities
# so it can capture packets without running as root at runtime

DAEMON_BIN="/usr/local/bin/oxidize-daemon"
SERVICE_FILE="/etc/systemd/system/oxidize-daemon.service"
RUN_DIR="/var/run/oxidize"

echo "╔══════════════════════════════════════╗"
echo "║   Oxidize Daemon Installer (Linux)   ║"
echo "╚══════════════════════════════════════╝"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Find the daemon binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_BIN=""

# Check common locations
for path in \
    "$SCRIPT_DIR/../target/release/oxidize-daemon" \
    "$SCRIPT_DIR/../daemon/target/release/oxidize-daemon" \
    "/tmp/oxidize-daemon" \
    "./oxidize-daemon"; do
    if [ -f "$path" ]; then
        SOURCE_BIN="$path"
        break
    fi
done

if [ -z "$SOURCE_BIN" ]; then
    echo "Error: oxidize-daemon binary not found"
    echo "Please build first: cargo build --release -p oxidize-daemon"
    exit 1
fi

echo "→ Installing daemon binary..."
cp "$SOURCE_BIN" "$DAEMON_BIN"
chmod 755 "$DAEMON_BIN"

# Grant network capabilities to the binary (install-time privilege)
# This allows packet capture without running as root
echo "→ Setting network capabilities (CAP_NET_ADMIN, CAP_NET_RAW)..."
if command -v setcap &> /dev/null; then
    setcap 'cap_net_admin,cap_net_raw+eip' "$DAEMON_BIN"
    echo "  ✓ Capabilities set - no runtime elevation needed"
else
    echo "  ⚠ setcap not found - install libcap2-bin"
    echo "  The daemon will need to run as root"
fi

echo "→ Creating run directory..."
mkdir -p "$RUN_DIR"
chmod 755 "$RUN_DIR"

# Create dedicated user for the daemon
echo "→ Creating oxidize system user..."
if ! id -u oxidize &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin oxidize
    echo "  ✓ User 'oxidize' created"
else
    echo "  ✓ User 'oxidize' already exists"
fi
chown oxidize:oxidize "$RUN_DIR"

echo "→ Setting up iptables NFQUEUE rules..."
# Create iptables rules file for persistence
mkdir -p /etc/oxidize
cat > /etc/oxidize/nfqueue-rules.sh << 'RULES'
#!/bin/bash
# Oxidize NFQUEUE iptables rules
# These are loaded at boot to enable packet capture

QUEUE_NUM=0

# Clear existing oxidize rules
iptables -D OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true

# Add NFQUEUE rule for outbound UDP
iptables -I OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass

echo "NFQUEUE rules applied (queue $QUEUE_NUM)"
RULES
chmod +x /etc/oxidize/nfqueue-rules.sh

echo "→ Installing systemd service..."
cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=oxidize
Group=oxidize
ExecStartPre=/etc/oxidize/nfqueue-rules.sh
ExecStart=/usr/local/bin/oxidize-daemon
ExecStopPost=/sbin/iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/run/oxidize

# Required capabilities (already set via setcap, but belt-and-suspenders)
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

echo "→ Reloading systemd..."
systemctl daemon-reload

echo "→ Enabling and starting service..."
systemctl enable oxidize-daemon
systemctl start oxidize-daemon

echo ""
echo "✅ Oxidize daemon installed and running!"
echo ""
echo "Privileges configured at install-time:"
echo "  • CAP_NET_ADMIN, CAP_NET_RAW capabilities set on binary"
echo "  • NFQUEUE iptables rules auto-configured"
echo "  • Runs as unprivileged 'oxidize' user"
echo ""
echo "Commands:"
echo "  systemctl status oxidize-daemon  - Check status"
echo "  systemctl stop oxidize-daemon    - Stop daemon"
echo "  journalctl -u oxidize-daemon -f  - View logs"
