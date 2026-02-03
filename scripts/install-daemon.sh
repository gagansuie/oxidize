#!/bin/bash
set -e

# Oxidize Daemon Installer for Linux
# This script installs the oxidize-daemon as a systemd service
# TUN-only capture/injection path

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
# This allows TUN access without running as root
echo "→ Setting network capabilities (CAP_NET_ADMIN)..."
if command -v setcap &> /dev/null; then
    setcap 'cap_net_admin+eip' "$DAEMON_BIN"
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

echo "→ Installing systemd service..."
cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/oxidize-daemon
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

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
echo "Configuration:"
echo "  • Runs as root for TUN access (CAP_NET_ADMIN)"
echo ""
echo "Commands:"
echo "  systemctl status oxidize-daemon  - Check status"
echo "  systemctl stop oxidize-daemon    - Stop daemon"
echo "  journalctl -u oxidize-daemon -f  - View logs"
