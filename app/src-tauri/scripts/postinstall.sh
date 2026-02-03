#!/bin/bash
# Post-install script for Oxidize (Linux)
# This runs after .deb/.rpm package installation
# CRITICAL: This script MUST exit 0 or dpkg fails with code 100

# Log everything for debugging
LOG_FILE="/tmp/oxidize-postinstall.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== Oxidize postinstall started at $(date) ==="
echo "Running as user: $(whoami)"
echo "PWD: $(pwd)"

DAEMON_BIN="/usr/bin/oxidize-daemon"
SERVICE_FILE="/etc/systemd/system/oxidize-daemon.service"
RUN_DIR="/var/run/oxidize"
CONFIG_DIR="/etc/oxidize"

echo "Setting up Oxidize daemon..."

# Create directories
mkdir -p "$RUN_DIR" 2>/dev/null || true
mkdir -p "$CONFIG_DIR" 2>/dev/null || true
chmod 755 "$RUN_DIR" 2>/dev/null || true
chmod 755 "$CONFIG_DIR" 2>/dev/null || true

# Create dedicated user for the daemon (optional)
id -u oxidize >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin oxidize 2>/dev/null || true
chown oxidize:oxidize "$RUN_DIR" 2>/dev/null || true

# Ensure daemon is executable
[ -f "$DAEMON_BIN" ] && chmod +x "$DAEMON_BIN" 2>/dev/null || true

# Set network capabilities if setcap exists (TUN requires CAP_NET_ADMIN)
command -v setcap >/dev/null 2>&1 && setcap 'cap_net_admin+eip' "$DAEMON_BIN" 2>/dev/null || true

# Create systemd service
cat > "$SERVICE_FILE" 2>/dev/null << 'EOF' || true
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/oxidize-daemon
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
PrivateTmp=true
ReadWritePaths=/var/run/oxidize

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service if systemctl exists
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable oxidize-daemon 2>/dev/null || true
    systemctl start oxidize-daemon 2>/dev/null || true
fi

echo "Oxidize daemon setup complete"

# CRITICAL: Always exit 0 to prevent dpkg failure
exit 0
