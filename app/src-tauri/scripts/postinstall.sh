#!/bin/bash
# Post-install script for Oxidize
# This runs after .deb/.rpm package installation

set -e

DAEMON_BIN="/usr/bin/oxidize-daemon"
SERVICE_FILE="/etc/systemd/system/oxidize-daemon.service"
RUN_DIR="/var/run/oxidize"

echo "Setting up Oxidize daemon..."

# Create run directory
mkdir -p "$RUN_DIR"
chmod 755 "$RUN_DIR"

# Install systemd service if daemon binary exists
if [ -f "$DAEMON_BIN" ]; then
    cat > "$SERVICE_FILE" << 'EOF'
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

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable oxidize-daemon
    systemctl start oxidize-daemon || true
    
    echo "✅ Oxidize daemon installed and started"
else
    echo "⚠️  Daemon binary not found at $DAEMON_BIN"
fi
