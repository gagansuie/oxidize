#!/bin/bash
# Post-install script for Oxidize (Linux)
# This runs after .deb/.rpm package installation
# Sets up daemon with proper capabilities for packet capture

set -e

DAEMON_BIN="/usr/bin/oxidize-daemon"
SERVICE_FILE="/etc/systemd/system/oxidize-daemon.service"
RUN_DIR="/var/run/oxidize"
CONFIG_DIR="/etc/oxidize"
# Tauri installs the app here, sidecar binaries are in the same directory
APP_DIR="/usr/lib/oxidize"

echo "Setting up Oxidize daemon..."

# Create directories
mkdir -p "$RUN_DIR"
mkdir -p "$CONFIG_DIR"
chmod 755 "$RUN_DIR"
chmod 755 "$CONFIG_DIR"

# Create dedicated user for the daemon
if ! id -u oxidize &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin oxidize 2>/dev/null || true
fi
chown oxidize:oxidize "$RUN_DIR" 2>/dev/null || true

# Find and copy the bundled daemon sidecar to /usr/bin
SIDECAR_DAEMON=$(find "$APP_DIR" -name "oxidize-daemon*" -type f 2>/dev/null | head -1)
if [ -n "$SIDECAR_DAEMON" ] && [ -f "$SIDECAR_DAEMON" ]; then
    echo "Found bundled daemon at: $SIDECAR_DAEMON"
    cp "$SIDECAR_DAEMON" "$DAEMON_BIN"
    chmod +x "$DAEMON_BIN"
    echo "Copied daemon to $DAEMON_BIN"
fi

# Install systemd service if daemon binary exists
if [ -f "$DAEMON_BIN" ]; then
    # Set network capabilities (allows packet capture without root)
    if command -v setcap &> /dev/null; then
        setcap 'cap_net_admin,cap_net_raw+eip' "$DAEMON_BIN" 2>/dev/null || true
    fi

    # Create iptables rules script
    cat > "$CONFIG_DIR/nfqueue-rules.sh" << 'RULES'
#!/bin/bash
QUEUE_NUM=0
iptables -D OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
iptables -I OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass
RULES
    chmod +x "$CONFIG_DIR/nfqueue-rules.sh"

    # Create systemd service
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
ExecStart=/usr/bin/oxidize-daemon
ExecStopPost=/sbin/iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/run/oxidize
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable oxidize-daemon
    systemctl start oxidize-daemon || true
    
    echo "✅ Oxidize daemon installed with packet capture capabilities"
else
    echo "⚠️  Daemon binary not found at $DAEMON_BIN"
fi
