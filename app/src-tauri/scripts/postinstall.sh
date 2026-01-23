#!/bin/bash
# Post-install script for Oxidize (Linux)
# This runs after .deb/.rpm package installation
# Sets up daemon with proper capabilities for packet capture

# Do NOT use set -e - we handle errors gracefully

DAEMON_BIN="/usr/bin/oxidize-daemon"
SERVICE_FILE="/etc/systemd/system/oxidize-daemon.service"
RUN_DIR="/var/run/oxidize"
CONFIG_DIR="/etc/oxidize"

echo "Setting up Oxidize daemon..."

# Create directories
mkdir -p "$RUN_DIR" || true
mkdir -p "$CONFIG_DIR" || true
chmod 755 "$RUN_DIR" 2>/dev/null || true
chmod 755 "$CONFIG_DIR" 2>/dev/null || true

# Create dedicated user for the daemon (optional, daemon runs as root for iptables)
if ! id -u oxidize &>/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin oxidize 2>/dev/null || true
fi
chown oxidize:oxidize "$RUN_DIR" 2>/dev/null || true

# Tauri bundles the daemon directly to /usr/bin/oxidize-daemon
# Just ensure it's executable
if [ -f "$DAEMON_BIN" ]; then
    chmod +x "$DAEMON_BIN" 2>/dev/null || true
    echo "Found daemon at $DAEMON_BIN"
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

    # Create systemd service (runs as root for NFQUEUE/iptables access)
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/etc/oxidize/nfqueue-rules.sh
ExecStart=/usr/bin/oxidize-daemon
ExecStopPost=/sbin/iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
PrivateTmp=true
ReadWritePaths=/var/run/oxidize

[Install]
WantedBy=multi-user.target
EOF

    if command -v systemctl &> /dev/null; then
        systemctl daemon-reload || true
        systemctl enable oxidize-daemon || true
        systemctl start oxidize-daemon || true
    else
        echo "⚠️  systemctl not available; skipping service enable/start"
    fi

    echo "✅ Oxidize daemon installed with packet capture capabilities"
else
    echo "⚠️  Daemon binary not found at $DAEMON_BIN"
fi
