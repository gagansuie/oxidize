#!/bin/bash
# Post-install script for Oxidize (macOS)
# This runs after .dmg/.pkg installation
# Sets up daemon with PF rules for packet capture

set -e

DAEMON_BIN="/Applications/Oxidize.app/Contents/MacOS/oxidize-daemon"
ALT_DAEMON_BIN="/usr/local/bin/oxidize-daemon"
LAUNCHD_PLIST="/Library/LaunchDaemons/sh.oxd.oxidize-daemon.plist"
PF_ANCHOR="/etc/pf.anchors/sh.oxd.oxidize"
RUN_DIR="/var/run/oxidize"
CONFIG_DIR="/etc/oxidize"

echo "Setting up Oxidize daemon..."

# Create directories
mkdir -p "$RUN_DIR"
mkdir -p "$CONFIG_DIR"
chmod 755 "$RUN_DIR"
chmod 755 "$CONFIG_DIR"

# Find daemon binary
if [ -f "$DAEMON_BIN" ]; then
    ACTUAL_DAEMON="$DAEMON_BIN"
elif [ -f "$ALT_DAEMON_BIN" ]; then
    ACTUAL_DAEMON="$ALT_DAEMON_BIN"
else
    echo "⚠️  Daemon binary not found"
    exit 0
fi

# Stop existing daemon if running
launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true

# Create PF anchor for divert rules
cat > "$PF_ANCHOR" << 'EOF'
# Oxidize PF anchor - divert UDP traffic for relay
pass out proto udp from any to any divert-to 127.0.0.1 port 8668
EOF
chmod 644 "$PF_ANCHOR"
chown root:wheel "$PF_ANCHOR"

# Add anchor to main PF config if not present
PF_CONF="/etc/pf.conf"
if ! grep -q "sh.oxd.oxidize" "$PF_CONF" 2>/dev/null; then
    cp "$PF_CONF" "$PF_CONF.oxidize-backup" 2>/dev/null || true
    cat >> "$PF_CONF" << 'EOF'

# Oxidize network relay anchor
anchor "sh.oxd.oxidize"
load anchor "sh.oxd.oxidize" from "/etc/pf.anchors/sh.oxd.oxidize"
EOF
fi

# Create launchd plist
cat > "$LAUNCHD_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>sh.oxd.oxidize-daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>pfctl -e 2>/dev/null; pfctl -f /etc/pf.conf 2>/dev/null; exec $ACTUAL_DAEMON</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/oxidize-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/oxidize-daemon.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
</dict>
</plist>
EOF
chmod 644 "$LAUNCHD_PLIST"
chown root:wheel "$LAUNCHD_PLIST"

# Enable PF and load service
pfctl -e 2>/dev/null || true
pfctl -f /etc/pf.conf 2>/dev/null || true
launchctl load "$LAUNCHD_PLIST" 2>/dev/null || true

echo "✅ Oxidize daemon installed with packet capture capabilities"
