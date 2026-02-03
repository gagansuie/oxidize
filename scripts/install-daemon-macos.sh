#!/bin/bash
set -e

# Oxidize Daemon Installer for macOS
# This script installs the oxidize-daemon as a privileged helper
# with launchd (TUN-only capture/injection path)
# Run with sudo

DAEMON_BIN="/usr/local/bin/oxidize-daemon"
LAUNCHD_PLIST="/Library/LaunchDaemons/sh.oxd.oxidize-daemon.plist"
RUN_DIR="/var/run/oxidize"
CONFIG_DIR="/etc/oxidize"

echo "╔══════════════════════════════════════╗"
echo "║   Oxidize Daemon Installer (macOS)   ║"
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

echo "→ Found daemon binary: $SOURCE_BIN"

# Stop existing daemon if running
echo "→ Checking for existing daemon..."
if launchctl list | grep -q "sh.oxd.oxidize-daemon"; then
    echo "  Stopping existing daemon..."
    launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
    sleep 1
fi

# Install daemon binary
echo "→ Installing daemon binary..."
cp "$SOURCE_BIN" "$DAEMON_BIN"
chmod 755 "$DAEMON_BIN"
chown root:wheel "$DAEMON_BIN"

# Create directories
echo "→ Creating directories..."
mkdir -p "$RUN_DIR"
mkdir -p "$CONFIG_DIR"
chmod 755 "$RUN_DIR"
chmod 755 "$CONFIG_DIR"

# Create launchd plist for the daemon
echo "→ Installing launchd service..."
cat > "$LAUNCHD_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>sh.oxd.oxidize-daemon</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/oxidize-daemon</string>
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
    
    <!-- Security: Run as root for packet capture capabilities -->
    <key>UserName</key>
    <string>root</string>
    
    <key>GroupName</key>
    <string>wheel</string>
    
</dict>
</plist>
EOF

chmod 644 "$LAUNCHD_PLIST"
chown root:wheel "$LAUNCHD_PLIST"

# Load the launchd service
echo "→ Loading launchd service..."
launchctl load "$LAUNCHD_PLIST"

# Wait a moment and check status
sleep 2
if launchctl list | grep -q "sh.oxd.oxidize-daemon"; then
    echo ""
    echo "✅ Oxidize daemon installed and running!"
else
    echo ""
    echo "⚠ Service installed but may not be running. Check logs for details."
fi

echo ""
echo "Privileges configured at install-time:"
echo "  • launchd service runs with root privileges"
echo "  • Automatic startup on boot"
echo ""
echo "Commands:"
echo "  sudo launchctl list | grep oxidize     - Check status"
echo "  sudo launchctl unload $LAUNCHD_PLIST   - Stop daemon"
echo "  tail -f /var/log/oxidize-daemon.log   - View logs"
echo ""
