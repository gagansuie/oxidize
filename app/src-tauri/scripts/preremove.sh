#!/bin/bash
# Pre-remove script for Oxidize (Linux)
# This runs before .deb/.rpm package uninstallation
# Stops and cleans up the daemon service

set -e

SERVICE_NAME="oxidize-daemon"
CONFIG_DIR="/etc/oxidize"

echo "Stopping Oxidize daemon..."

# Stop and disable systemd service
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME" || true
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME" || true
fi

# Remove iptables rules
iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true

# Remove service file
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload || true

# Remove config directory
rm -rf "$CONFIG_DIR"

# Remove run directory
rm -rf "/var/run/oxidize"

# Optionally remove the oxidize user (commented out to preserve data)
# userdel oxidize 2>/dev/null || true

echo "✅ Oxidize daemon stopped and cleaned up"
