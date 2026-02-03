#!/bin/bash
# Pre-remove script for Oxidize (Linux)
# This runs before .deb/.rpm package uninstallation
# CRITICAL: This script MUST exit 0 or dpkg fails with code 100

# Log everything for debugging
LOG_FILE="/tmp/oxidize-preremove.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== Oxidize preremove started at $(date) ==="
echo "Running as user: $(whoami)"

SERVICE_NAME="oxidize-daemon"
CONFIG_DIR="/etc/oxidize"

echo "Stopping Oxidize daemon..."

# Stop and disable systemd service
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
fi

# Remove files
rm -f "/etc/systemd/system/$SERVICE_NAME.service" 2>/dev/null || true
rm -f "/usr/bin/oxidize-daemon" 2>/dev/null || true
rm -rf "$CONFIG_DIR" 2>/dev/null || true
rm -rf "/var/run/oxidize" 2>/dev/null || true

echo "Oxidize daemon cleanup complete"

# CRITICAL: Always exit 0 to prevent dpkg failure
exit 0
