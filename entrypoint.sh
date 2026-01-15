#!/bin/bash
set -e

echo "Setting up server environment..."

echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

echo "Starting oxidize-server..."
exec "$@"
