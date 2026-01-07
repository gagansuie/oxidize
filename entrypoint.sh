#!/bin/bash
set -e

echo "Setting up TUN device..."

# Create /dev/net/tun if it doesn't exist
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

echo "Starting oxidize-server..."
exec "$@"
