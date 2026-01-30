#!/bin/bash
# End-to-end test script for Oxidize TCP/UDP implementation
# Run with: sudo ./test-e2e.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Oxidize E2E Test ==="

# Kill any existing oxidize processes
pkill -9 oxidize-server 2>/dev/null || true
pkill -9 oxidize-daemon 2>/dev/null || true
sleep 1

# Start server in background
echo "[1/5] Starting server..."
./target/release/oxidize-server --listen "[::]:51820" --disable-metrics --disable-http &
SERVER_PID=$!
sleep 2

# Start daemon in background  
echo "[2/5] Starting daemon..."
./target/release/oxidize-daemon &
DAEMON_PID=$!
sleep 3

# Connect client to local server
echo "[3/5] Connecting client..."
./target/release/oxidize-client --server 127.0.0.1:51820 &
CLIENT_PID=$!
sleep 3

# Test UDP (DNS)
echo "[4/5] Testing UDP (DNS lookup)..."
if dig @8.8.8.8 google.com +short +timeout=5 > /dev/null 2>&1; then
    echo "  ✅ UDP DNS: PASS"
else
    echo "  ❌ UDP DNS: FAIL"
fi

# Test TCP (HTTP)
echo "[5/5] Testing TCP (HTTP request)..."
if curl -s --max-time 10 http://httpbin.org/ip > /dev/null 2>&1; then
    echo "  ✅ TCP HTTP: PASS"
else
    echo "  ❌ TCP HTTP: FAIL"
fi

# Test internet connectivity
echo ""
echo "=== Verifying no network blackhole ==="
if ping -c 3 8.8.8.8 > /dev/null 2>&1; then
    echo "  ✅ Internet connectivity: PASS"
else
    echo "  ❌ Internet connectivity: FAIL (potential blackhole!)"
fi

# Cleanup
echo ""
echo "=== Cleanup ==="
kill $CLIENT_PID 2>/dev/null || true
kill $DAEMON_PID 2>/dev/null || true  
kill $SERVER_PID 2>/dev/null || true
echo "Done."
