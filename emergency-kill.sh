#!/bin/bash
# Emergency kill script - run when tunnel breaks internet
echo "🛑 Killing oxidize-daemon..."
sudo pkill -9 oxidize-daemon 2>/dev/null
echo "🧹 Flushing iptables rules..."
sudo iptables -F OUTPUT
sudo iptables -F INPUT
sudo iptables -t nat -F
sudo iptables -t mangle -F
echo "✅ Network restored. You may need to wait a few seconds."
