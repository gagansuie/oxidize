#!/bin/bash
# Oxidize Server - iptables DDoS Protection Rules
# Apply on relay servers for network-level rate limiting

set -e

TUNNEL_PORT="${1:-4433}"
METRICS_PORT="${2:-9090}"

echo "Applying iptables DDoS protection rules..."
echo "  Tunnel port: $TUNNEL_PORT (UDP)"
echo "  Metrics port: $METRICS_PORT (TCP)"

# Flush existing custom rules (but keep default chains)
iptables -F OXIDIZE_RATELIMIT 2>/dev/null || true
iptables -N OXIDIZE_RATELIMIT 2>/dev/null || true

# Remove existing jumps to our chain
iptables -D INPUT -j OXIDIZE_RATELIMIT 2>/dev/null || true

# ============================================================================
# Rate Limiting Rules
# ============================================================================

# 1. Allow established connections (after initial rate limit check)
iptables -A OXIDIZE_RATELIMIT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 2. Rate limit NEW UDP connections to tunnel port
#    - Allow 50 new connections per second per IP
#    - Burst of 100 allowed
iptables -A OXIDIZE_RATELIMIT -p udp --dport $TUNNEL_PORT -m state --state NEW \
    -m hashlimit \
    --hashlimit-name tunnel_conn \
    --hashlimit-upto 50/sec \
    --hashlimit-burst 100 \
    --hashlimit-mode srcip \
    --hashlimit-htable-expire 10000 \
    -j ACCEPT

# 3. Drop excessive new UDP connections (connection flood protection)
iptables -A OXIDIZE_RATELIMIT -p udp --dport $TUNNEL_PORT -m state --state NEW -j DROP

# 4. Rate limit UDP packets overall per IP
#    - Allow 2000 packets per second per IP (generous for VPN traffic)
#    - Burst of 5000 allowed
iptables -A OXIDIZE_RATELIMIT -p udp --dport $TUNNEL_PORT \
    -m hashlimit \
    --hashlimit-name tunnel_pps \
    --hashlimit-upto 2000/sec \
    --hashlimit-burst 5000 \
    --hashlimit-mode srcip \
    --hashlimit-htable-expire 10000 \
    -j ACCEPT

# 5. Drop excessive packets (packet flood protection)
iptables -A OXIDIZE_RATELIMIT -p udp --dport $TUNNEL_PORT -j DROP

# 6. Allow metrics port (TCP) with connection limit
iptables -A OXIDIZE_RATELIMIT -p tcp --dport $METRICS_PORT -m connlimit --connlimit-above 10 -j DROP
iptables -A OXIDIZE_RATELIMIT -p tcp --dport $METRICS_PORT -j ACCEPT

# 7. Accept all other traffic (handled by default policy)
iptables -A OXIDIZE_RATELIMIT -j RETURN

# ============================================================================
# Insert our chain at the beginning of INPUT
# ============================================================================
iptables -I INPUT 1 -j OXIDIZE_RATELIMIT

# ============================================================================
# SYN Flood Protection (general TCP hardening)
# ============================================================================
iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# ============================================================================
# ICMP Flood Protection
# ============================================================================
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# ============================================================================
# Invalid Packet Protection
# ============================================================================
iptables -A INPUT -m state --state INVALID -j DROP

echo "iptables DDoS protection rules applied successfully!"
echo ""
echo "Current rules:"
iptables -L OXIDIZE_RATELIMIT -n -v
