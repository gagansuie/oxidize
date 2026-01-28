#!/bin/bash
# Oxidize Real-time Stats Display
# Fetches and displays stats from the relay server's Prometheus endpoint

set -e

SERVER="${1:?Error: Server IP required. Usage: $0 <server_ip> [metrics_port] [interval] [oxtunnel_port]}"
METRICS_PORT="${2:-9090}"
INTERVAL="${3:-2}"
OX_PORT="${4:-51820}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

HAS_PREV=0
PREV_BYTES_SENT=0
PREV_BYTES_RECV=0
PREV_PKTS_SENT=0
PREV_PKTS_RECV=0
PREV_HANDSHAKES=0

SERVER_IPV4=""
SERVER_IPV6=""
METRICS_URL=""

format_bytes() {
    local bytes=$1
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc) KB"
    else
        echo "$bytes B"
    fi
}

check_udp_ipv6_status() {
    echo ""
    echo -e "${BOLD}${BLUE}🌐 TRANSPORT CHECK${NC}"

    local udp_v4="Inactive"
    local udp_v6="Inactive"

    if command -v ss >/dev/null 2>&1; then
        if [ -n "$SERVER_IPV4" ]; then
            local peers_v4
            peers_v4=$(ss -u -n 2>/dev/null | awk 'NR>1 {print $5}' || true)
            if echo "$peers_v4" | grep -q "${SERVER_IPV4}:${OX_PORT}$"; then
                udp_v4="Active"
            fi
        fi

        if [ -n "$SERVER_IPV6" ]; then
            local peers_v6
            peers_v6=$(ss -u -n -6 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/\[//g; s/\]//g' || true)
            if echo "$peers_v6" | grep -qi "${SERVER_IPV6}:${OX_PORT}$"; then
                udp_v6="Active"
            fi
        fi
    fi

    echo -e "├─ UDP IPv4: ${GREEN}${udp_v4}${NC}"
    echo -e "└─ UDP IPv6: ${GREEN}${udp_v6}${NC}"
}

is_ipv6() {
    [[ "$1" == *:* ]]
}

format_metrics_url() {
    local host="$1"
    if is_ipv6 "$host"; then
        echo "http://[${host}]:${METRICS_PORT}/metrics"
    else
        echo "http://${host}:${METRICS_PORT}/metrics"
    fi
}

resolve_server_ips() {
    if is_ipv6 "$SERVER"; then
        SERVER_IPV6="$SERVER"
        return
    fi

    if [[ "$SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SERVER_IPV4="$SERVER"
        return
    fi

    if command -v getent >/dev/null 2>&1; then
        local addrs
        addrs=$(getent ahosts "$SERVER" 2>/dev/null | awk '{print $1}' | sort -u || true)
        SERVER_IPV4=$(echo "$addrs" | grep -m1 -E '^[0-9.]+$' || true)
        SERVER_IPV6=$(echo "$addrs" | grep -m1 -E ':' || true)
    fi
}

to_int() {
    echo "${1:-0}" | awk '{printf "%.0f", $1}'
}

calc_delta() {
    local current="$1"
    local prev="$2"
    if [ "$current" -lt "$prev" ]; then
        echo 0
    else
        echo $((current - prev))
    fi
}

calc_rate() {
    local delta="$1"
    local interval="$2"
    if [ "$interval" -le 0 ]; then
        echo 0
    else
        awk -v d="$delta" -v i="$interval" 'BEGIN { printf "%.0f", d / i }'
    fi
}

format_uptime() {
    local secs=$1
    local days=$((secs / 86400))
    local hours=$(((secs % 86400) / 3600))
    local mins=$(((secs % 3600) / 60))
    local s=$((secs % 60))
    
    if [ $days -gt 0 ]; then
        echo "${days}d ${hours}h ${mins}m"
    elif [ $hours -gt 0 ]; then
        echo "${hours}h ${mins}m ${s}s"
    elif [ $mins -gt 0 ]; then
        echo "${mins}m ${s}s"
    else
        echo "${s}s"
    fi
}

parse_metric() {
    local metrics="$1"
    local name="$2"
    echo "$metrics" | grep "^${name}" | head -1 | awk '{print $2}' | tr -d '\r'
}

clear_screen() {
    printf "\033[2J\033[H"
}

print_header() {
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║              ${GREEN}⚡ OXIDIZE REAL-TIME STATS ⚡${CYAN}                    ║${NC}"
    echo -e "${BOLD}${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Server: ${YELLOW}${SERVER}:${METRICS_PORT}${NC}                                       "
    if [ -n "$SERVER_IPV4" ] || [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}║${NC} Resolved: ${BLUE}${SERVER_IPV4:-none}${NC} ${BLUE}${SERVER_IPV6:-}${NC}"
    fi
    echo -e "${CYAN}║${NC} Updated: ${BLUE}$(date '+%Y-%m-%d %H:%M:%S')${NC}                            "
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

update_metrics_cache() {
    local metrics="$1"

    local bytes_sent_raw=$(parse_metric "$metrics" "oxidize_oxidize_relay_bytes_sent_total")
    local bytes_recv_raw=$(parse_metric "$metrics" "oxidize_oxidize_relay_bytes_received_total")
    local pkts_sent_raw=$(parse_metric "$metrics" "oxidize_oxidize_relay_packets_sent_total")
    local pkts_recv_raw=$(parse_metric "$metrics" "oxidize_relay_packets_received_total")
    local active_sessions_raw=$(parse_metric "$metrics" "oxidize_relay_connections_active")
    local total_sessions_raw=$(parse_metric "$metrics" "oxidize_relay_connections_total")
    local compression_saved_raw=$(parse_metric "$metrics" "oxidize_relay_compression_saved_bytes")
    local handshakes_raw=$(parse_metric "$metrics" "oxidize_tunnel_handshakes_completed")
    local invalid_pkts_raw=$(parse_metric "$metrics" "oxidize_tunnel_invalid_packets")
    local uptime_raw=$(parse_metric "$metrics" "oxidize_relay_uptime_seconds")

    BYTES_SENT=$(to_int "${bytes_sent_raw:-0}")
    BYTES_RECV=$(to_int "${bytes_recv_raw:-0}")
    PKTS_SENT=$(to_int "${pkts_sent_raw:-0}")
    PKTS_RECV=$(to_int "${pkts_recv_raw:-0}")
    ACTIVE_SESSIONS=$(to_int "${active_sessions_raw:-0}")
    TOTAL_SESSIONS=$(to_int "${total_sessions_raw:-0}")
    COMPRESSION_SAVED=$(to_int "${compression_saved_raw:-0}")
    HANDSHAKES=$(to_int "${handshakes_raw:-0}")
    INVALID_PKTS=$(to_int "${invalid_pkts_raw:-0}")
    UPTIME=$(to_int "${uptime_raw:-0}")

    if [ "$HAS_PREV" -eq 1 ]; then
        DELTA_BYTES_SENT=$(calc_delta "$BYTES_SENT" "$PREV_BYTES_SENT")
        DELTA_BYTES_RECV=$(calc_delta "$BYTES_RECV" "$PREV_BYTES_RECV")
        DELTA_PKTS_SENT=$(calc_delta "$PKTS_SENT" "$PREV_PKTS_SENT")
        DELTA_PKTS_RECV=$(calc_delta "$PKTS_RECV" "$PREV_PKTS_RECV")
        DELTA_HANDSHAKES=$(calc_delta "$HANDSHAKES" "$PREV_HANDSHAKES")
    else
        DELTA_BYTES_SENT=0
        DELTA_BYTES_RECV=0
        DELTA_PKTS_SENT=0
        DELTA_PKTS_RECV=0
        DELTA_HANDSHAKES=0
    fi

    RATE_BYTES_SENT=$(calc_rate "$DELTA_BYTES_SENT" "$INTERVAL")
    RATE_BYTES_RECV=$(calc_rate "$DELTA_BYTES_RECV" "$INTERVAL")
    RATE_PKTS_SENT=$(calc_rate "$DELTA_PKTS_SENT" "$INTERVAL")
    RATE_PKTS_RECV=$(calc_rate "$DELTA_PKTS_RECV" "$INTERVAL")

    PREV_BYTES_SENT="$BYTES_SENT"
    PREV_BYTES_RECV="$BYTES_RECV"
    PREV_PKTS_SENT="$PKTS_SENT"
    PREV_PKTS_RECV="$PKTS_RECV"
    PREV_HANDSHAKES="$HANDSHAKES"
    HAS_PREV=1
}

print_stats() {
    echo ""
    echo -e "${BOLD}${BLUE}📊 TRAFFIC STATS${NC}"
    echo -e "├─ Bytes Sent:     ${GREEN}$(format_bytes ${BYTES_SENT})${NC}"
    echo -e "├─ Bytes Received: ${GREEN}$(format_bytes ${BYTES_RECV})${NC}"
    echo -e "├─ Packets Sent:   ${YELLOW}${PKTS_SENT}${NC}"
    echo -e "└─ Packets Recv:   ${YELLOW}${PKTS_RECV}${NC}"

    echo ""
    echo -e "${BOLD}${BLUE}📈 REAL-TIME RATES${NC}"
    echo -e "├─ TX Rate: ${GREEN}$(format_bytes ${RATE_BYTES_SENT})/s${NC}"
    echo -e "├─ RX Rate: ${GREEN}$(format_bytes ${RATE_BYTES_RECV})/s${NC}"
    echo -e "├─ TX PPS:  ${YELLOW}${RATE_PKTS_SENT}${NC}"
    echo -e "└─ RX PPS:  ${YELLOW}${RATE_PKTS_RECV}${NC}"

    echo ""
    echo -e "${BOLD}${BLUE}🔌 CONNECTION STATS${NC}"
    echo -e "├─ Active Sessions: ${GREEN}${ACTIVE_SESSIONS}${NC}"
    echo -e "├─ Total Sessions:  ${YELLOW}${TOTAL_SESSIONS}${NC}"
    echo -e "├─ Handshakes:      ${CYAN}${HANDSHAKES}${NC} (+${DELTA_HANDSHAKES})"
    echo -e "└─ Invalid Packets: ${RED}${INVALID_PKTS}${NC}"

    echo ""
    echo -e "${BOLD}${BLUE}⏱️  SERVER INFO${NC}"
    echo -e "└─ Uptime: ${GREEN}$(format_uptime ${UPTIME})${NC}"
}

check_daemon_status() {
    echo ""
    echo -e "${BOLD}${BLUE}🖥️  LOCAL DAEMON STATUS${NC}"
    
    if [ -S "/var/run/oxidize/daemon.sock" ]; then
        # Try to get status from daemon
        local response=$(echo '{"type":"Status"}' | sudo socat - UNIX-CONNECT:/var/run/oxidize/daemon.sock 2>/dev/null || echo '{"success":false}')
        if echo "$response" | grep -q '"success":true'; then
            echo -e "├─ Socket: ${GREEN}Connected${NC}"
            local connected=$(echo "$response" | grep -o '"connected":[^,}]*' | cut -d: -f2)
            local server_addr=$(echo "$response" | grep -o '"server_addr":"[^"]*"' | cut -d: -f2- | tr -d '"')
            if [ "$connected" = "true" ]; then
                echo -e "├─ Tunnel: ${GREEN}Active${NC}"
                if [ -n "$server_addr" ]; then
                    echo -e "└─ Server: ${YELLOW}${server_addr}${NC}"
                else
                    echo -e "└─ Server: ${YELLOW}Unknown${NC}"
                fi
            else
                echo -e "└─ Tunnel: ${YELLOW}Disconnected${NC}"
            fi
        else
            echo -e "├─ Socket: ${GREEN}Available${NC}"
            echo -e "└─ Status: ${YELLOW}Unknown${NC}"
        fi
    else
        echo -e "└─ Socket: ${RED}Not running${NC}"
    fi
}

main() {
    resolve_server_ips
    METRICS_URL=$(format_metrics_url "$SERVER")

    echo -e "${CYAN}Connecting to ${METRICS_URL}...${NC}"
    
    # Test connection first
    if ! curl -sf --connect-timeout 3 "$METRICS_URL" > /dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to metrics endpoint at ${METRICS_URL}${NC}"
        echo "Make sure the Oxidize server is running and the metrics port is accessible."
        exit 1
    fi
    
    echo -e "${GREEN}Connected! Refreshing every ${INTERVAL}s (Ctrl+C to exit)${NC}"
    sleep 1
    
    while true; do
        clear_screen
        print_header
        
        # Fetch metrics
        local metrics=$(curl -sf --connect-timeout 3 "$METRICS_URL" 2>/dev/null || true)
        
        if [ -n "$metrics" ]; then
            update_metrics_cache "$metrics"
            print_stats
        else
            echo -e "${RED}Failed to fetch metrics${NC}"
        fi
        
        check_udp_ipv6_status
        check_daemon_status
        
        echo ""
        echo -e "${CYAN}Press Ctrl+C to exit${NC}"
        
        sleep "$INTERVAL"
    done
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${GREEN}Goodbye!${NC}"; exit 0' INT

main
