#!/bin/bash
# Oxidize Real-time Stats Display
# Fetches and displays stats from the relay server's Prometheus endpoint

set -e

SERVER="${1:?Error: Server IP required. Usage: $0 <server_ip>}"
METRICS_PORT="${2:-9090}"
INTERVAL="${3:-2}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

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
    echo -e "${CYAN}║${NC} Updated: ${BLUE}$(date '+%Y-%m-%d %H:%M:%S')${NC}                            "
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_stats() {
    local metrics="$1"
    
    # Parse all metrics (using actual Prometheus metric names)
    local bytes_sent=$(parse_metric "$metrics" "oxidize_oxidize_relay_bytes_sent_total")
    local bytes_recv=$(parse_metric "$metrics" "oxidize_oxidize_relay_bytes_received_total")
    local pkts_sent=$(parse_metric "$metrics" "oxidize_oxidize_relay_packets_sent_total")
    local pkts_recv=$(parse_metric "$metrics" "oxidize_relay_packets_received_total")
    local active_sessions=$(parse_metric "$metrics" "oxidize_relay_connections_active")
    local total_sessions=$(parse_metric "$metrics" "oxidize_relay_connections_total")
    local compression_saved=$(parse_metric "$metrics" "oxidize_relay_compression_saved_bytes")
    local handshakes=$(parse_metric "$metrics" "oxidize_tunnel_handshakes_completed")
    local invalid_pkts=$(parse_metric "$metrics" "oxidize_tunnel_invalid_packets")
    local uptime=$(parse_metric "$metrics" "oxidize_relay_uptime_seconds")
    
    # Default to 0 if empty
    bytes_sent=${bytes_sent:-0}
    bytes_recv=${bytes_recv:-0}
    pkts_sent=${pkts_sent:-0}
    pkts_recv=${pkts_recv:-0}
    active_sessions=${active_sessions:-0}
    total_sessions=${total_sessions:-0}
    handshakes=${handshakes:-0}
    invalid_pkts=${invalid_pkts:-0}
    uptime=${uptime:-0}
    
    echo ""
    echo -e "${BOLD}${BLUE}📊 TRAFFIC STATS${NC}"
    echo -e "├─ Bytes Sent:     ${GREEN}$(format_bytes ${bytes_sent%.*})${NC}"
    echo -e "├─ Bytes Received: ${GREEN}$(format_bytes ${bytes_recv%.*})${NC}"
    echo -e "├─ Packets Sent:   ${YELLOW}${pkts_sent%.*}${NC}"
    echo -e "└─ Packets Recv:   ${YELLOW}${pkts_recv%.*}${NC}"
    
    echo ""
    echo -e "${BOLD}${BLUE}🔌 CONNECTION STATS${NC}"
    echo -e "├─ Active Sessions: ${GREEN}${active_sessions%.*}${NC}"
    echo -e "├─ Total Sessions:  ${YELLOW}${total_sessions%.*}${NC}"
    echo -e "├─ Handshakes:      ${CYAN}${handshakes%.*}${NC}"
    echo -e "└─ Invalid Packets: ${RED}${invalid_pkts%.*}${NC}"
    
    echo ""
    echo -e "${BOLD}${BLUE}⏱️  SERVER INFO${NC}"
    echo -e "└─ Uptime: ${GREEN}$(format_uptime ${uptime%.*})${NC}"
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
            if [ "$connected" = "true" ]; then
                echo -e "└─ Tunnel: ${GREEN}Active${NC}"
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
    echo -e "${CYAN}Connecting to ${SERVER}:${METRICS_PORT}...${NC}"
    
    # Test connection first
    if ! curl -sf --connect-timeout 3 "http://${SERVER}:${METRICS_PORT}/metrics" > /dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to metrics endpoint at ${SERVER}:${METRICS_PORT}${NC}"
        echo "Make sure the Oxidize server is running and the metrics port is accessible."
        exit 1
    fi
    
    echo -e "${GREEN}Connected! Refreshing every ${INTERVAL}s (Ctrl+C to exit)${NC}"
    sleep 1
    
    while true; do
        clear_screen
        print_header
        
        # Fetch metrics
        local metrics=$(curl -sf --connect-timeout 3 "http://${SERVER}:${METRICS_PORT}/metrics" 2>/dev/null)
        
        if [ -n "$metrics" ]; then
            print_stats "$metrics"
        else
            echo -e "${RED}Failed to fetch metrics${NC}"
        fi
        
        check_daemon_status
        
        echo ""
        echo -e "${CYAN}Press Ctrl+C to exit${NC}"
        
        sleep "$INTERVAL"
    done
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${GREEN}Goodbye!${NC}"; exit 0' INT

main
