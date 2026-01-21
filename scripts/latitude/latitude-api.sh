#!/bin/bash
#
# Latitude.sh API Script for Oxidize
# Deploy and manage bare metal servers via API
#
# Usage:
#   ./latitude-api.sh deploy              # Deploy new server in Chicago
#   ./latitude-api.sh list                # List all servers
#   ./latitude-api.sh status <server_id>  # Get server status
#   ./latitude-api.sh delete <server_id>  # Delete server
#   ./latitude-api.sh regions             # List available regions
#   ./latitude-api.sh plans               # List available plans
#   ./latitude-api.sh ssh-keys            # List SSH keys
#
# Required: LATITUDE_API_KEY environment variable
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# API Configuration
API_BASE="https://api.latitude.sh"
API_VERSION="2024-06-01"

# Check API key
if [[ -z "$LATITUDE_API_KEY" ]]; then
    log_error "LATITUDE_API_KEY environment variable not set"
    echo ""
    echo "Get your API key from: https://www.latitude.sh/dashboard/account/api-keys"
    echo "Then run: export LATITUDE_API_KEY='your_api_key_here'"
    exit 1
fi

# API request helper
api_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    if [[ -n "$data" ]]; then
        curl -s -X "$method" \
            -H "Authorization: Bearer $LATITUDE_API_KEY" \
            -H "Content-Type: application/json" \
            -H "API-Version: $API_VERSION" \
            -d "$data" \
            "$API_BASE$endpoint"
    else
        curl -s -X "$method" \
            -H "Authorization: Bearer $LATITUDE_API_KEY" \
            -H "Content-Type: application/json" \
            -H "API-Version: $API_VERSION" \
            "$API_BASE$endpoint"
    fi
}

# ============================================
# List Regions
# ============================================
cmd_regions() {
    log_info "Fetching available regions..."
    
    response=$(api_request GET "/regions")
    
    echo ""
    echo "Available Regions:"
    echo "══════════════════════════════════════════════════════════════"
    echo "$response" | jq -r '.data[] | "\(.attributes.slug)\t\(.attributes.city), \(.attributes.country)"' 2>/dev/null || echo "$response"
    echo ""
}

# ============================================
# List Plans
# ============================================
cmd_plans() {
    log_info "Fetching available plans..."
    
    response=$(api_request GET "/plans")
    
    echo ""
    echo "Available Plans:"
    echo "══════════════════════════════════════════════════════════════"
    printf "%-25s %-10s %-10s %-15s\n" "Plan" "CPU" "RAM" "Price"
    echo "──────────────────────────────────────────────────────────────"
    echo "$response" | jq -r '.data[] | "\(.attributes.slug)\t\(.attributes.specs.cpu.cores)c\t\(.attributes.specs.memory.total)\t$\(.attributes.pricing.hourly)/hr"' 2>/dev/null || echo "$response"
    echo ""
}

# ============================================
# List SSH Keys
# ============================================
cmd_ssh_keys() {
    log_info "Fetching SSH keys..."
    
    response=$(api_request GET "/ssh_keys")
    
    echo ""
    echo "SSH Keys:"
    echo "══════════════════════════════════════════════════════════════"
    echo "$response" | jq -r '.data[] | "\(.id)\t\(.attributes.name)"' 2>/dev/null || echo "$response"
    echo ""
}

# ============================================
# List Projects
# ============================================
cmd_projects() {
    log_info "Fetching projects..."
    
    response=$(api_request GET "/projects")
    
    echo ""
    echo "Projects:"
    echo "══════════════════════════════════════════════════════════════"
    echo "$response" | jq -r '.data[] | "\(.id)\t\(.attributes.name)"' 2>/dev/null || echo "$response"
    echo ""
}

# ============================================
# List Servers
# ============================================
cmd_list() {
    log_info "Fetching servers..."
    
    response=$(api_request GET "/servers")
    
    echo ""
    echo "Servers:"
    echo "══════════════════════════════════════════════════════════════"
    printf "%-20s %-15s %-10s %-20s\n" "ID" "Hostname" "Status" "IP"
    echo "──────────────────────────────────────────────────────────────"
    echo "$response" | jq -r '.data[] | "\(.id)\t\(.attributes.hostname)\t\(.attributes.status)\t\(.attributes.primary_ipv4 // "pending")"' 2>/dev/null || echo "$response"
    echo ""
}

# ============================================
# Get Server Status
# ============================================
cmd_status() {
    local server_id=$1
    
    if [[ -z "$server_id" ]]; then
        log_error "Server ID required: ./latitude-api.sh status <server_id>"
        exit 1
    fi
    
    log_info "Fetching server status: $server_id"
    
    response=$(api_request GET "/servers/$server_id")
    
    echo ""
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

# ============================================
# Deploy Server
# ============================================
cmd_deploy() {
    log_info "Deploying Oxidize server in Chicago..."
    
    # First, get project ID
    log_info "Fetching project ID..."
    projects=$(api_request GET "/projects")
    PROJECT_ID=$(echo "$projects" | jq -r '.data[0].id' 2>/dev/null)
    
    if [[ -z "$PROJECT_ID" || "$PROJECT_ID" == "null" ]]; then
        log_error "No project found. Create a project first at https://www.latitude.sh/dashboard"
        exit 1
    fi
    log_success "Using project: $PROJECT_ID"
    
    # Get SSH key ID
    log_info "Fetching SSH key..."
    ssh_keys=$(api_request GET "/ssh_keys")
    SSH_KEY_ID=$(echo "$ssh_keys" | jq -r '.data[0].id' 2>/dev/null)
    
    if [[ -z "$SSH_KEY_ID" || "$SSH_KEY_ID" == "null" ]]; then
        log_warn "No SSH key found. Add one at https://www.latitude.sh/dashboard/account/ssh-keys"
        SSH_KEY_PARAM=""
    else
        log_success "Using SSH key: $SSH_KEY_ID"
        SSH_KEY_PARAM="\"ssh_keys\": [\"$SSH_KEY_ID\"],"
    fi
    
    # Deploy configuration
    # Chicago = "chi" or "ord"
    # Plans: m4-metal-small, f4-metal-small, etc.
    
    HOSTNAME="oxidize-relay"
    SITE="chi"  # Chicago
    PLAN="m4-metal-small"  # $189/mo, 6c, 64GB, 2x10Gbps
    OS="ubuntu_22_04_x64_lts"
    
    log_info "Deploying server..."
    log_info "  Hostname: $HOSTNAME"
    log_info "  Location: Chicago ($SITE)"
    log_info "  Plan: $PLAN"
    log_info "  OS: Ubuntu 22.04 LTS"
    
    # Create server request
    payload=$(cat <<EOF
{
    "data": {
        "type": "servers",
        "attributes": {
            "project": "$PROJECT_ID",
            "plan": "$PLAN",
            "site": "$SITE",
            "operating_system": "$OS",
            "hostname": "$HOSTNAME",
            $SSH_KEY_PARAM
            "raid": "raid-1"
        }
    }
}
EOF
)
    
    response=$(api_request POST "/servers" "$payload")
    
    # Check for errors
    if echo "$response" | jq -e '.errors' > /dev/null 2>&1; then
        log_error "Deployment failed:"
        echo "$response" | jq '.errors'
        exit 1
    fi
    
    # Extract server info
    SERVER_ID=$(echo "$response" | jq -r '.data.id' 2>/dev/null)
    
    if [[ -z "$SERVER_ID" || "$SERVER_ID" == "null" ]]; then
        log_error "Failed to get server ID from response:"
        echo "$response" | jq '.'
        exit 1
    fi
    
    log_success "Server deployment initiated!"
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  Server ID:  $SERVER_ID"
    echo "  Hostname:   $HOSTNAME"
    echo "  Location:   Chicago"
    echo "  Plan:       $PLAN"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
    log_info "Server is provisioning. Check status with:"
    echo "  ./latitude-api.sh status $SERVER_ID"
    echo ""
    log_info "Once ready, deploy Oxidize with:"
    echo "  ssh root@<IP> 'git clone https://github.com/gagansuie/oxidize.git && cd oxidize && sudo ./scripts/latitude/latitude-setup.sh'"
    echo ""
    
    # Save server info
    mkdir -p /tmp/latitude
    echo "$response" > /tmp/latitude/last-deploy.json
    echo "$SERVER_ID" > /tmp/latitude/server-id
}

# ============================================
# Delete Server
# ============================================
cmd_delete() {
    local server_id=$1
    
    if [[ -z "$server_id" ]]; then
        log_error "Server ID required: ./latitude-api.sh delete <server_id>"
        exit 1
    fi
    
    log_warn "Deleting server: $server_id"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Cancelled"
        exit 0
    fi
    
    response=$(api_request DELETE "/servers/$server_id")
    
    if [[ -z "$response" ]]; then
        log_success "Server deleted successfully"
    else
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

# ============================================
# Wait for server
# ============================================
cmd_wait() {
    local server_id=$1
    
    if [[ -z "$server_id" ]]; then
        # Try to get from last deploy
        if [[ -f /tmp/latitude/server-id ]]; then
            server_id=$(cat /tmp/latitude/server-id)
        else
            log_error "Server ID required: ./latitude-api.sh wait <server_id>"
            exit 1
        fi
    fi
    
    log_info "Waiting for server $server_id to be ready..."
    
    while true; do
        response=$(api_request GET "/servers/$server_id")
        status=$(echo "$response" | jq -r '.data.attributes.status' 2>/dev/null)
        ip=$(echo "$response" | jq -r '.data.attributes.primary_ipv4 // "pending"' 2>/dev/null)
        
        echo -ne "\r  Status: $status | IP: $ip          "
        
        if [[ "$status" == "on" || "$status" == "active" ]]; then
            echo ""
            log_success "Server is ready!"
            log_success "IP Address: $ip"
            echo ""
            echo "Connect with: ssh root@$ip"
            break
        elif [[ "$status" == "failed" || "$status" == "error" ]]; then
            echo ""
            log_error "Server deployment failed"
            exit 1
        fi
        
        sleep 10
    done
}

# ============================================
# Main
# ============================================
case "${1:-}" in
    regions)
        cmd_regions
        ;;
    plans)
        cmd_plans
        ;;
    ssh-keys|ssh_keys)
        cmd_ssh_keys
        ;;
    projects)
        cmd_projects
        ;;
    list|ls)
        cmd_list
        ;;
    status)
        cmd_status "$2"
        ;;
    deploy)
        cmd_deploy
        ;;
    delete|rm)
        cmd_delete "$2"
        ;;
    wait)
        cmd_wait "$2"
        ;;
    *)
        echo "Latitude.sh API Script for Oxidize"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  deploy              Deploy new server in Chicago"
        echo "  list                List all servers"
        echo "  status <id>         Get server status"
        echo "  wait [id]           Wait for server to be ready"
        echo "  delete <id>         Delete server"
        echo "  regions             List available regions"
        echo "  plans               List available plans"
        echo "  ssh-keys            List SSH keys"
        echo "  projects            List projects"
        echo ""
        echo "Environment:"
        echo "  LATITUDE_API_KEY    Your API key (required)"
        echo ""
        echo "Get API key: https://www.latitude.sh/dashboard/account/api-keys"
        ;;
esac
