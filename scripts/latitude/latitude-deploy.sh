#!/bin/bash
#
# Latitude.sh Bare Metal Deploy Script for Oxidize
# Builds, installs, and manages Oxidize server on Latitude.sh
#
# Usage: ./latitude-deploy.sh [--build|--install|--config|--tls|--restart|--status|--health|--logs|--full]
#
# Latitude.sh Chicago with dual 10Gbps NICs
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

# Configuration
OXIDIZE_USER="oxidize"
OXIDIZE_DIR="/opt/oxidize"
CONFIG_DIR="/etc/oxidize"
LOG_DIR="/var/log/oxidize"
BINARY_NAME="oxidize-server"
SERVICE_NAME="oxidize"
LISTEN_PORT=4433

# Parse arguments
ACTION=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --build) ACTION="build" ;;
        --install) ACTION="install" ;;
        --config) ACTION="config" ;;
        --tls) ACTION="tls" ;;
        --restart) ACTION="restart" ;;
        --status) ACTION="status" ;;
        --health) ACTION="health" ;;
        --logs) ACTION="logs" ;;
        --full) ACTION="full" ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [[ -z "$ACTION" ]]; then
    echo "Usage: $0 [--build|--install|--config|--tls|--restart|--status|--health|--logs|--full]"
    echo ""
    echo "Options:"
    echo "  --build    Build Oxidize server binary"
    echo "  --install  Install binary and systemd service"
    echo "  --config   Generate configuration file"
    echo "  --tls      Setup TLS certificates"
    echo "  --restart  Restart Oxidize service"
    echo "  --status   Show service status"
    echo "  --health   Run health check"
    echo "  --logs     Show recent logs"
    echo "  --full     Complete deployment (build + install + config + tls + restart)"
    exit 1
fi

# ============================================
# Build
# ============================================
do_build() {
    log_info "Building Oxidize server..."
    
    # Ensure Rust is available
    if ! command -v cargo &> /dev/null; then
        log_error "Rust not installed. Run latitude-setup.sh first"
        exit 1
    fi
    
    # Find project root
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    
    cd "$PROJECT_ROOT"
    
    # Build release
    log_info "Building release binary..."
    cargo build --release --bin oxidize-server
    
    log_success "Build complete: target/release/$BINARY_NAME"
}

# ============================================
# Install
# ============================================
do_install() {
    log_info "Installing Oxidize server..."
    
    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "Run as root: sudo $0 --install"
        exit 1
    fi
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    BINARY_PATH="$PROJECT_ROOT/target/release/$BINARY_NAME"
    
    if [[ ! -f "$BINARY_PATH" ]]; then
        log_error "Binary not found. Run --build first"
        exit 1
    fi
    
    # Create user if not exists
    if ! id "$OXIDIZE_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false "$OXIDIZE_USER"
        log_success "Created user: $OXIDIZE_USER"
    fi
    
    # Create directories
    mkdir -p "$OXIDIZE_DIR" "$CONFIG_DIR" "$LOG_DIR" /var/run/oxidize
    
    # Install binary
    cp "$BINARY_PATH" "$OXIDIZE_DIR/"
    chmod +x "$OXIDIZE_DIR/$BINARY_NAME"
    
    # Set permissions
    chown -R "$OXIDIZE_USER:$OXIDIZE_USER" "$OXIDIZE_DIR" "$LOG_DIR" /var/run/oxidize
    chown -R root:root "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    # Install systemd service
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Oxidize Network Relay Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$OXIDIZE_DIR
ExecStart=$OXIDIZE_DIR/$BINARY_NAME --config $CONFIG_DIR/server.toml
Restart=always
RestartSec=5
LimitNOFILE=2097152
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_IPC_LOCK
Environment=RUST_LOG=info
Environment=RUST_BACKTRACE=1

# Performance
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=99
Nice=-20

# Security
NoNewPrivileges=false
ProtectSystem=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    log_success "Installed to $OXIDIZE_DIR/$BINARY_NAME"
    log_success "Systemd service: $SERVICE_NAME"
}

# ============================================
# Configure
# ============================================
do_config() {
    log_info "Generating configuration..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Run as root: sudo $0 --config"
        exit 1
    fi
    
    # Load NIC config if available
    if [[ -f "$CONFIG_DIR/nic-config.env" ]]; then
        source "$CONFIG_DIR/nic-config.env"
    else
        DATA_NIC=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
    fi
    
    # Get public IP
    PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "0.0.0.0")
    
    cat > "$CONFIG_DIR/server.toml" << EOF
# Oxidize Server Configuration
# Latitude.sh Chicago - Dual NIC DPDK Setup

[server]
# Public address for clients
listen_addr = "0.0.0.0:$LISTEN_PORT"
public_ip = "$PUBLIC_IP"

# TLS certificates
cert_path = "$CONFIG_DIR/certs/server.crt"
key_path = "$CONFIG_DIR/certs/server.key"

[network]
# Data plane NIC (for DPDK)
interface = "${DATA_NIC:-eth0}"

# Kernel bypass mode: "dpdk"
kernel_bypass = "dpdk"

# Number of worker threads (match CPU cores)
workers = $(nproc)

# Enable zero-copy mode
zero_copy = true

[performance]
# Hugepages
hugepages = true
hugepage_size = "2MB"

# Buffer sizes
rx_ring_size = 4096
tx_ring_size = 4096

# Batch processing
batch_size = 64

[quic]
# QUIC configuration
max_idle_timeout_ms = 30000
initial_rtt_ms = 100
max_udp_payload_size = 1350

# Connection limits
max_concurrent_streams = 100
max_connections = 10000

[logging]
level = "info"
file = "$LOG_DIR/oxidize.log"
EOF
    
    log_success "Configuration written to $CONFIG_DIR/server.toml"
}

# ============================================
# TLS Setup
# ============================================
do_tls() {
    log_info "Setting up TLS certificates..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Run as root: sudo $0 --tls"
        exit 1
    fi
    
    CERT_DIR="$CONFIG_DIR/certs"
    mkdir -p "$CERT_DIR"
    
    if [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]]; then
        log_warn "Certificates already exist. Skipping..."
        return
    fi
    
    # Generate self-signed certificate
    log_info "Generating self-signed certificate..."
    
    PUBLIC_IP=$(curl -s ifconfig.me || echo "localhost")
    
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -days 365 -nodes \
        -subj "/CN=$PUBLIC_IP/O=Oxidize/C=US" \
        -addext "subjectAltName=IP:$PUBLIC_IP,DNS:localhost"
    
    chmod 600 "$CERT_DIR/server.key"
    chmod 644 "$CERT_DIR/server.crt"
    
    log_success "TLS certificates generated"
    log_info "For production, replace with Let's Encrypt or real certificates"
}

# ============================================
# Firewall
# ============================================
do_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp comment 'SSH'
        ufw allow $LISTEN_PORT/udp comment 'Oxidize QUIC'
        ufw --force enable
        log_success "UFW configured"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=$LISTEN_PORT/udp
        firewall-cmd --reload
        log_success "firewalld configured"
    else
        # Use iptables directly
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p udp --dport $LISTEN_PORT -j ACCEPT
        log_success "iptables configured"
    fi
}

# ============================================
# Service Management
# ============================================
do_restart() {
    log_info "Restarting Oxidize service..."
    systemctl restart $SERVICE_NAME
    sleep 2
    systemctl status $SERVICE_NAME --no-pager
}

do_status() {
    systemctl status $SERVICE_NAME --no-pager || true
    echo ""
    log_info "Recent logs:"
    journalctl -u $SERVICE_NAME -n 20 --no-pager || true
}

do_health() {
    log_info "Running health check..."
    
    # Check service
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_success "Service: running"
    else
        log_error "Service: not running"
        exit 1
    fi
    
    # Check port
    if ss -ulnp | grep -q ":$LISTEN_PORT"; then
        log_success "Port $LISTEN_PORT: listening"
    else
        log_error "Port $LISTEN_PORT: not listening"
        exit 1
    fi
    
    # Check hugepages
    HP=$(cat /proc/sys/vm/nr_hugepages)
    if [[ $HP -gt 0 ]]; then
        log_success "Hugepages: $HP"
    else
        log_warn "Hugepages: not configured"
    fi
    
    log_success "Health check passed"
}

do_logs() {
    journalctl -u $SERVICE_NAME -f
}

# ============================================
# Full Deployment
# ============================================
do_full() {
    log_info "Starting full deployment..."
    echo ""
    
    do_build
    echo ""
    
    do_install
    echo ""
    
    do_config
    echo ""
    
    do_tls
    echo ""
    
    do_firewall
    echo ""
    
    do_restart
    echo ""
    
    do_health
    echo ""
    
    log_success "═══════════════════════════════════════════════════════════"
    log_success "  OXIDIZE DEPLOYED ON LATITUDE.SH CHICAGO"
    log_success "═══════════════════════════════════════════════════════════"
    PUBLIC_IP=$(curl -s ifconfig.me || echo "YOUR_IP")
    echo ""
    echo "  Server: $PUBLIC_IP:$LISTEN_PORT"
    echo "  Config: $CONFIG_DIR/server.toml"
    echo "  Logs:   journalctl -u $SERVICE_NAME -f"
    echo ""
}

# Execute action
case $ACTION in
    build) do_build ;;
    install) do_install ;;
    config) do_config ;;
    tls) do_tls ;;
    restart) do_restart ;;
    status) do_status ;;
    health) do_health ;;
    logs) do_logs ;;
    full) do_full ;;
esac
