#!/bin/bash
#
# Vultr Deployment Script for Oxidize
# Deploys and configures Oxidize server on Vultr bare metal
#
# Usage: ./vultr-deploy.sh [--build] [--restart]
#
# Prerequisites:
#   - Run vultr-setup.sh first

set -e

# Configuration
OXIDIZE_DIR="/opt/oxidize"
CONFIG_FILE="/etc/oxidize/server.toml"
SERVICE_NAME="oxidize-server"
BINARY_NAME="oxidize-server"
LISTEN_ADDR="0.0.0.0:4433"
METRICS_PORT="9090"

# Vultr Chicago specific
VULTR_REGION="ord"  # Chicago
VULTR_HOSTNAME="oxidize-chi"

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

# Check root for service installation
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Run as root: sudo $0"
        exit 1
    fi
}

# ============================================
# Build
# ============================================
build_server() {
    log_info "Building Oxidize server..."
    
    cd "$OXIDIZE_DIR" || cd "$(dirname "$0")/.."
    
    # Build release
    if command -v cargo &> /dev/null; then
        RUSTFLAGS="-C target-cpu=native" cargo build --release -p relay-server
    else
        log_error "Cargo not found. Install Rust first."
        exit 1
    fi
    
    log_success "Build complete"
}

# ============================================
# Install
# ============================================
install_server() {
    log_info "Installing Oxidize server..."
    
    local src_dir
    if [[ -d "$OXIDIZE_DIR" ]]; then
        src_dir="$OXIDIZE_DIR"
    else
        src_dir="$(dirname "$0")/.."
    fi
    
    # Find binary
    local binary=""
    for path in \
        "$src_dir/target/release/$BINARY_NAME" \
        "$src_dir/target/release/relay-server" \
        "./target/release/$BINARY_NAME"; do
        if [[ -f "$path" ]]; then
            binary="$path"
            break
        fi
    done
    
    if [[ -z "$binary" ]]; then
        log_error "Binary not found. Run with --build first."
        exit 1
    fi
    
    # Install binary
    cp "$binary" "/usr/local/bin/$BINARY_NAME"
    chmod +x "/usr/local/bin/$BINARY_NAME"
    log_success "Binary installed to /usr/local/bin/$BINARY_NAME"
    
    # Install config if not exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        install_config
    fi
}

# ============================================
# Configuration
# ============================================
install_config() {
    log_info "Installing server configuration..."
    
    mkdir -p /etc/oxidize
    
    cat > "$CONFIG_FILE" << 'EOF'
# Oxidize Server Configuration - Vultr Chicago (ord)
# Optimized for bare metal with 25 Gbps NIC

# === Connection Limits ===
# Vultr bare metal with 32GB+ RAM can handle 50k+ connections
max_connections = 50000

# === Compression ===
enable_compression = true
compression_threshold = 512

# === Buffers ===
# Larger buffers for high-throughput bare metal
buffer_size = 131072

# === Keepalive ===
keepalive_interval = 30
connection_timeout = 300

# === Acceleration ===
enable_tcp_acceleration = true
enable_deduplication = true

# === TLS ===
# Generate with: certbot certonly --standalone -d your-domain.com
# tls_cert_path = "/etc/oxidize/cert.pem"
# tls_key_path = "/etc/oxidize/key.pem"

# === Rate Limiting ===
rate_limit_per_ip = 1000
rate_limit_window_secs = 60

# === ROHC Header Compression ===
enable_rohc = true
rohc_max_size = 1500

# === 0-RTT ===
enable_0rtt = true
max_early_data_size = 4294967295

# === AI Engine ===
enable_ai_engine = true

# === Kernel Bypass (DPDK) ===
# Enabled by default on Linux - uses DPDK for high throughput
enable_kernel_bypass = true
bypass_interface = "auto"    # Auto-detect or specify e.g. "enp1s0f0"
bypass_queues = 4            # Number of RX/TX queues
bypass_zero_copy = true      # Enable zero-copy mode (requires kernel 5.4+)
EOF

    log_success "Configuration installed to $CONFIG_FILE"
}

# ============================================
# TLS Certificates
# ============================================
setup_tls() {
    local domain="${1:-}"
    
    if [[ -z "$domain" ]]; then
        log_warn "No domain specified, using self-signed certificate"
        
        # Generate self-signed cert
        if [[ ! -f "/etc/oxidize/cert.pem" ]]; then
            log_info "Generating self-signed certificate..."
            openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
                -nodes -keyout /etc/oxidize/key.pem -out /etc/oxidize/cert.pem \
                -subj "/CN=oxidize-server" \
                -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
            log_success "Self-signed certificate generated"
        fi
    else
        log_info "Setting up Let's Encrypt for $domain..."
        
        # Install certbot if needed
        if ! command -v certbot &> /dev/null; then
            apt-get install -y certbot
        fi
        
        # Get certificate
        certbot certonly --standalone -d "$domain" --non-interactive --agree-tos \
            --email "admin@$domain" || {
            log_error "Certbot failed. Make sure port 80 is open and DNS is configured."
            exit 1
        }
        
        # Link certificates
        ln -sf "/etc/letsencrypt/live/$domain/fullchain.pem" /etc/oxidize/cert.pem
        ln -sf "/etc/letsencrypt/live/$domain/privkey.pem" /etc/oxidize/key.pem
        
        # Update config
        sed -i 's|# tls_cert_path|tls_cert_path|' "$CONFIG_FILE"
        sed -i 's|# tls_key_path|tls_key_path|' "$CONFIG_FILE"
        
        log_success "TLS configured with Let's Encrypt"
    fi
}

# ============================================
# Systemd Service
# ============================================
install_service() {
    log_info "Installing systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Oxidize Relay Server (Vultr Chicago)
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/gagansuie/oxidize

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/$BINARY_NAME --listen $LISTEN_ADDR --config $CONFIG_FILE
Restart=always
RestartSec=5

# Performance tuning
LimitNOFILE=1048576
LimitMEMLOCK=infinity

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=oxidize

# Environment
Environment=RUST_LOG=info
Environment=RUST_BACKTRACE=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed"
}

# ============================================
# Firewall
# ============================================
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Check for ufw
    if command -v ufw &> /dev/null; then
        ufw allow 4433/udp comment "Oxidize QUIC"
        ufw allow 4433/tcp comment "Oxidize QUIC fallback"
        ufw allow $METRICS_PORT/tcp comment "Oxidize metrics"
        ufw allow 22/tcp comment "SSH"
        log_success "UFW rules configured"
    # Check for firewalld
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=4433/udp
        firewall-cmd --permanent --add-port=4433/tcp
        firewall-cmd --permanent --add-port=$METRICS_PORT/tcp
        firewall-cmd --reload
        log_success "Firewalld rules configured"
    # Fallback to iptables
    else
        iptables -A INPUT -p udp --dport 4433 -j ACCEPT
        iptables -A INPUT -p tcp --dport 4433 -j ACCEPT
        iptables -A INPUT -p tcp --dport $METRICS_PORT -j ACCEPT
        log_success "Iptables rules configured"
    fi
}

# ============================================
# Start/Restart
# ============================================
start_service() {
    log_info "Starting Oxidize server..."
    
    systemctl enable $SERVICE_NAME
    systemctl restart $SERVICE_NAME
    
    sleep 2
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_success "Oxidize server is running"
        
        # Show status
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║     OXIDIZE SERVER RUNNING                                ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        
        # Get public IP
        local public_ip=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
        
        echo "  Region:      Vultr Chicago (ord)"
        echo "  Listen:      $LISTEN_ADDR"
        echo "  Public IP:   $public_ip"
        echo "  Metrics:     http://$public_ip:$METRICS_PORT/metrics"
        echo "  Health:      http://$public_ip:$METRICS_PORT/health"
        echo ""
        echo "  Logs:        journalctl -u $SERVICE_NAME -f"
        echo "  Status:      systemctl status $SERVICE_NAME"
        echo ""
        
        echo "  Mode:        DPDK kernel bypass (auto-detected)"
        echo ""
    else
        log_error "Failed to start Oxidize server"
        journalctl -u $SERVICE_NAME -n 20 --no-pager
        exit 1
    fi
}

# ============================================
# Health Check
# ============================================
health_check() {
    log_info "Running health check..."
    
    local health_url="http://localhost:$METRICS_PORT/health"
    
    if curl -sf "$health_url" > /dev/null 2>&1; then
        log_success "Health check passed"
        
        # Get metrics
        echo ""
        echo "Current metrics:"
        curl -s "http://localhost:$METRICS_PORT/metrics" | grep -E "^oxidize_" | head -20
    else
        log_error "Health check failed"
        exit 1
    fi
}

# ============================================
# Main
# ============================================

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     OXIDIZE VULTR DEPLOYMENT                              ║"
echo "║     Chicago (ord) Bare Metal                              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

case "${1:-}" in
    --build|-b)
        build_server
        ;;
    --install|-i)
        check_root
        install_server
        install_service
        configure_firewall
        ;;
    --config|-c)
        check_root
        install_config
        ;;
    --tls)
        check_root
        setup_tls "${2:-}"
        ;;
    --restart|-r)
        check_root
        start_service
        ;;
    --status|-s)
        systemctl status $SERVICE_NAME --no-pager
        ;;
    --health|-h)
        health_check
        ;;
    --logs|-l)
        journalctl -u $SERVICE_NAME -f
        ;;
    --full)
        check_root
        build_server
        install_server
        install_service
        configure_firewall
        start_service
        health_check
        ;;
    --help)
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  --build, -b     Build Oxidize server"
        echo "  --install, -i   Install binary and service"
        echo "  --config, -c    Install/reset configuration"
        echo "  --tls [domain]  Setup TLS certificates"
        echo "  --restart, -r   Restart server"
        echo "  --status, -s    Show server status"
        echo "  --health, -h    Run health check"
        echo "  --logs, -l      Follow server logs"
        echo "  --full          Full deployment (build + install + start)"
        echo ""
        ;;
    *)
        # Default: full deployment
        check_root
        build_server
        install_server
        install_service
        configure_firewall
        start_service
        health_check
        ;;
esac
