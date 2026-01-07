#!/bin/bash
# Oxidize Client Installer - One-Click Install
# Usage: curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/install.sh | sudo bash

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/oxidize"
SERVICE_DIR="/etc/systemd/system"
BINARY_NAME="oxidize-client"
SERVER_ADDR="oxd.sh:4433"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                   Oxidize Installer                        ║"
    echo "║         High-Performance Network Tunnel                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

set_server_address() {
    # Allow override via argument, otherwise use default (oxd.sh:4433)
    if [ -n "$1" ] && [ "$1" != "uninstall" ]; then
        SERVER_ADDR="$1"
    fi
    echo -e "${GREEN}Server: $SERVER_ADDR${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This installer requires root privileges.${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [ "$(uname)" == "Darwin" ]; then
        OS="macos"
        VERSION=$(sw_vers -productVersion)
    else
        OS="unknown"
    fi
    echo -e "${GREEN}Detected OS: $OS $VERSION${NC}"
}

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    case $OS in
        ubuntu|debian|pop|linuxmint|elementary|zorin)
            apt-get update -qq
            apt-get install -y -qq iproute2 iptables resolvconf curl
            ;;
        fedora|centos|rhel)
            dnf install -y iproute iptables curl
            ;;
        arch)
            pacman -S --noconfirm iproute2 iptables curl
            ;;
        macos)
            # macOS doesn't need extra deps for basic TUN
            echo "macOS detected - minimal dependencies needed"
            ;;
        *)
            echo -e "${YELLOW}Unknown OS - skipping dependency installation${NC}"
            ;;
    esac
}

download_binary() {
    echo -e "${YELLOW}Downloading oxidize-client...${NC}"
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac
    
    case $OS in
        macos) PLATFORM="apple-darwin" ;;
        *) PLATFORM="unknown-linux-musl" ;;
    esac
    
    # Check if binary exists locally (for development)
    if [ -f "./target/release/$BINARY_NAME" ]; then
        echo "Using local build..."
        cp "./target/release/$BINARY_NAME" "$INSTALL_DIR/"
    else
        # Download from releases
        REPO="gagansuie/oxidize"
        TARGET="$ARCH-$PLATFORM"
        
        # Get latest release tag
        LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -z "$LATEST_TAG" ]; then
            echo -e "${RED}Failed to get latest release. Building from source...${NC}"
            build_from_source
            return
        fi
        
        ARCHIVE_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/oxidize-client-$LATEST_TAG-$TARGET.tar.gz"
        
        echo "Downloading from: $ARCHIVE_URL"
        TEMP_DIR=$(mktemp -d)
        if ! curl -fsSL "$ARCHIVE_URL" -o "$TEMP_DIR/oxidize-client.tar.gz"; then
            echo -e "${RED}Download failed. Building from source...${NC}"
            rm -rf "$TEMP_DIR"
            build_from_source
            return
        fi
        
        # Extract binary
        tar -xzf "$TEMP_DIR/oxidize-client.tar.gz" -C "$TEMP_DIR"
        cp "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
        rm -rf "$TEMP_DIR"
    fi
    
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo -e "${GREEN}Binary installed to $INSTALL_DIR/$BINARY_NAME${NC}"
}

build_from_source() {
    echo -e "${YELLOW}Building from source...${NC}"
    
    # Check for cargo
    if ! command -v cargo &> /dev/null; then
        echo "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    cargo build --release --package relay-client
    cp "./target/release/$BINARY_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
}

create_config() {
    echo -e "${YELLOW}Creating configuration...${NC}"
    
    mkdir -p "$CONFIG_DIR"
    
    if [ ! -f "$CONFIG_DIR/client.toml" ]; then
        cat > "$CONFIG_DIR/client.toml" << 'EOF'
# Oxidize Client Configuration

# Relay server address (REQUIRED - set this!)
# server = "your-server.com:4433"

# Enable compression
enable_compression = true
compression_threshold = 512

# Buffer sizes
buffer_size = 65536
max_packet_queue = 10000

# TUN interface settings
tun_mtu = 1400

# Connection settings
reconnect_interval = 5
keepalive_interval = 30

# DNS settings
enable_dns_prefetch = true
dns_cache_size = 1000
EOF
        echo -e "${GREEN}Config created at $CONFIG_DIR/client.toml${NC}"
    else
        echo "Config already exists, skipping..."
    fi
}

create_systemd_service() {
    if [ "$OS" == "macos" ]; then
        create_launchd_service
        return
    fi
    
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > "$SERVICE_DIR/oxidize.service" << EOF
[Unit]
Description=Oxidize Network Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONFIG_DIR/oxidize.env
ExecStart=$INSTALL_DIR/$BINARY_NAME --server \${SERVER_ADDR} --config $CONFIG_DIR/client.toml
ExecStop=/bin/kill -SIGTERM \$MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/resolv.conf /run

# Required for TUN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    # Create environment file
    cat > "$CONFIG_DIR/oxidize.env" << EOF
# Relay server address (configured during install)
SERVER_ADDR=$SERVER_ADDR
EOF

    systemctl daemon-reload
    
    # Auto-start and enable the service
    echo -e "${YELLOW}Starting Oxidize service...${NC}"
    systemctl enable oxidize
    systemctl start oxidize
    
    echo -e "${GREEN}✅ Oxidize service started and enabled on boot${NC}"
}

create_launchd_service() {
    echo -e "${YELLOW}Creating launchd service for macOS...${NC}"
    
    PLIST_PATH="/Library/LaunchDaemons/com.oxidize.client.plist"
    
    cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.oxidize.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/$BINARY_NAME</string>
        <string>--server</string>
        <string>$SERVER_ADDR</string>
        <string>--config</string>
        <string>$CONFIG_DIR/client.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/oxidize.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/oxidize.error.log</string>
</dict>
</plist>
EOF

    # Auto-start the service
    echo -e "${YELLOW}Starting Oxidize service...${NC}"
    launchctl load "$PLIST_PATH"
    
    echo -e "${GREEN}✅ Oxidize service started and enabled on boot${NC}"
}

setup_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    case $OS in
        ubuntu|debian|fedora|centos|rhel|arch)
            # Allow TUN traffic
            if command -v ufw &> /dev/null; then
                ufw allow out on oxidize0
                ufw allow in on oxidize0
            fi
            
            # iptables rules for NAT (if server mode)
            # iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
            ;;
        macos)
            # macOS PF rules would go here
            echo "macOS firewall configuration skipped"
            ;;
    esac
}

print_success() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           ✅ Oxidize Installation Complete!               ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}Status:${NC}"
    echo "  • Server: $SERVER_ADDR"
    echo "  • Service: Running and enabled on boot"
    echo "  • TUN interface: Active (all traffic tunneled)"
    echo ""
    echo -e "${BLUE}Commands:${NC}"
    echo "  sudo systemctl status oxidize   # Check status"
    echo "  sudo systemctl restart oxidize  # Restart"
    echo "  sudo systemctl stop oxidize     # Stop"
    echo "  sudo journalctl -u oxidize -f   # View logs"
    echo ""
    echo -e "${BLUE}Uninstall:${NC}"
    echo "  sudo $0 uninstall"
    echo ""
    echo -e "${GREEN}Your traffic is now optimized! 🚀${NC}"
    echo ""
}

uninstall() {
    echo -e "${YELLOW}Uninstalling Oxidize...${NC}"
    
    # Stop service
    systemctl stop oxidize 2>/dev/null || true
    systemctl disable oxidize 2>/dev/null || true
    
    # Remove files
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    rm -f "$SERVICE_DIR/oxidize.service"
    rm -rf "$SERVICE_DIR/oxidize.service.d"
    rm -rf "$CONFIG_DIR"
    
    # macOS
    launchctl unload /Library/LaunchDaemons/com.oxidize.client.plist 2>/dev/null || true
    rm -f /Library/LaunchDaemons/com.oxidize.client.plist
    
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}Uninstallation complete${NC}"
}

# Main
main() {
    print_banner
    
    if [ "$1" == "uninstall" ]; then
        check_root
        uninstall
        exit 0
    fi
    
    check_root
    set_server_address "$1"
    detect_os
    install_dependencies
    download_binary
    create_config
    create_systemd_service
    # setup_firewall  # Uncomment if needed
    print_success
}

main "$@"
