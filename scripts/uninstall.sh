#!/bin/bash
# Oxidize Complete Uninstaller - Cross-Platform
# Usage: curl -fsSL https://raw.githubusercontent.com/gagansuie/oxidize/main/scripts/uninstall.sh | bash
# Works on: Linux, macOS, Windows (Git Bash/WSL/PowerShell)

set -e

# Colors (disabled on Windows native)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
fi

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              Oxidize Complete Uninstaller                  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

detect_os() {
    case "$(uname -s)" in
        Linux*)
            if grep -qEi "(Microsoft|WSL)" /proc/version 2>/dev/null; then
                OS="wsl"
            else
                if [ -f /etc/os-release ]; then
                    . /etc/os-release
                    OS=$ID
                else
                    OS="linux"
                fi
            fi
            ;;
        Darwin*)
            OS="macos"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="windows"
            ;;
        *)
            OS="unknown"
            ;;
    esac
    echo -e "${GREEN}Detected OS: $OS${NC}"
}

check_root() {
    # Skip root check on Windows
    if [[ "$OS" == "windows" || "$OS" == "wsl" ]]; then
        return
    fi
    
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This uninstaller requires root privileges.${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Get the real user (not root) for cleaning user directories
get_real_user() {
    if [ -n "$SUDO_USER" ]; then
        REAL_USER="$SUDO_USER"
        REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        REAL_USER="$USER"
        REAL_HOME="$HOME"
    fi
    echo -e "${BLUE}User home: $REAL_HOME${NC}"
}

uninstall_linux() {
    echo -e "${YELLOW}Stopping services...${NC}"
    systemctl stop oxidize 2>/dev/null || true
    systemctl stop oxidize-daemon 2>/dev/null || true
    systemctl disable oxidize 2>/dev/null || true
    systemctl disable oxidize-daemon 2>/dev/null || true

    echo -e "${YELLOW}Removing binaries...${NC}"
    rm -f /usr/local/bin/oxidize-client
    rm -f /usr/local/bin/oxidize-daemon

    echo -e "${YELLOW}Removing service files...${NC}"
    rm -f /etc/systemd/system/oxidize.service
    rm -f /etc/systemd/system/oxidize-daemon.service
    rm -rf /etc/systemd/system/oxidize.service.d
    rm -rf /etc/systemd/system/oxidize-daemon.service.d

    echo -e "${YELLOW}Removing system config...${NC}"
    rm -rf /etc/oxidize

    echo -e "${YELLOW}Removing runtime directories...${NC}"
    rm -rf /var/run/oxidize

    echo -e "${YELLOW}Cleaning iptables NFQUEUE rules...${NC}"
    iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -p udp --dport 67 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -p udp --dport 68 -j ACCEPT 2>/dev/null || true

    echo -e "${YELLOW}Removing system user...${NC}"
    userdel oxidize 2>/dev/null || true

    systemctl daemon-reload 2>/dev/null || true
}

uninstall_macos() {
    echo -e "${YELLOW}Stopping launchd service...${NC}"
    launchctl unload /Library/LaunchDaemons/com.oxidize.client.plist 2>/dev/null || true

    echo -e "${YELLOW}Removing binaries...${NC}"
    rm -f /usr/local/bin/oxidize-client
    rm -f /usr/local/bin/oxidize-daemon

    echo -e "${YELLOW}Removing launchd plist...${NC}"
    rm -f /Library/LaunchDaemons/com.oxidize.client.plist

    echo -e "${YELLOW}Removing system config...${NC}"
    rm -rf /etc/oxidize

    echo -e "${YELLOW}Removing logs...${NC}"
    rm -f /var/log/oxidize.log
    rm -f /var/log/oxidize.error.log
}

uninstall_user_data() {
    echo -e "${YELLOW}Removing user app data...${NC}"
    
    # Tauri app data directories
    rm -rf "$REAL_HOME/.local/share/oxidize-app"
    rm -rf "$REAL_HOME/.local/share/com.oxidize.app"
    
    # User config
    rm -rf "$REAL_HOME/.config/oxidize"
    
    # macOS app data
    rm -rf "$REAL_HOME/Library/Application Support/com.oxidize.app"
    rm -rf "$REAL_HOME/Library/Caches/com.oxidize.app"
    rm -rf "$REAL_HOME/Library/Preferences/com.oxidize.app.plist"
}

uninstall_windows() {
    echo -e "${YELLOW}Uninstalling on Windows...${NC}"
    
    # Check if we're in Git Bash/MSYS or need to call PowerShell
    INSTALL_DIR="/c/Program Files/Oxidize"
    INSTALL_DIR_WIN="C:\\Program Files\\Oxidize"
    APPDATA_DIR="$LOCALAPPDATA/com.oxidize.app"
    CONFIG_DIR="$APPDATA/Oxidize"
    
    # Stop and remove Windows service via PowerShell
    echo -e "${YELLOW}Stopping service...${NC}"
    powershell.exe -Command "Stop-Service -Name 'OxidizeDaemon' -Force -ErrorAction SilentlyContinue" 2>/dev/null || true
    powershell.exe -Command "sc.exe delete 'OxidizeDaemon'" 2>/dev/null || true
    
    # Remove firewall rule
    echo -e "${YELLOW}Removing firewall rule...${NC}"
    powershell.exe -Command "Remove-NetFirewallRule -DisplayName 'Oxidize Daemon' -ErrorAction SilentlyContinue" 2>/dev/null || true
    
    # Remove install directory
    echo -e "${YELLOW}Removing program files...${NC}"
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}  ✓ Removed $INSTALL_DIR_WIN${NC}"
    fi
    
    # Also try via PowerShell for permissions
    powershell.exe -Command "Remove-Item -Path '$INSTALL_DIR_WIN' -Recurse -Force -ErrorAction SilentlyContinue" 2>/dev/null || true
    
    # Clean WinDivert from PATH
    echo -e "${YELLOW}Cleaning system PATH...${NC}"
    powershell.exe -Command "
        \$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        \$newPath = (\$path -split ';' | Where-Object { \$_ -notlike '*Oxidize*' }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', \$newPath, 'Machine')
    " 2>/dev/null || true
    
    # Remove user app data
    echo -e "${YELLOW}Removing user app data...${NC}"
    [ -d "$APPDATA_DIR" ] && rm -rf "$APPDATA_DIR"
    [ -d "$CONFIG_DIR" ] && rm -rf "$CONFIG_DIR"
    
    # Also via PowerShell
    powershell.exe -Command "
        Remove-Item -Path \"\$env:LOCALAPPDATA\\com.oxidize.app\" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:APPDATA\\Oxidize\" -Recurse -Force -ErrorAction SilentlyContinue
    " 2>/dev/null || true
}

uninstall_wsl() {
    echo -e "${YELLOW}Detected WSL - cleaning both Linux and Windows installations...${NC}"
    
    # Clean Linux side
    uninstall_linux
    
    # Also clean Windows side if accessible
    if command -v powershell.exe &> /dev/null; then
        echo -e "${YELLOW}Cleaning Windows installation from WSL...${NC}"
        uninstall_windows
    fi
}

uninstall_local_builds() {
    local repo_path="$1"
    
    if [ -z "$repo_path" ] || [ ! -d "$repo_path" ]; then
        return
    fi
    
    echo -e "${YELLOW}Cleaning local builds in $repo_path...${NC}"
    
    # Clean Rust target directories (client, server, daemon, common)
    if [ -d "$repo_path/target" ]; then
        echo "  Removing target/ directory..."
        rm -rf "$repo_path/target"
    fi
    
    # Clean Tauri app builds
    if [ -d "$repo_path/app/src-tauri/target" ]; then
        echo "  Removing app/src-tauri/target/ directory..."
        rm -rf "$repo_path/app/src-tauri/target"
    fi
    
    # Clean Tauri generated files
    if [ -d "$repo_path/app/src-tauri/gen" ]; then
        echo "  Removing app/src-tauri/gen/ directory..."
        rm -rf "$repo_path/app/src-tauri/gen"
    fi
    
    # Clean node_modules for Tauri frontend
    if [ -d "$repo_path/app/node_modules" ]; then
        echo "  Removing app/node_modules/ directory..."
        rm -rf "$repo_path/app/node_modules"
    fi
    
    # Clean bun lockfile artifacts
    rm -f "$repo_path/app/bun.lockb" 2>/dev/null || true
    
    # Clean any downloaded HF models
    if [ -d "$repo_path/hf_download" ]; then
        echo "  Removing hf_download/ directory..."
        rm -rf "$repo_path/hf_download"
    fi
    
    echo -e "${GREEN}  ✓ Local builds cleaned${NC}"
}

print_success() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           ✅ Oxidize Completely Uninstalled!              ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}Removed:${NC}"
    echo "  • Binaries from /usr/local/bin"
    echo "  • Systemd/launchd services"
    echo "  • Configuration from /etc/oxidize"
    echo "  • User app data"
    echo "  • iptables NFQUEUE rules"
    echo "  • System user 'oxidize'"
    echo "  • Local builds (target/, node_modules/, Tauri gen/)"
    echo ""
    echo -e "${GREEN}Your system is clean!${NC}"
    echo ""
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --local-only       Only clean local builds (no system uninstall)"
    echo "  --repo PATH        Specify custom repo path for local builds cleanup"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0                           # Full uninstall"
    echo "  sudo $0 --repo /path/to/oxidize   # Full uninstall + clean specific repo"
    echo "  $0 --local-only                   # Only clean local builds (no sudo needed)"
}

main() {
    LOCAL_ONLY=false
    CUSTOM_REPO=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --local-only)
                LOCAL_ONLY=true
                shift
                ;;
            --repo)
                CUSTOM_REPO="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    if [ "$LOCAL_ONLY" = true ]; then
        echo -e "${YELLOW}Local-only mode: cleaning build artifacts only${NC}"
        REAL_HOME="$HOME"
        
        # Use custom repo or detect from script location
        if [ -n "$CUSTOM_REPO" ]; then
            uninstall_local_builds "$CUSTOM_REPO"
        else
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
            REPO_DIR="$(dirname "$SCRIPT_DIR")"
            if [ -f "$REPO_DIR/Cargo.toml" ]; then
                uninstall_local_builds "$REPO_DIR"
            else
                echo -e "${RED}Could not detect oxidize repo. Use --repo PATH${NC}"
                exit 1
            fi
        fi
        
        echo -e "${GREEN}✅ Local builds cleaned!${NC}"
        exit 0
    fi
    
    detect_os
    check_root
    get_real_user

    case $OS in
        ubuntu|debian|fedora|centos|rhel|arch|pop|linuxmint|elementary|zorin|linux)
            uninstall_linux
            ;;
        macos)
            uninstall_macos
            ;;
        windows)
            uninstall_windows
            ;;
        wsl)
            uninstall_wsl
            ;;
        *)
            echo -e "${YELLOW}Unknown OS - attempting Linux uninstall...${NC}"
            uninstall_linux
            ;;
    esac

    uninstall_user_data
    
    # Clean custom repo if specified
    if [ -n "$CUSTOM_REPO" ]; then
        uninstall_local_builds "$CUSTOM_REPO"
    fi
    
    # Check if running from repo directory and clean local builds
    if [ -f "$REAL_HOME/.oxidize-install-path" ]; then
        INSTALL_PATH=$(cat "$REAL_HOME/.oxidize-install-path")
        if [ -d "$INSTALL_PATH" ]; then
            uninstall_local_builds "$INSTALL_PATH"
        fi
    fi
    
    # Also check current directory if it looks like oxidize repo
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
    REPO_DIR="$(dirname "$SCRIPT_DIR")"
    if [ -f "$REPO_DIR/Cargo.toml" ] && grep -q "oxidize" "$REPO_DIR/Cargo.toml" 2>/dev/null; then
        uninstall_local_builds "$REPO_DIR"
    fi
    
    print_success
}

main "$@"
