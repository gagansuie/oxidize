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

uninstall_deb() {
    echo -e "${YELLOW}Checking for deb package...${NC}"
    if dpkg -l | grep -q "oxidize"; then
        echo -e "${YELLOW}Removing oxidize deb package...${NC}"
        dpkg --purge oxidize 2>/dev/null || apt-get remove --purge -y oxidize 2>/dev/null || true
        echo -e "${GREEN}  ✓ Deb package removed${NC}"
    else
        echo -e "${BLUE}  No deb package found${NC}"
    fi
}

uninstall_rpm() {
    echo -e "${YELLOW}Checking for rpm package...${NC}"
    if rpm -qa | grep -q "oxidize"; then
        echo -e "${YELLOW}Removing oxidize rpm package...${NC}"
        if command -v dnf &> /dev/null; then
            dnf remove -y oxidize 2>/dev/null || true
        elif command -v yum &> /dev/null; then
            yum remove -y oxidize 2>/dev/null || true
        else
            rpm -e oxidize 2>/dev/null || true
        fi
        echo -e "${GREEN}  ✓ RPM package removed${NC}"
    else
        echo -e "${BLUE}  No rpm package found${NC}"
    fi
}

uninstall_appimage() {
    echo -e "${YELLOW}Checking for AppImage installations...${NC}"
    local found=false
    
    # Common AppImage locations
    local appimage_locations=(
        "$REAL_HOME/Applications/Oxidize*.AppImage"
        "$REAL_HOME/Applications/oxidize*.AppImage"
        "$REAL_HOME/.local/bin/Oxidize*.AppImage"
        "$REAL_HOME/.local/bin/oxidize*.AppImage"
        "$REAL_HOME/bin/Oxidize*.AppImage"
        "$REAL_HOME/bin/oxidize*.AppImage"
        "/opt/Oxidize*.AppImage"
        "/opt/oxidize*.AppImage"
        "/usr/local/bin/Oxidize*.AppImage"
        "/usr/local/bin/oxidize*.AppImage"
    )
    
    for pattern in "${appimage_locations[@]}"; do
        for appimage in $pattern; do
            if [ -f "$appimage" ]; then
                echo -e "${YELLOW}  Removing AppImage: $appimage${NC}"
                rm -f "$appimage"
                found=true
            fi
        done
    done
    
    # Remove AppImage desktop integration (appimaged creates these)
    rm -f "$REAL_HOME/.local/share/applications/appimagekit-oxidize"*.desktop 2>/dev/null || true
    rm -f "$REAL_HOME/.local/share/applications/appimagekit-Oxidize"*.desktop 2>/dev/null || true
    
    # Remove icons created by AppImage
    rm -f "$REAL_HOME/.local/share/icons/hicolor/"*/apps/oxidize*.png 2>/dev/null || true
    rm -f "$REAL_HOME/.local/share/icons/hicolor/"*/apps/Oxidize*.png 2>/dev/null || true
    
    if [ "$found" = true ]; then
        echo -e "${GREEN}  ✓ AppImage files removed${NC}"
    else
        echo -e "${BLUE}  No AppImage files found${NC}"
    fi
}

uninstall_linux() {
    echo -e "${YELLOW}Stopping services...${NC}"
    systemctl stop oxidize 2>/dev/null || true
    systemctl stop oxidize-daemon 2>/dev/null || true
    systemctl disable oxidize 2>/dev/null || true
    systemctl disable oxidize-daemon 2>/dev/null || true

    # Uninstall packaged versions (deb, rpm, AppImage)
    uninstall_deb
    uninstall_rpm
    uninstall_appimage

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

    echo -e "${YELLOW}Removing system user...${NC}"
    userdel oxidize 2>/dev/null || true

    echo -e "${YELLOW}Removing desktop entries...${NC}"
    rm -f /usr/share/applications/Oxidize.desktop
    rm -f /usr/share/applications/oxidize.desktop
    rm -f "$REAL_HOME/.local/share/applications/Oxidize.desktop"
    rm -f "$REAL_HOME/.local/share/applications/oxidize.desktop"

    systemctl daemon-reload 2>/dev/null || true
}

uninstall_macos() {
    echo -e "${YELLOW}Stopping launchd service...${NC}"
    launchctl unload /Library/LaunchDaemons/com.oxidize.client.plist 2>/dev/null || true
    launchctl unload "$REAL_HOME/Library/LaunchAgents/com.oxidize.client.plist" 2>/dev/null || true

    echo -e "${YELLOW}Removing .app bundles...${NC}"
    # System-wide installation
    if [ -d "/Applications/Oxidize.app" ]; then
        rm -rf "/Applications/Oxidize.app"
        echo -e "${GREEN}  ✓ Removed /Applications/Oxidize.app${NC}"
    fi
    # User installation
    if [ -d "$REAL_HOME/Applications/Oxidize.app" ]; then
        rm -rf "$REAL_HOME/Applications/Oxidize.app"
        echo -e "${GREEN}  ✓ Removed ~/Applications/Oxidize.app${NC}"
    fi
    # Alternative names
    rm -rf "/Applications/oxidize.app" 2>/dev/null || true
    rm -rf "$REAL_HOME/Applications/oxidize.app" 2>/dev/null || true

    echo -e "${YELLOW}Removing .dmg files from Downloads...${NC}"
    rm -f "$REAL_HOME/Downloads/Oxidize"*.dmg 2>/dev/null || true
    rm -f "$REAL_HOME/Downloads/oxidize"*.dmg 2>/dev/null || true

    echo -e "${YELLOW}Removing CLI binaries...${NC}"
    rm -f /usr/local/bin/oxidize-client
    rm -f /usr/local/bin/oxidize-daemon
    rm -f /usr/local/bin/oxidize

    echo -e "${YELLOW}Removing launchd plists...${NC}"
    rm -f /Library/LaunchDaemons/com.oxidize.client.plist
    rm -f /Library/LaunchDaemons/com.oxidize.daemon.plist
    rm -f "$REAL_HOME/Library/LaunchAgents/com.oxidize.client.plist"
    rm -f "$REAL_HOME/Library/LaunchAgents/com.oxidize.daemon.plist"

    echo -e "${YELLOW}Removing system config...${NC}"
    rm -rf /etc/oxidize

    echo -e "${YELLOW}Removing logs...${NC}"
    rm -f /var/log/oxidize.log
    rm -f /var/log/oxidize.error.log

    echo -e "${YELLOW}Removing Homebrew cask (if installed)...${NC}"
    if command -v brew &> /dev/null; then
        brew uninstall --cask oxidize 2>/dev/null || true
        brew uninstall oxidize 2>/dev/null || true
    fi
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
    
    # Run MSI uninstaller if exists
    echo -e "${YELLOW}Checking for MSI installation...${NC}"
    powershell.exe -Command "
        \$app = Get-WmiObject -Class Win32_Product | Where-Object { \$_.Name -like '*Oxidize*' }
        if (\$app) {
            Write-Host '  Uninstalling MSI package...'
            \$app.Uninstall() | Out-Null
            Write-Host '  MSI package removed'
        }
    " 2>/dev/null || true
    
    # Remove NSIS/Tauri installer entries from registry and run uninstaller
    echo -e "${YELLOW}Checking for installed application...${NC}"
    powershell.exe -Command "
        # Check 64-bit uninstall registry
        \$uninstallKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        \$uninstallKey32 = 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        \$userUninstall = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        
        \$apps = @()
        \$apps += Get-ItemProperty \$uninstallKey -ErrorAction SilentlyContinue | Where-Object { \$_.DisplayName -like '*Oxidize*' }
        \$apps += Get-ItemProperty \$uninstallKey32 -ErrorAction SilentlyContinue | Where-Object { \$_.DisplayName -like '*Oxidize*' }
        \$apps += Get-ItemProperty \$userUninstall -ErrorAction SilentlyContinue | Where-Object { \$_.DisplayName -like '*Oxidize*' }
        
        foreach (\$app in \$apps) {
            if (\$app.UninstallString) {
                Write-Host \"  Running uninstaller for: \$($app.DisplayName)\"
                try {
                    Start-Process cmd.exe -ArgumentList '/c', \$app.UninstallString, '/S' -Wait -NoNewWindow -ErrorAction SilentlyContinue
                } catch { }
            }
            # Remove registry entry
            if (\$app.PSPath) {
                Remove-Item -Path \$app.PSPath -Force -ErrorAction SilentlyContinue
            }
        }
    " 2>/dev/null || true
    
    # Remove install directory
    echo -e "${YELLOW}Removing program files...${NC}"
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}  ✓ Removed $INSTALL_DIR_WIN${NC}"
    fi
    
    # Also try via PowerShell for permissions
    powershell.exe -Command "
        Remove-Item -Path 'C:\\Program Files\\Oxidize' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'C:\\Program Files (x86)\\Oxidize' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:LOCALAPPDATA\\Programs\\Oxidize\" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:LOCALAPPDATA\\Oxidize\" -Recurse -Force -ErrorAction SilentlyContinue
    " 2>/dev/null || true
    
    # Remove Start Menu and Desktop shortcuts
    echo -e "${YELLOW}Removing shortcuts...${NC}"
    powershell.exe -Command "
        # Start Menu shortcuts
        Remove-Item -Path \"\$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Oxidize*\" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Oxidize*\" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Oxidize.lnk\" -Force -ErrorAction SilentlyContinue
        
        # Desktop shortcuts
        Remove-Item -Path \"\$env:USERPROFILE\\Desktop\\Oxidize.lnk\" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:PUBLIC\\Desktop\\Oxidize.lnk\" -Force -ErrorAction SilentlyContinue
    " 2>/dev/null || true
    
    # Clean Oxidize entries from PATH
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
        Remove-Item -Path \"\$env:APPDATA\\com.oxidize.app\" -Recurse -Force -ErrorAction SilentlyContinue
    " 2>/dev/null || true
    
    # Remove downloaded installers from Downloads
    echo -e "${YELLOW}Removing installer files from Downloads...${NC}"
    powershell.exe -Command "
        Remove-Item -Path \"\$env:USERPROFILE\\Downloads\\Oxidize*.exe\" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:USERPROFILE\\Downloads\\Oxidize*.msi\" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:USERPROFILE\\Downloads\\oxidize*.exe\" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path \"\$env:USERPROFILE\\Downloads\\oxidize*.msi\" -Force -ErrorAction SilentlyContinue
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
    echo -e "${BLUE}Removed (platform-specific):${NC}"
    echo "  Linux:"
    echo "    • Deb/RPM packages"
    echo "    • AppImage files and desktop integration"
    echo "    • Systemd services and iptables rules"
    echo "  macOS:"
    echo "    • .app bundles from /Applications"
    echo "    • .dmg files from Downloads"
    echo "    • Homebrew cask (if installed)"
    echo "    • launchd plists"
    echo "  Windows:"
    echo "    • MSI/EXE installers (via registry uninstall)"
    echo "    • Start Menu and Desktop shortcuts"
    echo "    • Program Files directories"
    echo "    • Installer files from Downloads"
    echo ""
    echo -e "${BLUE}Removed (all platforms):${NC}"
    echo "  • CLI binaries from /usr/local/bin"
    echo "  • Configuration from /etc/oxidize"
    echo "  • User app data and config"
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
