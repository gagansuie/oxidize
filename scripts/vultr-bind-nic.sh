#!/bin/bash
#
# Vultr NIC Binding Script for DPDK
# Binds a network interface to VFIO-PCI for kernel bypass
#
# Usage: sudo ./vultr-bind-nic.sh [interface|pci_address]
#
# Examples:
#   sudo ./vultr-bind-nic.sh eth1           # Bind by interface name
#   sudo ./vultr-bind-nic.sh 0000:01:00.0   # Bind by PCI address
#   sudo ./vultr-bind-nic.sh --list         # List available NICs
#   sudo ./vultr-bind-nic.sh --unbind eth1  # Restore to kernel driver

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

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "Run as root: sudo $0"
    exit 1
fi

# State file to track original drivers
STATE_FILE="/etc/oxidize/nic-binding-state"
mkdir -p /etc/oxidize

# ============================================
# Helper Functions
# ============================================

# Get PCI address from interface name
get_pci_from_iface() {
    local iface=$1
    local pci_path="/sys/class/net/$iface/device"
    if [[ -L "$pci_path" ]]; then
        basename "$(readlink -f "$pci_path")"
    fi
}

# Get interface name from PCI address
get_iface_from_pci() {
    local pci=$1
    for net in /sys/bus/pci/devices/$pci/net/*; do
        if [[ -d "$net" ]]; then
            basename "$net"
            return
        fi
    done
}

# Get current driver for PCI device
get_driver() {
    local pci=$1
    local driver_path="/sys/bus/pci/devices/$pci/driver"
    if [[ -L "$driver_path" ]]; then
        basename "$(readlink -f "$driver_path")"
    fi
}

# Get vendor and device ID
get_device_id() {
    local pci=$1
    local vendor=$(cat "/sys/bus/pci/devices/$pci/vendor" 2>/dev/null)
    local device=$(cat "/sys/bus/pci/devices/$pci/device" 2>/dev/null)
    echo "$vendor $device"
}

# List all network devices
list_devices() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║     AVAILABLE NETWORK DEVICES                                         ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo ""
    printf "%-14s %-12s %-15s %-10s %-20s\n" "PCI Address" "Interface" "Driver" "Speed" "Description"
    echo "────────────────────────────────────────────────────────────────────────────"
    
    for pci in /sys/bus/pci/devices/*; do
        pci_addr=$(basename "$pci")
        class=$(cat "$pci/class" 2>/dev/null || echo "")
        
        # Check if it's a network device (class 0x02xxxx)
        if [[ "$class" == 0x02* ]]; then
            iface=$(get_iface_from_pci "$pci_addr")
            driver=$(get_driver "$pci_addr")
            
            # Get speed if interface exists
            speed="N/A"
            if [[ -n "$iface" ]] && [[ -f "/sys/class/net/$iface/speed" ]]; then
                speed_val=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "?")
                if [[ "$speed_val" != "?" ]] && [[ "$speed_val" -gt 0 ]]; then
                    if [[ "$speed_val" -ge 10000 ]]; then
                        speed="${speed_val}Mbps"
                    else
                        speed="${speed_val}Mbps"
                    fi
                fi
            fi
            
            # Get description from lspci
            desc=$(lspci -s "$pci_addr" 2>/dev/null | cut -d: -f3 | xargs || echo "Unknown")
            desc=${desc:0:20}
            
            # Mark if bound to DPDK
            if [[ "$driver" == "vfio-pci" ]] || [[ "$driver" == "uio_pci_generic" ]]; then
                driver="${driver} (DPDK)"
                iface="<bound>"
            fi
            
            printf "%-14s %-12s %-15s %-10s %-20s\n" \
                "$pci_addr" "${iface:-<none>}" "${driver:-<none>}" "$speed" "$desc"
        fi
    done
    
    echo ""
    echo "DPDK-compatible drivers: Intel i350, i210, x520, x540, x550, x710, xxv710"
    echo "                         Mellanox ConnectX-4/5/6"
    echo ""
    
    # Show binding state
    if [[ -f "$STATE_FILE" ]]; then
        echo "Currently bound to DPDK (from state file):"
        cat "$STATE_FILE"
        echo ""
    fi
}

# Bind NIC to VFIO-PCI
bind_to_dpdk() {
    local pci=$1
    
    log_info "Binding $pci to vfio-pci..."
    
    # Get current driver
    local current_driver=$(get_driver "$pci")
    local iface=$(get_iface_from_pci "$pci")
    
    if [[ "$current_driver" == "vfio-pci" ]]; then
        log_success "Already bound to vfio-pci"
        return 0
    fi
    
    # Check if this is the management interface (has default route)
    if [[ -n "$iface" ]]; then
        local has_default_route=$(ip route show default | grep "$iface" || true)
        if [[ -n "$has_default_route" ]]; then
            log_error "Interface $iface has the default route!"
            log_error "Binding this to DPDK will disconnect you from the server."
            log_error "Use a secondary NIC for DPDK, or configure OOB management."
            echo ""
            read -p "Are you SURE you want to continue? (type 'yes' to confirm): " confirm
            if [[ "$confirm" != "yes" ]]; then
                log_info "Aborted."
                exit 1
            fi
        fi
        
        # Bring interface down
        log_info "Bringing down interface $iface..."
        ip link set "$iface" down 2>/dev/null || true
    fi
    
    # Save original driver state
    if [[ -n "$current_driver" ]]; then
        echo "$pci $current_driver $iface" >> "$STATE_FILE"
        log_info "Saved original driver: $current_driver"
    fi
    
    # Unbind from current driver
    if [[ -n "$current_driver" ]]; then
        log_info "Unbinding from $current_driver..."
        echo "$pci" > "/sys/bus/pci/devices/$pci/driver/unbind" 2>/dev/null || true
    fi
    
    # Get device ID for vfio-pci
    local dev_id=$(get_device_id "$pci")
    
    # Load vfio-pci if needed
    modprobe vfio-pci 2>/dev/null || true
    
    # Enable unsafe IOMMU if needed (for systems without proper IOMMU)
    if [[ ! -d "/sys/bus/pci/drivers/vfio-pci" ]]; then
        log_warn "Enabling vfio-pci with allow_unsafe_interrupts..."
        modprobe vfio enable_unsafe_noiommu_mode=1 2>/dev/null || true
        modprobe vfio-pci 2>/dev/null || true
    fi
    
    # Bind to vfio-pci
    log_info "Binding to vfio-pci..."
    echo "$dev_id" > /sys/bus/pci/drivers/vfio-pci/new_id 2>/dev/null || true
    echo "$pci" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || {
        # Try uio_pci_generic as fallback
        log_warn "vfio-pci bind failed, trying uio_pci_generic..."
        modprobe uio_pci_generic
        echo "$dev_id" > /sys/bus/pci/drivers/uio_pci_generic/new_id 2>/dev/null || true
        echo "$pci" > /sys/bus/pci/drivers/uio_pci_generic/bind
    }
    
    # Verify
    local new_driver=$(get_driver "$pci")
    if [[ "$new_driver" == "vfio-pci" ]] || [[ "$new_driver" == "uio_pci_generic" ]]; then
        log_success "Successfully bound $pci to $new_driver"
        
        # Set permissions for non-root access (optional)
        chmod 666 /dev/vfio/* 2>/dev/null || true
    else
        log_error "Failed to bind $pci to DPDK driver"
        exit 1
    fi
}

# Unbind NIC from DPDK (restore kernel driver)
unbind_from_dpdk() {
    local pci=$1
    
    log_info "Restoring $pci to kernel driver..."
    
    local current_driver=$(get_driver "$pci")
    
    if [[ "$current_driver" != "vfio-pci" ]] && [[ "$current_driver" != "uio_pci_generic" ]]; then
        log_warn "$pci is not bound to DPDK driver (current: $current_driver)"
        return 0
    fi
    
    # Find original driver from state file
    local original_driver=""
    if [[ -f "$STATE_FILE" ]]; then
        original_driver=$(grep "^$pci " "$STATE_FILE" | awk '{print $2}')
    fi
    
    if [[ -z "$original_driver" ]]; then
        # Try to detect appropriate driver
        local vendor=$(cat "/sys/bus/pci/devices/$pci/vendor" 2>/dev/null)
        case "$vendor" in
            0x8086) original_driver="ixgbe" ;;  # Intel 10G
            0x15b3) original_driver="mlx5_core" ;;  # Mellanox
            *)      original_driver="ixgbe" ;;  # Default guess
        esac
        log_warn "No saved driver, guessing: $original_driver"
    fi
    
    # Unbind from DPDK driver
    echo "$pci" > "/sys/bus/pci/devices/$pci/driver/unbind" 2>/dev/null || true
    
    # Load and bind to kernel driver
    modprobe "$original_driver" 2>/dev/null || true
    
    # Trigger driver probe
    echo "$pci" > /sys/bus/pci/drivers_probe 2>/dev/null || true
    
    sleep 1
    
    local new_driver=$(get_driver "$pci")
    local new_iface=$(get_iface_from_pci "$pci")
    
    if [[ -n "$new_iface" ]]; then
        ip link set "$new_iface" up 2>/dev/null || true
        log_success "Restored $pci to $new_driver (interface: $new_iface)"
    else
        log_success "Restored $pci to $new_driver"
    fi
    
    # Remove from state file
    if [[ -f "$STATE_FILE" ]]; then
        grep -v "^$pci " "$STATE_FILE" > "${STATE_FILE}.tmp" || true
        mv "${STATE_FILE}.tmp" "$STATE_FILE"
    fi
}

# ============================================
# Main
# ============================================

case "${1:-}" in
    --list|-l)
        list_devices
        ;;
    --unbind|-u)
        if [[ -z "${2:-}" ]]; then
            log_error "Usage: $0 --unbind <interface|pci_address>"
            exit 1
        fi
        target=$2
        # Convert interface to PCI if needed
        if [[ "$target" =~ ^[a-z] ]]; then
            pci=$(get_pci_from_iface "$target")
            if [[ -z "$pci" ]]; then
                log_error "Cannot find PCI address for interface $target"
                exit 1
            fi
        else
            pci=$target
        fi
        unbind_from_dpdk "$pci"
        ;;
    --help|-h)
        echo "Usage: $0 [options] [interface|pci_address]"
        echo ""
        echo "Options:"
        echo "  --list, -l           List available network devices"
        echo "  --unbind, -u <dev>   Unbind device from DPDK, restore kernel driver"
        echo "  --help, -h           Show this help"
        echo ""
        echo "Examples:"
        echo "  $0 --list            # List all network devices"
        echo "  $0 eth1              # Bind eth1 to DPDK"
        echo "  $0 0000:01:00.0      # Bind by PCI address"
        echo "  $0 --unbind eth1     # Restore eth1 to kernel driver"
        ;;
    "")
        list_devices
        echo "Usage: $0 <interface|pci_address>"
        echo "       $0 --list"
        ;;
    *)
        target=$1
        # Convert interface to PCI if needed
        if [[ "$target" =~ ^[a-z] ]]; then
            pci=$(get_pci_from_iface "$target")
            if [[ -z "$pci" ]]; then
                log_error "Cannot find PCI address for interface $target"
                exit 1
            fi
            log_info "Interface $target -> PCI $pci"
        else
            pci=$target
        fi
        
        # Verify PCI address exists
        if [[ ! -d "/sys/bus/pci/devices/$pci" ]]; then
            log_error "PCI device $pci not found"
            exit 1
        fi
        
        bind_to_dpdk "$pci"
        
        echo ""
        log_success "NIC ready for DPDK/kernel bypass"
        echo ""
        echo "Next steps:"
        echo "  1. Build Oxidize with kernel-bypass: cargo build --release --features kernel-bypass"
        echo "  2. Run server: sudo ./target/release/oxidize-server --listen 0.0.0.0:4433 --dpdk-pci $pci"
        echo ""
        ;;
esac
