#!/bin/bash
#
# DPDK NIC Binding Script for Oxidize
# Binds a network interface to DPDK-compatible driver (vfio-pci)
#
# Usage: sudo ./bind-nic.sh <interface_or_pci>
#
# Examples:
#   ./bind-nic.sh eth1           # Bind by interface name
#   ./bind-nic.sh enp1s0f1       # Bind by interface name
#   ./bind-nic.sh 0000:01:00.1   # Bind by PCI address

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "Run as root: sudo $0 <interface>"
    exit 1
fi

# Check arguments
if [[ -z "$1" ]]; then
    echo "Usage: $0 <interface_or_pci_address>"
    echo ""
    echo "Examples:"
    echo "  $0 eth1"
    echo "  $0 enp1s0f1"
    echo "  $0 0000:01:00.1"
    echo ""
    echo "Current NIC status:"
    dpdk-devbind --status-dev net 2>/dev/null || ip link show
    exit 1
fi

TARGET="$1"
PCI_ADDR=""
IFACE_NAME=""

# ============================================
# Step 1: Resolve interface to PCI address
# ============================================
if [[ "$TARGET" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$ ]]; then
    # Already a PCI address
    PCI_ADDR="$TARGET"
    log_info "Using PCI address: $PCI_ADDR"
else
    # Interface name - resolve to PCI
    IFACE_NAME="$TARGET"
    
    if [[ ! -d "/sys/class/net/$IFACE_NAME" ]]; then
        log_error "Interface $IFACE_NAME does not exist"
        exit 1
    fi
    
    # Get PCI address from sysfs
    if [[ -L "/sys/class/net/$IFACE_NAME/device" ]]; then
        PCI_PATH=$(readlink -f "/sys/class/net/$IFACE_NAME/device")
        PCI_ADDR=$(basename "$PCI_PATH")
        log_info "Interface $IFACE_NAME -> PCI $PCI_ADDR"
    else
        log_error "Cannot find PCI address for $IFACE_NAME"
        exit 1
    fi
fi

# ============================================
# Step 2: Check IOMMU
# ============================================
log_info "Checking IOMMU status..."

IOMMU_ENABLED=false
if dmesg | grep -q "IOMMU enabled"; then
    IOMMU_ENABLED=true
    log_success "IOMMU is enabled"
elif [[ -d "/sys/kernel/iommu_groups" ]] && [[ $(ls /sys/kernel/iommu_groups | wc -l) -gt 0 ]]; then
    IOMMU_ENABLED=true
    log_success "IOMMU groups detected"
else
    log_warn "IOMMU may not be enabled"
    log_warn "For vfio-pci, IOMMU is recommended"
    log_warn "Add 'intel_iommu=on' or 'amd_iommu=on' to kernel cmdline"
fi

# ============================================
# Step 3: Load vfio-pci module
# ============================================
log_info "Loading vfio-pci module..."

modprobe vfio-pci || {
    log_error "Failed to load vfio-pci module"
    log_info "Trying uio_pci_generic instead..."
    modprobe uio_pci_generic
}

if lsmod | grep -q vfio_pci; then
    DRIVER="vfio-pci"
    log_success "vfio-pci module loaded"
elif lsmod | grep -q uio_pci_generic; then
    DRIVER="uio_pci_generic"
    log_success "uio_pci_generic module loaded"
else
    log_error "No suitable DPDK driver available"
    exit 1
fi

# ============================================
# Step 4: Get current driver info
# ============================================
log_info "Getting device info for $PCI_ADDR..."

CURRENT_DRIVER=""
if [[ -L "/sys/bus/pci/devices/$PCI_ADDR/driver" ]]; then
    CURRENT_DRIVER=$(basename $(readlink "/sys/bus/pci/devices/$PCI_ADDR/driver"))
fi

if [[ -n "$CURRENT_DRIVER" ]]; then
    log_info "Current driver: $CURRENT_DRIVER"
    
    if [[ "$CURRENT_DRIVER" == "$DRIVER" ]]; then
        log_success "Device already bound to $DRIVER"
        exit 0
    fi
else
    log_info "No current driver (device is unbound)"
fi

# ============================================
# Step 5: Bring interface down (if bound to kernel driver)
# ============================================
if [[ -n "$IFACE_NAME" ]] && ip link show "$IFACE_NAME" &>/dev/null; then
    log_info "Bringing down interface $IFACE_NAME..."
    ip link set "$IFACE_NAME" down || true
fi

# ============================================
# Step 6: Unbind from current driver
# ============================================
if [[ -n "$CURRENT_DRIVER" ]]; then
    log_info "Unbinding from $CURRENT_DRIVER..."
    echo "$PCI_ADDR" > "/sys/bus/pci/devices/$PCI_ADDR/driver/unbind" 2>/dev/null || true
    sleep 1
fi

# ============================================
# Step 7: Enable VFIO no-IOMMU mode if needed
# ============================================
if [[ "$DRIVER" == "vfio-pci" ]] && [[ "$IOMMU_ENABLED" == "false" ]]; then
    log_warn "Enabling VFIO no-IOMMU mode (less secure)..."
    echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true
fi

# ============================================
# Step 8: Bind to DPDK driver
# ============================================
log_info "Binding $PCI_ADDR to $DRIVER..."

# Get vendor and device ID
VENDOR_ID=$(cat "/sys/bus/pci/devices/$PCI_ADDR/vendor" | sed 's/0x//')
DEVICE_ID=$(cat "/sys/bus/pci/devices/$PCI_ADDR/device" | sed 's/0x//')

log_info "Vendor: $VENDOR_ID, Device: $DEVICE_ID"

# Add new device ID to driver
echo "$VENDOR_ID $DEVICE_ID" > "/sys/bus/pci/drivers/$DRIVER/new_id" 2>/dev/null || true

# Bind device
echo "$PCI_ADDR" > "/sys/bus/pci/drivers/$DRIVER/bind" 2>/dev/null || {
    log_error "Failed to bind $PCI_ADDR to $DRIVER"
    log_info "Trying dpdk-devbind..."
    dpdk-devbind -b "$DRIVER" "$PCI_ADDR" || exit 1
}

# ============================================
# Step 9: Verify binding
# ============================================
sleep 1
NEW_DRIVER=""
if [[ -L "/sys/bus/pci/devices/$PCI_ADDR/driver" ]]; then
    NEW_DRIVER=$(basename $(readlink "/sys/bus/pci/devices/$PCI_ADDR/driver"))
fi

if [[ "$NEW_DRIVER" == "$DRIVER" ]]; then
    log_success "Successfully bound $PCI_ADDR to $DRIVER"
else
    log_error "Binding verification failed"
    log_info "Current driver: $NEW_DRIVER (expected: $DRIVER)"
    exit 1
fi

# ============================================
# Step 10: Save binding configuration
# ============================================
mkdir -p /etc/oxidize
echo "PCI_ADDR=$PCI_ADDR" > /etc/oxidize/dpdk-nic.conf
echo "DRIVER=$DRIVER" >> /etc/oxidize/dpdk-nic.conf
echo "ORIGINAL_DRIVER=$CURRENT_DRIVER" >> /etc/oxidize/dpdk-nic.conf
if [[ -n "$IFACE_NAME" ]]; then
    echo "IFACE_NAME=$IFACE_NAME" >> /etc/oxidize/dpdk-nic.conf
fi

log_success "Binding configuration saved to /etc/oxidize/dpdk-nic.conf"

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     NIC BOUND TO DPDK SUCCESSFULLY                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_success "PCI Address: $PCI_ADDR"
log_success "Driver:      $DRIVER"
if [[ -n "$IFACE_NAME" ]]; then
    log_success "Interface:   $IFACE_NAME (no longer visible to kernel)"
fi
echo ""

# Show status
log_info "DPDK NIC Status:"
dpdk-devbind --status-dev net 2>/dev/null | grep -A5 "DPDK-compatible" || true
echo ""
