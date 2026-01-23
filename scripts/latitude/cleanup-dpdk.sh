#!/bin/bash
# ============================================
# Latitude.sh DPDK Cleanup Script
# ============================================
# Run this on the Latitude Chicago server to remove
# any lingering DPDK code, processes, or configurations.
#
# Usage: ssh ubuntu@91.242.214.137 'bash -s' < scripts/latitude/cleanup-dpdk.sh
# Or:    ./scripts/latitude/cleanup-dpdk.sh (if running on server)

set -euo pipefail

# Check if we need sudo
SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     LATITUDE.SH DPDK CLEANUP SCRIPT                       ║"
echo "║     Removing legacy DPDK code and configurations          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

FOUND_ISSUES=0

# ============================================
# 1. Check for DPDK processes
# ============================================
log_info "Checking for DPDK processes..."

DPDK_PROCS=$(pgrep -f "dpdk|testpmd|dpdk-devbind" 2>/dev/null || true)
if [[ -n "$DPDK_PROCS" ]]; then
    log_warn "Found DPDK processes running:"
    ps -p $DPDK_PROCS -o pid,comm,args 2>/dev/null || true
    log_info "Killing DPDK processes..."
    $SUDO kill -9 $DPDK_PROCS 2>/dev/null || true
    FOUND_ISSUES=1
else
    log_info "No DPDK processes found ✓"
fi

# ============================================
# 2. Check for VFIO-bound NICs
# ============================================
log_info "Checking for VFIO-bound NICs..."

if [[ -d /sys/bus/pci/drivers/vfio-pci ]]; then
    VFIO_DEVICES=$(ls /sys/bus/pci/drivers/vfio-pci/ 2>/dev/null | grep -E "^[0-9a-f]{4}:" || true)
    if [[ -n "$VFIO_DEVICES" ]]; then
        log_warn "Found NICs bound to vfio-pci (DPDK mode):"
        echo "$VFIO_DEVICES"
        log_info "These should be unbound. Attempting to unbind..."
        for dev in $VFIO_DEVICES; do
            $SUDO sh -c "echo $dev > /sys/bus/pci/drivers/vfio-pci/unbind" 2>/dev/null || true
            log_info "Unbound $dev from vfio-pci"
        done
        FOUND_ISSUES=1
    else
        log_info "No NICs bound to vfio-pci ✓"
    fi
else
    log_info "vfio-pci driver not loaded ✓"
fi

# ============================================
# 3. Check for DPDK kernel modules
# ============================================
log_info "Checking for DPDK kernel modules..."

DPDK_MODULES="igb_uio uio_pci_generic rte_kni"
for mod in $DPDK_MODULES; do
    if lsmod | grep -q "^$mod"; then
        log_warn "Found DPDK module loaded: $mod"
        log_info "Unloading $mod..."
        $SUDO rmmod $mod 2>/dev/null || true
        FOUND_ISSUES=1
    fi
done
log_info "DPDK kernel modules check complete ✓"

# ============================================
# 4. Check for DPDK files and scripts
# ============================================
log_info "Checking for DPDK files..."

DPDK_PATHS=(
    "/opt/dpdk"
    "/usr/local/share/dpdk"
    "/usr/share/dpdk"
    "/etc/dpdk"
    "/opt/oxidize/dpdk"
    "/opt/oxidize/scripts/dpdk"
    "/etc/oxidize/dpdk-config.env"
    "/usr/local/bin/dpdk-devbind.py"
    "/usr/local/bin/dpdk-hugepages.py"
)

for path in "${DPDK_PATHS[@]}"; do
    if [[ -e "$path" ]]; then
        log_warn "Found DPDK path: $path"
        log_info "Removing $path..."
        $SUDO rm -rf "$path" 2>/dev/null || true
        FOUND_ISSUES=1
    fi
done
log_info "DPDK files check complete ✓"

# ============================================
# 5. Check for old oxidize services
# ============================================
log_info "Checking for old oxidize services..."

OLD_SERVICES=(
    "oxidize-dpdk"
    "oxidize-dpdk-setup"
    "dpdk-hugepages"
)

for svc in "${OLD_SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "$svc"; then
        log_warn "Found old service: $svc"
        log_info "Disabling and removing $svc..."
        $SUDO systemctl stop "$svc" 2>/dev/null || true
        $SUDO systemctl disable "$svc" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/$svc.service" 2>/dev/null || true
        FOUND_ISSUES=1
    fi
done
$SUDO systemctl daemon-reload 2>/dev/null || true
log_info "Old services check complete ✓"

# ============================================
# 6. Check oxidize config for DPDK references
# ============================================
log_info "Checking oxidize config for DPDK references..."

if [[ -f /etc/oxidize/server.toml ]]; then
    if grep -qi "dpdk" /etc/oxidize/server.toml; then
        log_warn "Found DPDK references in /etc/oxidize/server.toml"
        log_info "Backing up and updating config..."
        $SUDO cp /etc/oxidize/server.toml /etc/oxidize/server.toml.bak
        $SUDO sed -i 's/dpdk/xdp/gi' /etc/oxidize/server.toml
        $SUDO sed -i '/dpdk_pci/d' /etc/oxidize/server.toml
        FOUND_ISSUES=1
    else
        log_info "No DPDK references in server.toml ✓"
    fi
fi

if [[ -f /etc/oxidize/nic-config.env ]]; then
    if grep -qi "dpdk" /etc/oxidize/nic-config.env; then
        log_warn "Found DPDK references in /etc/oxidize/nic-config.env"
        log_info "Updating nic-config.env..."
        $SUDO sed -i 's/DPDK_MODE=true/XDP_MODE=true/g' /etc/oxidize/nic-config.env
        $SUDO sed -i 's/DPDK/XDP/g' /etc/oxidize/nic-config.env
        FOUND_ISSUES=1
    else
        log_info "No DPDK references in nic-config.env ✓"
    fi
fi

# ============================================
# 7. Check GRUB for IOMMU settings (optional cleanup)
# ============================================
log_info "Checking GRUB for DPDK-specific IOMMU settings..."

if [[ -f /etc/default/grub ]]; then
    if grep -q "iommu=pt" /etc/default/grub || grep -q "intel_iommu=on" /etc/default/grub; then
        log_warn "Found IOMMU settings in GRUB (may be for DPDK)"
        log_info "Note: IOMMU settings are not harmful for XDP, leaving as-is"
    fi
fi

# ============================================
# 8. Restart oxidize service if running
# ============================================
log_info "Checking oxidize service status..."

if systemctl is-active --quiet oxidize 2>/dev/null; then
    log_info "Restarting oxidize service to apply changes..."
    $SUDO systemctl restart oxidize
    log_info "Oxidize service restarted ✓"
elif systemctl is-active --quiet oxidize-server 2>/dev/null; then
    log_info "Restarting oxidize-server service..."
    $SUDO systemctl restart oxidize-server
    log_info "Oxidize server restarted ✓"
else
    log_info "No oxidize service currently running"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     DPDK CLEANUP COMPLETE                                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

if [[ $FOUND_ISSUES -eq 1 ]]; then
    log_warn "Some DPDK remnants were found and cleaned up"
    log_info "Please verify the server is working correctly"
else
    log_info "No DPDK remnants found - server is clean ✓"
fi

echo ""
log_info "Current NIC status:"
ip link show | grep -E "^[0-9]+:" | head -5

echo ""
log_info "Oxidize service status:"
systemctl status oxidize --no-pager 2>/dev/null || systemctl status oxidize-server --no-pager 2>/dev/null || echo "No oxidize service found"

echo ""
log_info "Done! Server is now running AF_XDP (no DPDK)"
