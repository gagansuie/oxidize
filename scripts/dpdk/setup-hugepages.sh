#!/bin/bash
#
# DPDK Hugepages Setup Script for Oxidize
# Configures hugepages for DPDK memory allocation
#
# Usage: sudo ./setup-hugepages.sh [size_gb]
#
# Arguments:
#   size_gb    Size of hugepages in GB (default: auto-detect based on RAM)

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
    log_error "Run as root: sudo $0 [size_gb]"
    exit 1
fi

# Get system info
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
NUM_CPUS=$(nproc)

# Calculate hugepages size
if [[ -n "$1" ]]; then
    HUGEPAGES_GB="$1"
else
    # Auto-calculate: Use 25% of RAM for hugepages, min 2GB, max 32GB
    HUGEPAGES_GB=$((TOTAL_RAM_GB / 4))
    [[ $HUGEPAGES_GB -lt 2 ]] && HUGEPAGES_GB=2
    [[ $HUGEPAGES_GB -gt 32 ]] && HUGEPAGES_GB=32
fi

# Calculate number of 2MB hugepages
HUGEPAGE_SIZE_MB=2
NUM_HUGEPAGES=$((HUGEPAGES_GB * 1024 / HUGEPAGE_SIZE_MB))

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     HUGEPAGES CONFIGURATION FOR DPDK                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_info "System RAM: ${TOTAL_RAM_GB}GB"
log_info "CPU Cores:  ${NUM_CPUS}"
log_info "Hugepages:  ${HUGEPAGES_GB}GB (${NUM_HUGEPAGES} x 2MB pages)"

# ============================================
# Step 1: Check current hugepages
# ============================================
CURRENT_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
log_info "Current hugepages: $CURRENT_HUGEPAGES"

# ============================================
# Step 2: Mount hugetlbfs if not mounted
# ============================================
if ! mount | grep -q hugetlbfs; then
    log_info "Mounting hugetlbfs..."
    mkdir -p /dev/hugepages
    mount -t hugetlbfs nodev /dev/hugepages
    log_success "hugetlbfs mounted at /dev/hugepages"
else
    log_success "hugetlbfs already mounted"
fi

# ============================================
# Step 3: Configure hugepages at runtime
# ============================================
log_info "Configuring ${NUM_HUGEPAGES} hugepages..."

# Clear page cache first
sync
echo 3 > /proc/sys/vm/drop_caches

# Set hugepages
echo $NUM_HUGEPAGES > /proc/sys/vm/nr_hugepages
sleep 1

# Verify
ACTUAL_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
if [[ $ACTUAL_HUGEPAGES -lt $NUM_HUGEPAGES ]]; then
    log_warn "Only allocated $ACTUAL_HUGEPAGES of $NUM_HUGEPAGES requested"
    log_warn "System may not have enough contiguous memory"
else
    log_success "Allocated $ACTUAL_HUGEPAGES hugepages"
fi

# ============================================
# Step 4: NUMA-aware hugepage allocation
# ============================================
if [[ -d /sys/devices/system/node ]]; then
    NUMA_NODES=$(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l)
    
    if [[ $NUMA_NODES -gt 1 ]]; then
        log_info "NUMA system detected ($NUMA_NODES nodes)"
        PAGES_PER_NODE=$((NUM_HUGEPAGES / NUMA_NODES))
        
        for node in /sys/devices/system/node/node*; do
            NODE_ID=$(basename $node | sed 's/node//')
            echo $PAGES_PER_NODE > "$node/hugepages/hugepages-2048kB/nr_hugepages" 2>/dev/null || true
            ACTUAL=$(cat "$node/hugepages/hugepages-2048kB/nr_hugepages" 2>/dev/null || echo 0)
            log_info "  Node $NODE_ID: $ACTUAL hugepages"
        done
    fi
fi

# ============================================
# Step 5: Make persistent across reboots
# ============================================
log_info "Making hugepages persistent..."

# Add to sysctl
cat > /etc/sysctl.d/99-hugepages.conf << EOF
# DPDK Hugepages Configuration
vm.nr_hugepages = $NUM_HUGEPAGES
vm.hugetlb_shm_group = 0
EOF

# Add to fstab if not present
if ! grep -q hugetlbfs /etc/fstab; then
    echo "nodev /dev/hugepages hugetlbfs defaults 0 0" >> /etc/fstab
    log_success "Added hugetlbfs to /etc/fstab"
fi

# Add to grub for early allocation (more reliable)
GRUB_FILE="/etc/default/grub"
if [[ -f "$GRUB_FILE" ]]; then
    if ! grep -q "hugepages=" "$GRUB_FILE"; then
        log_info "Adding hugepages to GRUB..."
        sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"default_hugepagesz=2M hugepagesz=2M hugepages=$NUM_HUGEPAGES /" "$GRUB_FILE"
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            update-grub
        elif command -v grub2-mkconfig &> /dev/null; then
            grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
        
        log_success "GRUB updated (hugepages will be allocated at boot)"
    else
        log_info "Hugepages already configured in GRUB"
    fi
fi

# ============================================
# Step 6: Verify final configuration
# ============================================
echo ""
log_info "Final hugepage status:"

FINAL_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
HUGEPAGE_FREE=$(grep HugePages_Free /proc/meminfo | awk '{print $2}')
HUGEPAGE_TOTAL=$(grep HugePages_Total /proc/meminfo | awk '{print $2}')

log_success "Total:     $HUGEPAGE_TOTAL pages"
log_success "Free:      $HUGEPAGE_FREE pages"
log_success "Size:      $((HUGEPAGE_TOTAL * 2))MB"

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     HUGEPAGES CONFIGURED SUCCESSFULLY                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_success "Hugepages: $FINAL_HUGEPAGES x 2MB = $((FINAL_HUGEPAGES * 2))MB"
log_success "Mount:     /dev/hugepages"
log_success "Config:    /etc/sysctl.d/99-hugepages.conf"
echo ""

if [[ $FINAL_HUGEPAGES -lt $NUM_HUGEPAGES ]]; then
    log_warn "Requested $NUM_HUGEPAGES but only got $FINAL_HUGEPAGES"
    log_warn "Reboot for full allocation from GRUB"
fi
echo ""
