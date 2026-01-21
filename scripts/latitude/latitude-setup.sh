#!/bin/bash
#
# Latitude.sh Bare Metal Setup Script for Oxidize
# Configures hugepages, VFIO, DPDK, and dependencies for kernel bypass
#
# Usage: sudo ./latitude-setup.sh
#
# Tested on: Ubuntu 22.04/24.04, Debian 12
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

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "Run as root: sudo $0"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     LATITUDE.SH BARE METAL SETUP FOR OXIDIZE              ║"
echo "║     Dual-NIC DPDK Kernel Bypass Configuration             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    log_error "Cannot detect OS"
    exit 1
fi
log_info "Detected OS: $OS $OS_VERSION"

# ============================================
# Step 1: Install Dependencies
# ============================================
log_info "Installing dependencies..."

apt-get update -qq

apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libnuma-dev \
    libpcap-dev \
    libelf-dev \
    linux-headers-$(uname -r) \
    pciutils \
    hwloc \
    numactl \
    msr-tools \
    curl \
    git \
    htop \
    iotop \
    net-tools \
    ethtool \
    python3 \
    python3-pip \
    meson \
    ninja-build \
    libbpf-dev \
    clang \
    llvm

log_success "Dependencies installed"

# ============================================
# Step 2: Install Rust (if not present)
# ============================================
if ! command -v cargo &> /dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    log_success "Rust installed"
else
    log_success "Rust already installed: $(rustc --version)"
fi

# ============================================
# Step 3: Configure Hugepages
# ============================================
log_info "Configuring hugepages..."

CURRENT_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
log_info "Current hugepages: $CURRENT_HUGEPAGES"

# Calculate hugepages based on RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

if [[ $TOTAL_RAM_GB -ge 128 ]]; then
    HUGEPAGES=8192  # 16GB for 128GB+ systems
elif [[ $TOTAL_RAM_GB -ge 64 ]]; then
    HUGEPAGES=4096  # 8GB for 64GB systems
elif [[ $TOTAL_RAM_GB -ge 32 ]]; then
    HUGEPAGES=2048  # 4GB for 32GB systems
else
    HUGEPAGES=1024  # 2GB for smaller systems
fi

log_info "Setting $HUGEPAGES hugepages (${HUGEPAGES}x2MB = $((HUGEPAGES * 2))MB)"

# Set hugepages now
echo $HUGEPAGES > /proc/sys/vm/nr_hugepages

# Make persistent
if ! grep -q "vm.nr_hugepages" /etc/sysctl.conf; then
    echo "vm.nr_hugepages = $HUGEPAGES" >> /etc/sysctl.conf
fi

# Mount hugetlbfs if not mounted
if ! mount | grep -q hugetlbfs; then
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
fi

log_success "Hugepages configured: $(cat /proc/sys/vm/nr_hugepages)"

# ============================================
# Step 4: Enable IOMMU (for VFIO/DPDK)
# ============================================
log_info "Checking IOMMU status..."

IOMMU_ENABLED=$(dmesg | grep -i "IOMMU enabled" || true)
if [[ -z "$IOMMU_ENABLED" ]]; then
    log_warn "IOMMU may not be enabled in BIOS/GRUB"
    
    if ! grep -q "intel_iommu=on" /etc/default/grub && ! grep -q "amd_iommu=on" /etc/default/grub; then
        # Detect CPU vendor
        CPU_VENDOR=$(grep -m1 vendor_id /proc/cpuinfo | awk '{print $3}')
        
        if [[ "$CPU_VENDOR" == "GenuineIntel" ]]; then
            IOMMU_PARAM="intel_iommu=on iommu=pt"
        else
            IOMMU_PARAM="amd_iommu=on iommu=pt"
        fi
        
        log_info "Adding IOMMU to GRUB: $IOMMU_PARAM"
        sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"$IOMMU_PARAM /" /etc/default/grub
        
        # Also add hugepages to GRUB for boot-time allocation
        if ! grep -q "hugepagesz" /etc/default/grub; then
            sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"default_hugepagesz=2M hugepagesz=2M hugepages=$HUGEPAGES /" /etc/default/grub
        fi
        
        update-grub
        log_warn "GRUB updated - REBOOT REQUIRED for IOMMU"
        NEEDS_REBOOT=1
    fi
else
    log_success "IOMMU is enabled"
fi

# ============================================
# Step 5: Load VFIO Modules
# ============================================
log_info "Loading VFIO modules..."

modprobe vfio-pci || log_warn "vfio-pci module not available (may need reboot)"
modprobe uio || true
modprobe uio_pci_generic || true

# Make persistent
cat > /etc/modules-load.d/oxidize-dpdk.conf << EOF
vfio-pci
uio
uio_pci_generic
EOF

log_success "VFIO modules configured"

# ============================================
# Step 6: Detect Network Interfaces (Dual NIC)
# ============================================
log_info "Detecting network interfaces (Latitude.sh dual-NIC setup)..."

echo ""
echo "Available network interfaces:"
echo "══════════════════════════════════════════════════════════════════════"
printf "%-12s %-18s %-10s %-15s %-15s\n" "Interface" "MAC Address" "Speed" "Driver" "PCI Address"
echo "══════════════════════════════════════════════════════════════════════"

MGMT_NIC=""
DATA_NIC=""
NIC_COUNT=0

for iface in /sys/class/net/*; do
    iface_name=$(basename "$iface")
    if [[ "$iface_name" != "lo" && -d "$iface/device" ]]; then
        mac=$(cat "$iface/address" 2>/dev/null || echo "N/A")
        speed=$(cat "$iface/speed" 2>/dev/null || echo "?")
        driver=$(basename "$(readlink -f "$iface/device/driver")" 2>/dev/null || echo "N/A")
        pci=$(basename "$(readlink -f "$iface/device")" 2>/dev/null || echo "N/A")
        
        printf "%-12s %-18s %-10s %-15s %-15s\n" "$iface_name" "$mac" "${speed}Mbps" "$driver" "$pci"
        
        # Track NICs for dual-NIC setup
        if [[ $NIC_COUNT -eq 0 ]]; then
            MGMT_NIC="$iface_name"
        elif [[ $NIC_COUNT -eq 1 ]]; then
            DATA_NIC="$iface_name"
        fi
        ((NIC_COUNT++)) || true
    fi
done
echo ""

if [[ $NIC_COUNT -ge 2 ]]; then
    log_success "Dual-NIC detected: Management=$MGMT_NIC, Data=$DATA_NIC"
    
    # Save NIC configuration
    cat > /etc/oxidize/nic-config.env << EOF
# Latitude.sh Dual-NIC Configuration
# Management NIC: SSH, API, control plane
MGMT_NIC=$MGMT_NIC

# Data NIC: DPDK, high-performance data plane
DATA_NIC=$DATA_NIC
EOF
    log_success "NIC config saved to /etc/oxidize/nic-config.env"
else
    log_warn "Only $NIC_COUNT NIC(s) detected - single NIC mode"
    MGMT_NIC=$(ls /sys/class/net | grep -v lo | head -1)
    DATA_NIC=$MGMT_NIC
fi

# Show PCI devices
log_info "PCI network devices:"
echo ""
lspci | grep -i "ethernet\|network" || true
echo ""

# ============================================
# Step 7: Create Oxidize directories
# ============================================
log_info "Creating Oxidize directories..."

mkdir -p /etc/oxidize
mkdir -p /var/log/oxidize
mkdir -p /var/run/oxidize
mkdir -p /etc/oxidize/certs

log_success "Directories created"

# ============================================
# Step 8: System Tuning for High-Performance Networking
# ============================================
log_info "Applying system tuning..."

cat > /etc/sysctl.d/99-oxidize-performance.conf << EOF
# Oxidize Performance Tuning for DPDK Kernel Bypass
# Latitude.sh Dual-NIC High-Performance Configuration

# Network buffers (increased for 10Gbps)
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 65535
net.core.optmem_max = 67108864

# UDP tuning (critical for QUIC)
net.ipv4.udp_mem = 131072 262144 524288
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# TCP tuning (for fallback/control plane)
net.ipv4.tcp_rmem = 4096 131072 268435456
net.ipv4.tcp_wmem = 4096 131072 268435456
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# Connection tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

# Memory
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10

# File descriptors
fs.file-max = 4194304
fs.nr_open = 4194304

# ARP cache (for high connection count)
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 65536
EOF

sysctl -p /etc/sysctl.d/99-oxidize-performance.conf > /dev/null 2>&1 || true

# Increase limits
cat > /etc/security/limits.d/99-oxidize.conf << EOF
* soft nofile 2097152
* hard nofile 2097152
* soft memlock unlimited
* hard memlock unlimited
root soft nofile 2097152
root hard nofile 2097152
root soft memlock unlimited
root hard memlock unlimited
EOF

log_success "System tuning applied"

# ============================================
# Step 9: Disable IRQ Balance (for CPU pinning)
# ============================================
log_info "Configuring IRQ affinity..."

if systemctl is-active --quiet irqbalance; then
    systemctl stop irqbalance
    systemctl disable irqbalance
    log_success "irqbalance disabled (for manual CPU pinning)"
else
    log_success "irqbalance already disabled"
fi

# ============================================
# Step 10: Configure Data NIC for DPDK
# ============================================
if [[ -n "$DATA_NIC" && "$DATA_NIC" != "$MGMT_NIC" ]]; then
    log_info "Configuring data NIC ($DATA_NIC) for high-performance..."
    
    # Enable multi-queue
    ethtool -L "$DATA_NIC" combined $(nproc) 2>/dev/null || true
    
    # Disable offloads for DPDK compatibility
    ethtool -K "$DATA_NIC" rx off tx off sg off tso off gso off gro off lro off 2>/dev/null || true
    
    # Set ring buffer sizes
    ethtool -G "$DATA_NIC" rx 4096 tx 4096 2>/dev/null || true
    
    log_success "Data NIC optimized for kernel bypass"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     LATITUDE.SH SETUP COMPLETE                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_success "Hugepages:     $(cat /proc/sys/vm/nr_hugepages) x 2MB"
log_success "Total RAM:     ${TOTAL_RAM_GB}GB"
log_success "CPU Cores:     $(nproc)"
log_success "NUMA Nodes:    $(numactl --hardware 2>/dev/null | grep "available:" | awk '{print $2}' || echo '1')"
log_success "Management NIC: $MGMT_NIC"
log_success "Data NIC:       $DATA_NIC"
echo ""

if [[ -n "${NEEDS_REBOOT:-}" ]]; then
    echo ""
    log_warn "═══════════════════════════════════════════════════════════"
    log_warn "  REBOOT REQUIRED to enable IOMMU for DPDK"
    log_warn "  Run: sudo reboot"
    log_warn "═══════════════════════════════════════════════════════════"
    echo ""
fi

echo "Next steps:"
echo "  1. Reboot if IOMMU was configured"
echo "  2. Install DPDK:    ./scripts/dpdk/install-dpdk.sh"
echo "  3. Setup hugepages: ./scripts/dpdk/setup-hugepages.sh"
echo "  4. Bind data NIC:   ./scripts/dpdk/bind-nic.sh $DATA_NIC"
echo "  5. Deploy server:   ./scripts/latitude/latitude-deploy.sh"
echo ""
