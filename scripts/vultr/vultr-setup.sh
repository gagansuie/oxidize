#!/bin/bash
#
# Vultr Bare Metal Setup Script for Oxidize
# Configures AF_XDP/XDP kernel bypass for high-performance networking
#
# Usage: sudo ./vultr-setup.sh
#
# Tested on: Ubuntu 22.04/24.04, Debian 12
# Vultr Chicago (ord) bare metal with 25 Gbps NIC

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
echo "║     VULTR BARE METAL SETUP FOR OXIDIZE                    ║"
echo "║     AF_XDP/XDP High-Performance Networking                ║"
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

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [[ $KERNEL_MAJOR -lt 5 ]] || [[ $KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 4 ]]; then
    log_error "Kernel version $KERNEL_VERSION is too old. AF_XDP requires Linux 5.4+"
    exit 1
fi
log_success "Kernel $KERNEL_VERSION supports AF_XDP"

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
    libelf-dev \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    bpftool \
    clang \
    llvm \
    pciutils \
    hwloc \
    numactl \
    curl \
    git \
    htop \
    iotop \
    net-tools \
    ethtool \
    iproute2

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

TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

if [[ $TOTAL_RAM_GB -ge 64 ]]; then
    HUGEPAGES=2048  # 4GB
elif [[ $TOTAL_RAM_GB -ge 32 ]]; then
    HUGEPAGES=1024  # 2GB
else
    HUGEPAGES=512   # 1GB
fi

log_info "Setting $HUGEPAGES hugepages"

echo $HUGEPAGES > /proc/sys/vm/nr_hugepages

if ! grep -q "vm.nr_hugepages" /etc/sysctl.conf; then
    echo "vm.nr_hugepages = $HUGEPAGES" >> /etc/sysctl.conf
fi

if ! mount | grep -q hugetlbfs; then
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
fi

log_success "Hugepages configured: $(cat /proc/sys/vm/nr_hugepages)"

# ============================================
# Step 4: Enable BPF JIT
# ============================================
log_info "Enabling BPF JIT compiler..."

echo 1 > /proc/sys/net/core/bpf_jit_enable
if ! grep -q "net.core.bpf_jit_enable" /etc/sysctl.conf; then
    echo "net.core.bpf_jit_enable = 1" >> /etc/sysctl.conf
fi

log_success "BPF JIT enabled"

# ============================================
# Step 5: Detect Network Interface
# ============================================
log_info "Detecting network interfaces..."

DEFAULT_IF=$(ip route | grep default | awk '{print $5}' | head -1)
XDP_DRIVERS="i40e ixgbe mlx5_core mlx4_en nfp bnxt_en virtio_net veth igb e1000e"

if [[ -n "$DEFAULT_IF" ]]; then
    DRIVER=$(ethtool -i $DEFAULT_IF 2>/dev/null | grep "driver" | awk '{print $2}')
    log_info "Default interface: $DEFAULT_IF (driver: $DRIVER)"
    
    if echo "$XDP_DRIVERS" | grep -qw "$DRIVER"; then
        log_success "Driver $DRIVER supports native XDP mode"
    else
        log_warn "Driver $DRIVER may only support generic XDP mode"
    fi
fi

# ============================================
# Step 6: Create Directories
# ============================================
log_info "Creating Oxidize directories..."

mkdir -p /etc/oxidize
mkdir -p /var/log/oxidize
mkdir -p /var/run/oxidize
mkdir -p /etc/oxidize/certs
mkdir -p /opt/oxidize

log_success "Directories created"

# ============================================
# Step 7: System Tuning
# ============================================
log_info "Applying system tuning..."

cat > /etc/sysctl.d/99-oxidize-xdp.conf << EOF
# Oxidize AF_XDP Performance Tuning
net.core.bpf_jit_enable = 1
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 65535
net.ipv4.udp_mem = 131072 262144 524288
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
vm.swappiness = 10
fs.file-max = 4194304
EOF

sysctl -p /etc/sysctl.d/99-oxidize-xdp.conf > /dev/null 2>&1 || true

cat > /etc/security/limits.d/99-oxidize.conf << EOF
* soft nofile 2097152
* hard nofile 2097152
* soft memlock unlimited
* hard memlock unlimited
EOF

log_success "System tuning applied"

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     VULTR AF_XDP SETUP COMPLETE                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_success "Kernel:     $(uname -r) (AF_XDP ready)"
log_success "BPF JIT:    Enabled"
log_success "Hugepages:  $(cat /proc/sys/vm/nr_hugepages) x 2MB"
log_success "Interface:  ${DEFAULT_IF:-eth0}"
echo ""
echo "Next steps:"
echo "  1. Run: ./scripts/vultr/vultr-deploy.sh"
echo ""
