#!/bin/bash
#
# Latitude.sh Bare Metal Setup Script for Oxidize
# Configures AF_XDP/XDP kernel bypass for high-performance networking
#
# Usage: sudo ./latitude-setup.sh
#
# Tested on: Ubuntu 22.04/24.04, Debian 12
# Latitude.sh Chicago with dual 10Gbps NICs
#
# AF_XDP Benefits:
# - Event-driven (no dedicated CPU cores)
# - Low power consumption
# - Full kernel integration
# - 10-25 Gbps throughput
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

# Check kernel version for AF_XDP support
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
# Step 3: Configure Hugepages (optional for AF_XDP)
# ============================================
log_info "Configuring hugepages..."

CURRENT_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
log_info "Current hugepages: $CURRENT_HUGEPAGES"

# Calculate hugepages based on RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

if [[ $TOTAL_RAM_GB -ge 128 ]]; then
    HUGEPAGES=4096  # 8GB for 128GB+ systems
elif [[ $TOTAL_RAM_GB -ge 64 ]]; then
    HUGEPAGES=2048  # 4GB for 64GB systems
elif [[ $TOTAL_RAM_GB -ge 32 ]]; then
    HUGEPAGES=1024  # 2GB for 32GB systems
else
    HUGEPAGES=512   # 1GB for smaller systems
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
# Step 4: Enable BPF JIT
# ============================================
log_info "Enabling BPF JIT compiler..."

echo 1 > /proc/sys/net/core/bpf_jit_enable
if ! grep -q "net.core.bpf_jit_enable" /etc/sysctl.conf; then
    echo "net.core.bpf_jit_enable = 1" >> /etc/sysctl.conf
fi

log_success "BPF JIT enabled"

# ============================================
# Step 5: Detect Network Interfaces (Dual NIC)
# ============================================
log_info "Detecting network interfaces (Latitude.sh dual-NIC setup)..."

echo ""
echo "Available network interfaces:"
echo "══════════════════════════════════════════════════════════════════════"
printf "%-12s %-18s %-10s %-15s %-15s\n" "Interface" "MAC Address" "Speed" "Driver" "XDP Support"
echo "══════════════════════════════════════════════════════════════════════"

MGMT_NIC=""
DATA_NIC=""
NIC_COUNT=0

# XDP-native drivers
XDP_DRIVERS="i40e ixgbe mlx5_core mlx4_en nfp bnxt_en virtio_net veth igb e1000e"

for iface in /sys/class/net/*; do
    iface_name=$(basename "$iface")
    if [[ "$iface_name" != "lo" && -d "$iface/device" ]]; then
        mac=$(cat "$iface/address" 2>/dev/null || echo "N/A")
        speed=$(cat "$iface/speed" 2>/dev/null || echo "?")
        driver=$(basename "$(readlink -f "$iface/device/driver")" 2>/dev/null || echo "N/A")
        
        # Check XDP support
        xdp_support="generic"
        if echo "$XDP_DRIVERS" | grep -qw "$driver"; then
            xdp_support="native ✓"
        fi
        
        printf "%-12s %-18s %-10s %-15s %-15s\n" "$iface_name" "$mac" "${speed}Mbps" "$driver" "$xdp_support"
        
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
else
    log_warn "Only $NIC_COUNT NIC(s) detected - single NIC mode"
    MGMT_NIC=$(ls /sys/class/net | grep -v lo | head -1)
    DATA_NIC=$MGMT_NIC
fi

# ============================================
# Step 6: Create Oxidize directories
# ============================================
log_info "Creating Oxidize directories..."

mkdir -p /etc/oxidize
mkdir -p /var/log/oxidize
mkdir -p /var/run/oxidize
mkdir -p /etc/oxidize/certs

# Save NIC configuration
cat > /etc/oxidize/nic-config.env << EOF
# Latitude.sh Dual-NIC Configuration
# Generated on $(date)

# Management NIC: SSH, API, control plane
MGMT_NIC=$MGMT_NIC

# Data NIC: AF_XDP high-performance data plane
DATA_NIC=$DATA_NIC

# XDP attach mode: native, generic, or offload
XDP_MODE=native
EOF

log_success "NIC config saved to /etc/oxidize/nic-config.env"

# ============================================
# Step 7: System Tuning for High-Performance Networking
# ============================================
log_info "Applying system tuning..."

cat > /etc/sysctl.d/99-oxidize-xdp.conf << EOF
# Oxidize Performance Tuning for AF_XDP
# Latitude.sh High-Performance Configuration

# BPF/XDP settings
net.core.bpf_jit_enable = 1

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

# SO_BUSY_POLL - reduces latency by ~10µs
# Kernel will busy-poll for 50µs before sleeping
net.core.busy_poll = 50
net.core.busy_read = 50
EOF

sysctl -p /etc/sysctl.d/99-oxidize-xdp.conf > /dev/null 2>&1 || true

# Increase limits for AF_XDP
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
# Step 8: CPU Governor (Performance Mode)
# ============================================
log_info "Setting CPU governor to performance mode..."

# Install cpufrequtils if not present
apt-get install -y cpufrequtils 2>/dev/null || true

# Set performance governor for all CPUs
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [[ -f "$cpu" ]]; then
        echo performance > "$cpu" 2>/dev/null || true
    fi
done

# Make persistent via systemd
cat > /etc/systemd/system/cpu-performance.service << 'CPUEOF'
[Unit]
Description=Set CPU Governor to Performance
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $cpu 2>/dev/null || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
CPUEOF

systemctl daemon-reload
systemctl enable cpu-performance.service 2>/dev/null || true

# Disable frequency scaling if available
if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
fi

log_success "CPU governor set to performance"

# ============================================
# Step 9: IRQ Affinity for Multi-Queue NICs
# ============================================
log_info "Configuring IRQ affinity..."

# Create IRQ affinity script
cat > /etc/oxidize/set-irq-affinity.sh << 'IRQEOF'
#!/bin/bash
# Set IRQ affinity for NIC queues
# Spreads interrupts across CPU cores for better parallelism

NIC=${1:-eth0}
CORES=$(nproc)

# Find IRQs for this NIC
IRQS=$(grep "$NIC" /proc/interrupts | awk '{print $1}' | tr -d ':')

if [[ -z "$IRQS" ]]; then
    echo "No IRQs found for $NIC"
    exit 0
fi

CORE=0
for IRQ in $IRQS; do
    # Set affinity to specific core (bitmask)
    MASK=$(printf '%x' $((1 << CORE)))
    echo $MASK > /proc/irq/$IRQ/smp_affinity 2>/dev/null || true
    echo "IRQ $IRQ -> CPU $CORE (mask: $MASK)"
    CORE=$(( (CORE + 1) % CORES ))
done

echo "IRQ affinity configured for $NIC across $CORES cores"
IRQEOF
chmod +x /etc/oxidize/set-irq-affinity.sh

# Apply IRQ affinity now if DATA_NIC is set
if [[ -n "$DATA_NIC" ]]; then
    /etc/oxidize/set-irq-affinity.sh "$DATA_NIC" 2>/dev/null || true
fi

log_success "IRQ affinity configured"

# ============================================
# Step 10: Configure Data NIC for XDP
# ============================================
if [[ -n "$DATA_NIC" ]]; then
    log_info "Configuring data NIC ($DATA_NIC) for XDP..."
    
    # Enable multi-queue for XDP
    QUEUES=$(nproc)
    if [[ $QUEUES -gt 16 ]]; then
        QUEUES=16  # Cap at 16 queues
    fi
    ethtool -L "$DATA_NIC" combined $QUEUES 2>/dev/null || true
    
    # Set ring buffer sizes
    ethtool -G "$DATA_NIC" rx 4096 tx 4096 2>/dev/null || true
    
    # Enable XDP features (keep most offloads for non-XDP traffic)
    ethtool -K "$DATA_NIC" rxvlan off txvlan off 2>/dev/null || true
    
    log_success "Data NIC optimized for XDP"
fi

# ============================================
# Step 11: Create XDP setup script
# ============================================
cat > /etc/oxidize/attach-xdp.sh << 'EOF'
#!/bin/bash
# Attach XDP program to interface
# Usage: ./attach-xdp.sh <interface> <xdp_program.o>

INTERFACE=${1:-eth1}
XDP_PROG=${2:-/opt/oxidize/oxidize-xdp.o}

if [[ ! -f "$XDP_PROG" ]]; then
    echo "XDP program not found: $XDP_PROG"
    echo "Using standard sockets (XDP acceleration disabled)"
    exit 0
fi

# Attach XDP program
ip link set dev $INTERFACE xdp obj $XDP_PROG sec xdp

echo "XDP program attached to $INTERFACE"
ip link show $INTERFACE | grep xdp
EOF
chmod +x /etc/oxidize/attach-xdp.sh

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     LATITUDE.SH AF_XDP SETUP COMPLETE                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_success "Kernel:         $(uname -r) (AF_XDP ready)"
log_success "BPF JIT:        Enabled"
log_success "SO_BUSY_POLL:   50µs (low latency)"
log_success "CPU Governor:   Performance"
log_success "IRQ Affinity:   Multi-queue spread"
log_success "Hugepages:      $(cat /proc/sys/vm/nr_hugepages) x 2MB"
log_success "Total RAM:      ${TOTAL_RAM_GB}GB"
log_success "CPU Cores:      $(nproc)"
log_success "NUMA Nodes:     $(numactl --hardware 2>/dev/null | grep "available:" | awk '{print $2}' || echo '1')"
log_success "Management NIC: $MGMT_NIC"
log_success "Data NIC:       $DATA_NIC"
echo ""

echo "Next steps:"
echo "  1. Deploy server: ./scripts/latitude/latitude-deploy.sh"
echo ""
echo "XDP will be automatically enabled when the server starts."
echo "No reboot required for AF_XDP."
echo ""
