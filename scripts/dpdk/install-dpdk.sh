#!/bin/bash
#
# DPDK Installation Script for Oxidize
# Installs DPDK 25.11 and configures the system for kernel bypass
#
# Usage: sudo ./install-dpdk.sh [--with-mlx5]
#
# Options:
#   --with-mlx5    Include Mellanox mlx5 PMD support (requires OFED)
#
# Tested on: Ubuntu 22.04/24.04, Debian 12
# Requires: 64-bit x86 CPU, 2GB+ RAM, root access

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

# Configuration
DPDK_VERSION="25.11"
DPDK_DIR="/opt/dpdk"
DPDK_BUILD_DIR="/opt/dpdk/build"
INSTALL_MLX5=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --with-mlx5)
            INSTALL_MLX5=true
            shift
            ;;
    esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "Run as root: sudo $0"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     DPDK ${DPDK_VERSION} INSTALLATION FOR OXIDIZE                  ║"
echo "║     High-Performance Kernel Bypass Setup                  ║"
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
# Step 1: Install Build Dependencies
# ============================================
log_info "Installing build dependencies..."

case $OS in
    ubuntu|debian)
        apt-get update
        apt-get install -y \
            build-essential \
            meson \
            ninja-build \
            python3 \
            python3-pip \
            python3-pyelftools \
            libnuma-dev \
            libpcap-dev \
            libssl-dev \
            libjansson-dev \
            pkg-config \
            linux-headers-$(uname -r) \
            pciutils \
            hwloc \
            libhwloc-dev \
            libbsd-dev \
            wget \
            curl \
            tar
        
        # Install pyelftools if not available via apt
        pip3 install pyelftools meson || true
        ;;
    
    fedora|rhel|centos|rocky|alma)
        dnf install -y \
            gcc \
            gcc-c++ \
            meson \
            ninja-build \
            python3 \
            python3-pip \
            python3-pyelftools \
            numactl-devel \
            libpcap-devel \
            openssl-devel \
            jansson-devel \
            pkgconfig \
            kernel-devel \
            pciutils \
            hwloc \
            hwloc-devel \
            libbsd-devel \
            wget \
            curl \
            tar
        ;;
    
    *)
        log_error "Unsupported OS: $OS"
        exit 1
        ;;
esac

log_success "Build dependencies installed"

# ============================================
# Step 2: Install Mellanox OFED (optional)
# ============================================
if [[ "$INSTALL_MLX5" == "true" ]]; then
    log_info "Installing Mellanox OFED for mlx5 PMD support..."
    
    # Check if mlx5 NICs exist
    if lspci | grep -i mellanox > /dev/null; then
        log_info "Mellanox NIC detected, installing OFED..."
        
        case $OS in
            ubuntu|debian)
                # Add Mellanox repo
                wget -qO - https://linux.mellanox.com/public/keys/GPG-KEY-Mellanox.pub | apt-key add -
                echo "deb https://linux.mellanox.com/public/repo/mlnx_ofed/latest/ubuntu${OS_VERSION}/x86_64/" > /etc/apt/sources.list.d/mellanox.list
                apt-get update
                apt-get install -y mlnx-ofed-kernel-dkms rdma-core ibverbs-utils || log_warn "OFED installation failed, continuing without mlx5"
                ;;
            *)
                log_warn "OFED installation not implemented for $OS, skipping mlx5"
                ;;
        esac
    else
        log_warn "No Mellanox NIC detected, skipping OFED installation"
    fi
fi

# ============================================
# Step 3: Download DPDK
# ============================================
log_info "Downloading DPDK ${DPDK_VERSION}..."

mkdir -p /opt
cd /opt

if [[ -d "$DPDK_DIR" ]]; then
    log_warn "DPDK directory exists, removing..."
    rm -rf "$DPDK_DIR"
fi

wget -q "https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz" -O dpdk.tar.xz
tar xf dpdk.tar.xz
# Handle both naming conventions (dpdk-X.Y.Z and dpdk-stable-X.Y.Z)
if [[ -d "dpdk-stable-${DPDK_VERSION}" ]]; then
    mv "dpdk-stable-${DPDK_VERSION}" dpdk
elif [[ -d "dpdk-${DPDK_VERSION}" ]]; then
    mv "dpdk-${DPDK_VERSION}" dpdk
else
    log_error "DPDK directory not found after extraction"
    ls -la
    exit 1
fi
rm dpdk.tar.xz

log_success "DPDK ${DPDK_VERSION} downloaded to ${DPDK_DIR}"

# ============================================
# Step 4: Configure DPDK Build
# ============================================
log_info "Configuring DPDK build..."

cd "$DPDK_DIR"

# Create meson build directory
meson setup build \
    --prefix=/usr/local \
    -Dexamples=all \
    -Dplatform=native \
    -Denable_kmods=true \
    -Dtests=false \
    -Dmax_memseg_lists=512 \
    -Dmax_numa_nodes=8

log_success "DPDK build configured"

# ============================================
# Step 5: Build DPDK
# ============================================
log_info "Building DPDK (this may take 5-10 minutes)..."

cd "$DPDK_BUILD_DIR"
ninja -j$(nproc)

log_success "DPDK built successfully"

# ============================================
# Step 6: Install DPDK
# ============================================
log_info "Installing DPDK..."

ninja install
ldconfig

# Export PKG_CONFIG path
echo 'export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH' >> /etc/profile.d/dpdk.sh
echo 'export LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH' >> /etc/profile.d/dpdk.sh
chmod +x /etc/profile.d/dpdk.sh
source /etc/profile.d/dpdk.sh

log_success "DPDK installed to /usr/local"

# ============================================
# Step 7: Install DPDK Kernel Modules
# ============================================
log_info "Installing DPDK kernel modules..."

# Load vfio-pci (preferred for IOMMU systems)
modprobe vfio-pci || log_warn "vfio-pci not available"

# Install igb_uio if needed (for non-IOMMU systems)
if [[ -f "$DPDK_DIR/kernel/linux/igb_uio/igb_uio.ko" ]]; then
    cp "$DPDK_DIR/kernel/linux/igb_uio/igb_uio.ko" /lib/modules/$(uname -r)/
    depmod -a
    modprobe igb_uio || true
fi

# Make modules persistent
cat > /etc/modules-load.d/dpdk.conf << EOF
vfio-pci
uio
EOF

log_success "Kernel modules configured"

# ============================================
# Step 8: Create DPDK Tools
# ============================================
log_info "Installing DPDK tools..."

# Copy dpdk-devbind.py to PATH
cp "$DPDK_DIR/usertools/dpdk-devbind.py" /usr/local/bin/
chmod +x /usr/local/bin/dpdk-devbind.py

# Create symlink for convenience
ln -sf /usr/local/bin/dpdk-devbind.py /usr/local/bin/dpdk-devbind

log_success "DPDK tools installed"

# ============================================
# Step 9: Verify Installation
# ============================================
log_info "Verifying DPDK installation..."

# Check pkg-config
if pkg-config --exists libdpdk; then
    DPDK_VER=$(pkg-config --modversion libdpdk)
    log_success "DPDK version: $DPDK_VER"
else
    log_warn "pkg-config cannot find libdpdk (may need to source /etc/profile.d/dpdk.sh)"
fi

# Check dpdk-devbind
if command -v dpdk-devbind &> /dev/null; then
    log_success "dpdk-devbind available"
else
    log_warn "dpdk-devbind not in PATH"
fi

# Show available NICs
echo ""
log_info "Available network interfaces:"
dpdk-devbind --status-dev net 2>/dev/null || ip link show

# ============================================
# Summary
# ============================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     DPDK INSTALLATION COMPLETE                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_success "DPDK Version:  ${DPDK_VERSION}"
log_success "Install Path:  /usr/local"
log_success "Config Path:   /etc/profile.d/dpdk.sh"
echo ""

echo "Next steps:"
echo "  1. Source environment:  source /etc/profile.d/dpdk.sh"
echo "  2. Configure hugepages: ./scripts/dpdk/setup-hugepages.sh"
echo "  3. Bind NIC to DPDK:    ./scripts/dpdk/bind-nic.sh <interface>"
echo ""
echo "Example:"
echo "  dpdk-devbind --status-dev net    # Show NIC status"
echo "  dpdk-devbind -b vfio-pci 0000:01:00.1  # Bind NIC to DPDK"
echo ""
