#!/bin/bash
# Oxidize AF_XDP Setup Script
# Configures system for AF_XDP zero-copy packet I/O
#
# Usage: sudo ./xdp-setup.sh <interface> [port]
# Example: sudo ./xdp-setup.sh eth0 51820

set -e

INTERFACE="${1:-eth0}"
PORT="${2:-51820}"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║            Oxidize AF_XDP Setup                                ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║ Interface: $INTERFACE"
echo "║ Port: $PORT"
echo "╚════════════════════════════════════════════════════════════════╝"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: Must run as root"
    exit 1
fi

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
    echo "❌ Error: Kernel 5.4+ required for AF_XDP (found: $(uname -r))"
    exit 1
fi
echo "✅ Kernel version: $(uname -r)"

# Check interface exists
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "❌ Error: Interface $INTERFACE not found"
    exit 1
fi
echo "✅ Interface $INTERFACE exists"

# Get driver info
DRIVER=$(readlink -f /sys/class/net/$INTERFACE/device/driver 2>/dev/null | xargs basename 2>/dev/null || echo "unknown")
echo "   Driver: $DRIVER"

# Check for XDP-capable drivers
XDP_NATIVE_DRIVERS="i40e ice ixgbe mlx5_core mlx4_en bnxt_en nfp virtio_net veth"
XDP_MODE="generic"
for drv in $XDP_NATIVE_DRIVERS; do
    if [ "$DRIVER" = "$drv" ]; then
        XDP_MODE="native"
        break
    fi
done
echo "   XDP Mode: $XDP_MODE"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
apt-get update -qq
apt-get install -y -qq ethtool iproute2 >/dev/null 2>&1 || true

# Configure NIC for optimal XDP performance
echo ""
echo "🔧 Configuring NIC..."

# Disable GRO/GSO/TSO for XDP (they interfere with zero-copy)
ethtool -K $INTERFACE gro off gso off tso off 2>/dev/null || true
echo "   Disabled GRO/GSO/TSO"

# Enable hardware timestamping if available
ethtool -T $INTERFACE 2>/dev/null | grep -q "hardware-raw-clock" && \
    ethtool -T $INTERFACE rx-hardware-timestamp on 2>/dev/null || true

# Get number of queues
RX_QUEUES=$(ls -d /sys/class/net/$INTERFACE/queues/rx-* 2>/dev/null | wc -l || echo "1")
TX_QUEUES=$(ls -d /sys/class/net/$INTERFACE/queues/tx-* 2>/dev/null | wc -l || echo "1")
echo "   RX Queues: $RX_QUEUES, TX Queues: $TX_QUEUES"

# Configure huge pages for UMEM
echo ""
echo "📄 Configuring huge pages..."
HUGEPAGES_CURRENT=$(cat /proc/sys/vm/nr_hugepages)
HUGEPAGES_NEEDED=64  # 64 x 2MB = 128MB for UMEM

if [ "$HUGEPAGES_CURRENT" -lt "$HUGEPAGES_NEEDED" ]; then
    echo $HUGEPAGES_NEEDED > /proc/sys/vm/nr_hugepages
    echo "   Allocated $HUGEPAGES_NEEDED huge pages"
else
    echo "   Huge pages already configured: $HUGEPAGES_CURRENT"
fi

# Mount hugetlbfs if not mounted
if ! mount | grep -q hugetlbfs; then
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    echo "   Mounted hugetlbfs at /mnt/huge"
fi

# Configure sysctl for network performance
echo ""
echo "⚡ Configuring kernel parameters..."
cat > /etc/sysctl.d/90-oxidize-xdp.conf << EOF
# Oxidize AF_XDP optimizations
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 65535
net.core.optmem_max = 65536
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.udp_mem = 65536 131072 262144
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 0
EOF
sysctl -p /etc/sysctl.d/90-oxidize-xdp.conf >/dev/null 2>&1
echo "   Applied sysctl optimizations"

# Set CPU affinity for NIC interrupts
echo ""
echo "🔗 Configuring IRQ affinity..."
IRQ_SCRIPT="/usr/local/bin/set-irq-affinity.sh"
cat > $IRQ_SCRIPT << 'EOF'
#!/bin/bash
INTERFACE=$1
IRQS=$(grep $INTERFACE /proc/interrupts | awk '{print $1}' | tr -d ':')
CPU=0
for IRQ in $IRQS; do
    echo $CPU > /proc/irq/$IRQ/smp_affinity_list 2>/dev/null || true
    CPU=$((CPU + 1))
done
EOF
chmod +x $IRQ_SCRIPT
$IRQ_SCRIPT $INTERFACE 2>/dev/null || true
echo "   Set IRQ affinity for $INTERFACE"

# Create systemd service for persistence
echo ""
echo "📋 Creating systemd service..."
cat > /etc/systemd/system/oxidize-xdp-setup.service << EOF
[Unit]
Description=Oxidize AF_XDP Setup
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/oxidize-xdp-setup.sh $INTERFACE $PORT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Copy this script to /usr/local/bin
cp "$0" /usr/local/bin/oxidize-xdp-setup.sh
chmod +x /usr/local/bin/oxidize-xdp-setup.sh

systemctl daemon-reload
systemctl enable oxidize-xdp-setup.service >/dev/null 2>&1
echo "   Created oxidize-xdp-setup.service"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║            ✅ AF_XDP Setup Complete                            ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║ Interface: $INTERFACE ($DRIVER)"
echo "║ XDP Mode: $XDP_MODE"
echo "║ Huge Pages: $(cat /proc/sys/vm/nr_hugepages)"
echo "║ RX/TX Queues: $RX_QUEUES / $TX_QUEUES"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║ Start server with:"
echo "║   oxidize-server --listen 0.0.0.0:$PORT --xdp $INTERFACE"
echo "╚════════════════════════════════════════════════════════════════╝"
