#!/bin/bash
# Setup script for Firecracker microVM isolation backend
#
# This script:
# 1. Downloads kernel and rootfs
# 2. Builds the guest agent
# 3. Injects the guest agent into the rootfs
#
# Requirements:
# - firecracker installed
# - KVM available (/dev/kvm)
# - Root access for mounting rootfs

set -e

WORK_DIR="${WORK_DIR:-/tmp/agentd-firecracker}"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/x86_64/vmlinux-6.1.102"
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/x86_64/ubuntu-24.04.ext4"

echo "=== Firecracker Setup for agentd ==="
echo "Work directory: $WORK_DIR"
mkdir -p "$WORK_DIR"

# Download kernel
KERNEL_PATH="$WORK_DIR/vmlinux.bin"
if [ ! -f "$KERNEL_PATH" ]; then
    echo "Downloading kernel..."
    curl -fSL "$KERNEL_URL" -o "$KERNEL_PATH"
    echo "Kernel downloaded: $KERNEL_PATH"
else
    echo "Kernel already exists: $KERNEL_PATH"
fi

# Download rootfs
ROOTFS_PATH="$WORK_DIR/rootfs.ext4"
if [ ! -f "$ROOTFS_PATH" ]; then
    echo "Downloading rootfs (Ubuntu 24.04)..."
    curl -fSL "$ROOTFS_URL" -o "$ROOTFS_PATH"
    echo "Rootfs downloaded: $ROOTFS_PATH"
else
    echo "Rootfs already exists: $ROOTFS_PATH"
fi

# Build guest agent
AGENT_BIN="$(dirname "$0")/../target/release/fc-guest-agent"
if [ ! -f "$AGENT_BIN" ]; then
    echo "Building guest agent..."
    cd "$(dirname "$0")/.."
    cargo build --release --bin fc-guest-agent
    cd -
fi

echo "Guest agent binary: $AGENT_BIN"

# Inject guest agent into rootfs
echo ""
echo "=== Injecting guest agent into rootfs ==="
echo "This requires root access to mount the ext4 image."
echo ""

MOUNT_DIR="$WORK_DIR/mnt"
mkdir -p "$MOUNT_DIR"

if [ "$EUID" -eq 0 ]; then
    # Expand rootfs if needed (to have space for agent)
    # Check current size
    CURRENT_SIZE=$(stat -c%s "$ROOTFS_PATH")
    MIN_SIZE=$((512 * 1024 * 1024))  # 512MB minimum
    if [ "$CURRENT_SIZE" -lt "$MIN_SIZE" ]; then
        echo "Expanding rootfs to 512MB..."
        truncate -s 512M "$ROOTFS_PATH"
        e2fsck -f -y "$ROOTFS_PATH" || true
        resize2fs "$ROOTFS_PATH"
    fi

    # Mount and copy agent
    mount -o loop "$ROOTFS_PATH" "$MOUNT_DIR"

    echo "Copying guest agent to /sbin/agent..."
    cp "$AGENT_BIN" "$MOUNT_DIR/sbin/agent"
    chmod +x "$MOUNT_DIR/sbin/agent"

    # Create a minimal init script that starts the agent
    cat > "$MOUNT_DIR/etc/init.d/agentd" << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          agentd
# Required-Start:    $local_fs
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: agentd guest agent
### END INIT INFO

case "$1" in
    start)
        /sbin/agent &
        ;;
    stop)
        killall agent 2>/dev/null || true
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
exit 0
EOF
    chmod +x "$MOUNT_DIR/etc/init.d/agentd"

    # Enable the service
    if [ -d "$MOUNT_DIR/etc/rc3.d" ]; then
        ln -sf ../init.d/agentd "$MOUNT_DIR/etc/rc3.d/S99agentd" 2>/dev/null || true
    fi

    umount "$MOUNT_DIR"
    echo "Guest agent installed successfully!"
else
    echo "Run this script as root to inject the guest agent, or run:"
    echo ""
    echo "  sudo bash -c '"
    echo "    mkdir -p $MOUNT_DIR"
    echo "    mount -o loop $ROOTFS_PATH $MOUNT_DIR"
    echo "    cp $AGENT_BIN $MOUNT_DIR/sbin/agent"
    echo "    chmod +x $MOUNT_DIR/sbin/agent"
    echo "    umount $MOUNT_DIR"
    echo "  '"
    echo ""
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To use Firecracker backend, start agentd with:"
echo "  ISOLATION=firecracker ./target/debug/agentd run --config config.toml"
echo ""
echo "Or specify firecracker explicitly:"
echo "  ./target/debug/agentd run --config config.toml --isolation firecracker"
echo ""
echo "Configuration:"
echo "  Kernel: $KERNEL_PATH"
echo "  Rootfs: $ROOTFS_PATH"
echo "  Guest agent: $AGENT_BIN"
