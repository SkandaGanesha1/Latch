#!/usr/bin/env bash
# ==============================================================================
# qnx/run_qemu.sh
#
# LATCH — Last Authority for Trusted Control Handoff
# QNX SDP 8.0 / Hypervisor 8.0 QEMU Launch Runner
#
# Supports both:
#   1. x86_64 Target: QNX SDP 8.0 Quick Start Target Image (QSTI)
#      - KVM hardware acceleration (--enable-kvm --cpu host)
#      - IDE virtual disk (disk-qemu.vmdk / disk-qemu)
#      - Userland networking with SSH port forward (localhost:2222 -> QNX:22)
#      - Serial console on stdio
#   2. AArch64 Target: ARMv8 Virt Machine (matching Raspberry Pi 4B specs)
#      - 4x Cortex-A72 cores, GICv2 interrupt controller
#      - PL011 Serial console connected to stdio
#      - VirtIO console for black-channel frame transport
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ARCH=""
IFS_FILE=""
DISK_FILE=""
MEM_MB="2048"
CPUS="4"
SSH_PORT="2222"
GRAPHICS="no"
EXTRA_ARGS=()

print_usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  -a, --arch <arch>          Target architecture: x86_64 or aarch64 (default: auto-detect)
  -k, --kernel <ifs_path>    Path to QNX bootable IFS image (e.g. ifs.bin or latch_qemu.ifs)
  -d, --disk <disk_path>     Path to QNX virtual disk (e.g. disk-qemu.vmdk or .qcow2)
  -m, --mem <size_mb>        RAM size in MB (default: 2048)
  -c, --cpus <count>         vCPU count (default: 4)
  -p, --ssh-port <port>      Host SSH forwarding port (default: 2222 -> guest:22)
  -g, --graphics             Enable graphical display (default: headless/serial)
  -h, --help                 Display this help menu

Examples:
  # Auto-boot QNX SDP 8.0 Quick Start Target Image (x86_64 with KVM & SSH):
  $0

  # Explicit disk & kernel:
  $0 --disk ~/qnx800/images/qemu/qemu/output/disk-qemu.vmdk --kernel ~/qnx800/images/qemu/qemu/output/ifs.bin

  # Boot AArch64 IFS:
  $0 --arch aarch64 --kernel build/nto-aarch64-le/latch_qemu.ifs
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -k|--kernel)
            IFS_FILE="$2"
            shift 2
            ;;
        -d|--disk)
            DISK_FILE="$2"
            shift 2
            ;;
        -m|--mem)
            MEM_MB="$2"
            shift 2
            ;;
        -c|--cpus)
            CPUS="$2"
            shift 2
            ;;
        -p|--ssh-port)
            SSH_PORT="$2"
            shift 2
            ;;
        -g|--graphics)
            GRAPHICS="yes"
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Expand tilde in paths if present
[[ -n "$IFS_FILE" ]] && IFS_FILE="${IFS_FILE/#\~/$HOME}"
[[ -n "$DISK_FILE" ]] && DISK_FILE="${DISK_FILE/#\~/$HOME}"

# Auto-detect disk image if not specified
if [[ -z "$DISK_FILE" ]]; then
    for candidate in \
        "$HOME/qnx800/images/qemu/qemu/output/disk-qemu.vmdk" \
        "$HOME/qnx800/images/qemu/qemu/output/disk-qemu" \
        "$HOME/qnx800_qemu/output/disk-qemu.vmdk" \
        "$HOME/qnx800_qemu/output/disk-qemu" \
        "$SCRIPT_DIR/build/qnx-qemu.qcow2" \
        "$SCRIPT_DIR/qnx-qemu.qcow2" \
        "$SCRIPT_DIR/qnx800.qcow2"; do
        if [[ -f "$candidate" ]]; then
            DISK_FILE="$candidate"
            echo "Auto-detected QNX virtual disk: $DISK_FILE"
            break
        fi
    done
fi

# Auto-detect IFS image if not specified
if [[ -z "$IFS_FILE" ]]; then
    for candidate in \
        "$HOME/qnx800/images/qemu/qemu/output/ifs.bin" \
        "$HOME/qnx800_qemu/output/ifs.bin" \
        "$SCRIPT_DIR/build/nto-aarch64-le/latch_qemu.ifs" \
        "$SCRIPT_DIR/build/nto-aarch64-le/latch_rpi4.ifs" \
        "$SCRIPT_DIR/latch_qemu.ifs" \
        "$SCRIPT_DIR/latch_rpi4.ifs"; do
        if [[ -f "$candidate" ]]; then
            IFS_FILE="$candidate"
            echo "Auto-detected QNX IFS image: $IFS_FILE"
            break
        fi
    done
fi

# Determine architecture
if [[ -z "$ARCH" ]]; then
    if [[ -n "$IFS_FILE" && -f "$IFS_FILE" ]]; then
        file_desc=$(file "$IFS_FILE" 2>/dev/null || true)
        if [[ "$file_desc" =~ Intel|i386|x86-64|x86_64 ]]; then
            ARCH="x86_64"
        elif [[ "$file_desc" =~ ARM|aarch64 ]]; then
            ARCH="aarch64"
        fi
    fi
    if [[ -z "$ARCH" && -n "$DISK_FILE" && "$DISK_FILE" =~ qemu ]]; then
        ARCH="x86_64"
    fi
    # Default fallback to host architecture if x86_64
    if [[ -z "$ARCH" ]]; then
        uname_m=$(uname -m)
        if [[ "$uname_m" == "x86_64" ]]; then
            ARCH="x86_64"
        else
            ARCH="aarch64"
        fi
    fi
fi

echo "================================================================"
echo " LATCH — QNX SDP 8.0 Virtual Machine Runner"
echo " Architecture : $ARCH"
echo " CPUs / RAM   : $CPUS vCPUs | ${MEM_MB} MB"
echo " SSH Forward  : localhost:${SSH_PORT} -> guest:22"
echo "================================================================"

if [[ "$ARCH" == "x86_64" ]]; then
    QEMU_BIN="$(which qemu-system-x86_64 2>/dev/null || true)"
    if [[ -z "$QEMU_BIN" ]]; then
        echo "ERROR: 'qemu-system-x86_64' not found in PATH."
        exit 1
    fi

    QEMU_CMD=("$QEMU_BIN" -smp "$CPUS" -m "$MEM_MB")

    # Hardware acceleration
    if [[ -w "/dev/kvm" ]]; then
        QEMU_CMD+=(--enable-kvm --cpu host)
    else
        QEMU_CMD+=(--cpu max)
    fi

    # Disk
    if [[ -n "$DISK_FILE" ]]; then
        if [[ ! -f "$DISK_FILE" ]]; then
            echo "ERROR: Specified disk image '$DISK_FILE' does not exist."
            exit 1
        fi
        if [[ "$DISK_FILE" =~ \.vmdk$ ]]; then
            QEMU_CMD+=(-drive "file=$DISK_FILE,if=ide,id=drv0")
        elif [[ "$DISK_FILE" =~ \.qcow2$ ]]; then
            QEMU_CMD+=(-drive "file=$DISK_FILE,format=qcow2,if=ide,id=drv0")
        else
            QEMU_CMD+=(-drive "file=$DISK_FILE,format=raw,if=ide,id=drv0")
        fi
    fi

    # Kernel (IFS)
    if [[ -n "$IFS_FILE" ]]; then
        if [[ ! -f "$IFS_FILE" ]]; then
            echo "ERROR: Specified IFS image '$IFS_FILE' does not exist."
            exit 1
        fi
        QEMU_CMD+=(-kernel "$IFS_FILE")
    fi

    # Networking with SSH port forwarding
    QEMU_CMD+=(
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
        -device "virtio-net-pci,netdev=net0,mac=52:54:00:cf:bf:ed"
        -object "rng-random,filename=/dev/urandom,id=rng0"
        -device "virtio-rng-pci,rng=rng0"
    )

    # Console & Display
    if [[ "$GRAPHICS" == "yes" ]]; then
        QEMU_CMD+=(-vga none -device virtio-vga-gl -display sdl,gl=on -serial mon:stdio)
    else
        QEMU_CMD+=(-display none -serial mon:stdio)
    fi

elif [[ "$ARCH" == "aarch64" ]]; then
    QEMU_BIN="$(which qemu-system-aarch64 2>/dev/null || true)"
    if [[ -z "$QEMU_BIN" ]]; then
        echo "ERROR: 'qemu-system-aarch64' not found in PATH."
        exit 1
    fi

    QEMU_CMD=(
        "$QEMU_BIN"
        -M virt,gic-version=2
        -cpu cortex-a72
        -smp "$CPUS"
        -m "$MEM_MB"
        -nographic
        -serial mon:stdio
        -device virtio-serial-device
        -chardev pty,id=virtcon
        -device virtconsole,chardev=virtcon
    )

    if [[ -n "$IFS_FILE" ]]; then
        if [[ ! -f "$IFS_FILE" ]]; then
            echo "ERROR: Specified IFS image '$IFS_FILE' does not exist."
            exit 1
        fi
        QEMU_CMD+=(-kernel "$IFS_FILE")
    fi

    if [[ -n "$DISK_FILE" ]]; then
        if [[ ! -f "$DISK_FILE" ]]; then
            echo "ERROR: Specified disk image '$DISK_FILE' does not exist."
            exit 1
        fi
        QEMU_CMD+=(-drive "file=$DISK_FILE,format=qcow2,if=virtio")
    fi
else
    echo "ERROR: Unsupported architecture '$ARCH'. Use 'x86_64' or 'aarch64'."
    exit 1
fi

if [[ -z "$IFS_FILE" && -z "$DISK_FILE" ]]; then
    echo "ERROR: No bootable IFS kernel or virtual disk found."
    exit 1
fi

echo "QEMU Binary   : $QEMU_BIN"
echo "Booting Kernel: ${IFS_FILE:-[From Disk]}"
echo "Virtual Disk  : ${DISK_FILE:-[None]}"
echo "----------------------------------------------------------------"
echo "Tips:"
echo "  - To exit QEMU: Press 'Ctrl-A X' or 'Ctrl-C'"
echo "  - Once booted, SSH into QNX: ssh -p ${SSH_PORT} root@localhost"
echo "  - Default users: root (passwordless/configured), qnxuser"
echo "================================================================"
echo "Launching QEMU..."
echo ""

exec "${QEMU_CMD[@]}" "${EXTRA_ARGS[@]}"
