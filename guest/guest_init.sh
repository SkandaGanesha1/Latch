#!/bin/sh
# ==============================================================================
# guest/guest_init.sh
#
# LATCH — Last Authority for Trusted Control Handoff
# Minimal Untrusted Linux Guest Init Script for QNX Hypervisor 8.0 (qvm)
# ==============================================================================

echo "=== LATCH Linux Guest Starting (Cortex-A72 cores 2-3) ==="

# Mount essential filesystems
mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mount -t devtmpfs none /dev 2>/dev/null

# Identify virtio-console device
CONSOLE_DEV="/dev/hvc0"
if [ ! -c "$CONSOLE_DEV" ]; then
    echo "Creating $CONSOLE_DEV node..."
    mknod "$CONSOLE_DEV" c 229 0 2>/dev/null
fi

echo "Connecting untrusted policy generator to $CONSOLE_DEV..."

# Run liar.py fault injection suite or continuous loop
if [ -f "/app/liar.py" ]; then
    python3 /app/liar.py suite --device "$CONSOLE_DEV" --period-ms 1.0
elif [ -f "./liar.py" ]; then
    python3 ./liar.py suite --device "$CONSOLE_DEV" --period-ms 1.0
else
    echo "liar.py not found in /app. Entering fallback idle loop."
    while true; do sleep 1; done
fi

echo "=== Guest execution finished ==="

