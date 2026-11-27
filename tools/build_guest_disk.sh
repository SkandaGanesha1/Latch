#!/usr/bin/env bash
#
# build_guest_disk.sh -- pack the guest's read-only ASSET DISK.
#
# WHAT THIS PRODUCES
# ------------------
# An ext4 filesystem image that the QNX Hypervisor hands to the guest as a
# read-only virtio-blk disk.  It carries two things:
#
#     /latch_model.gguf   the language model
#     /latch_infer        the statically linked AArch64 inference program
#                         (llama.cpp + the independent action-schema validator)
#
# WHY THE ASSETS ARE NOT IN THE INITRAMFS
# ---------------------------------------
# The guest's initramfs is the guest's root filesystem, and the tracked
# `guest/linux-guest.initrd` must stay byte-identical.  Putting a 138 MiB
# model there would also mean every machine that wants to rebuild it needs a
# cross toolchain AND the model.
#
# But there is a SECOND, measured reason, and it is the reason this script
# exists in this shape:
#
#   QNX Hypervisor 8.0's `qvm` loads a guest blob (the Linux Image, the
#   initramfs) into guest memory through `load_blob()`.  That function has
#   two paths.  A small blob is copied straight into guest memory; a blob
#   above a size threshold is transferred through qvm's MESSAGE-BLOCK
#   mechanism, in 64 KiB chunks, with the guest servicing each chunk.
#
#   Measured on the QEMU AArch64 target (2026-11-26): with the inference
#   binary in the initramfs the initramfs was 8.9 MiB and the guest kernel
#   printed
#
#       Initramfs unpacking failed: invalid magic at start of compressed archive
#
#   after 30 ms -- i.e. the kernel was handed a buffer that was NOT the gzip
#   archive.  The blob's bytes never arrived, because the message-block
#   chunks are serviced by the QNX guest-BSP support code, and this guest is
#   an UPSTREAM Linux 6.12, which has no such driver.  The scripted GOVERNOR
#   profile's 3.3 KiB initramfs goes through the direct-copy path and works.
#
#   The fix is therefore structural, not a matter of picking a smaller
#   number: the INITRAMFS stays tiny (the policy only, a few KiB) and the
#   large assets travel on the virtio-blk disk, which is served over the
#   virtio protocol and does not go through qvm's blob loader at all.
#
# THE DISK IS READ-ONLY AT THE DEVICE
# -----------------------------------
# The hypervisor's virtio-blk vdev supports `hostdev [<]<pathname>`, where
# the `<` makes the backing file read-only to the guest.  The guest is the
# untrusted side, and the model and the inference program are inputs it must
# not be able to rewrite -- so the read-only property is enforced by the
# HYPERVISOR, not by the guest behaving.
#
# THE IMAGE IS A BUILD INPUT, NOT A REPOSITORY ARTIFACT
# ------------------------------------------------------
# Like the guest kernel Image (GUEST_IMAGE), the model is an external input.
# The model itself is NOT in this repository.
#
# USAGE
# -----
#     tools/build_guest_disk.sh --model /path/to/model.gguf \
#                               --infer /path/to/latch_infer \
#                               [--out build/latch_guest_disk.img] \
#                               [--example-u <mrad>] [--prompt <file>]
#
# It prints the SHA-256 of every input and of the produced image, so the
# transcript that proves what ran is self-describing.
#
# THE EXPERIMENT PARAMETERS
# -------------------------
# `--example-u` and `--prompt` set the PROMPT, not the safety envelope.
# The envelope lives in the signed manifest and is enforced by the trusted
# QNX supervisor, which never sees any of this.  These two files are the
# model's INPUTS, and they are what an experiment varies:
#
#     --example-u 400   the worked example in the prompt says 400 mrad, so
#                       the model copies 400 mrad
#     --prompt <file>   the user prompt body (e.g. a prompt injection)
#
# They are installed on the disk as /latch_example_u and /latch_prompt.txt,
# which the guest sees at /model/.  When they are absent the inference
# program uses its documented built-in defaults and says so on the console.

set -euo pipefail

MODEL=""
INFER=""
OUT=""
EXAMPLE_U=""
PROMPT=""
KEEP_DIR=0

while [ $# -gt 0 ]; do
    case "$1" in
        --model)     MODEL="$2"; shift 2 ;;
        --infer)     INFER="$2"; shift 2 ;;
        --out)       OUT="$2"; shift 2 ;;
        --example-u) EXAMPLE_U="$2"; shift 2 ;;
        --prompt)    PROMPT="$2"; shift 2 ;;
        --keep-dir)  KEEP_DIR=1; shift ;;
        -h|--help)   sed -n '2,62p' "$0"; exit 0 ;;
        *) echo "build_guest_disk.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$REPO_ROOT/build/latch_guest_disk.img}"

say() { printf '[guest-disk] %s\n' "$*"; }
die() { printf '[guest-disk] ERROR: %s\n' "$*" >&2; exit 1; }

[ -n "$MODEL" ] || die "--model is required"
[ -f "$MODEL" ] || die "the model '$MODEL' does not exist"
[ -n "$INFER" ] || die "--infer is required"
[ -f "$INFER" ] || die "the inference program '$INFER' does not exist"
if [ -n "$EXAMPLE_U" ]; then
    case "$EXAMPLE_U" in
        ''|*[!0-9-]*) die "--example-u must be an integer (got '$EXAMPLE_U')" ;;
    esac
fi
if [ -n "$PROMPT" ]; then
    [ -f "$PROMPT" ] || die "the prompt file '$PROMPT' does not exist"
fi
command -v mke2fs >/dev/null 2>&1 || die "mke2fs is not installed (e2fsprogs)"

MODEL_SIZE=$(stat -c %s "$MODEL")
MODEL_SHA=$(sha256sum "$MODEL" | cut -d' ' -f1)
INFER_SIZE=$(stat -c %s "$INFER")
INFER_SHA=$(sha256sum "$INFER" | cut -d' ' -f1)

# The image has to hold the assets plus ext4's metadata, its inode table
# and its journal.  The journal is pinned to 8 MiB below -- ext4's default
# scales with the filesystem size, and for a ~190 MiB image the default
# journal alone can eat the headroom.
#
# 48 MiB of headroom is measured, not guessed: with 16 MiB the image built
# but mke2fs could not allocate a block for the model file.
HEADROOM=$((48 * 1024 * 1024))
IMAGE_SIZE=$((MODEL_SIZE + INFER_SIZE + HEADROOM))
# mke2fs counts in 1024-byte blocks; round UP to whole megabytes so the
# filesystem is not created with zero free blocks.
IMAGE_MB=$(( (IMAGE_SIZE + 1024 * 1024 - 1) / (1024 * 1024) ))

say "model      : $MODEL"
say "model size : $MODEL_SIZE bytes"
say "model sha  : $MODEL_SHA"
say "infer      : $INFER"
say "infer size : $INFER_SIZE bytes"
say "infer sha  : $INFER_SHA"
say "image      : $OUT (${IMAGE_MB} MiB)"

TMP="$(mktemp -d)"
cleanup() { if [ "$KEEP_DIR" -eq 0 ]; then rm -rf "$TMP"; fi; }
trap cleanup EXIT
mkdir -p "$TMP/root"
cp "$MODEL" "$TMP/root/latch_model.gguf"
chmod 0644 "$TMP/root/latch_model.gguf"
cp "$INFER" "$TMP/root/latch_infer"
# The inference program is EXECUTED by the guest policy, so it needs the
# execute bit.  mke2fs -d preserves the staging directory's modes.
chmod 0755 "$TMP/root/latch_infer"

# The experiment's prompt parameters.  They are optional: when they are
# absent the inference program uses its documented built-in defaults and
# says so on the console.
if [ -n "$EXAMPLE_U" ]; then
    printf '%s\n' "$EXAMPLE_U" > "$TMP/root/latch_example_u"
    chmod 0644 "$TMP/root/latch_example_u"
    say "example-u  : $EXAMPLE_U mrad (installed as /latch_example_u)"
fi
if [ -n "$PROMPT" ]; then
    cp "$PROMPT" "$TMP/root/latch_prompt.txt"
    chmod 0644 "$TMP/root/latch_prompt.txt"
    say "prompt     : $PROMPT (installed as /latch_prompt.txt)"
    say "prompt sha : $(sha256sum "$PROMPT" | cut -d' ' -f1)"
fi

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# -d populates the filesystem from a directory WITHOUT needing a loop
# mount, which is why this works unprivileged inside a container.
#
# -F forces the filesystem onto a regular file (not a block device).
# -b 4096 matches the guest's page size assumptions.
# -I 256 avoids the 128-byte-inode warning (those cannot express dates
#       beyond 2038, and mke2fs warns about it).
# -J size=8 pins the journal to 8 MiB so it cannot eat the headroom.
mke2fs -q -F -t ext4 -b 4096 -I 256 -J size=8 -L LATCHDISK \
        -d "$TMP/root" "$OUT" "${IMAGE_MB}M" \
    || die "mke2fs failed"

# Prove the image actually contains both assets, by reading them back with
# debugfs (no mount, no root).
if command -v debugfs >/dev/null 2>&1; then
    debugfs -R "stat /latch_model.gguf" "$OUT" 2>/dev/null | grep -q "Size:" \
        || die "the image does not contain /latch_model.gguf"
    debugfs -R "stat /latch_infer" "$OUT" 2>/dev/null | grep -q "Size:" \
        || die "the image does not contain /latch_infer"
    # The execute bit has to survive the image build: the guest EXECS the
    # inference program straight out of this mount.
    debugfs -R "stat /latch_infer" "$OUT" 2>/dev/null | grep -q "Mode:  0755" \
        || die "/latch_infer in the image is not executable (mode 0755)"
    say "verified: debugfs can read /latch_model.gguf and /latch_infer out of the image"
else
    say "NOTE: debugfs is not installed; the image contents were NOT verified"
fi

IMAGE_SHA=$(sha256sum "$OUT" | cut -d' ' -f1)
say "image sha  : $IMAGE_SHA"
say "DONE"
