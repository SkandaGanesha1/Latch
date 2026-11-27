#!/usr/bin/env bash
#
# build_aarch64_sysroot.sh -- build a self-contained AArch64 Linux sysroot
# for cross-compiling the guest-side inference binary.
#
# WHY THIS EXISTS
# ---------------
# The in-guest inference binary (guest/latch_infer.cpp) is a statically
# linked AArch64 C++ program: llama.cpp is C++, and a static binary is the
# only form that can run in the guest without shipping a loader and a
# shared-library tree.
#
# The workstation's `aarch64-linux-gnu-gcc` (Fedora, GCC 16.2.1) is only
# half a toolchain: its own sysroot directory (/usr/aarch64-linux-gnu/sys-root)
# is EMPTY and the Fedora cross packages ship no target libstdc++. The
# `sysroot-aarch64-fc45-glibc` package supplies a complete glibc 2.44 for
# AArch64, but under the RED HAT triple, and the aarch64 `gcc`/`libgcc`/
# `libstdc++` RPMs supply the C++ runtime under that triple too.
#
# So the sysroot is assembled from RPMs:
#
#   * sysroot-aarch64-fc45-glibc  -- glibc 2.44 (headers, libc.a, crt*.o)
#   * gcc            (aarch64)    -- crtbegin/crtend, libgcc.a
#   * libgcc         (aarch64)    -- libgcc.a
#   * libstdc++      (aarch64)    -- libstdc++.so (shared; unused)
#   * libstdc++-devel(aarch64)    -- the C++ headers
#   * libstdc++-static(aarch64)   -- libstdc++.a
#   * libatomic      (aarch64)    -- libatomic.a
#
# THE ONE NON-OBVIOUS STEP: MERGING libgcc_eh.a INTO libgcc.a
# -----------------------------------------------------------
# On AArch64 the unwinder lives in a SEPARATE archive, libgcc_eh.a, and
# GCC's link spec does NOT put `-lgcc_eh` on the command line. The link
# line GCC actually emits for a static C++ link is:
#
#     -lstdc++ -lm --start-group -lgcc -latomic_asneeded -lc --end-group
#
# and Red Hat's libgcc.a contains neither `_Unwind_Resume` nor
# `__gcc_personality_v0` -- both live in libgcc_eh.a. glibc's own libc.a
# references `_Unwind_Resume` (pthread cancellation cleanup) and
# libstdc++.a references `__gcc_personality_v0`, so the link FAILS with:
#
#     undefined reference to `_Unwind_Resume'
#     undefined reference to `__gcc_personality_v0'
#
# Adding `-lgcc_eh` on the command line does NOT fix it: the user library
# is placed BEFORE `-lc`, and GNU ld resolves archive members in command
# line order, so libgcc_eh.a has already been scanned when libc.a
# introduces the reference. (This was measured, not assumed -- see the
# link-line dump in the commit that introduced this script.)
#
# The fix that works is to fold the libgcc_eh.a members INTO libgcc.a.
# `-lgcc` is inside the same --start-group as `-lc`, and a start-group is
# rescanned until no new undefined symbol remains, so the unwinder is
# found. Members already present in libgcc.a are skipped, so there is no
# duplicate-definition error.
#
# USAGE
# -----
#     tools/build_aarch64_sysroot.sh [--dest DIR] [--rpm-cache DIR]
#                                     [--keep-rpms]
#
# Then source the generated flags:
#
#     source build/aarch64-sysroot/flags.env
#     $CXX $CXXFLAGS -o latch_infer latch_infer.cpp $LDFLAGS
#
# This is a WORKSTATION tool. CI does not cross-compile the AArch64
# guest, so CI never runs this script; it exists so that the guest
# binary is reproducible on a build machine, not just on the machine
# that happened to build it first.

set -euo pipefail

DEST=""
RPM_CACHE=""
KEEP_RPMS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --dest)      DEST="$2"; shift 2 ;;
        --rpm-cache) RPM_CACHE="$2"; shift 2 ;;
        --keep-rpms) KEEP_RPMS=1; shift ;;
        -h|--help)   sed -n '2,60p' "$0"; exit 0 ;;
        *) echo "build_aarch64_sysroot.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${DEST:-$REPO_ROOT/build/aarch64-sysroot}"
RPM_CACHE="${RPM_CACHE:-$REPO_ROOT/build/aarch64-rpm-cache}"

GCC_TRIPLE="aarch64-redhat-linux"
# The exact GCC version, e.g. 16.2.1. `g++ -dumpversion` only gives the
# major version on some distros, so ask the RPM database first and fall
# back to the compiler.
GCC_VER="$(rpm -q --qf '%{VERSION}' gcc-aarch64-linux-gnu 2>/dev/null || true)"
if [ -z "$GCC_VER" ]; then
    GCC_VER="$(aarch64-linux-gnu-g++ -dumpfullversion 2>/dev/null || true)"
fi
[ -n "$GCC_VER" ] || GCC_VER="16.2.1"
# The runtime library directory is keyed on the MAJOR version ("16"), not
# the full one.
GCC_MAJOR="${GCC_VER%%.*}"

say() { printf '[sysroot] %s\n' "$*"; }
die() { printf '[sysroot] ERROR: %s\n' "$*" >&2; exit 1; }

command -v aarch64-linux-gnu-g++ >/dev/null 2>&1 \
    || die "aarch64-linux-gnu-g++ is not installed"
command -v rpm2cpio >/dev/null 2>&1 || die "rpm2cpio is not installed"
command -v cpio >/dev/null 2>&1 || die "cpio is not installed"

mkdir -p "$DEST" "$RPM_CACHE"

# --------------------------------------------------------------------------
# 1. Fetch the RPMs.
# --------------------------------------------------------------------------
# The aarch64 *target* packages are named `gcc`, `libgcc`, `libstdc++`,
# `libstdc++-devel`, `libstdc++-static` and `libatomic` with the aarch64
# architecture; the glibc sysroot is a noarch package.
#
# An existing cache is reused: a rebuild on an air-gapped machine must
# still work.
# --------------------------------------------------------------------------
fetch_rpms() {
    local specs=(
        "sysroot-aarch64-fc45-glibc"
        "gcc:${GCC_VER}"
        "libgcc:${GCC_VER}"
        "libstdc++:${GCC_VER}"
        "libstdc++-devel:${GCC_VER}"
        "libstdc++-static:${GCC_VER}"
        "libatomic:${GCC_VER}"
    )
    local spec name ver
    for spec in "${specs[@]}"; do
        name="${spec%%:*}"
        ver="${spec#*:}"
        [ "$ver" = "$name" ] && ver=""
        local pattern
        if [ -n "$ver" ]; then
            pattern="${name}-${ver}-*.fc45.aarch64.rpm"
        else
            pattern="${name}-*.fc45.noarch.rpm"
        fi
        if compgen -G "$RPM_CACHE/$pattern" >/dev/null; then
            say "cached: $pattern"
            continue
        fi
        if [ -n "$ver" ]; then
            say "downloading $name-$ver (aarch64)..."
            dnf download --quiet --arch=aarch64 --destdir "$RPM_CACHE" "$name-$ver" \
                >/dev/null 2>&1 \
                || dnf download --quiet --arch=aarch64 --destdir "$RPM_CACHE" "$name" \
                >/dev/null 2>&1 \
                || die "dnf download failed for $name-$ver"
        else
            say "downloading $name (noarch)..."
            dnf download --quiet --destdir "$RPM_CACHE" "$name" >/dev/null 2>&1 \
                || die "dnf download failed for $name"
        fi
    done
}

fetch_rpms

# --------------------------------------------------------------------------
# 2. Extract everything into DEST.
# --------------------------------------------------------------------------
say "extracting into $DEST ..."
shopt -s nullglob
for rpm in "$RPM_CACHE"/*.rpm; do
    ( cd "$DEST" && rpm2cpio "$rpm" | cpio -idm --quiet 2>/dev/null )
done
shopt -u nullglob

# The glibc sysroot RPM unpacks under
#   usr/aarch64-redhat-linux/sys-root/fc45/
# but the cross compiler expects the sysroot's own tree at the root
# (usr/include, usr/lib64, ...). Move it up and drop the now-empty nest.
GLIBC_NEST="$DEST/usr/aarch64-redhat-linux/sys-root/fc45"
if [ -d "$GLIBC_NEST" ]; then
    cp -a "$GLIBC_NEST/." "$DEST/"
    rm -rf "$DEST/usr/aarch64-redhat-linux"
fi

[ -f "$DEST/usr/lib64/libc.a" ] || die "glibc static library missing at $DEST/usr/lib64/libc.a"
[ -f "$DEST/usr/lib64/crt1.o" ] || die "glibc startup files missing at $DEST/usr/lib64/crt1.o"

GCC_LIBDIR="$DEST/usr/lib/gcc/$GCC_TRIPLE/$GCC_MAJOR"
[ -d "$GCC_LIBDIR" ] || die "GCC runtime directory missing at $GCC_LIBDIR"
[ -f "$GCC_LIBDIR/libstdc++.a" ] \
    || die "libstdc++.a missing at $GCC_LIBDIR/libstdc++.a"

# --------------------------------------------------------------------------
# 3. Fold libgcc_eh.a into libgcc.a (see the header for why).
# --------------------------------------------------------------------------
EH_LIB="$GCC_LIBDIR/libgcc_eh.a"
GCC_LIB="$GCC_LIBDIR/libgcc.a"
if [ -f "$EH_LIB" ]; then
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    # NOTE: `nm ... | grep -q` under `set -o pipefail` is a trap: grep -q
    # exits at the first match, nm takes SIGPIPE, and the pipeline reports
    # failure even though the symbol WAS found. Redirect nm to a file
    # first, then grep the file.
    if aarch64-linux-gnu-nm "$GCC_LIB" > "$TMP/nm.txt" 2>/dev/null \
        && grep -qE ' T _Unwind_Resume$' "$TMP/nm.txt"; then
        say "libgcc.a already provides _Unwind_Resume; nothing to merge"
    else
        say "merging libgcc_eh.a into libgcc.a ..."
        ( cd "$TMP" && aarch64-linux-gnu-ar x "$EH_LIB" )
        cp "$GCC_LIB" "$TMP/libgcc.combined.a"
        for obj in "$TMP"/*.o; do
            member="$(basename "$obj")"
            if aarch64-linux-gnu-ar t "$GCC_LIB" > "$TMP/members.txt" \
                && grep -qx "$member" "$TMP/members.txt"; then
                continue   # already present: do not create a duplicate symbol
            fi
            aarch64-linux-gnu-ar r "$TMP/libgcc.combined.a" "$obj"
        done
        cp "$TMP/libgcc.combined.a" "$GCC_LIB"
        aarch64-linux-gnu-nm "$GCC_LIB" > "$TMP/nm2.txt" 2>/dev/null || true
        grep -qE ' T _Unwind_Resume$' "$TMP/nm2.txt" \
            || die "the merge did not produce _Unwind_Resume"
        say "merged: _Unwind_Resume and __gcc_personality_v0 are now in libgcc.a"
    fi
else
    say "no libgcc_eh.a in the sysroot; assuming libgcc.a already has the unwinder"
fi

# --------------------------------------------------------------------------
# 4. Emit the flags, and prove the toolchain with a hello-world.
# --------------------------------------------------------------------------
CXX_INC=""
for d in "$DEST/usr/include/c++/$GCC_MAJOR" \
         "$DEST/usr/include/c++/$GCC_MAJOR/$GCC_TRIPLE" \
         "$DEST/usr/include/c++/$GCC_MAJOR/backward"; do
    [ -d "$d" ] && CXX_INC="$CXX_INC -I$d"
done

cat > "$DEST/flags.env" <<EOF
# Generated by tools/build_aarch64_sysroot.sh -- do not hand-edit.
# Source this file, then use \$CXX \$CXXFLAGS ... \$LDFLAGS.
SYSROOT="$DEST"
CXX="aarch64-linux-gnu-g++"
CXXFLAGS="--sysroot=$DEST -B$GCC_LIBDIR/$CXX_INC -static -O2 -fno-plt -pthread"
LDFLAGS="-static -pthread"
EOF

say "proving the toolchain with a static C++ hello-world ..."
TMP="$(mktemp -d)"
cat > "$TMP/probe.cpp" <<'EOF'
#include <cstdio>
#include <string>
#include <vector>
int main() {
    std::vector<std::string> v{"latch", "sysroot", "ok"};
    for (const auto &s : v) std::printf("%s\n", s.c_str());
    return 0;
}
EOF
# shellcheck disable=SC1090
( set -a; . "$DEST/flags.env"; set +a
  "$CXX" $CXXFLAGS "$TMP/probe.cpp" -o "$TMP/probe" $LDFLAGS ) \
    || die "the static C++ probe did not link"

file "$TMP/probe" | grep -q "statically linked" \
    || die "the probe is not a static binary: $(file "$TMP/probe")"

if command -v qemu-aarch64-static >/dev/null 2>&1; then
    out="$(qemu-aarch64-static "$TMP/probe")"
    [ "$out" = "$(printf 'latch\nsysroot\nok')" ] \
        || die "the probe ran but printed '$out'"
    say "probe ran under qemu-aarch64-static: $(printf '%s' "$out" | tr '\n' ' ')"
fi

rm -rf "$TMP"
trap - EXIT

say "DONE.  sysroot : $DEST"
say "flags       : $DEST/flags.env"
