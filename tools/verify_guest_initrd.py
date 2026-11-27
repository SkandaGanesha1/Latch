#!/usr/bin/env python3
"""Check that a generated GOVERNOR initrd contains the v2 freestanding /init.

The expected scenario depends on the PROFILE the initrd was built for, so
the profile is an explicit argument:

    verify_guest_initrd.py INITRD            # the scripted GOVERNOR profile
    verify_guest_initrd.py INITRD soak       # the U-4 latency-soak profile

Guessing the profile from the binary would make the check self-fulfilling:
a binary that lost its markers would be classified as "some other profile"
and pass.  The caller states which profile it asked for, and the checker
holds that profile to its OWN markers -- AND to the ABSENCE of the other
profiles' markers, because an initrd that carried two scenarios would run
the wrong one.
"""

from __future__ import annotations

import gzip
import pathlib
import struct
import sys


def extract_newc(data: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        if header[:6] != b"070701":
            raise ValueError(f"invalid cpio newc header at offset {offset}")
        fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        file_size = fields[6]
        name_size = fields[11]
        offset += 110
        if name_size < 1 or offset + name_size > len(data):
            raise ValueError("invalid cpio filename length")
        name = data[offset:offset + name_size - 1].decode("utf-8")
        offset = (offset + name_size + 3) & ~3
        if offset + file_size > len(data):
            raise ValueError(f"truncated cpio member {name!r}")
        payload = data[offset:offset + file_size]
        offset = (offset + file_size + 3) & ~3
        if name == "TRAILER!!!":
            break
        files[name.removeprefix("./")] = payload
    return files


# The scripted GOVERNOR profile's scenario markers.
SCRIPTED_MARKERS = [
    b"[GOVERNOR] v2 demo",
    b"four liveness heartbeats",
    b"[A4] guest CPU spinner",
    b"heartbeat-only traffic must not recover rung",
    b"25 coherent commands recover",
    b"recovered rung accepts fresh canonical commands",
    b"unknown unit rejected",
    b"guest stops sending",
]

# The U-4 latency-soak profile's scenario markers.
SOAK_MARKERS = [
    b"[LATENCY] soak:",
    b"in-envelope CMD_V2 stream",
    b"the console stays quiet until the soak ends",
]


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(f"usage: {sys.argv[0]} GOVERNOR_INITRD [scripted|soak]", file=sys.stderr)
        return 2
    profile = sys.argv[2] if len(sys.argv) == 3 else "scripted"
    if profile not in ("scripted", "soak"):
        print(f"[GUEST_INITRD FAIL] unknown profile {profile!r}", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    try:
        archive = gzip.decompress(path.read_bytes())
        files = extract_newc(archive)
    except (OSError, EOFError, ValueError) as exc:
        print(f"[GUEST_INITRD FAIL] {exc}", file=sys.stderr)
        return 1

    init = files.get("init")
    if init is None or len(init) < 64 or init[:4] != b"\x7fELF":
        print("[GUEST_INITRD FAIL] archive has no ELF /init", file=sys.stderr)
        return 1
    if init[4] != 2 or init[5] != 1 or struct.unpack_from("<H", init, 18)[0] != 183:
        print("[GUEST_INITRD FAIL] /init is not a little-endian AArch64 ELF64 binary", file=sys.stderr)
        return 1

    missing: list[str] = []
    if profile == "scripted":
        has_delay_marker = (b"scripted 110 ms heartbeat delay" in init or
                            b"scripted 55 ms heartbeat delay" in init)
        missing = [marker.decode() for marker in SCRIPTED_MARKERS if marker not in init]
        if not has_delay_marker:
            missing.append("scripted 55/110 ms heartbeat delay")
        # The soak profile is a DIFFERENT scenario.  An initrd that carried
        # both would run the scripted demo instead of the soak.
        if b"[LATENCY] soak:" in init:
            missing.append("must NOT contain the latency-soak scenario")
    else:
        missing = [marker.decode() for marker in SOAK_MARKERS if marker not in init]
        # The scripted demo's markers must be ABSENT: the soak replaces that
        # scenario, and a binary that carried both would run the demo.
        for marker in SCRIPTED_MARKERS:
            if marker in init:
                missing.append(f"must NOT contain the scripted scenario ({marker.decode()})")
    if missing:
        print(f"[GUEST_INITRD FAIL] /init lacks the {profile} profile's markers: {missing}", file=sys.stderr)
        return 1
    if b"phase 1/9: legal ramp" in init:
        print("[GUEST_INITRD FAIL] GOVERNOR initrd contains the legacy v1 fault suite", file=sys.stderr)
        return 1
    print(f"[GUEST_INITRD PASS] {path}: ELF64/AArch64 {profile} guest policy embedded ({len(init)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
