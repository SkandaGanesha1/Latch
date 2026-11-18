#!/usr/bin/env python3
"""Check that a generated GOVERNOR initrd contains the v2 freestanding /init."""

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


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} GOVERNOR_INITRD", file=sys.stderr)
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
    has_delay_marker = (b"scripted 110 ms heartbeat delay" in init or
                        b"scripted 55 ms heartbeat delay" in init)
    required = [b"[GOVERNOR] v2 demo", b"four liveness heartbeats",
                b"[A4] guest CPU spinner",
                b"heartbeat-only traffic must not recover rung",
                b"25 coherent commands recover", b"recovered rung accepts fresh canonical commands",
                b"unknown unit rejected",
                b"guest stops sending"]
    missing = [marker.decode() for marker in required if marker not in init]
    if not has_delay_marker:
        missing.append("scripted 55/110 ms heartbeat delay")
    if missing:
        print(f"[GUEST_INITRD FAIL] /init lacks v2 scenario markers: {missing}", file=sys.stderr)
        return 1
    if b"phase 1/9: legal ramp" in init:
        print("[GUEST_INITRD FAIL] GOVERNOR initrd contains the legacy v1 fault suite", file=sys.stderr)
        return 1
    print(f"[GUEST_INITRD PASS] {path}: ELF64/AArch64 v2 guest policy embedded ({len(init)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
