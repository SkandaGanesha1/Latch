#!/usr/bin/env python3
"""Create a disposable, unrestricted policy-generation IFS buildfile.

The normal GOVERNOR buildfile remains the source for the enforced image.
The generated image must only be used in an isolated development environment.
"""
import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--probe", action="store_true", help="include test-only target probe")
    args = parser.parse_args()
    text = args.source.read_text(encoding="utf-8")
    push = "    secpolpush /proc/boot/secpol.bin"
    library = "libsecpol.so.1\n"
    binary = "[perms=0755] secpolpush\n"
    for marker in (push, library, binary):
        if text.count(marker) != 1:
            raise SystemExit(f"expected exactly one marker: {marker!r}")
    text = text.replace(library, library + "libsecpol-gen.so.1\nsecpol-preload.so\n")
    text = text.replace(binary, binary + "[perms=0755] secpolgenerate\n")
    text = text.replace(push, "    # DEVELOPMENT ONLY: unrestricted policy generation\n"
                        "    secpolgenerate -u -t 100\n"
                        "    LD_PRELOAD=secpol-preload.so\n"
                        "    procmgr_symlink /proc/boot/libsecpol-gen.so.1 /proc/boot/libsecpol.so.1\n"
                        + push)
    if args.probe:
        text += "\n[uid=0 gid=0 perms=0755] /proc/boot/latch_target_probe = build/nto-aarch64-le/latch_target_probe\n"
    args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
