#!/usr/bin/env python3
"""Create a disposable, unrestricted policy-generation IFS buildfile.

The normal GOVERNOR buildfile remains the source for the enforced image.
The generated image must only be used in an isolated development environment.

The generated image also carries `latch_secpol_dump`, a DEVELOPMENT-ONLY
reader for the `/dev/secpolgenerate/*` observation files: the minimal IFS
has no `cat`, no `ls` and no `dd`, and the audit needs to read five
pseudo-files that QNX's own utilities do not expose.  The reader is linked
ONLY into this disposable image, never into the enforced deployment image.
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
    # THE GENERATOR INVOCATION IS DELIBERATELY THE PROVEN ONE.
    #
    # `secpolgenerate -u -t 100` is what the QNX System Security Guide's own
    # recipe uses ("secpolgenerate -u -t 50"), and it is what the v12 audit
    # image used -- and the v12 audit's PLAIN BLOCKING READ of
    # /dev/secpolgenerate/policy reached EOF and captured all 74 lines.
    #
    # Adding `-f 1` ("flush the trace events every second") was tried and
    # MEASURED TO BREAK THE SNAPSHOT: with it, the observation stream never
    # reaches EOF, so a blocking read never returns and the audit hangs.
    # The option is about the trace-event log, and it keeps the generator's
    # flush machinery running, so the policy snapshot is never finalised.
    #
    # Do not "improve" this line without re-measuring the capture.
    text = text.replace(push, "    # DEVELOPMENT ONLY: unrestricted policy generation\n"
                        "    # NO -f HERE: it was measured to stop the observation stream\n"
                        "    # from ever reaching EOF.  See the comment in\n"
                        "    # tools/generate_secpol_audit_build.py.\n"
                        "    secpolgenerate -u -t 100\n"
                        "    LD_PRELOAD=secpol-preload.so\n"
                        "    procmgr_symlink /proc/boot/libsecpol-gen.so.1 /proc/boot/libsecpol.so.1\n"
                        + push)
    if args.probe:
        text += "\n[uid=0 gid=0 perms=0755] /proc/boot/latch_target_probe = build/nto-aarch64-le/latch_target_probe\n"
    # The DEVELOPMENT-ONLY reader for the observation files.
    text += ("\n# DEVELOPMENT ONLY: the secpolgenerate observation reader.\n"
             "# It is linked only into this disposable audit image; the enforced\n"
             "# deployment image never carries it.\n"
             "[uid=0 gid=0 perms=0755] /proc/boot/latch_secpol_dump = build/nto-aarch64-le/latch_secpol_dump\n")
    args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
