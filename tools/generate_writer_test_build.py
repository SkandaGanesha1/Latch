#!/usr/bin/env python3
"""Make a test image with the enforced policy and no competing guest VM."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
text = args.source.read_text(encoding="utf-8")
vm = "    on -T qvm_host_t /proc/boot/qvm @/proc/boot/latch_qemu_governor.qvmconf &"
if text.count(vm) != 1:
    raise SystemExit("expected exactly one qvm startup command")
text = text.replace(vm, "    # VM disabled only for exclusive-writer testing")
text += "\n[uid=0 gid=0 perms=0755] /proc/boot/latch_target_probe = build/nto-aarch64-le/latch_target_probe\n"
args.output.write_text(text, encoding="utf-8")
