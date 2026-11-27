#!/usr/bin/env python3
"""Make a test image with the enforced policy and no competing guest VM."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
text = args.source.read_text(encoding="utf-8")

# The guest VM is started by the guest-lifecycle daemon, so the daemon's
# launch line is what has to go: leaving it in place would start a guest
# that competes for the proposal node, which is exactly what this image
# exists to avoid.  The `waitfor` that follows it goes with it, or the
# image would idle for its timeout on every boot.
vm = ("    on -T latch_guestd_t /proc/boot/latch_guestd -q /proc/boot/qvm "
      "-c /proc/boot/latch_qemu_governor.qvmconf &\n"
      "    waitfor /dev/latch/guestctl 4")
if text.count(vm) != 1:
    raise SystemExit("expected exactly one guest-lifecycle startup command")
text = text.replace(vm, '''    # Test-only processes are started by the privileged boot script under
    # the already-authorized verification domain. The operator shell is not
    # granted authority to transition types or write proposals.
    display_msg "WRITER_TEST_BEGIN"
    on -T latch_verify_t /proc/boot/latch_target_probe hold /dev/latch/proposal &
    waitfor /dev/shmem/latch-probe-ready 10
    display_msg "WRITER_TEST_COMPETE"
    on -T latch_verify_t /proc/boot/latch_target_probe try /dev/latch/proposal
    waitfor /dev/shmem/latch-probe-closed 30
    display_msg "WRITER_TEST_REOPEN"
    on -T latch_verify_t /proc/boot/latch_target_probe try /dev/latch/proposal
    display_msg "WRITER_TEST_END"''')
text += "\n[uid=0 gid=0 perms=0755] /proc/boot/latch_target_probe = build/nto-aarch64-le/latch_target_probe\n"
args.output.write_text(text, encoding="utf-8")
