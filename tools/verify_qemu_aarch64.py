#!/usr/bin/env python3
"""
tools/verify_qemu_aarch64.py

Automated end-to-end QEMU AArch64 virt verification harness for LATCH.
Boots build/nto-aarch64-le/latch_qemu.ifs under qemu-system-aarch64 (EL2 VHE, GICv2),
waits for the Linux 6.12 guest /init to stream the 200-tick LATH fault suite over
virtio-console -> pipe -> latch-ingest -> latchd, and asserts all 5 latch_verify
microkernel invariants pass (VERIFY_RC=0).
"""
import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ifs_path = Path(
        os.environ.get(
            "LATCH_QEMU_IFS",
            repo_root / "qnx" / "build" / "nto-aarch64-le" / "latch_qemu.ifs",
        )
    )
    if not ifs_path.is_file():
        print(f"ERROR: Missing IFS image at {ifs_path}. Build with 'make -C qnx ifs-qemu-aarch64 GUEST_IMAGE=/path/to/Image'.", file=sys.stderr)
        return 1

    cmd = [
        "qemu-system-aarch64",
        "-M", "virt,virtualization=on,gic-version=2",
        "-cpu", "cortex-a76",
        "-smp", "4",
        "-m", "2048",
        "-nographic",
        "-serial", "mon:stdio",
        "-kernel", str(ifs_path),
    ]

    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        cmd,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
    )
    os.close(slave_fd)

    buf = bytearray()

    def read_for(secs: float, stop_on: bytes | None = None) -> bool:
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([master_fd], [], [], 0.2)
            if r:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                buf.extend(data)
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
                if stop_on and stop_on in buf:
                    return True
        return False

    try:
        if not read_for(25.0, stop_on=b"# "):
            print("\nERROR: Timed out waiting for QNX ksh prompt.", file=sys.stderr)
            return 1

        # Wait for Linux 6.12 guest boot + /init 200-tick LATH suite under QEMU TCG
        read_for(20.0)

        for command, wait_s in [
            (b"/proc/boot/latchctl status\n", 1.5),
            (b"/proc/boot/latch_verify -m /proc/boot/latch.manifest\n", 3.0),
            (b"echo VERIFY_RC=$?\n", 1.0),
        ]:
            os.write(master_fd, command)
            read_for(wait_s)

        text = buf.decode("utf-8", errors="replace")

        checks = [
            (r"syspage::hypinfo::flags=0x00000001", "QNX EL2 VHE hypinfo flag"),
            (r"Proposals Received\s*:\s*200", "200 guest proposals received"),
            (r"Wire Faults Caught\s*:\s*12", "12 wire faults caught"),
            (r"Envelope Vetoes\s*:\s*7\b", "7 keep-out envelope vetoes"),
            (r"Ring Drops / WCET\s*:\s*0 drops", "0 ring drops"),
            (r"\[LATCH VERIFY\] ALL 5 MICROKERNEL CRITICALITY INVARIANTS VERIFIED \(PASS\)\.", "latch_verify 5/5 PASS"),
            (r"VERIFY_RC=0", "VERIFY_RC=0"),
        ]

        failed = []
        for pattern, label in checks:
            if not re.search(pattern, text):
                failed.append(label)

        print("\n=== QEMU AArch64 Verification Summary ===")
        if failed:
            print("FAILED assertions:", ", ".join(failed), file=sys.stderr)
            return 1
        print("PASS: All QEMU AArch64 virt QNX 8.0 + QVM + Linux 6.12 assertions verified.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master_fd)


if __name__ == "__main__":
    raise SystemExit(main())

