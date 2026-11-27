#!/usr/bin/env python3
"""
tools/verify_qemu_aarch64.py

Automated end-to-end QEMU AArch64 virt verification harness for LATCH.
Boots the dedicated latch_qemu_legacy_verify.ifs under qemu-system-aarch64,
waits for the Linux guest /init to stream its LATH fault suite over
virtio-console -> pipe -> latch-ingest -> latchd, captures the guest status,
then explicitly terminates the guest and its ingest writer before running the
separate latch_verify session. The test image starts a fixed trigger launcher
as latch_verify_t; the ordinary operator shell does not acquire that type.
"""
import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capture_evidence import guest_suite_frames  # noqa: E402


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ifs_path = Path(
        os.environ.get(
            "LATCH_QEMU_IFS",
            repo_root / "qnx" / "build" / "nto-aarch64-le" / "latch_qemu_legacy_verify.ifs",
        )
    )
    if not ifs_path.is_file():
        print(f"ERROR: Missing IFS image at {ifs_path}. Build with 'make -C qnx ifs-qemu-legacy-verify GUEST_IMAGE=/path/to/Image'.", file=sys.stderr)
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

        # Wait for the Linux 6.12 guest to boot and emit its suite under
        # QEMU TCG. The suite size is read from the guest policy's own
        # source, so this harness can never drift away from the code it
        # is verifying.
        suite_frames = guest_suite_frames()

        # Wait for the guest's suite by STATE, not by a fixed delay: poll
        # `latchctl status` until the supervisor reports that it has
        # received the whole suite.
        deadline = time.time() + 600.0
        received = 0
        while time.time() < deadline:
            os.write(master_fd, b"/proc/boot/latchctl status\n")
            read_for(3.0)
            text = buf.decode("utf-8", errors="replace")
            for m in re.finditer(r"Proposals Received\s*:\s*(\d+)", text):
                received = int(m.group(1))
            if received >= suite_frames:
                break
            read_for(3.0)
        if received < suite_frames:
            print("\nERROR: the guest's suite did not arrive (%d of %d frames)."
                  % (received, suite_frames), file=sys.stderr)
            return 1

        # Preserve guest counters BEFORE a new writer session. The ingest
        # process owns the exclusive writer OCB even after the guest stops
        # sending. Stop the disposable QEMU guest and its ingest process to
        # hand that OCB to latch_verify; never weaken writer exclusivity.
        # QNX slay has an unusual, ambiguous exit status; successful opening
        # and completion by latch_verify is the actual handoff test.
        for command, wait_s in [
            (b"/proc/boot/latchctl status\n", 2.0),
            (b"echo LATCH_TEST_GUEST_HANDOFF_BEGIN\n", 1.0),
            (b"/proc/boot/slay -9 qvm\n", 2.0),
            (b"/proc/boot/slay -9 latch-ingest\n", 2.0),
        ]:
            os.write(master_fd, command)
            read_for(wait_s)

        # OBSERVABLE HANDOFF (L-2).
        #
        # The previous revision started latch_verify after a fixed 2 s sleep
        # and relied on the resource manager having processed the ingest's
        # disconnect by then.  When it had not, latch_verify's own open of
        # the proposal node was refused with EBUSY and the run failed for a
        # reason unrelated to the invariants under test -- a timing accident
        # dressed up as a safety result.
        #
        # The supervisor now REPORTS whether the exclusive writer OCB is
        # still held (DCMD_LATCH_GET_SESSION_STATUS).  The verifier is
        # started only after the supervisor itself says the writer is gone,
        # so the ordering is enforced by observed state rather than by a
        # timer.  If the writer is genuinely never released, this fails with
        # "writer still held" instead of a confusing EBUSY from the verifier.
        handoff = False
        handoff_deadline = time.time() + 30.0
        while time.time() < handoff_deadline:
            mark = len(buf)
            os.write(master_fd, b"/proc/boot/latchctl session-status\n")
            read_for(1.5)
            fresh = buf[mark:].decode("utf-8", errors="replace")
            m = re.search(r"Writer Held\s*:\s*([01])\b", fresh)
            if m and m.group(1) == "0":
                handoff = True
                break
        if not handoff:
            print("\nERROR: the supervisor still holds the exclusive proposal "
                  "writer after the guest teardown; the handoff did not happen.",
                  file=sys.stderr)
            return 1

        verify_mark = len(buf)
        os.write(master_fd, b"echo start > /dev/shmem/latch_verify_trigger\n")
        verify_deadline = time.time() + 30.0
        while time.time() < verify_deadline:
            read_for(0.5)
            fresh = buf[verify_mark:].decode("utf-8", errors="replace")
            if re.search(r"VERIFY_RC=\d+\b", fresh):
                read_for(0.5)
                break

        text = buf.decode("utf-8", errors="replace")

        checks = [
            (r"syspage::hypinfo::flags=0x00000001", "QNX EL2 VHE hypinfo flag"),
            # The frame count comes from the guest policy, not from a
            # literal. The previous revision asserted 200, which the
            # 84-frame guest can never produce -- so `make verify-qemu`,
            # the command the README advertises as the end-to-end proof,
            # could never pass against the repo's own evidence.
            (r"Proposals Received\s*:\s*%d\b" % suite_frames,
             "%d guest proposals received" % suite_frames),
            (r"Wire Faults Caught\s*:\s*12", "12 wire faults caught"),
            (r"Envelope Vetoes\s*:\s*7\b", "7 keep-out envelope vetoes"),
            (r"Ring Drops / WCET\s*:\s*0 drops", "0 ring drops"),
            (r"LATCH_TEST_GUEST_HANDOFF_BEGIN", "explicit guest handoff"),
            # The handoff itself is asserted, not merely attempted: the
            # supervisor must have reported that the exclusive writer OCB
            # was released BEFORE the verifier was allowed to start.
            (r"Writer Held\s*:\s*0\b", "writer OCB released (observable handoff)"),
            (r"LATCH_TEST_VERIFY_LAUNCH", "typed test verifier launched"),
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

