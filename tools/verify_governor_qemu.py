#!/usr/bin/env python3
"""Boot the opt-in GOVERNOR IFS and verify its guest-to-QNX runtime path."""

from __future__ import annotations

import os
import json
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ifs = Path(os.environ.get(
        "GOVERNOR_QEMU_IFS",
        root / "qnx/build/nto-aarch64-le/latch_qemu_governor.ifs"))
    if not ifs.is_file():
        print(f"[GOVERNOR_QEMU FAIL] missing IFS: {ifs}", file=sys.stderr)
        return 1
    contract = json.loads((root / "qnx/contracts/governor_servo.manifest").read_text(encoding="utf-8"))
    lease_ticks = int(contract["governor"]["deadman"]["lease_ticks"])

    qemu = os.environ.get("QEMU_SYSTEM_AARCH64", "qemu-system-aarch64")
    cmd = [qemu, "-M", "virt,virtualization=on,gic-version=2", "-cpu", "cortex-a76",
           "-smp", "4", "-m", "2048", "-accel", "tcg,thread=multi", "-nographic",
           "-serial", "mon:stdio", "-kernel", str(ifs)]
    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    transcript = bytearray()

    def read_prompt(timeout: float) -> bytes:
        start = len(transcript)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
                if transcript.endswith(b"# "):
                    break
        return bytes(transcript[start:])

    def command(text: str, timeout: float = 2.0) -> bytes:
        os.write(master, text.encode("ascii") + b"\n")
        return read_prompt(timeout)

    try:
        if not read_prompt(90.0).endswith(b"# "):
            print("[GOVERNOR_QEMU FAIL] no QNX operator shell prompt", file=sys.stderr)
            return 1

        expected_frames = 235
        deadline = time.monotonic() + 40.0
        samples: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            sample = command("/proc/boot/latchctl status", timeout=3.0)
            text = sample.decode("utf-8", errors="replace")
            received = re.search(r"Proposals Received\s*:\s*(\d+)", text)
            rung = re.search(r"rung=([A-Z_]+)\s*\((\d+)\)", text)
            angle = re.search(r"Actuator Angle\s*:\s*(-?\d+)\s*mrad", text)
            lease = re.search(r"lease age\s*(\d+)\s*ticks", text)
            coherent = re.search(r"Coherence\s*:\s*(valid|unset)\s*\|\s*counter=(\d+)", text)
            recovery = re.search(r"Recovery Clean\s*:\s*(\d+)\s*accepted commands", text)
            if received and rung:
                snap: dict[str, object] = {
                    "received": int(received.group(1)), "rung": rung.group(1),
                    "rung_id": int(rung.group(2)),
                    "angle": int(angle.group(1)) if angle else None,
                    "lease_age": int(lease.group(1)) if lease else None,
                    "recovery": int(recovery.group(1)) if recovery else None,
                    "coherence": int(coherent.group(2)) if coherent else None,
                    "text": text,
                }
                if snap["received"] > 0:
                    samples.append(snap)
                # During the A4 hold, a fresh command has restarted the lease,
                # but heartbeat-only messages must leave the rung at ADVISE.
                if snap["received"] >= 155:
                    break
            time.sleep(0.05 if not samples else 0.003)

        a4_samples = [s for s in samples if 5 <= s["received"] <= 155]
        if not a4_samples or any(s["rung"] != "ADVISE" for s in a4_samples):
            observed = [(s["received"], s["rung"], s["lease_age"], s["coherence"], s["recovery"])
                        for s in samples]
            tail = samples[-1]["text"] if samples else transcript.decode("utf-8", errors="replace")[-2400:]
            print(f"[GOVERNOR_QEMU FAIL] A4 delayed heartbeat did not hold ADVISE through heartbeat-only traffic; samples={observed}; last_output={tail!r}",
                  file=sys.stderr)
            return 1
        a4 = a4_samples[0]
        if not isinstance(a4["lease_age"], int) or a4["lease_age"] >= lease_ticks:
            print(f"[GOVERNOR_QEMU FAIL] A4 sample has stale lease age: {a4}", file=sys.stderr)
            return 1
        if a4["coherence"] is None or a4["coherence"] < 5:
            print(f"[GOVERNOR_QEMU FAIL] A4 sample did not show progressed coherence: {a4}", file=sys.stderr)
            return 1
        hold = [s for s in a4_samples if s["received"] >= 10]
        if hold and hold[-1]["recovery"] != 0:
            print(f"[GOVERNOR_QEMU FAIL] heartbeat-only hold accumulated recovery credit: {hold[-1]}", file=sys.stderr)
            return 1
        print(f"[GOVERNOR_QEMU] A4 observed: received={a4['received']} rung={a4['rung']} "
              f"lease_age={a4['lease_age']} coherence={a4['coherence']}")

        # Let the paced recovery stream and final deadman silence complete.
        final: dict[str, object] | None = None
        recovered = False
        runtime_samples: list[tuple[int, str, int | None, int | None]] = []
        runtime_detail: list[dict[str, object]] = []
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            sample = command("/proc/boot/latchctl status", timeout=3.0)
            text = sample.decode("utf-8", errors="replace")
            received = re.search(r"Proposals Received\s*:\s*(\d+)", text)
            rung = re.search(r"rung=([A-Z_]+)\s*\((\d+)\)", text)
            angle = re.search(r"Actuator Angle\s*:\s*(-?\d+)\s*mrad", text)
            lease = re.search(r"lease age\s*(\d+)\s*ticks", text)
            faults = re.search(r"Latched Fault Bits\s*:\s*([^\r\n]+)", text)
            active = re.search(r"Active Fault Bits\s*:\s*([^\r\n]+)", text)
            recovery = re.search(r"Recovery Clean\s*:\s*(\d+)\s*accepted commands", text)
            if received and rung:
                angle_value = int(angle.group(1)) if angle else None
                final = {"received": int(received.group(1)), "rung": rung.group(1),
                         "lease_age": int(lease.group(1)) if lease else None,
                         "faults": faults.group(1).strip() if faults else "",
                         "active": active.group(1).strip() if active else "",
                         "recovery": int(recovery.group(1)) if recovery else None}
                runtime_detail.append(final.copy())
                runtime_samples.append((final["received"], final["rung"], angle_value,
                                        int(recovery.group(1)) if recovery else None))
                if (180 <= final["received"] <= 230 and final["rung"] == "HP" and
                    angle_value is not None and angle_value > 0):
                    recovered = True
                if final["received"] >= expected_frames and final["rung"] == "LATCH":
                    break
            time.sleep(0.003)

        if final is None or final["received"] != expected_frames:
            print(f"[GOVERNOR_QEMU FAIL] expected {expected_frames} received frames; got {final}", file=sys.stderr)
            return 1
        if final["rung"] != "LATCH" or "HEARTBEAT" not in final["faults"]:
            print(f"[GOVERNOR_QEMU FAIL] lease silence did not reach LATCH with HEARTBEAT fault: {final}", file=sys.stderr)
            return 1
        if not recovered:
            details = [(s["received"], s["rung"], s["lease_age"], s["active"], s["recovery"])
                       for s in runtime_detail[-12:]]
            print(f"[GOVERNOR_QEMU FAIL] did not observe clean-command recovery to HP with command motion; runtime={runtime_samples}; latest_status={details}",
                  file=sys.stderr)
            return 1

        manifest = command("/proc/boot/latchctl manifest-verify /proc/boot/governor_servo.manifest")
        if b"admissibility SATISFIED" not in manifest:
            print("[GOVERNOR_QEMU FAIL] target did not verify the schema-3 manifest sidecar", file=sys.stderr)
            return 1
        guest_log = command("/proc/boot/latchctl console", timeout=4.0)
        guest_text = guest_log.decode("utf-8", errors="replace")
        # The QEMU guest serial reliably captures kernel boot and init handoff,
        # while later /dev/kmsg phase markers are best-effort under this TCG
        # setup. Runtime status assertions above are the authoritative evidence
        # for the GOVERNOR/A4 transitions.
        for marker in ("=== LATCH Linux 6.12 Guest Userspace (/init) Alive ===",
                       "/dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2"):
            if marker not in guest_text:
                print(f"[GOVERNOR_QEMU FAIL] guest console lacks marker {marker!r}; output={guest_text[-3000:]!r}", file=sys.stderr)
                return 1

        print(f"[GOVERNOR_QEMU PASS] schema-3 sidecar valid; {expected_frames} v2 proposals; "
              "A4 demotion held through heartbeat-only traffic; clean-command recovery observed; "
              "final lease expiry reached LATCH")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master)


if __name__ == "__main__":
    raise SystemExit(main())
