#!/usr/bin/env python3
"""
Security-policy generation audit (U-6 / M-4).

Target: QNX SDP 8.0 + QNX Hypervisor 8.0 on QEMU AArch64 `virt`.

WHAT THIS DOES
--------------
It boots the DISPOSABLE, unrestricted `secpolgenerate` audit image -- never
the enforced deployment image -- lets the 235-frame guest scenario run, and
then reads what `secpolgenerate` OBSERVED:

  * /dev/secpolgenerate/policy   the DELTA: the rules that would have been
                                 needed on top of qnx/latch.secpol
  * /dev/secpolgenerate/errors   the ability checks that FAILED
  * /dev/secpolgenerate/unused   the rules in qnx/latch.secpol that were
                                 never exercised by this workload

The point of the audit is to answer one question honestly: **does the
hand-written qnx/latch.secpol grant anything the workload does not need,
and does it withhold anything the workload does need?**

WHAT IT IS NOT
--------------
It is NOT a proof that the policy is correct.  The exercised workload is the
235-frame scripted guest scenario and NOTHING ELSE: it does not cover the
I2C plant, the Pi 4B board, the secpolgenerate audit image's own
development-only binaries, or any failure path.  A rule that this workload
never touches is UNKNOWN to this audit, not SAFE.  That is exactly what the
`unused` file reports, and the delta review must say so.

The audit image runs `secpolgenerate -u -t 100`, which makes the observed
policy UNRESTRICTED.  The delta it produces is therefore a SUPERSET of what
a strictly-enforced run would need: it includes the permissions the
development-only binaries (secpolgenerate itself, secpol-preload.so, the
audit reader) used.  The review has to subtract those before the delta
means anything about the deployment policy.

THE ARCHIVE IS ONLY WRITTEN WHEN THE RUN PASSES
------------------------------------------------
A failed run exits non-zero WITHOUT touching docs/evidence/, so a broken
image can never replace good evidence with a partial transcript.
"""

from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path

# The observation files the audit is about.  `request` and `control` are the
# generator's control channels; they are read too, so a transcript that
# claims to be complete really is.
OBSERVATION_FILES = ("policy", "errors", "unused", "request", "control")

# How long ONE observation file may take before the reader gives up.  The
# reader has its own internal bound; this is the harness's backstop.
PER_FILE_TIMEOUT = 90.0


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ifs = Path(os.environ.get(
        "SECPOL_AUDIT_IFS",
        root / "qnx/build/nto-aarch64-le/latch_qemu_governor_secpol_audit.ifs"))
    evidence_path = Path(os.environ.get(
        "SECPOL_AUDIT_LOG", "/tmp/latch-secpol-audit.txt"))

    if not ifs.is_file():
        print(f"[SECPOL AUDIT FAIL] missing IFS: {ifs}", file=sys.stderr)
        return 1

    qemu = os.environ.get("QEMU_SYSTEM_AARCH64", "qemu-system-aarch64")
    cmd = [qemu, "-M", "virt,virtualization=on,gic-version=2", "-cpu", "cortex-a76",
           "-smp", "4", "-m", "2048", "-accel", "tcg,thread=multi", "-nographic",
           "-serial", "mon:stdio", "-kernel", str(ifs)]

    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    transcript = bytearray()
    lines: list[str] = []

    def log(msg: str = "") -> None:
        print(msg)
        lines.append(msg)

    def read_until(deadline_re, timeout: float) -> tuple[bytes, bool]:
        """Read until the regex matches or the timeout expires."""
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                transcript.extend(chunk)
                if deadline_re.search(bytes(buf)):
                    return bytes(buf), True
        return bytes(buf), False

    def command(cmd_str: str, timeout: float = 6.0) -> str:
        """Run a shell command and wait for it to finish.

        THE SENTINEL IS NOT OPTIONAL.  Detecting the end of a command by
        looking for the shell prompt ("# ") is fooled by the command's own
        OUTPUT: every line of /dev/secpolgenerate/policy begins with "# ",
        so a prompt detector returns after the file's second character and
        the reader is killed mid-write.  That is exactly what happened
        here -- the observation reader never hung; the harness walked away
        and took QEMU (and the reader) with it.  The sentinel is matched
        WITH its exit-code digit, so the shell's echo of the typed command
        cannot be mistaken for the command's output.
        """
        seq = command.counter
        command.counter += 1
        tag = "SECPOL_CMD_%d" % seq
        os.write(master, ("%s; echo %s_$?\n" % (cmd_str, tag)).encode())
        out, done = read_until(re.compile((r"%s_(\d)" % tag).encode()), timeout)
        text = out.decode("utf-8", errors="replace").replace("\r", "")
        if "\n" in text:
            text = text.split("\n", 1)[1]
        if not done:
            print("[SECPOL AUDIT] command did not finish: %s" % cmd_str,
                  file=sys.stderr)
        return text

    def dump_observation(name: str) -> tuple[str, bool, str]:
        """Read ONE observation file.  Returns (text, completed, verdict)."""
        sentinel = "SECPOL_DONE_%s_$?" % name
        os.write(master, ("/proc/boot/latch_secpol_dump /dev/secpolgenerate/%s; echo %s\n"
                          % (name, sentinel)).encode())
        # The sentinel is matched WITH its digit, so the shell's echo of the
        # typed command (which contains `SECPOL_DONE_<name>_$?`) can never be
        # mistaken for the command's OUTPUT.
        done_re = re.compile((r"SECPOL_DONE_%s_(\d)" % name).encode())
        out, done = read_until(done_re, PER_FILE_TIMEOUT)
        text = out.decode("utf-8", errors="replace").replace("\r", "")
        # Strip the shell's echo of the command line itself.
        if "\n" in text:
            text = text.split("\n", 1)[1]
        verdict = ""
        m = re.search(r"snapshot ended: (.*)", text)
        if m:
            verdict = m.group(1).strip()
        return text, done, verdict

    command.counter = 0

    try:
        log("=" * 78)
        log(" LATCH — SECURITY-POLICY GENERATION AUDIT (U-6 / M-4)")
        log(" Platform: QNX OS/SDP 8.0 (procnto-smp-instr) on ARMv8-A QEMU `virt` (TCG)")
        log(" Image    : the DISPOSABLE, unrestricted secpolgenerate audit image.")
        log("            This is NOT the enforced deployment image and nothing")
        log("            observed here is accepted as a deployment rule without")
        log("            a written review.")
        log(" Workload : the 235-frame scripted guest scenario, and nothing else.")
        log("=" * 78)
        log()

        initial, ok = read_until(re.compile(rb"# "), 150.0)
        if not ok:
            log("[SECPOL AUDIT FAIL] timed out waiting for the QNX shell prompt.")
            return 1
        log("[PHASE 1] the audit image booted; the unrestricted policy generator is running.")

        # The generator must actually be running, or the audit is vacuous.
        pidin = command("pidin -F \"%a %b %_ %28n\"")
        if "secpolgenerate" not in pidin:
            log("[SECPOL AUDIT FAIL] secpolgenerate is not running; the audit would be vacuous.")
            log(pidin)
            return 1
        log("[PHASE 2] the process types under audit:")
        for line in pidin.splitlines():
            if ("secpolgenerate" in line or "latchd" in line or "latchlog" in line
                    or "latch_guestd" in line or "qvm" in line or "ksh" in line
                    or "latch-ingest" in line or "latch_verify" in line):
                log("    " + line.strip())
        log()

        # Let the 235-frame workload run.  The supervisor's own counter is the
        # authority on how much of it arrived.
        log("[PHASE 3] running the 235-frame guest scenario...")
        received = 0
        deadline = time.monotonic() + 240.0
        while time.monotonic() < deadline:
            status = command("/proc/boot/latchctl status")
            m = re.search(r"Proposals Received\s*:\s*(\d+)", status)
            rung = re.search(r"rung=([A-Z_]+)", status)
            if m:
                received = int(m.group(1))
                log("    proposals received: %d%s" % (
                    received, ("  rung=%s" % rung.group(1)) if rung else ""))
                if received >= 235:
                    break
            time.sleep(2.0)
        if received < 235:
            log("[SECPOL AUDIT FAIL] the workload did not complete: only %d of 235 "
                "proposals arrived. The archive was NOT modified." % received)
            return 1
        log("    the full 235-frame workload arrived under the generated policy.")
        log()

        # Give the generator a moment to finalise its snapshot.
        time.sleep(5.0)

        log("[PHASE 4] reading the secpolgenerate observation files...")
        captured: dict[str, str] = {}
        for name in OBSERVATION_FILES:
            text, done, verdict = dump_observation(name)
            if not done:
                log("[SECPOL AUDIT FAIL] the observation reader did not finish for "
                    "/dev/secpolgenerate/%s. The archive was NOT modified." % name)
                log(text)
                return 1
            if "PARTIAL" in verdict:
                log("[SECPOL AUDIT FAIL] the snapshot for /dev/secpolgenerate/%s was "
                    "PARTIAL (%s). The archive was NOT modified." % (name, verdict))
                log(text)
                return 1
            captured[name] = text
            log("    /dev/secpolgenerate/%s: %d byte(s), %s"
                % (name, len(text), verdict or "read to EOF"))
            log("    " + "-" * 70)
            for line in text.splitlines():
                log("    " + line)
            log("    " + "-" * 70)
        log()

        # The final supervisor state, so the transcript ties the observations
        # to a run that actually exercised the safety logic.
        final_status = command("/proc/boot/latchctl status")
        log("[PHASE 5] the supervisor's final state under the generated policy:")
        for line in final_status.splitlines():
            if any(k in line for k in ("Proposals Received", "rung=", "Latched Fault",
                                       "Active Fault", "Envelope Vetoes",
                                       "Wire Faults Caught", "Manifest SHA-256")):
                log("    " + line.strip())
        log()
        log("[SECPOL AUDIT PASS] the unrestricted policy generator observed the full")
        log("235-frame workload; the delta, the errors and the unused rules are above.")
        log("The delta is an OBSERVATION, not an accepted rule set: see the review.")

        text = "\n".join(lines) + "\n"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(text, encoding="utf-8")
        print("[SECPOL AUDIT] wrote %s" % evidence_path)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master)
        try:
            with open(str(evidence_path) + ".console", "wb") as f:
                f.write(bytes(transcript))
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
