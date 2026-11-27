#!/usr/bin/env python3
"""Boot the DISPOSABLE verdict-watcher image and verify the CONTROL channel.

WHAT THIS PROVES
----------------
W4 proved that a host-side verdict REACHES a freestanding guest policy.
W5 asks the question that matters: when the TRUSTED SUPERVISOR refuses the
guest's proposal, does the guest find out -- and does it stop asking?

One boot answers it, and it answers it with FOUR independent observations:

  1. THE VERDICT ARRIVED AND WAS UNDERSTOOD.  The guest's own report
     carries `acc=<n>` (the proposals the supervisor accepted) and
     `rej=<n>` (the ones it refused).  A guest that could not parse the
     verdict would report neither.

  2. THE GUEST STOPPED WHEN IT WAS TOLD NO.  The report's `stop=reject`
     is the guest's own decision, and the SUPERVISOR'S final rung is
     LATCH with a HEARTBEAT fault -- which can only happen if the guest
     went SILENT.  A guest that kept asking after being told no would
     hold the lease open and the ladder would never reach LATCH.  The
     two observations are independent: one is the guest's account of
     itself, the other is the trusted host's account of the guest.

  3. NOTHING WAS LOST.  The guest's `sent` (the frames it put on the
     wire) must equal the supervisor's `Proposals Received`.  A dropped
     frame, a duplicated frame or a miscount would show up as a
     difference, and the difference would be the supervisor's, not the
     guest's.

  4. EVERY COMMAND GOT EXACTLY ONE VERDICT: `cmds == acc + rej`.

WHY THIS IS NOT THE W4 HARNESS WITH A DIFFERENT NAME
----------------------------------------------------
W4 published SYNTHETIC frames from `latch_fb_pump`.  This image has NO
pump: the only publisher of a verdict is `latchd` itself, so the verdict
the guest reads is the verdict of the thing that actually decides.  The
transport is byte-for-byte the same (the SAME qvmconf is reused), so the
only difference between the two measurements is WHO publishes and WHAT
the guest does with the answer.

A NOTE ON COMMAND COMPLETION
----------------------------
The command's end is detected with a SENTINEL whose exit-code digit is
matched, never with the shell prompt.  Every line of QNX's
`/dev/secpolgenerate/policy` begins with `# `, so a prompt-based detector
fires on the OUTPUT of a command whose output happens to look like the
prompt -- and the harness then walks away and kills the machine mid-run.
That is not hypothetical: it is what broke the secpolgenerate audit
harness on this very target.
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path


# The fields the guest's report MUST carry.  A report that is missing one
# of them is not a report; it is a fragment, and a fragment is not a
# measurement.
REQUIRED_FIELDS = (
    "port", "opens", "reads", "frames", "changes", "sent", "cmds", "acc",
    "rej", "foreign", "stale", "dup", "torn", "empty", "to", "polls",
    "maxrt", "epoch", "stop", "last", "end",
)


def format_report(report: dict) -> str:
    """The structured, human-readable report the evidence archive carries."""
    out: list[str] = []
    add = out.append
    add("=" * 78)
    add("LATCH -- HOST->GUEST VERDICT WATCHER (W5, EXPERIMENTAL)")
    add("=" * 78)
    add("IFS                 : %s" % report.get("ifs", ""))
    add("Signed contract    : qnx/contracts/governor_servo.manifest")
    add("Verdict            : %s" % report.get("verdict", "FAIL"))
    add("")
    add("--- WHAT THIS MEASUREMENT IS ---")
    add("The verdict on the wire is the verdict of the TRUSTED SUPERVISOR:")
    add("this image has no `latch_fb_pump`, and `latchd -f /dev/latch/")
    add("feedback_pub` publishes one verdict per MOTION PROPOSAL -- ACCEPT")
    add("when it accepted the proposal and is still in HP, REJECT when it")
    add("refused it or it is no longer following the guest.  The transport")
    add("is byte-for-byte the same as W4's (the SAME qvmconf is reused), so")
    add("the only difference between the two measurements is WHO publishes")
    add("and WHAT the guest does with the answer.")
    add("")
    add("The guest is a FREESTANDING AArch64 binary with no libc.  It")
    add("decodes the verdict, correlates it with the proposal it answers")
    add("by BOTH the sequence number and the session epoch, and stops")
    add("proposing when the supervisor says no.  The session epoch is")
    add("LEARNED from the first verdict and pinned for the rest of the")
    add("session: the trusted side binds it, so the guest never chooses it.")
    add("")
    add("THE DECISIVE OBSERVATION IS THE SUPERVISOR'S FINAL RUNG.  It can")
    add("only reach LATCH if the guest went SILENT, because the signed")
    add("lease expired.  A guest that kept asking after being told no")
    add("would hold the lease open, and the ladder would never get there.")
    add("So the guest's own `stop=reject` and the trusted host's `LATCH`")
    add("are INDEPENDENT accounts of the same event.")
    add("")
    marker = report.get("marker")
    if isinstance(marker, dict):
        for key in REQUIRED_FIELDS:
            add("%-20s: %s" % (key, marker.get(key)))
    else:
        add("(no complete [FBVERDICT] marker was found in the guest console)")
    add("")
    add("--- THE SUPERVISOR'S OWN ACCOUNT ---")
    add("%-14s %-14s %-12s %s" % ("received", "rung", "lease_age", "faults"))
    for s in report.get("samples", []):  # type: ignore[union-attr]
        add("%-14s %-14s %-12s %s" % (
            s.get("received"), s.get("rung"), s.get("lease_age"), s.get("faults")))
    add("")
    add("--- THE FINAL LADDER ---")
    final = report.get("final")
    add("FINAL STATE        : %s" % json.dumps(final, sort_keys=True))
    add("")
    add("--- THE SIGNED CONTRACT, VERIFIED ON THE TARGET ---")
    add((report.get("manifest_verify", "") or "").rstrip())
    add("")
    add("--- THE GUEST'S OWN CONSOLE (from /dev/shmem/guest_console.log) ---")
    add((report.get("guest_console", "") or "").rstrip())
    add("")
    return "\n".join(out) + "\n"


def parse_fbverdict_marker(text: str) -> tuple[str, dict[str, str]] | None:
    """Extract a COMPLETE `[FBVERDICT]` report from a guest console dump.

    Returns `(raw, fields)` or `None`.

    "Complete" is judged by the SENTINEL, not by a regular expression's
    greediness.  The guest writes the whole report in one `/dev/kmsg`
    record and it ends with `end=1`; a report that was cut short by the
    console does not end with it, and a harness that accepted a fragment
    would be reporting a measurement it never made.

    THE LINE ENDING IS NOT `\\r\\n`, AND THAT MATTERS.
    MEASURED on the QEMU AArch64 target (2026-11-26): the console ends a
    line with **THREE** carriage returns and a newline (`\\r\\r\\r\\n`), so
    a regex that consumes one `\\r` and then demands the end of the line
    NEVER MATCHES -- and the harness then reports "the guest never
    reported a marker" for a marker that is sitting right there in the
    transcript, complete and correct.  The pattern therefore stops at the
    first carriage return, and the completeness judgement is made by the
    sentinel and the field census.
    """
    for candidate in re.finditer(r"\[FBVERDICT\][^\r\n]*", text):
        raw = candidate.group(0).strip()
        if not raw.endswith("end=1"):
            continue
        fields = dict(re.findall(r"(\w+)=([^\s]+)", raw))
        if any(k not in fields for k in REQUIRED_FIELDS):
            continue
        return raw, fields
    return None


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ifs = Path(os.environ.get(
        "FBVERDICT_QEMU_IFS",
        root / "qnx/build/nto-aarch64-le/latch_qemu_fbverdict.ifs"))
    if not ifs.is_file():
        print(f"[FBVERDICT_QEMU FAIL] missing IFS: {ifs}", file=sys.stderr)
        return 1
    contract = json.loads((root / "qnx/contracts/governor_servo.manifest").read_text(encoding="utf-8"))
    lease_ticks = int(contract["governor"]["deadman"]["lease_ticks"])

    transcript_path = os.environ.get("FBVERDICT_QEMU_TRANSCRIPT")
    transcript_file = None
    if transcript_path is not None:
        transcript_file = open(transcript_path, "wb")
    report_path = os.environ.get("FBVERDICT_QEMU_REPORT")
    report: dict[str, object] = {
        "ifs": str(ifs),
        "lease_ticks": lease_ticks,
        "contract_sha256": contract.get("_sidecar_sha256", ""),
        "marker": None,
        "samples": [],
        "final": None,
        "guest_console": "",
        "manifest_verify": "",
        "verdict": "FAIL",
    }

    def write_report() -> None:
        if not report_path:
            return
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(format_report(report))

    qemu = os.environ.get("QEMU_SYSTEM_AARCH64", "qemu-system-aarch64")
    cmd = [qemu, "-M", "virt,virtualization=on,gic-version=2", "-cpu", "cortex-a76",
           "-smp", "4", "-m", "2048", "-accel", "tcg,thread=multi", "-nographic",
           "-serial", "mon:stdio", "-kernel", str(ifs)]
    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    transcript = bytearray()
    tag_counter = [0]

    def pump(timeout: float) -> bytes:
        """Read whatever arrives, for up to `timeout` seconds."""
        start = len(transcript)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if not ready:
                continue
            try:
                chunk = os.read(master, 8192)
            except OSError:
                break
            if not chunk:
                break
            transcript.extend(chunk)
            if transcript_file is not None:
                transcript_file.write(chunk)
                transcript_file.flush()
        return bytes(transcript[start:])

    def wait_for_prompt(timeout: float) -> bool:
        """Wait for the operator shell's PROMPT.

        The prompt is only used for the INITIAL handshake -- before any
        command has been sent.  Once a command is running, its end is
        detected with a sentinel (see `command`), because a command's own
        output can contain a line that looks exactly like the prompt.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
                if transcript_file is not None:
                    transcript_file.write(chunk)
                    transcript_file.flush()
            if transcript.endswith(b"# "):
                return True
        return False

    def command(text: str, timeout: float = 5.0) -> bytes:
        """Run a command and return its output.

        The end of the command is detected with a SENTINEL whose exit-code
        digit is matched -- never with the shell prompt, because a command's
        own output can contain a line that looks exactly like the prompt.
        """
        tag_counter[0] += 1
        tag = "LATCHFBV%d" % tag_counter[0]
        os.write(master, (text + "; echo " + tag + "_$?\n").encode("ascii"))
        pattern = re.compile(re.escape(tag).encode("ascii") + rb"_(\d)")
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
                if transcript_file is not None:
                    transcript_file.write(chunk)
                    transcript_file.flush()
                if pattern.search(bytes(transcript[start:])):
                    break
        return bytes(transcript[start:])

    def read_status() -> dict[str, object] | None:
        sample = command("/proc/boot/latchctl status", timeout=4.0)
        text = sample.decode("utf-8", errors="replace")
        received = re.search(r"Proposals Received\s*:\s*(\d+)", text)
        rung = re.search(r"rung=([A-Z_]+)\s*\((\d+)\)", text)
        lease = re.search(r"lease age\s*(\d+)\s*ticks", text)
        faults = re.search(r"Latched Fault Bits\s*:\s*([^\r\n]+)", text)
        if not received or not rung:
            return None
        return {
            "received": int(received.group(1)),
            "rung": rung.group(1),
            "rung_id": int(rung.group(2)),
            "lease_age": int(lease.group(1)) if lease else None,
            "faults": faults.group(1).strip() if faults else "",
        }

    try:
        # ---- the operator shell must come up -----------------------------
        if not wait_for_prompt(180.0):
            print("[FBVERDICT_QEMU FAIL] no QNX operator shell prompt", file=sys.stderr)
            return 1
        boot = command("echo LATCHFBV_BOOT", timeout=30.0)
        if not re.search(rb"LATCHFBV\d+_\d", boot):
            print(f"[FBVERDICT_QEMU FAIL] the operator shell did not answer the sentinel "
                  f"handshake: {boot[-400:]!r}", file=sys.stderr)
            return 1

        # ---- (1) the guest's own report ----------------------------------
        # The report is written AFTER the final silence, so it appears
        # late.  Poll for it rather than assuming a timing: the Linux boot
        # under TCG takes tens of seconds.
        marker: tuple[str, dict[str, str]] | None = None
        guest_text = ""
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            guest_text = command("/proc/boot/latchctl console", timeout=6.0).decode(
                "utf-8", errors="replace")
            found = parse_fbverdict_marker(guest_text)
            if found:
                marker = found
                break
            time.sleep(1.0)
        if marker is None:
            report["guest_console"] = guest_text
            print("[FBVERDICT_QEMU FAIL] the guest never reported a COMPLETE "
                  "[FBVERDICT] marker; the verdict channel did not deliver. "
                  "tail=%r" % guest_text[-3000:], file=sys.stderr)
            return 1

        raw, fields = marker
        report["marker"] = dict(fields)
        report["marker"]["raw"] = raw
        print(f"[FBVERDICT_QEMU] guest report: {raw}")

        def num(name: str) -> int:
            try:
                return int(str(fields.get(name, "0")), 0)
            except ValueError:
                return -1

        sent = num("sent")
        cmds = num("cmds")
        acc = num("acc")
        rej = num("rej")
        foreign = num("foreign")
        stale = num("stale")
        dups = num("dup")
        timeouts = num("to")
        changes = num("changes")
        epoch = num("epoch")

        if fields.get("port") == "none":
            print(f"[FBVERDICT_QEMU FAIL] no candidate device carried the verdict "
                  f"channel: {raw!r}", file=sys.stderr)
            return 1
        if changes < 1:
            print(f"[FBVERDICT_QEMU FAIL] the verdict file never changed under "
                  f"the guest's polling: {raw!r}", file=sys.stderr)
            return 1
        if rej != 1:
            print(f"[FBVERDICT_QEMU FAIL] the guest did not record exactly ONE "
                  f"refusal: {raw!r}", file=sys.stderr)
            return 1
        if fields.get("stop") != "reject":
            print(f"[FBVERDICT_QEMU FAIL] the guest did not stop on the refusal: "
                  f"{raw!r}", file=sys.stderr)
            return 1
        if acc < 1:
            print(f"[FBVERDICT_QEMU FAIL] the guest recorded no acceptance at all: "
                  f"{raw!r}", file=sys.stderr)
            return 1
        if cmds != acc + rej:
            print(f"[FBVERDICT_QEMU FAIL] the guest's command census does not "
                  f"close: cmds={cmds} acc={acc} rej={rej}; {raw!r}", file=sys.stderr)
            return 1
        if foreign != 0 or stale != 0 or dups != 0:
            print(f"[FBVERDICT_QEMU FAIL] the correlation was not clean: "
                  f"foreign={foreign} stale={stale} dup={dups}; {raw!r}",
                  file=sys.stderr)
            return 1
        if timeouts != 0:
            print(f"[FBVERDICT_QEMU FAIL] the guest timed out on the channel: "
                  f"to={timeouts}; {raw!r}", file=sys.stderr)
            return 1
        if epoch == 0:
            print(f"[FBVERDICT_QEMU FAIL] the guest did not learn the session "
                  f"epoch: {raw!r}", file=sys.stderr)
            return 1

        # ---- (2) the supervisor's account --------------------------------
        samples: list[dict[str, object]] = []
        final: dict[str, object] | None = None
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            snap = read_status()
            if snap is not None:
                samples.append(snap)
                final = snap
                if snap["received"] >= sent and snap["rung"] == "LATCH":
                    break
            time.sleep(0.05)
        report["samples"] = samples[-32:]
        if final is None:
            print("[FBVERDICT_QEMU FAIL] the supervisor never reported a status",
                  file=sys.stderr)
            return 1

        # ---- (3) NOTHING WAS LOST ---------------------------------------
        # The guest's own count of the frames it put on the wire must equal
        # the supervisor's count of the frames it consumed.  A difference
        # would be a dropped frame, a duplicated frame or a miscount --
        # and it would be the SUPERVISOR's number that is wrong, not the
        # guest's.
        if final["received"] != sent:
            print(f"[FBVERDICT_QEMU FAIL] the supervisor received {final['received']} "
                  f"frames but the guest sent {sent}: {raw!r}", file=sys.stderr)
            return 1

        # ---- (4) THE GUEST STOPPED ---------------------------------------
        # The signed lease expired (the guest went silent) and the ladder
        # ratcheted to LATCH.  A guest that kept asking would hold the
        # lease open, so this is the trusted host's independent account of
        # the guest having stopped.
        if final["rung"] != "LATCH":
            print(f"[FBVERDICT_QEMU FAIL] the final rung is {final['rung']!r}, not "
                  f"LATCH: the guest's silence did not expire the lease. {final}",
                  file=sys.stderr)
            return 1
        if "HEARTBEAT" not in str(final["faults"]):
            print(f"[FBVERDICT_QEMU FAIL] the final latch does not carry the "
                  f"HEARTBEAT fault: {final}", file=sys.stderr)
            return 1

        manifest = command("/proc/boot/latchctl manifest-verify /proc/boot/governor_servo.manifest")
        report["manifest_verify"] = manifest.decode("utf-8", errors="replace")
        if b"admissibility SATISFIED" not in manifest:
            print("[FBVERDICT_QEMU FAIL] target did not verify the schema-3 manifest sidecar",
                  file=sys.stderr)
            return 1

        guest_text = command("/proc/boot/latchctl console", timeout=8.0).decode(
            "utf-8", errors="replace")
        report["guest_console"] = guest_text
        for needed in ("=== LATCH Linux 6.12 Guest Userspace (/init) Alive ===",
                       "/dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2",
                       "[FBVERDICT]"):
            if needed not in guest_text:
                print(f"[FBVERDICT_QEMU FAIL] guest console lacks marker {needed!r}; "
                      f"tail={guest_text[-3000:]!r}", file=sys.stderr)
                return 1

        report["final"] = final
        report["verdict"] = "PASS"
        print("[FBVERDICT_QEMU PASS] the trusted supervisor's own verdict reached "
              "the freestanding guest, the guest understood it (the verdict "
              "vocabulary is closed, the session epoch was learned and pinned), "
              "and the guest STOPPED when it was told no: the guest reports "
              f"rej={rej} stop=reject with acc={acc} accepted proposals, the "
              f"supervisor received exactly the {sent} frames the guest sent, "
              "and the lease then expired and the ladder reached LATCH")
        return 0
    finally:
        # The report is written even when the run FAILED: a failing run must
        # still leave the evidence that explains why it failed.
        write_report()
        if transcript_file is not None:
            transcript_file.close()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master)


if __name__ == "__main__":
    sys.exit(main())
