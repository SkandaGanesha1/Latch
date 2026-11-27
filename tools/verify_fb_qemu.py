#!/usr/bin/env python3
"""Boot the DISPOSABLE feedback-transport probe image and verify the transport.

WHAT THIS PROVES
----------------
One boot answers TWO questions, and both are answered by measurement:

  1. Does a host-side verdict reach a freestanding guest policy?
     The verdict lives at SECTOR 0 of a 1 MiB backing file that the
     hypervisor opens READ-ONLY (`hostdev <`), so the guest cannot write
     the channel at all.  The guest polls the sector with `pread64`,
     re-synchronises on the frame MAGIC, validates the CRC, and reports
     what it saw in ONE `[FBPROBE]` marker on the kernel log.  The marker
     is emitted BEFORE the session opens, so the supervisor's dead-man
     never sees the probe's silence.

     The decisive field is `changes`: the number of times the sequence
     number CHANGED under the guest's own polling.  A fixed image is not
     a channel, so `frames >= 1` alone is NOT a pass.

  2. Does the feedback device leave the BLACK CHANNEL undisturbed?
     The scenario is the UNCHANGED 235-frame GOVERNOR scenario, so the
     supervisor's own measurements (A4 demotion held at ADVISE, clean
     recovery to HP, the final lease expiry reaching LATCH) must be
     exactly what they are without the feedback device.

Question 1 is the transport experiment.  Question 2 is what makes the
experiment trustworthy: a "working" transport that broke the safety path
would be worse than no transport at all.

THREE TRANSPORTS WERE TRIED FIRST AND ARE REJECTED BY MEASUREMENT
(see AGENTS.md §4c): a QNX pseudo-terminal (its open ORDER decides
usability, and any process could write it), the PL011 vdev's host->guest
injection (the guest's RX-enable gate is never satisfied by Linux
`amba-pl011`), and the virtio-console's input direction (its pulse is
unreachable).

A NOTE ON THE MARKER
--------------------
The `[FBPROBE]` line is accepted only when it is COMPLETE: it must end in
`eN=<digits>` AND its per-candidate census (`p0..pN`, `e0..eN`) must be
contiguous from 0 and finish on the highest index.  An earlier version of
this harness matched `[FBPROBE][^\\r\\n]*` and accepted a line the console
reader had truncated mid-field, which is a false PASS waiting to happen.

Two artefacts can be written out, so the evidence archive is GENERATED and
never hand-edited:

    FB_QEMU_TRANSCRIPT   the raw serial transcript, verbatim
    FB_QEMU_REPORT       the structured report

Both are written even when the run FAILS, so a failing run still leaves
the evidence that explains why it failed.

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


def format_report(report: dict) -> str:
    """The structured, human-readable report the evidence archive carries."""
    out: list[str] = []
    add = out.append
    add("=" * 78)
    add("LATCH -- HOST->GUEST FEEDBACK-TRANSPORT PROBE (W4, EXPERIMENTAL)")
    add("=" * 78)
    add("IFS                 : %s" % report.get("ifs", ""))
    add("Signed contract    : qnx/contracts/governor_servo.manifest")
    add("Verdict            : %s" % report.get("verdict", "FAIL"))
    add("")
    add("--- THE TRANSPORT MEASUREMENT ---")
    add("The verdict lives at sector 0 of a 1 MiB backing file that the")
    add("hypervisor opens READ-ONLY (`hostdev </dev/shmem/latch_feedback.img`),")
    add("so the guest cannot write the channel at all.  The guest polls the")
    add("sector with pread64, re-synchronises on the frame MAGIC and validates")
    add("the CRC; a frame that failed either check would not have been counted,")
    add("so a positive result cannot be a framing accident.")
    add("")
    add("`changes` is the decisive field: the number of times the sequence")
    add("number CHANGED under the guest's own polling.  A fixed image is not a")
    add("channel, so `frames >= 1` alone is NOT a pass.")
    add("")
    add("THE GUEST'S PAGE CACHE IS THE TRANSPORT'S ADVERSARY, AND THE REPORT")
    add("SAYS WHICH MECHANISM GOT PAST IT.  `dir=1` is a direct (O_DIRECT)")
    add("read that never caches; `dir=0` is a buffered read preceded by")
    add("POSIX_FADV_DONTNEED, which drops the cached pages so the read goes")
    add("back to the device.  `derr` is why the O_DIRECT open was refused")
    add("(`0` = it was accepted) and `ferr` is why the advice was refused")
    add("(`0` = it was accepted).  A freshness failure has to be")
    add("attributable, so the reason is carried in the report rather than")
    add("guessed at.")
    add("")
    add("The host-side writer is `latch_fb_sink`: the ONLY process that may")
    add("write the file, which accepts a frame only on its one-sided WRITE node")
    add("and copies the latest one out on a dedicated writer thread.  Three")
    add("other transports were tried first and are REJECTED BY MEASUREMENT:")
    add("a QNX pseudo-terminal (its open ORDER decides usability, and any")
    add("process could write it), the PL011 vdev's host->guest injection (the")
    add("guest's RX-enable gate is never satisfied by Linux amba-pl011), and")
    add("the virtio-console's input direction (its pulse is unreachable).")
    add("")
    add("The verdict file is written BEFORE the frame is mirrored into the")
    add("mailbox, because the mailbox is a vestigial mirror that nothing reads")
    add("any more: when the file write was conditional on the mailbox")
    add("accepting the frame, a full mailbox starved the transport and the")
    add("measured write count froze.")
    add("")
    probe = report.get("probe")
    if isinstance(probe, dict):
        for key in ("port", "opens", "dir", "bytes", "frames", "seq", "changes",
                    "bad", "epoch", "verdict", "rung", "faults"):
            add("%-20s: %s" % (key, probe.get(key)))
        add("%-20s: %s" % ("per-candidate", probe.get("per_port")))
        add("%-20s: %s" % ("open errno", probe.get("open_errno")))
        add("%-20s: %s" % ("raw marker", probe.get("raw", "")))
    else:
        add("(no [FBPROBE] marker was found in the guest console)")
    add("")
    add("--- THE BLACK CHANNEL, ON THE SAME BOOT ---")
    add("The scenario is the UNCHANGED 235-frame GOVERNOR scenario.  These are")
    add("the supervisor's own measurements: if the feedback port had disturbed")
    add("the frame path, they would not match the profile without it.")
    add("")
    add("%-10s %-10s %-12s %-10s %-10s" % ("received", "rung", "lease_age", "coherence", "recovery"))
    for s in report.get("a4_samples", []):  # type: ignore[union-attr]
        add("%-10s %-10s %-12s %-10s %-10s" % (
            s.get("received"), s.get("rung"), s.get("lease_age"),
            s.get("coherence"), s.get("recovery")))
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


def parse_fbprobe_marker(text: str) -> tuple[str, dict[str, str]] | None:
    """Extract a COMPLETE `[FBPROBE]` report from a guest console dump.

    Returns `(raw, fields)` or `None`.

    "Complete" is not a matter of taste here.  An earlier version of this
    harness matched `\\[FBPROBE\\][^\\r\\n]*` and accepted a line the console
    reader had truncated mid-field -- a partial line is indistinguishable
    from a whole one under that regex, and it would have been reported as a
    measurement.  Two conditions must hold:

      * the per-candidate census must be CONTIGUOUS from 0 -- every `pN=`
        and every `eN=` for N in 0..max -- and the line must end on the
        HIGHEST of those indices.  A line cut anywhere inside the census
        therefore fails even if it happens to end on `eK=<digits>` for some
        K < max; and
      * the line must END in `eN=<digits>`, which is the last field the
        guest writes.

    A line that fails either condition is treated as not-yet-delivered and
    the caller keeps polling; the guest writes the whole report in one
    `/dev/kmsg` record, so a genuinely complete line always appears.

    THE LINE ENDING IS NOT `\r\\n`, AND THAT MATTERS.
    MEASURED on the QEMU AArch64 target (2026-11-26): the console ends a
    line with **THREE** carriage returns and a newline (`\\r\\r\\r\\n`), so
    a regex that consumes one `\\r` and then demands the end of the line
    (`[^\\r\\n]*\\r?$`) NEVER MATCHES -- and the harness then reports "the
    guest never reported a marker" for a marker that is sitting right there
    in the transcript, complete and correct.  The pattern therefore stops
    at the first carriage return and the completeness judgement is made by
    the census, which is what the completeness judgement was for.
    """
    match: re.Match[str] | None = None
    raw = ""
    fields: dict[str, str] = {}
    for candidate in re.finditer(r"\[FBPROBE\][^\r\n]*", text):
        raw = candidate.group(0).strip()
        fields = dict(re.findall(r"(\w+)=([^\s]+)", raw))

        def census(prefix: str, f: dict[str, str] = fields) -> list[int]:
            return sorted(int(k[len(prefix):]) for k in f
                          if k.startswith(prefix) and k[len(prefix):].isdigit())

        ports = census("p")
        errnos = census("e")
        if not ports or not errnos:
            continue
        if ports != list(range(len(ports))) or errnos != list(range(len(errnos))):
            continue
        if len(ports) != len(errnos):
            continue
        tail = re.search(r"\be(\d+)=(\d+)$", raw)
        if tail is None or int(tail.group(1)) != max(errnos):
            continue
        match = candidate
        break
    if match is None:
        return None
    return raw, fields


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ifs = Path(os.environ.get(
        "FB_QEMU_IFS",
        root / "qnx/build/nto-aarch64-le/latch_qemu_fbprobe.ifs"))
    if not ifs.is_file():
        print(f"[FB_QEMU FAIL] missing IFS: {ifs}", file=sys.stderr)
        return 1
    contract = json.loads((root / "qnx/contracts/governor_servo.manifest").read_text(encoding="utf-8"))
    lease_ticks = int(contract["governor"]["deadman"]["lease_ticks"])

    transcript_path = os.environ.get("FB_QEMU_TRANSCRIPT")
    transcript_file = None
    if transcript_path is not None:
        transcript_file = open(transcript_path, "wb")
    report_path = os.environ.get("FB_QEMU_REPORT")
    report: dict[str, object] = {
        "ifs": str(ifs),
        "lease_ticks": lease_ticks,
        "contract_sha256": contract.get("_sidecar_sha256", ""),
        "probe": None,
        "a4_samples": [],
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
        tag = "LATCHFB%d" % tag_counter[0]
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

    try:
        # ---- the operator shell must come up -----------------------------
        if not wait_for_prompt(180.0):
            print("[FB_QEMU FAIL] no QNX operator shell prompt", file=sys.stderr)
            return 1
        # Prove the shell is alive AND that the sentinel handshake works.
        boot = command("echo LATCHFB_BOOT", timeout=30.0)
        if not re.search(rb"LATCHFB\d+_\d", boot):
            print(f"[FB_QEMU FAIL] the operator shell did not answer the sentinel "
                  f"handshake: {boot[-400:]!r}", file=sys.stderr)
            return 1
        # ---- (1) the transport measurement -------------------------------
        # The probe runs BEFORE the session opens, so its marker is in the
        # guest console log early.  Poll for it rather than assuming a
        # timing: the Linux boot under TCG takes tens of seconds.
        marker: tuple[str, dict[str, str]] | None = None
        guest_text = ""
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            guest_text = command("/proc/boot/latchctl console", timeout=6.0).decode(
                "utf-8", errors="replace")
            found = parse_fbprobe_marker(guest_text)
            if found:
                marker = found
                break
            time.sleep(1.0)
        if marker is None:
            report["guest_console"] = guest_text
            print("[FB_QEMU FAIL] the guest never reported a COMPLETE [FBPROBE] "
                  "marker; the transport did not deliver. tail=%r" % guest_text[-3000:],
                  file=sys.stderr)
            return 1

        raw, fields = marker
        probe = {
            "raw": raw,
            "port": fields.get("port", "?"),
            "opens": fields.get("opens", "?"),
            "dir": fields.get("dir", "?"),
            "derr": fields.get("derr", "?"),
            "ferr": fields.get("ferr", "?"),
            "rerr": fields.get("rerr", "?"),
            "bytes": fields.get("bytes", "?"),
            "frames": fields.get("frames", "?"),
            "seq": fields.get("seq", "?"),
            "changes": fields.get("changes", "?"),
            "bad": fields.get("bad", "?"),
            "epoch": fields.get("epoch", "?"),
            "verdict": fields.get("verdict", "?"),
            "rung": fields.get("rung", "?"),
            "faults": fields.get("faults", "?"),
            "per_port": {k: v for k, v in fields.items()
                         if k.startswith("p") and k[1:].isdigit()},
            "open_errno": {k: v for k, v in fields.items()
                           if k.startswith("e") and k[1:].isdigit()},
        }
        report["probe"] = probe
        try:
            frames = int(str(probe["frames"]))
            nbytes = int(str(probe["bytes"]))
            changes = int(str(probe["changes"]))
        except ValueError:
            print(f"[FB_QEMU FAIL] the [FBPROBE] marker is malformed: {raw!r}",
                  file=sys.stderr)
            return 1
        # The pass bar.  `port != none` says a device carried CRC-valid
        # frames; `frames >= 1` says the guest read at least one; and
        # `changes >= 1` says the HOST'S WRITES WERE VISIBLE TO THE GUEST
        # -- the property the transport exists to have.  Without the third
        # condition a static file would pass, and a static file is not a
        # channel.
        if probe["port"] == "none" or frames < 1 or nbytes < 1 or changes < 1:
            # The report is self-describing: `opens` says how many candidate
            # devices opened, `eN` says why the others did not, `pN` says
            # valid/changes per candidate, and `bad` says how many reads
            # failed the CRC.  Print all of it: a transport fault is only
            # fixable if the report says WHICH stage failed.
            print(f"[FB_QEMU FAIL] the verdict file did not deliver a changing "
                  f"CRC-valid sequence: {raw!r}", file=sys.stderr)
            return 1
        print(f"[FB_QEMU] transport observed: {raw}")

        # ---- (2) the black channel, on the same boot ---------------------
        expected_frames = 235
        deadline = time.monotonic() + 60.0
        samples: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            sample = command("/proc/boot/latchctl status", timeout=4.0)
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
                if snap["received"] >= 155:
                    break
            time.sleep(0.05 if not samples else 0.003)

        a4_samples = [s for s in samples if 5 <= s["received"] <= 155]
        report["a4_samples"] = [
            {k: v for k, v in s.items() if k != "text"} for s in a4_samples[:64]]
        if not a4_samples or any(s["rung"] != "ADVISE" for s in a4_samples):
            observed = [(s["received"], s["rung"], s["lease_age"], s["coherence"], s["recovery"])
                        for s in samples]
            print(f"[FB_QEMU FAIL] the black channel was disturbed: the A4 window did not "
                  f"hold ADVISE; samples={observed}", file=sys.stderr)
            return 1
        a4 = a4_samples[0]
        if not isinstance(a4["lease_age"], int) or a4["lease_age"] >= lease_ticks:
            print(f"[FB_QEMU FAIL] A4 sample has stale lease age: {a4}", file=sys.stderr)
            return 1
        print(f"[FB_QEMU] black channel intact: A4 observed: received={a4['received']} "
              f"rung={a4['rung']} lease_age={a4['lease_age']}")

        # Let the paced recovery stream and the final deadman silence complete.
        final: dict[str, object] | None = None
        recovered = False
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            sample = command("/proc/boot/latchctl status", timeout=4.0)
            text = sample.decode("utf-8", errors="replace")
            received = re.search(r"Proposals Received\s*:\s*(\d+)", text)
            rung = re.search(r"rung=([A-Z_]+)\s*\((\d+)\)", text)
            angle = re.search(r"Actuator Angle\s*:\s*(-?\d+)\s*mrad", text)
            lease = re.search(r"lease age\s*(\d+)\s*ticks", text)
            faults = re.search(r"Latched Fault Bits\s*:\s*([^\r\n]+)", text)
            recovery = re.search(r"Recovery Clean\s*:\s*(\d+)\s*accepted commands", text)
            if received and rung:
                angle_value = int(angle.group(1)) if angle else None
                final = {"received": int(received.group(1)), "rung": rung.group(1),
                         "lease_age": int(lease.group(1)) if lease else None,
                         "faults": faults.group(1).strip() if faults else "",
                         "recovery": int(recovery.group(1)) if recovery else None}
                if (180 <= final["received"] <= 230 and final["rung"] == "HP" and
                        angle_value is not None and angle_value > 0):
                    recovered = True
                if final["received"] >= expected_frames and final["rung"] == "LATCH":
                    break
            time.sleep(0.003)

        if final is None or final["received"] != expected_frames:
            print(f"[FB_QEMU FAIL] expected {expected_frames} received frames; got {final}",
                  file=sys.stderr)
            return 1
        if final["rung"] != "LATCH" or "HEARTBEAT" not in str(final["faults"]):
            print(f"[FB_QEMU FAIL] lease silence did not reach LATCH with HEARTBEAT fault: "
                  f"{final}", file=sys.stderr)
            return 1
        if not recovered:
            print(f"[FB_QEMU FAIL] did not observe clean-command recovery to HP with command "
                  f"motion: {final}", file=sys.stderr)
            return 1

        manifest = command("/proc/boot/latchctl manifest-verify /proc/boot/governor_servo.manifest")
        report["manifest_verify"] = manifest.decode("utf-8", errors="replace")
        if b"admissibility SATISFIED" not in manifest:
            print("[FB_QEMU FAIL] target did not verify the schema-3 manifest sidecar",
                  file=sys.stderr)
            return 1

        guest_text = command("/proc/boot/latchctl console", timeout=8.0).decode(
            "utf-8", errors="replace")
        report["guest_console"] = guest_text
        for needed in ("=== LATCH Linux 6.12 Guest Userspace (/init) Alive ===",
                       "/dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2",
                       "[FBPROBE]"):
            if needed not in guest_text:
                print(f"[FB_QEMU FAIL] guest console lacks marker {needed!r}; "
                      f"tail={guest_text[-3000:]!r}", file=sys.stderr)
                return 1

        report["final"] = final
        report["verdict"] = "PASS"
        print("[FB_QEMU PASS] the host's verdict reached the freestanding guest "
              "through the read-only verdict file (the guest's own polling saw the "
              "sequence number change, with every frame re-synchronised on the magic "
              "and CRC-validated), and the black channel was undisturbed: the same "
              "boot delivered all 235 v2 proposals with the A4 demotion held at "
              "ADVISE and the final lease expiry reaching LATCH")
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
