#!/usr/bin/env python3
"""Boot the U-4 DECISION-LATENCY MEASUREMENT image and capture the distribution.

This harness replaces the withdrawn "61 us WCET" claim with a MEASUREMENT.
It does not measure the host, and it does not measure a simulation of the
supervisor: it boots the QNX AArch64 target, lets the trusted supervisor
sample its OWN per-tick decision latency once per tick for more than a
million ticks, and reads the resulting histogram back over an output-only
devctl (`latchctl latency`).

Three artefacts can be written out, so the evidence archive is GENERATED and
never hand-edited:

    LATENCY_QEMU_TRANSCRIPT   the raw serial transcript, verbatim
    LATENCY_QEMU_REPORT       the structured report: the sampled status
                              snapshots, the latency readout, the guest's
                              own console and the final verdict

Both are written even when the run FAILS, so a failing run still leaves the
evidence that explains why it failed.  The evidence generator refuses to
replace a good archive with a failing run.

THE COMMAND-END DETECTOR IS A SENTINEL, NOT A PROMPT
----------------------------------------------------
The QNX shell's prompt is "# ", and every line of some command output can
end in "# " -- so a detector that waits for the prompt walks away in the
middle of the command's own output.  Every command here therefore ends with
`; echo <TAG>_$?`, and the harness waits for the TAG with its exit-code
digit.  The exit code is part of the evidence, not decoration.

THE END OF THE SOAK IS OBSERVED, NOT TIMED
-------------------------------------------
The harness does not stop the measurement when a wall-clock budget expires.
It waits for the guest to STOP STREAMING -- the supervisor's proposal
counter stops advancing -- and only then reads the histogram, so the
distribution covers the WHOLE soak and not a prefix of it.  A fixed sleep
would have been the same mistake the project already paid for once (the
writer-session handoff), and the fix is the same shape: watch the state,
do not guess the time.
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


# The floor the plan sets: a million ticks is a distribution, and fewer than
# that is an anecdote.
DEFAULT_MIN_TICKS = 1_200_000

# How long to wait for the target to reach the floor AND for the guest to
# stop streaming.  The supervisor ticks at the contract's 1 kHz, so 1.2
# million ticks is ~20 minutes of target time, and the 35-minute soak ends
# at ~2.1 million ticks.  The budget is generous because a starved TCG host
# makes the tick rate fall, and the harness must not kill a run that is
# simply slow.
DEFAULT_TIMEOUT_S = 3_000.0

# How often the supervisor's status is sampled.  Each poll is a few
# kilobytes over the serial console, and the soak must not be perturbed by
# the measurement of it, so the poll is sparse.
DEFAULT_POLL_S = 20.0

# The proposal ring's depth, from the signed contract's ingest.queue_depth.
# The backlog has to stay well below it: a ring that fills is a producer
# that outran the consumer, and the workload would no longer be the one the
# measurement describes.
RING_DEPTH = 256

# The backlog ceiling the harness enforces: three quarters of the ring.
BACKLOG_CEILING = (RING_DEPTH * 3) // 4

# The position the soak's measured phase holds.  This is the workload the
# report describes, so it is also what the harness checks the target did.
SOAK_HOLD_MRAD = 100

# HOW THE HARNESS KNOWS THE GUEST WAS STILL ALIVE.
#
# The naive observable -- "the proposal counter advanced since the last
# poll" -- is WRONG, and it is wrong in the direction that turns the
# supervisor's CORRECT fail-closed behaviour into a false failure: the
# counter advances for the frames that arrive BETWEEN two polls, so a poll
# that lands after the guest has already stopped still shows a counter that
# moved.  The supervisor had, by then, done exactly what it is supposed to
# do (the lease expired, the ladder demoted one rung, and after five
# expiries it latched) -- and the harness called that a workload defect.
#
# The honest observable is the LEASE AGE: the number of supervisor ticks
# since the owner last sent a frame.  It is 0-4 while the guest is
# streaming and it grows without bound once the guest stops, so it says
# whether the producer was alive AT THE INSTANT OF THE POLL.
#
# The threshold is half the signed lease (100 ticks): a live producer
# renews the lease every tick it sends, so a lease age of more than half
# the lease means the producer is gone, not merely jittery.
LIVE_LEASE_AGE_TICKS = 50

# THE ACHIEVED RATE IS A RESULT, NOT AN INPUT.
#
# The workload this measurement describes is a producer streaming at the
# guest's own declared rate (900 Hz, stringified out of the build's macro
# and read back from the guest's plan marker).  The harness has to CHECK
# that the target actually achieved it, because a producer that runs at a
# third of the declared rate is a DIFFERENT WORKLOAD -- and the
# measurement's percentiles would describe that different workload while
# the report still said "900 Hz".
#
# THIS GATE IS NOT HYPOTHETICAL.  Measured on the QEMU AArch64 `virt`
# target (2026-11-27): a pacer that dropped the credit on ANY lateness
# removed the catch-up burst but cost a third of the rate -- 901/s became
# 610/s -- and that run PASSED every other criterion this file has (0 ring
# drops, a peak backlog of 4, HP throughout, the plant at rest).  A
# measurement with no criterion on the achieved rate cannot tell a 900 Hz
# workload from a 610 Hz one, and the archive would have carried both.
#
# The band is +-5%.  The measured streaming rate on the target is
# 894-899/s against a 900 Hz target -- inside 0.7% -- while the two
# measured regressions (610/s and 646/s) are 28% and 32% out.  The band
# discriminates decisively and still leaves the TCG host's jitter room.
RATE_TOLERANCE_FRACTION = 0.05


def format_report(report: dict) -> str:
    """The structured, human-readable report the evidence archive carries."""
    out: list[str] = []
    add = out.append
    add("=" * 78)
    add("LATCH -- ON-TARGET DECISION-LATENCY MEASUREMENT (U-4)")
    add("=" * 78)
    add("IFS                 : %s" % report.get("ifs", ""))
    add("Target              : QNX OS 8.0 / ARMv8-A, QEMU `virt`, TCG")
    add("Signed contract    : qnx/contracts/governor_servo.manifest")
    add("Tick floor         : %s ticks" % report.get("min_ticks", ""))
    add("Guest soak plan    : %s" % report.get("plan", "(not captured)"))
    add("Verdict            : %s" % report.get("verdict", "FAIL"))
    add("")

    add("--- THE GUEST'S OWN CONSOLE (from /dev/shmem/guest_console.log) ---")
    add((report.get("guest_console", "") or "").rstrip())
    add("")

    add("--- THE SOAK'S RATES, AS THE TARGET REPORTED THEM ---")
    for k, v in (report.get("rates", {}) or {}).items():
        add("%-20s: %s" % (k, v))
    add("")

    add("--- THE SUPERVISOR'S STATUS, SAMPLED DURING THE SOAK ---")
    add("%-12s %-12s %-12s %-10s %-10s %-10s %-12s %-8s %-8s %-6s" %
        ("tick", "proposals", "rung", "drops", "backlog", "overruns",
         "decision_lat", "theta", "vel", "alive"))
    for s in report.get("samples", []):  # type: ignore[union-attr]
        add("%-12s %-12s %-12s %-10s %-10s %-10s %-12s %-8s %-8s %-6s" %
            (s.get("tick"), s.get("proposals"), s.get("rung"),
             s.get("ring_drops"), s.get("backlog_peak"), s.get("wcet_overruns"),
             s.get("decision_latency"), s.get("theta_mrad"), s.get("velocity"),
             "yes" if s.get("live") else "no"))
    add("")

    add("--- THE LATENCY DISTRIBUTION (latchctl latency, verbatim) ---")
    add((report.get("latency_readout", "") or "").rstrip())
    add("")

    add("--- THE FINAL SUPERVISOR STATUS ---")
    add((report.get("final_status", "") or "").rstrip())
    add("")
    return "\n".join(out) + "\n"


def streaming_rate(samples: list[dict]):
    """The producer's achieved rate over the STREAMING WINDOW, in Hz.

    PURE, and that is the point: the consistency checker imports it and
    exercises it against a synthetic sample set that carries a long DEAD
    TAIL, so the property "the rate is read over the stream, not over the
    whole harness window" is proven without a 40-minute measurement.

    WHY THE STREAMING WINDOW.  The samples whose lease age says the
    producer was alive are the ones that describe the workload.  The
    samples after the guest stops describe the HARNESS: the guest has
    gone, the counter has frozen, and the wall clock has kept running.
    Averaged over the whole window those samples dilute the figure --
    a 60-second calibration reads 749/s window-wide against 898/s over
    the stream, and the 35-minute soak reads 888/s against 898/s.

    Returns None when the rate cannot be computed: fewer than two live
    polls, a missing counter, or a wall clock that did not advance.
    """
    live = [s for s in samples if s.get("live")]
    if len(live) < 2:
        return None
    first = live[0]
    last = live[-1]
    if first.get("proposals") is None or last.get("proposals") is None:
        return None
    if first.get("wall") is None or last.get("wall") is None:
        return None
    d_prop = last["proposals"] - first["proposals"]
    d_wall = last["wall"] - first["wall"]
    if d_wall <= 0:
        return None
    return d_prop / d_wall


def rate_verdict(stream_rate, target_hz, tolerance: float = RATE_TOLERANCE_FRACTION):
    """(ok, message) for the achieved producer rate.

    PURE, and that is the point: the consistency checker imports it and
    exercises it against the rates that were MEASURED on the target --
    including the two regressions -- so the gate's teeth are proven without
    a 40-minute measurement.

    The measured rates, all on the QEMU AArch64 `virt` target (2026-11-27),
    against a 900 Hz target:

        897.6/s   the K=4 allowance pacer -- ACCEPT (this is the archive)
        901/s     the original pacer      -- ACCEPT
        646/s     a one-period allowance   -- REJECT (28% slow)
        610/s     drop the credit always   -- REJECT (32% slow)
    """
    if stream_rate is None:
        return False, ("the achieved rate could not be computed from the live "
                       "samples: the soak collected fewer than two live polls, "
                       "or the wall clock did not advance")
    lo = target_hz * (1.0 - tolerance)
    hi = target_hz * (1.0 + tolerance)
    if stream_rate < lo or stream_rate > hi:
        return False, ("the producer achieved %.1f proposals/s over the "
                       "streaming window, outside the %.1f..%.1f band around "
                       "the target %d Hz. The workload is not the one the "
                       "measurement describes, so the percentiles describe a "
                       "different experiment."
                       % (stream_rate, lo, hi, target_hz))
    return True, ""


def _rates_table(samples: list[dict], first_tick, first_proposals,
                 stream_rate, plan: dict, peak_backlog: int,
                 poll_start: float) -> dict:
    """The soak's rates, in the shape the report carries them.

    TWO rates, and the difference between them is the point:

      * "guest proposals/s" is the rate over the WHOLE harness window, so
        it is contaminated by the tail after the guest stops;
      * "producer rate" is the rate over the STREAMING WINDOW -- the
        samples whose lease age says the producer was alive -- and that is
        the one the workload's declared rate is checked against.

    A 60-second calibration reads 749/s in the first and 898/s in the
    second, so a report that carried only the first would describe a
    workload the target never ran.
    """
    elapsed = max(1e-6, time.monotonic() - poll_start) if poll_start else 0.0
    first = samples[0] if samples else {}
    last = samples[-1] if samples else {}
    tick_span = (last.get("tick") or 0) - (first_tick or 0)
    prop_span = (last.get("proposals") or 0) - (first_proposals or 0)
    out = {
        "supervisor ticks/s": "%.1f" % (tick_span / elapsed) if tick_span else "n/a",
        "guest proposals/s": "%.1f" % (prop_span / elapsed) if prop_span else "n/a",
        "proposals per tick": "%.3f" % (prop_span / tick_span) if tick_span else "n/a",
        "peak backlog": "%s frames (ring depth %d)" % (peak_backlog, RING_DEPTH),
        "wall-clock seconds": "%.1f" % elapsed,
    }
    if stream_rate is not None:
        out["producer rate"] = "%.1f/s over the streaming window (target %s Hz)" % (
            stream_rate, plan.get("target_hz", "n/a"))
    return out


def parse_status(text: str) -> dict:
    """Pull the numbers the soak's acceptance criteria are stated in."""
    out: dict = {}

    def grab(pattern: str, cast=int):
        m = re.search(pattern, text)
        if not m:
            return None
        try:
            return cast(m.group(1))
        except ValueError:
            return None

    out["tick"] = grab(r"Tick Counter\s*:\s*(\d+)\s*ticks")
    out["proposals"] = grab(r"Proposals Received\s*:\s*(\d+)")
    out["ring_drops"] = grab(r"Ring Drops / WCET\s*:\s*(\d+)\s+drops")
    # The line is "Ring Drops / WCET : 0 drops | 8 overruns" -- the two
    # counters are separated by a PIPE, not by a slash.  The old pattern
    # expected a slash and never matched, so the overrun count read as None
    # and the acceptance check silently had nothing to check.
    out["wcet_overruns"] = grab(r"Ring Drops / WCET\s*:\s*\d+\s+drops\s*\|\s*(\d+)")
    out["backlog_peak"] = grab(r"Proposal Backlog\s*:\s*peak\s*(\d+)\s+frames")
    out["backlog_overruns"] = grab(r"Proposal Backlog\s*:\s*peak\s*\d+\s+frames\s*\|\s*(\d+)")
    # The plant's state.  The soak's workload is a HOLD at 100 mrad, so
    # these two numbers are the evidence that the measurement was taken on
    # the workload it claims to describe.
    out["theta_mrad"] = grab(r"Actuator Angle\s*:\s*(-?\d+)\s+mrad")
    out["velocity"] = grab(r"Velocity / Omega\s*:\s*(-?\d+)\s+mrad/tick")
    # The lease age: the supervisor's own count of the ticks since the
    # session owner last sent a frame.  It is the ONLY honest way to tell
    # "the guest is still streaming" from "the guest stopped between two
    # polls".
    out["lease_age"] = grab(r"V2 Session / Lease\s*:\s*\S+\s*\|\s*\d+\s+ticks left\s*\|\s*lease age\s*(\d+)\s*ticks")
    m = re.search(r"rung=([A-Z_]+)\s*\((\d+)\)", text)
    out["rung"] = m.group(1) if m else None
    m = re.search(r"Decision Latency\s*:\s*last\s*=\s*(\d+)\s*cyc", text)
    out["decision_latency"] = m.group(1) if m else None
    out["mode"] = grab(r"Current Mode\s*:\s*(\S+)")
    out["text"] = text
    return out


def parse_latency(text: str) -> dict:
    """Pull the distribution's headline numbers out of `latchctl latency`."""
    out: dict = {}

    def grab(pattern: str):
        m = re.search(pattern, text)
        return m.group(1) if m else None

    out["samples"] = grab(r"Samples \(ticks\)\s*:\s*(\d+)")
    out["decision_samples"] = grab(r"Decision-path samples\s*:\s*(\d+)")
    out["idle_samples"] = grab(r"Idle-path samples\s*:\s*(\d+)")
    out["motion_samples"] = grab(r"Motion evaluations\s*:\s*(\d+)")
    out["cycle_rate"] = grab(r"Cycle rate\s*:\s*(\d+) Hz")
    out["min_max"] = grab(r"Min / Max \(decision\)\s*:\s*(\d+ / \d+ cyc)")
    out["decision_p50_p99"] = grab(r"Decision path\s*:\s*p50 = \[(\d+), (\d+)\).*p99 = \[(\d+), (\d+)\)")
    out["idle_p50_p99"] = grab(r"Idle path\s*:\s*p50 = \[(\d+), (\d+)\].*p99 = \[(\d+), (\d+)\)")
    out["over_budget"] = grab(r"Over budget\s*:\s*(\d+) samples")
    out["over_period"] = grab(r"Over tick period\s*:\s*(\d+) samples")
    out["mode_ticks"] = grab(r"Mode ticks\s*:\s*(.+)")
    out["text"] = text
    return out


def parse_plan(text: str) -> dict:
    """Read the soak's own plan marker out of the guest console.

    The marker is the ONLY thing that says which workload the harness is
    looking at, and the guest states the rate and the duration it was BUILT
    with -- so the marker is checked against what the caller expected rather
    than trusted.
    """
    m = re.search(r"\[LATENCY\]\s*soak:\s*(\d+)\s*Hz\s+in-envelope\s+CMD_V2\s+stream"
                  r"\s+for\s+(\d+)\s*ms", text)
    if not m:
        return {}
    return {"target_hz": int(m.group(1)), "duration_ms": int(m.group(2))}


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ifs = Path(os.environ.get(
        "LATENCY_QEMU_IFS",
        root / "qnx/build/nto-aarch64-le/latch_qemu_latency.ifs"))
    if not ifs.is_file():
        print(f"[LATENCY_QEMU FAIL] missing IFS: {ifs}", file=sys.stderr)
        return 1

    min_ticks = int(os.environ.get("LATENCY_QEMU_MIN_TICKS", DEFAULT_MIN_TICKS))
    timeout_s = float(os.environ.get("LATENCY_QEMU_TIMEOUT", DEFAULT_TIMEOUT_S))
    poll_s = float(os.environ.get("LATENCY_QEMU_POLL", DEFAULT_POLL_S))
    expect_hz = os.environ.get("LATENCY_QEMU_EXPECT_HZ")
    expect_ms = os.environ.get("LATENCY_QEMU_EXPECT_DURATION_MS")

    # The transcript goes to a FILE.  A pty in memory is fine for a short
    # run, but this one lasts tens of minutes; capturing to disk means a
    # killed run still leaves the evidence behind.
    transcript_path = os.environ.get("LATENCY_QEMU_TRANSCRIPT")
    transcript_file = None
    if transcript_path is not None:
        transcript_file = open(transcript_path, "wb")
    report_path = os.environ.get("LATENCY_QEMU_REPORT")
    report: dict = {
        "ifs": str(ifs),
        "min_ticks": min_ticks,
        "samples": [],
        "rates": {},
        "latency_readout": "",
        "final_status": "",
        "guest_console": "",
        "plan": "(not captured)",
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

    def pump() -> None:
        """Drain whatever the console has produced into the transcript."""
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if not ready:
                return
            try:
                chunk = os.read(master, 8192)
            except OSError:
                return
            if not chunk:
                return
            transcript.extend(chunk)
            if transcript_file is not None:
                transcript_file.write(chunk)
                transcript_file.flush()

    def command(text: str, timeout: float = 10.0) -> tuple[bytes, int]:
        """Run a command and wait for its exit-code sentinel.

        The prompt is NOT the detector: the QNX shell's "# " prompt is a
        substring of some command output, and a detector that waits for it
        can walk away mid-command.  The sentinel carries the exit code, so
        a failed command is visible as a failed command.
        """
        tag_counter[0] += 1
        tag = "LATCOC%d" % tag_counter[0]
        payload = (text + "; echo " + tag + "_$?").encode("ascii") + b"\n"
        os.write(master, payload)
        start = len(transcript)
        pattern = re.compile((tag + r"_(\d)").encode("ascii"))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pump()
            m = pattern.search(transcript, start)
            if m:
                # Let the shell finish drawing the prompt, so the next
                # command starts on a clean line.
                time.sleep(0.05)
                pump()
                return bytes(transcript[start:]), int(m.group(1))
            time.sleep(0.02)
        return bytes(transcript[start:]), -1

    try:
        # ---- BOOT ------------------------------------------------------
        # The shell may not be up yet, so the readiness probe is retried.
        booted = False
        boot_deadline = time.monotonic() + 180.0
        while time.monotonic() < boot_deadline:
            out, rc = command("echo LATCH_LATENCY_BOOTED", timeout=20.0)
            if rc == 0 and b"LATCH_LATENCY_BOOTED" in out:
                booted = True
                break
            time.sleep(2.0)
        if not booted:
            print("[LATENCY_QEMU FAIL] no QNX operator shell", file=sys.stderr)
            write_report()
            return 1

        # ---- THE GUEST'S SOAK PLAN -------------------------------------
        # The guest prints its plan BEFORE the session opens and then leaves
        # the console quiet for the whole soak.  The marker proves the soak
        # profile is the one that is running -- a guest that booted the
        # wrong profile would produce a status line and no distribution.
        guest_log = command("/proc/boot/latchctl console", timeout=10.0)[0]
        guest_text = guest_log.decode("utf-8", errors="replace")
        report["guest_console"] = guest_text
        if "[LATENCY] ABORT" in guest_text:
            print("[LATENCY_QEMU FAIL] the guest ABORTED the soak: "
                  f"{guest_text[-2000:]!r}", file=sys.stderr)
            write_report()
            return 1
        if "[LATENCY] soak:" not in guest_text:
            print("[LATENCY_QEMU FAIL] the guest console does not carry the soak "
                  f"plan marker; output={guest_text[-3000:]!r}", file=sys.stderr)
            write_report()
            return 1

        plan = parse_plan(guest_text)
        if not plan:
            print("[LATENCY_QEMU FAIL] the soak plan marker is unreadable; "
                  f"output={guest_text[-3000:]!r}", file=sys.stderr)
            write_report()
            return 1
        report["plan"] = ("%d Hz for %d ms" % (plan["target_hz"], plan["duration_ms"]))
        if expect_hz is not None and int(expect_hz) != plan["target_hz"]:
            print(f"[LATENCY_QEMU FAIL] the guest was built for {plan['target_hz']} Hz, "
                  f"but the run asked for {expect_hz} Hz", file=sys.stderr)
            write_report()
            return 1
        if expect_ms is not None and int(expect_ms) != plan["duration_ms"]:
            print(f"[LATENCY_QEMU FAIL] the guest was built for {plan['duration_ms']} ms, "
                  f"but the run asked for {expect_ms} ms", file=sys.stderr)
            write_report()
            return 1

        # ---- THE SOAK --------------------------------------------------
        samples: list[dict] = []
        deadline = time.monotonic() + timeout_s
        reached = False
        guest_stopped = False
        seen_live = False
        first_tick = None
        first_proposals = None
        poll_start = time.monotonic()
        while time.monotonic() < deadline:
            out, rc = command("/proc/boot/latchctl status", timeout=20.0)
            text = out.decode("utf-8", errors="replace")
            st = parse_status(text)
            if st.get("tick") is not None:
                sample = {k: v for k, v in st.items() if k != "text"}
                # "The guest was still producing" is OBSERVED, through the
                # supervisor's own lease age.  A rung change is only a
                # failure while the guest was alive -- after it stops, the
                # dead-man is SUPPOSED to fire and the ladder is supposed to
                # ratchet down.
                lease_age = st.get("lease_age")
                live = lease_age is not None and lease_age <= LIVE_LEASE_AGE_TICKS
                sample["live"] = live
                # The wall clock at the poll.  The supervisor's tick index
                # counts its own ticks; this is the only clock that can turn
                # "proposals" into "proposals per SECOND", which is the unit
                # the guest's declared rate is in.
                sample["wall"] = time.monotonic()
                samples.append(sample)
                report["samples"] = samples[-512:]
                if first_tick is None:
                    first_tick = st["tick"]
                    first_proposals = st["proposals"]
                if st["tick"] >= min_ticks:
                    reached = True
                if live:
                    seen_live = True
                elif seen_live:
                    # The guest stopped sending.  The soak is over.
                    guest_stopped = True
                    break
            time.sleep(poll_s)

        if not reached:
            last = samples[-1] if samples else {}
            print(f"[LATENCY_QEMU FAIL] the supervisor never reached {min_ticks} ticks "
                  f"within {timeout_s:.0f}s; last={last}", file=sys.stderr)
            write_report()
            return 1
        if not guest_stopped:
            print(f"[LATENCY_QEMU FAIL] the guest never stopped streaming within "
                  f"{timeout_s:.0f}s; the histogram would cover a prefix of the "
                  "soak rather than the whole of it", file=sys.stderr)
            write_report()
            return 1

        # ---- THE DISTRIBUTION ------------------------------------------
        out, rc = command("/proc/boot/latchctl latency", timeout=30.0)
        readout = out.decode("utf-8", errors="replace")
        report["latency_readout"] = readout
        lat = parse_latency(readout)
        if rc != 0 or lat.get("samples") is None:
            print(f"[LATENCY_QEMU FAIL] `latchctl latency` failed (rc={rc}); "
                  f"output={readout[-2000:]!r}", file=sys.stderr)
            write_report()
            return 1

        total = int(lat["samples"])
        if total < min_ticks:
            print(f"[LATENCY_QEMU FAIL] the histogram carries {total} samples, "
                  f"below the {min_ticks}-tick floor", file=sys.stderr)
            write_report()
            return 1

        # The distribution has to be a DISTRIBUTION: both paths have to be
        # populated, or the headline percentile describes an empty workload.
        decision = int(lat["decision_samples"] or 0)
        idle = int(lat["idle_samples"] or 0)
        motion = int(lat["motion_samples"] or 0)
        if decision < total // 2:
            print(f"[LATENCY_QEMU FAIL] only {decision} of {total} samples took the "
                  "decision path: the guest did not keep the supervisor fed, so the "
                  "percentiles would describe an idle supervisor", file=sys.stderr)
            write_report()
            return 1
        if motion < decision // 2:
            print(f"[LATENCY_QEMU FAIL] only {motion} of {decision} decision-path "
                  "samples evaluated a motion proposal", file=sys.stderr)
            write_report()
            return 1

        # The supervisor must have been FOLLOWING the guest for the whole
        # streaming window: a lease expiry would demote the ladder and the
        # sample would describe a failed-closed supervisor.
        streaming_rungs = {s.get("rung") for s in samples if s.get("live") and s.get("rung")}
        if streaming_rungs and streaming_rungs != {"HP"}:
            print(f"[LATENCY_QEMU FAIL] the supervisor was not in HP while the guest "
                  f"was streaming: rungs={sorted(streaming_rungs)}", file=sys.stderr)
            write_report()
            return 1

        # THE WORKLOAD HAS TO BE THE WORKLOAD THE REPORT DESCRIBES.
        #
        # The soak's measured phase is a HOLD at 100 mrad: the plant stands
        # still while the supervisor keeps deciding.  If the plant had
        # drifted, or were still moving, the samples would describe a
        # different workload -- and the phrase "decision latency under load"
        # would mean something the report does not say.  These are checked
        # on the LIVE samples, because after the guest stops the dead-man is
        # SUPPOSED to fire and the supervisor is SUPPOSED to retract the
        # plant to home.
        streaming_samples = [s for s in samples if s.get("live")]

        # The peak backlog: the SECOND, independent witness that the
        # producer did not outrun the consumer.  It is computed HERE so
        # that a FAILING report carries it.
        backlogs = [s.get("backlog_peak") for s in samples
                    if s.get("backlog_peak") is not None]
        peak_backlog = max(backlogs) if backlogs else 0

        # ---- THE ACHIEVED RATE, OVER THE STREAMING WINDOW ---------------
        #
        # The rate is computed HERE, before the gates, so that a run that
        # FAILS one of them still leaves the achieved rate in its report --
        # a failure report that does not carry the number that explains it
        # is a worse report than no report.
        #
        # It is read over the STREAMING WINDOW -- the samples whose lease
        # age says the producer was alive at the instant of the poll.
        # Averaged over the WHOLE harness window it is contaminated by the
        # tail after the guest stops: a 60-second calibration reported
        # 749/s while its per-poll rates read 898-899/s, and even the full
        # 35-minute soak reports 888/s window-wide against ~898/s over the
        # stream.
        stream_rate = streaming_rate(samples)
        report["streaming_rate"] = stream_rate

        # The rates, as they stand right now.  They are refreshed at the
        # end of a successful run, but a failing run must carry them too.
        report["rates"] = _rates_table(samples, first_tick, first_proposals,
                                       stream_rate, plan, peak_backlog,
                                       poll_start)

        thetas = {s.get("theta_mrad") for s in streaming_samples
                  if s.get("theta_mrad") is not None}
        velocities = {s.get("velocity") for s in streaming_samples
                      if s.get("velocity") is not None}
        if not thetas or thetas != {SOAK_HOLD_MRAD}:
            print(f"[LATENCY_QEMU FAIL] the plant did not hold {SOAK_HOLD_MRAD} mrad "
                  f"throughout the streaming window: angles={sorted(thetas)}",
                  file=sys.stderr)
            write_report()
            return 1
        if velocities != {0}:
            print(f"[LATENCY_QEMU FAIL] the plant was not at rest during the "
                  f"streaming window: velocities={sorted(velocities)}",
                  file=sys.stderr)
            write_report()
            return 1

        # A ring drop means the producer outran the consumer and frames were
        # discarded: the workload was not the one the measurement describes.
        drops = [s.get("ring_drops") for s in samples if s.get("ring_drops") is not None]
        if drops and drops[-1] != 0:
            print(f"[LATENCY_QEMU FAIL] the proposal ring dropped {drops[-1]} frames: "
                  "the producer outran the consumer", file=sys.stderr)
            write_report()
            return 1

        # The backlog is the SECOND, independent witness of the same
        # property: it has to stay well below the ring's depth, or the ring
        # was about to fill and the sample was one hiccup away from a
        # different workload.  (The peak was computed above, so that a
        # failing report carries it.)
        if peak_backlog >= BACKLOG_CEILING:
            print(f"[LATENCY_QEMU FAIL] the proposal backlog peaked at {peak_backlog} "
                  f"frames, at or above the {BACKLOG_CEILING}-frame ceiling of the "
                  f"{RING_DEPTH}-slot ring", file=sys.stderr)
            write_report()
            return 1
        backlog_overruns = [s.get("backlog_overruns") for s in samples
                            if s.get("backlog_overruns") is not None]
        if backlog_overruns and backlog_overruns[-1] != 0:
            print(f"[LATENCY_QEMU FAIL] the proposal backlog went over its limit "
                  f"{backlog_overruns[-1]} times", file=sys.stderr)
            write_report()
            return 1

        # ---- THE ACHIEVED RATE ------------------------------------------
        #
        # The LAST workload check, and the one that would have caught the
        # rate-killing pacer.  Everything above says the producer kept the
        # supervisor fed; this says it fed it at the RATE the workload
        # claims.  A run that produced at two thirds of the declared rate
        # has measured a different experiment, and it passed every other
        # criterion on 2026-11-27.
        target_hz = int(plan["target_hz"])
        rate_ok, rate_msg = rate_verdict(stream_rate, target_hz)
        if not rate_ok:
            print(f"[LATENCY_QEMU FAIL] {rate_msg}", file=sys.stderr)
            write_report()
            return 1

        # ---- THE FINAL STATUS -------------------------------------------
        out, _ = command("/proc/boot/latchctl status", timeout=20.0)
        report["final_status"] = out.decode("utf-8", errors="replace")
        final = parse_status(report["final_status"])
        report["final"] = {k: v for k, v in final.items() if k != "text"}
        report["samples"] = samples[-512:]

        # ---- THE RATES, AS THE TARGET REPORTED THEM ---------------------
        report["rates"] = _rates_table(samples, first_tick, first_proposals,
                                       stream_rate, plan, peak_backlog,
                                       poll_start)

        report["verdict"] = "PASS"
        print(f"[LATENCY_QEMU PASS] {total} supervisor ticks sampled "
              f"({decision} decision-path, {motion} motion evaluations, {idle} idle); "
              f"rung=HP throughout the streaming window; ring drops=0; "
              f"producer rate={stream_rate:.1f}/s against a {target_hz} Hz target")
        print(f"[LATENCY_QEMU] {lat.get('min_max')} | "
              f"decision p50/p99 = {lat.get('decision_p50_p99')} | "
              f"cycle rate = {lat.get('cycle_rate')} Hz")
        write_report()
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
    raise SystemExit(main())
