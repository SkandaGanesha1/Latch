#!/usr/bin/env python3
"""Measure a synthetic Python periodic workload on the current Linux host.

WHAT THIS IS
    A measurement of a **synthetic Python loop** on the workstation's
    ordinary Linux scheduler. It is a real measurement with a real sample
    count on a real machine, and it is reproducible: this script is the
    source of the numbers.

WHAT THIS IS NOT
    * It is **not** the LATCH control loop. LATCH's supervisor is a
      purpose-built C process on QNX OS; this is Python on Linux.
    * It is **not** a "Linux GPOS" figure. There is no GPOS here, and the
      earlier artefact that used that label is withdrawn and quarantined
      (`docs/evidence/quarantine/REJECTED-linux-baseline/`).
    * It is **not** a worst-case execution time. The max in the report is
      an OBSERVED maximum over the samples taken, not a bound.
    * It is **not** a QNX-vs-Linux comparison. The QNX side of that
      comparison was itself a fabricated number and has been withdrawn; no
      QNX figure is quoted here, because there is no honest one to quote.

Every file this tool writes under `docs/evidence/` is generated. Nothing
here is hand-edited.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import pathlib
import platform
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List


def run_control_tick(duration_us: int = 15) -> None:
    """Simulates physical interlock check computation (matrix/interval math)."""
    start = time.perf_counter_ns()
    target_ns = duration_us * 1000
    acc = 0
    while time.perf_counter_ns() - start < target_ns:
        acc = (acc * 33 + 17) & 0xFFFFFFFF


def run_linux_benchmark(
    iterations: int = 2000,
    period_us: int = 1000,
    stress: bool = False,
) -> Dict[str, Any]:
    """Runs a synthetic periodic loop using the inherited scheduler."""
    stop_stress = threading.Event()

    def stress_worker():
        while not stop_stress.is_set():
            _ = [math.sin(x) * math.cos(x) for x in range(1000)]

    threads = []
    if stress:
        num_workers = max(2, (os.cpu_count() or 4) - 1)
        for _ in range(num_workers):
            t = threading.Thread(target=stress_worker, daemon=True)
            threads.append(t)
            t.start()

    latencies_us: List[float] = []
    period_ns = period_us * 1000
    deadline_misses = 0

    next_tick = time.perf_counter_ns()
    for _ in range(iterations):
        next_tick += period_ns
        run_control_tick(duration_us=12)

        now = time.perf_counter_ns()
        sleep_ns = next_tick - now
        if sleep_ns > 0:
            time.sleep(sleep_ns / 1e9)
            wake = time.perf_counter_ns()
            loop_latency_us = (wake - (next_tick - period_ns)) / 1000.0
        else:
            deadline_misses += 1
            loop_latency_us = (now - (next_tick - period_ns)) / 1000.0

        latencies_us.append(loop_latency_us)

    if stress:
        stop_stress.set()
        for t in threads:
            t.join(timeout=0.5)

    sorted_lats = sorted(latencies_us)
    n = len(sorted_lats)
    p50 = sorted_lats[int(n * 0.50)]
    p95 = sorted_lats[int(n * 0.95)]
    p99 = sorted_lats[int(n * 0.99)]
    max_lat = sorted_lats[-1]
    min_lat = sorted_lats[0]
    avg_lat = sum(sorted_lats) / n

    return {
        "iterations": iterations,
        "stress": stress,
        "min_us": min_lat,
        "p50_us": p50,
        "p95_us": p95,
        "p99_us": p99,
        "max_us": max_lat,
        "avg_us": avg_lat,
        "deadline_misses": deadline_misses,
        "samples": latencies_us,
    }


def cpu_model() -> str:
    """Best-effort CPU model string, or 'unknown'."""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def load_average() -> str:
    try:
        return ", ".join(f"{v:.2f}" for v in os.getloadavg())
    except (OSError, AttributeError):
        return "unknown"


def environment_block() -> List[str]:
    """The environment the numbers were measured in."""
    sched = "unknown"
    if hasattr(os, "sched_getscheduler"):
        names = {0: "SCHED_OTHER", 1: "SCHED_FIFO", 2: "SCHED_RR", 3: "SCHED_BATCH"}
        try:
            sched = names.get(os.sched_getscheduler(0), str(os.sched_getscheduler(0)))
        except OSError:
            sched = "unknown"
    affinity = "unknown"
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity = str(sorted(os.sched_getaffinity(0)))
        except OSError:
            affinity = "unknown"
    return [
        f"Host              : {platform.platform()}",
        f"Machine           : {platform.machine()}",
        f"CPU model         : {cpu_model()}",
        f"Logical CPUs      : {os.cpu_count()}",
        f"Python            : {platform.python_version()} ({platform.python_implementation()})",
        f"Kernel            : {platform.release()}",
        f"Scheduler policy  : {sched} (the INHERITED default -- this is the point)",
        f"CPU affinity      : {affinity}",
        f"Load average      : {load_average()} (at capture time)",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synthetic Python periodic-loop baseline on this Linux host")
    parser.add_argument("--iterations", type=int, default=1500, help="Loop iterations")
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent / "docs" / "evidence" / "baseline",
        help="Output directory for baseline evidence",
    )
    args = parser.parse_args()

    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print("[BASELINE] Running a synthetic Python periodic-loop experiment...")
    print("  1. Idle workstation test...")
    idle_res = run_linux_benchmark(iterations=args.iterations, stress=False)

    print("  2. Contended / stress test...")
    stress_res = run_linux_benchmark(iterations=args.iterations, stress=True)

    env = environment_block()

    # Format report
    report = []
    report.append("================================================================================")
    report.append(" LINUX SYNTHETIC PYTHON-LOOP BASELINE (synthetic; not GPOS; not a WCET)   ")
    report.append(" Current Linux host; synthetic Python loop; inherited scheduler          ")
    report.append("================================================================================")
    report.append("")
    report.extend(env)
    report.append("")
    report.append("WORKLOAD")
    report.append("  A Python loop that emulates the SHAPE of a periodic control task: a")
    report.append("  12 microsecond busy-loop 'control tick' followed by a sleep to the")
    report.append("  next 1000 microsecond period boundary. The busy loop is an integer")
    report.append("  recurrence; the sleep uses the ordinary time.sleep(), so the wake-up")
    report.append("  goes through the normal Linux scheduler -- no SCHED_FIFO, no priority,")
    report.append("  no CPU pinning, no real-time policy.")
    report.append("")
    report.append(f"  Samples per configuration : {args.iterations}")
    report.append(f"  Total samples             : {2 * args.iterations}")
    report.append("  Idle configuration        : no background load")
    report.append(f"  Stress configuration      : {max(2, (os.cpu_count() or 4) - 1)} Python "
                  "threads spinning on a sin/cos workload")
    report.append("")
    report.append("SUMMARY RESULTS TABLE (microseconds; loop wake-up latency):")
    report.append("+-----------------------------------+---------+---------+---------+---------+-----------+")
    report.append("| Benchmark Configuration           | Median  | p95     | p99     | Max loop| Deadlines |")
    report.append("+-----------------------------------+---------+---------+---------+---------+-----------+")
    report.append(f"| Linux Python (Idle)             | {idle_res['p50_us']:7.2f} | {idle_res['p95_us']:7.2f} | {idle_res['p99_us']:7.2f} | {idle_res['max_us']:7.2f} | {idle_res['deadline_misses']:4d}/{args.iterations} |")
    report.append(f"| Linux Python (Thread Stress)      | {stress_res['p50_us']:7.2f} | {stress_res['p95_us']:7.2f} | {stress_res['p99_us']:7.2f} | {stress_res['max_us']:7.2f} | {stress_res['deadline_misses']:4d}/{args.iterations} |")
    report.append("+-----------------------------------+---------+---------+---------+---------+-----------+")
    report.append("")
    report.append("HOW TO READ THIS")
    report.append("  * These are OBSERVED loop wake-up latencies on THIS machine, under")
    report.append("    THIS load, with THIS scheduler. The Max column is the largest")
    report.append("    sample that was taken -- it is NOT a worst-case execution time")
    report.append("    and it is not a bound of any kind.")
    report.append("  * 'Deadlines' counts iterations that were already past their")
    report.append("    deadline BEFORE the sleep began, so the sleep could not recover")
    report.append("    them. It is a count of observed late iterations, not a rate")
    report.append("    guarantee.")
    report.append("  * The numbers move with the machine's load. Re-running this script")
    report.append("    will produce DIFFERENT numbers. That is the point of measuring")
    report.append("    rather than quoting.")
    report.append("")
    report.append("WHAT THIS IS NOT")
    report.append("  * Not the LATCH control loop: LATCH's supervisor is a purpose-built")
    report.append("    C process on QNX OS. This is Python on Linux.")
    report.append("  * Not a 'Linux GPOS' figure. There is no GPOS in this measurement.")
    report.append("  * Not a WCET, and not a deadline-miss guarantee.")
    report.append("  * NOT a QNX-vs-Linux comparison. The QNX side of that comparison was")
    report.append("    a fabricated number and has been withdrawn; no QNX figure is")
    report.append("    quoted here, because there is no honest one to quote. The")
    report.append("    honest QNX-side numbers are the TCG observations in")
    report.append("    docs/evidence/governor/, and they are labelled as TCG")
    report.append("    observations, not WCETs either.")
    report.append("  * The withdrawn artefact this replaces is in")
    report.append("    docs/evidence/quarantine/REJECTED-linux-baseline/; nothing from")
    report.append("    that directory may be quoted.")
    report.append("")
    report.append("REPRODUCE")
    report.append("  python3 tools/benchmark_linux_native.py --iterations %d" % args.iterations)
    report.append("================================================================================")

    out_file = args.out_dir / "linux_baseline_metrics.txt"
    out_file.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(f"\n[SUCCESS] Wrote Linux baseline report to: {out_file}")

    # Write baseline tape CSV
    csv_file = args.out_dir / "linux_baseline_tape.csv"
    with csv_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["tick", "idle_latency_us", "stress_latency_us"])
        for i in range(min(len(idle_res["samples"]), len(stress_res["samples"]))):
            writer.writerow([i + 1, f"{idle_res['samples'][i]:.2f}", f"{stress_res['samples'][i]:.2f}"])
    print(f"[SUCCESS] Wrote baseline tape to: {csv_file}")

    # The directory README is GENERATED too: the archive rule is that nothing
    # under docs/evidence/ is hand-edited, and this file used to be a
    # hand-written withdrawal notice for an artefact that no longer exists.
    readme = []
    readme.append("# Linux baseline — a synthetic Python-loop measurement")
    readme.append("")
    readme.append("**This directory is GENERATED by `tools/benchmark_linux_native.py`.**")
    readme.append("Do not hand-edit anything here; re-run the tool instead.")
    readme.append("")
    readme.append("| File | What it is |")
    readme.append("|---|---|")
    readme.append("| `linux_baseline_metrics.txt` | The report: environment, workload definition, sample count, summary table, and the explicit list of what the numbers are NOT |")
    readme.append("| `linux_baseline_tape.csv` | The raw per-tick samples behind the table |")
    readme.append("")
    readme.append("## What this measurement is")
    readme.append("")
    readme.append("A **synthetic Python periodic loop** on this workstation's ordinary")
    readme.append("Linux scheduler: a 12 µs busy-loop tick, then a sleep to the next")
    readme.append("1 ms period boundary. The wake-up goes through the normal Linux")
    readme.append("scheduler — no `SCHED_FIFO`, no priority, no CPU pinning, no")
    readme.append("real-time policy.")
    readme.append("")
    readme.append("## What it is not")
    readme.append("")
    readme.append("- **Not** the LATCH control loop (that is a purpose-built C process on QNX OS).")
    readme.append("- **Not** a \"Linux GPOS\" figure — there is no GPOS in this measurement.")
    readme.append("- **Not** a WCET. The max is an observed maximum over the samples taken.")
    readme.append("- **Not** a QNX-vs-Linux comparison. The QNX side of that comparison was a")
    readme.append("  fabricated number and has been withdrawn; no QNX figure is quoted here.")
    readme.append("")
    readme.append("## The withdrawn artefact")
    readme.append("")
    readme.append("The earlier baseline that accompanied the rejected 61 µs benchmark had")
    readme.append("no reproducible source samples. It is quarantined at")
    readme.append("`docs/evidence/quarantine/REJECTED-linux-baseline/` and **nothing from")
    readme.append("that directory may be quoted**.")
    readme.append("")
    readme.append("## Reproduce")
    readme.append("")
    readme.append("```bash")
    readme.append("python3 tools/benchmark_linux_native.py --iterations 1500")
    readme.append("```")
    readme.append("")
    readme.append("The numbers move with the machine's load, so a re-run produces")
    readme.append("different numbers. That is the point of measuring rather than quoting.")
    readme.append("")
    readme_file = args.out_dir / "README.md"
    readme_file.write_text("\n".join(readme), encoding="utf-8")
    print(f"[SUCCESS] Wrote baseline README to: {readme_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

