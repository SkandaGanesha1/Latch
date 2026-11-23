#!/usr/bin/env python3
"""Summarize recorded execution times; this tool does not benchmark QNX itself.

The CSV must have cycles_in and cycles_out, or a latency_cycles column.
Supply the actual counter frequency and capture provenance. Execution duration
is not scheduling jitter or a deadline-miss measurement.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path


def summarize_tape(path: Path, cycles_per_second: int) -> dict[str, float | int]:
    if cycles_per_second <= 0:
        raise ValueError("cycles-per-second must be positive")
    samples: list[float] = []
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or ())
        if not ({"cycles_in", "cycles_out"} <= fields or "latency_cycles" in fields):
            raise ValueError("CSV requires cycles_in and cycles_out, or latency_cycles")
        for row_num, row in enumerate(reader, 2):
            try:
                if {"cycles_in", "cycles_out"} <= fields:
                    start, end = int(row["cycles_in"], 0), int(row["cycles_out"], 0)
                    if start < 0 or end < start:
                        raise ValueError("invalid or decreasing cycle counter")
                    cycles = end - start
                else:
                    cycles = int(row["latency_cycles"], 0)
                    if cycles < 0:
                        raise ValueError("negative latency")
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid cycle data at row {row_num}: {exc}") from exc
            samples.append(cycles * 1_000_000.0 / cycles_per_second)
    if not samples:
        raise ValueError("CSV contains no samples")
    samples.sort()
    def percentile(p: float) -> float:
        return samples[max(0, math.ceil(p * len(samples)) - 1)]
    return {"count": len(samples), "min_us": samples[0], "p50_us": percentile(.50),
            "p95_us": percentile(.95), "p99_us": percentile(.99), "max_us": samples[-1]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tape", type=Path, required=True, help="captured timing CSV")
    parser.add_argument("--cycles-per-second", type=int, required=True, help="counter frequency recorded for this capture")
    parser.add_argument("--platform", required=True, help="capture OS, hardware or virtualization")
    parser.add_argument("--workload", required=True, help="capture workload and load conditions")
    parser.add_argument("--manifest", type=Path, help="manifest containing timing.wcet_budget_us")
    parser.add_argument("--out", type=Path, help="optional report output; default stdout")
    args = parser.parse_args()
    try:
        stats = summarize_tape(args.tape, args.cycles_per_second)
        budget = None
        if args.manifest:
            with args.manifest.open(encoding="utf-8") as stream:
                budget = json.load(stream)["timing"]["wcet_budget_us"]
            if not isinstance(budget, (int, float)) or isinstance(budget, bool) or budget <= 0:
                raise ValueError("manifest timing.wcet_budget_us must be positive")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"[BENCHMARK ERROR] {exc}", file=sys.stderr)
        return 2
    lines = ["Observed decision execution duration (not WCET or scheduling jitter)",
             f"Source: {args.tape}", f"Platform: {args.platform}", f"Workload: {args.workload}",
             f"Counter frequency: {args.cycles_per_second} cycles/second",
             f"Samples: {stats['count']}"]
    for key in ("min_us", "p50_us", "p95_us", "p99_us", "max_us"):
        lines.append(f"{key}: {stats[key]:.3f}")
    if budget is not None:
        lines.append(f"Manifest decision budget: {budget} us (not a measured worst-case bound)")
    lines.append("No OS comparison or deadline miss count is inferred from these samples.")
    output = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
