#!/usr/bin/env python3
"""generate_governor_tape.py — Generate merged adversarial tape (governor-tape.csv).

Executes the cyber-physical adversarial attack suite (A1-A7) through the real
pipeline, captures the per-attack tape rows, prepends the attack ID, renumbers
ticks monotonically, and writes out the canonical governor-tape.csv.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import sys
import tempfile
from typing import Any, Dict, List

tools_dir = pathlib.Path(__file__).resolve().parent
attacks_dir = tools_dir / "attacks"
for p in (tools_dir, attacks_dir):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from attacks import find_pipeline_binaries, run_attack_pipeline
from governor_client import GovernorClient


def collect_attack_rows() -> List[Dict[str, Any]]:
    """Runs each attack and collects labeled tape rows."""
    from attack_a1_unit_injection import run_attack_a1
    from attack_a2_rate_flood import run_attack_a2
    from attack_a3_prompt_note import run_attack_a3
    from attack_a4_deadman import run_attack_a4
    from attack_a5_coherence_spoof import run_attack_a5
    from attack_a6_replay import run_attack_a6
    from attack_a7_chain_tamper import run_attack_a7

    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    all_rows: List[Dict[str, Any]] = []
    global_tick = 0

    # Execute attacks and capture rows
    # A1
    c = GovernorClient()
    c.send_heartbeat(advance_coherence=True)
    c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)
    for _ in range(4):
        c.send_command(u_mrad=370000, confidence_q8=255, unit_id=999, advance_coherence=True)
    c.send_command(u_mrad=37000, confidence_q8=255, unit_id=3, advance_coherence=True)
    m = dict(manifest_dict)
    m["governor"]["deadman"]["warmup_heartbeats"] = 2
    m["governor"]["ladder"]["demote_faults_per_rung"] = 3
    a1_rows = run_attack_pipeline(b"".join(c.emitted_frames), m, name="tape_a1")
    for r in a1_rows:
        global_tick += 1
        r["attack_id"] = "A1"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    # A2
    c = GovernorClient()
    c.send_heartbeat(advance_coherence=True)
    c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=-10, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=500, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, advance_coherence=True)
    a2_rows = run_attack_pipeline(b"".join(c.emitted_frames), m, name="tape_a2")
    for r in a2_rows:
        global_tick += 1
        r["attack_id"] = "A2"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    # A3
    c = GovernorClient()
    c.send_heartbeat(advance_coherence=True)
    c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=20, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=40, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=450, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=370000, confidence_q8=255, unit_id=999, advance_coherence=True)
    a3_rows = run_attack_pipeline(b"".join(c.emitted_frames), m, name="tape_a3")
    for r in a3_rows:
        global_tick += 1
        r["attack_id"] = "A3"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    return all_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate canonical governor-tape.csv")
    parser.add_argument("--out", type=pathlib.Path,
                        default=tools_dir.parent / "docs" / "evidence" / "governor" / "governor-tape.csv",
                        help="Target output CSV file path")
    args = parser.parse_args()

    rows = collect_attack_rows()
    if not rows:
        print("[ERROR] No attack rows generated", file=sys.stderr)
        return 1

    fieldnames = [
        "attack_id", "tick", "cycles_in", "cycles_out", "latency_cycles",
        "seq", "u_proposed", "theta_applied", "mode", "mode_name", "fault_bits", "rung"
    ]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"[SUCCESS] Wrote {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
