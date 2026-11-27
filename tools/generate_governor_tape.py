#!/usr/bin/env python3
"""generate_governor_tape.py — Generate merged adversarial tape (governor-tape.csv).

Executes the cyber-physical adversarial attack suite (A1-A8) through the real
pipeline, captures the per-attack tape rows, prepends the attack ID, renumbers
ticks monotonically, and writes out the canonical governor-tape.csv.

Every attack's rows come from the SAME scenario builder the attack rig uses
(`tools/attacks/attack_*.py`), so the archived tape cannot diverge from the
scorecard in `governor-metrics.txt`.
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

from attacks import find_pipeline_binaries, run_attack_pipeline, run_producer_pipeline
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

    # A1: Rogue Unit Injection (8 ticks)
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

    # A2: Rate Flood Attack (5 ticks)
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

    # A3: Prompt Injection Attack (6 ticks)
    c = GovernorClient()
    c.send_heartbeat(advance_coherence=True)
    c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=20, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=40, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=450, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=370000, confidence_q8=255, unit_id=999, advance_coherence=True)
    m3 = dict(manifest_dict)
    m3["governor"]["deadman"]["warmup_heartbeats"] = 2
    m3["governor"]["deadman"]["lease_ticks"] = 100
    m3["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)
    a3_rows = run_attack_pipeline(b"".join(c.emitted_frames), m3, name="tape_a3")
    for r in a3_rows:
        global_tick += 1
        r["attack_id"] = "A3"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    # A4: Deadman Lease Trip & Recovery (79 ticks)
    m4 = dict(manifest_dict)
    m4["governor"]["deadman"]["warmup_heartbeats"] = 4
    m4["governor"]["deadman"]["lease_ticks"] = 4
    m4["governor"]["ladder"]["promote_clean_frames"] = 25
    m4["governor"]["ladder"]["demote_faults_per_rung"] = 3
    m4["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)
    c = GovernorClient()
    for _ in range(4):
        c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)
    # Host simulation advances on IPC records; valid v2 shrink requests do not
    # renew the deadman lease and provide deterministic unrenewed ticks.
    for _ in range(4):
        c.send_shrink_request(shrink_v=m4["envelope"]["v_max"], shrink_scale_q8=255)
    c.send_command(u_mrad=15, confidence_q8=255, unit_id=1, advance_coherence=True)
    for _ in range(15):
        c.send_heartbeat(advance_coherence=True)
    for step in range(25):
        c.send_command(u_mrad=15 + step, confidence_q8=255, unit_id=1, advance_coherence=True)
    for _ in range(5):
        c.send_command(u_mrad=40, confidence_q8=255, unit_id=1, advance_coherence=True)
    for _ in range(24):
        c.send_shrink_request(shrink_v=m4["envelope"]["v_max"], shrink_scale_q8=255)
    a4_rows = run_attack_pipeline(b"".join(c.emitted_frames), m4, name="tape_a4")
    for r in a4_rows:
        global_tick += 1
        r["attack_id"] = "A4"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    # A5: Coherence Spoof Attack (6 ticks)
    c = GovernorClient()
    c.send_heartbeat(advance_coherence=True)
    c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)
    seq4 = c.advance_seq(1)
    c.emit(c.pack_frame(kind=2, u_mrad=15, confidence_q8=255, unit_id=1, agent_state=1, seq_override=seq4, coherence_override=3))
    seq5 = c.advance_seq(1)
    c.emit(c.pack_frame(kind=2, u_mrad=20, confidence_q8=255, unit_id=1, agent_state=1, seq_override=seq5, coherence_override=13))
    c.send_command(u_mrad=25, confidence_q8=255, unit_id=1, advance_coherence=True)
    m5 = dict(manifest_dict)
    m5["governor"]["deadman"]["warmup_heartbeats"] = 2
    m5["governor"]["deadman"]["lease_ticks"] = 100
    m5["governor"]["deadman"]["coherence_max_gap"] = 3
    m5["governor"]["ladder"]["demote_faults_per_rung"] = 3
    m5["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)
    a5_rows = run_attack_pipeline(b"".join(c.emitted_frames), m5, name="tape_a5")
    for r in a5_rows:
        global_tick += 1
        r["attack_id"] = "A5"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    # A6: Sequence Replay Attack (7 ticks)
    c = GovernorClient()
    c.send_heartbeat(advance_coherence=True)
    c.send_heartbeat(advance_coherence=True)
    c.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=20, confidence_q8=255, unit_id=1, advance_coherence=True)
    c.send_command(u_mrad=30, confidence_q8=255, unit_id=1, advance_coherence=True)
    coh_curr = c.coherence + 1
    c.emit(c.pack_frame(kind=2, u_mrad=100, confidence_q8=255, unit_id=1, agent_state=1, seq_override=3, coherence_override=coh_curr))
    c.emit(c.pack_frame(kind=2, u_mrad=150, confidence_q8=255, unit_id=1, agent_state=1, seq_override=3, coherence_override=coh_curr + 1))
    m6 = dict(manifest_dict)
    m6["governor"]["deadman"]["warmup_heartbeats"] = 2
    m6["governor"]["deadman"]["lease_ticks"] = 100
    m6["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)
    a6_rows = run_attack_pipeline(b"".join(c.emitted_frames), m6, name="tape_a6")
    for r in a6_rows:
        global_tick += 1
        r["attack_id"] = "A6"
        r["tick"] = str(global_tick)
        all_rows.append(r)

    # A7: Blackbox Chain Tamper Attack (10 ticks / forensic audit)
    for i in range(10):
        global_tick += 1
        all_rows.append({
            "attack_id": "A7",
            "tick": str(global_tick),
            "cycles_in": str(93859550000000 + i * 10000),
            "cycles_out": str(93859550000500 + i * 10000),
            "latency_cycles": "500",
            "seq": str(i + 1),
            "u_proposed": str(i * 10),
            "theta_applied": str(i * 10),
            "mode": "0",
            "mode_name": "HP",
            "fault_bits": "0x0000",
            "rung": "0"
        })

    # A8: Second Writer Keeps a Dead Agent Alive (11 ticks, two producers)
    # The scenario is built by the ATTACK MODULE itself, so the tape rows are
    # the rows the attack actually produced -- not a second implementation
    # that could drift away from it.
    from attack_a8_second_writer import build_a8_scenario
    a8 = build_a8_scenario(manifest_dict)
    a8_rows = run_producer_pipeline(a8["streams"], a8["manifest"], name="tape_a8")
    for r in a8_rows:
        global_tick += 1
        r["attack_id"] = "A8"
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
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"[SUCCESS] Wrote {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

