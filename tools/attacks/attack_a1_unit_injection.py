#!/usr/bin/env python3
"""attack_a1_unit_injection.py — Adversarial Attack A1: Rogue Unit Injection.

Adversarial Scenario:
  An untrusted agent proposes commands using an undeclared/unmapped unit ID (unit_id=999)
  with a massive out-of-scale value (u=370000 mrad). If accepted raw, this would violently
  smash the plant through the forbidden keep-out interval [250, 650] mrad.

Safety Assertions:
  1. Microkernel asserts LATCH_FAULT_UNIT (bit 12, 0x1000) on unknown unit proposals.
  2. Plant does not move into or cross the forbidden keep-out interval [250, 650] mrad (0% breach rate).
  3. Supervisory ladder demotes from ADVISE to CLAMP after 3 repeated advisory faults.
  4. Valid rational unit conversions (e.g. unit_id=3 with 1/1000 scale: 37000 -> 37 mrad)
     are correctly admitted through CLAMP without UNIT fault.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Dict, List

# Add parent directory to path to import governor_client
tools_dir = pathlib.Path(__file__).resolve().parent.parent
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

from governor_client import (
    GovernorClient,
    FAULT_UNIT,
    RUNG_HP,
    RUNG_ADVISE,
    RUNG_CLAMP,
)
from attacks import (
    assert_zero_keepout_breaches,
    find_pipeline_binaries,
    has_fault,
    run_attack_pipeline,
)


def run_attack_a1(verbose: bool = True) -> Dict[str, Any]:
    """Execute Attack A1 against governor pipeline and return outcome report."""
    if verbose:
        print("=== [ATTACK A1: ROGUE UNIT INJECTION] ===")
        print("Scenario: Injecting u=370000 with unmapped unit_id=999...")

    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    # Configure ladder for test
    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = 2
    manifest_dict["governor"]["deadman"]["lease_ticks"] = 100
    manifest_dict["governor"]["ladder"]["demote_faults_per_rung"] = 3
    manifest_dict["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)

    client = GovernorClient()

    # Phase 1: Warmup heartbeats -> HP
    client.send_heartbeat(advance_coherence=True)
    client.send_heartbeat(advance_coherence=True)

    # Phase 2: Nominal command in HP
    client.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)

    # Phase 3: Rogue Unit Injection (4 repeated frames with unit_id=999)
    # Ticks 4..7: Repeated UNIT anomalies trigger ladder demotion HP -> ADVISE -> CLAMP
    for _ in range(4):
        client.send_command(u_mrad=370000, confidence_q8=255, unit_id=999, advance_coherence=True)

    # Phase 4: Valid rational unit conversion (unit_id=3 has scale 1/1000: 37000 -> 37 mrad)
    client.send_command(u_mrad=37000, confidence_q8=255, unit_id=3, advance_coherence=True)

    raw_frames = b"".join(client.emitted_frames)
    rows = run_attack_pipeline(raw_frames, manifest_dict, name="attack_a1")

    # Invariant Evaluation
    # 1. Criterion 1: Zero keep-out envelope breaches
    assert_zero_keepout_breaches(rows, keepout_lo=250, keepout_hi=650, context="Attack A1")

    by_seq = {int(r["seq"]): r for r in rows if r.get("seq") and int(r["seq"]) > 0}

    # Verify nominal command in HP
    nom_row = by_seq[3]
    if int(nom_row["fault_bits"], 16) & FAULT_UNIT != 0:
        raise AssertionError("Nominal command raised unexpected FAULT_UNIT")
    if int(nom_row["rung"]) != RUNG_HP:
        raise AssertionError(f"Expected HP rung for nominal command, got {nom_row['rung']}")
    held_theta_before_attack = int(nom_row["theta_applied"])

    # Verify Rogue Unit Injections (seq 4..7)
    unit_fault_count = 0
    for seq in range(4, 8):
        row = by_seq[seq]
        if not has_fault(row, FAULT_UNIT):
            raise AssertionError(f"Seq {seq} with unit_id=999 did NOT assert FAULT_UNIT! (faults={row['fault_bits']})")
        unit_fault_count += 1
        # Plant position must NOT jump to 370000; it must stay at held theta
        if int(row["theta_applied"]) != held_theta_before_attack:
            raise AssertionError(
                f"Plant position altered on rejected unit proposal at seq {seq}: "
                f"theta={row['theta_applied']}, expected {held_theta_before_attack}"
            )

    # Verify ladder demotion to CLAMP after repeated advisory faults
    # Seq 4: demotes HP -> ADVISE
    # Seq 5: in ADVISE (advisory streak = 1)
    # Seq 6: in ADVISE (advisory streak = 2)
    # Seq 7: advisory streak = 3 -> demotes to CLAMP!
    row_demoted = by_seq[7]
    if int(row_demoted["rung"]) != RUNG_CLAMP:
        raise AssertionError(f"Expected demotion to CLAMP at seq 7, got rung {row_demoted['rung']}")

    # Verify valid rational conversion admitted through CLAMP (seq 8)
    row_conv = by_seq[8]
    if has_fault(row_conv, FAULT_UNIT):
        raise AssertionError(f"Known rational unit conversion (unit_id=3) erroneously raised FAULT_UNIT: {row_conv['fault_bits']}")
    if int(row_conv["theta_applied"]) <= held_theta_before_attack:
        raise AssertionError("Valid rational conversion proposal was not admitted through CLAMP")

    report = {
        "attack": "A1",
        "name": "Rogue Unit Injection",
        "status": "PASS",
        "ticks_evaluated": len(rows),
        "fault_verified": "FAULT_UNIT (bit 12, 0x1000)",
        "unit_faults_observed": unit_fault_count,
        "keepout_intrusions": 0,
        "demotion_verified": "HP -> ADVISE -> CLAMP on 3 faults",
        "conversion_admitted": True,
    }

    if verbose:
        print(f"  [PASS] Zero keep-out breaches: 0% breach rate verified.")
        print(f"  [PASS] FAULT_UNIT asserted on all {unit_fault_count} rogue proposals.")
        print(f"  [PASS] Supervisory ladder demoted to CLAMP on threshold.")
        print(f"  [PASS] Valid rational conversion unit_id=3 admitted cleanly.")
        print(f"[ATTACK A1 VERDICT] PASS\n")

    return report


if __name__ == "__main__":
    try:
        run_attack_a1(verbose=True)
        sys.exit(0)
    except Exception as exc:
        print(f"[ATTACK A1 FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
