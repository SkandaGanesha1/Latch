#!/usr/bin/env python3
"""attack_a5_coherence_spoof.py — Adversarial Attack A5: Coherence Spoof Attack.

Adversarial Scenario:
  An attacker attempts to spoof the deadman lease and bypass liveness verification
  by sending frozen coherence counters (delta = 0, e.g. from an infinite loop or stalled agent)
  or jumping the coherence counter forward by a large gap (delta = 10 > coherence_max_gap=3).

Safety Assertions:
  1. Microkernel detects frozen coherence counter (delta = 0) and asserts LATCH_FAULT_HEARTBEAT (bit 13).
  2. Microkernel detects coherence jump exceeding max gap (delta = 10 > 3) and asserts LATCH_FAULT_HEARTBEAT.
  3. Lease is NOT renewed by spoofed frames; supervisory ladder demotes deterministically.
  4. Zero keep-out envelope penetrations: plant never enters [250, 650] mrad (0% breach rate).
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Dict

tools_dir = pathlib.Path(__file__).resolve().parent.parent
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

from governor_client import (
    GovernorClient,
    FAULT_HEARTBEAT,
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


def run_attack_a5(verbose: bool = True) -> Dict[str, Any]:
    """Execute Attack A5 against governor pipeline and return outcome report."""
    if verbose:
        print("=== [ATTACK A5: COHERENCE SPOOF ATTACK] ===")
        print("Scenario: Injecting frozen counter (delta=0) and forward jump (delta=10 > max_gap=3)...")

    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = 2
    manifest_dict["governor"]["deadman"]["lease_ticks"] = 100
    manifest_dict["governor"]["deadman"]["coherence_max_gap"] = 3
    manifest_dict["governor"]["ladder"]["demote_faults_per_rung"] = 3
    manifest_dict["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)

    client = GovernorClient()

    # Phase 1: Warmup heartbeats -> HP
    client.send_heartbeat(advance_coherence=True)  # seq 1, coh 1
    client.send_heartbeat(advance_coherence=True)  # seq 2, coh 2

    # Phase 2: Nominal command in HP
    client.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)  # seq 3, coh 3

    # Phase 3: Frozen Coherence Spoof (delta = 0)
    # The client sends frames with identical coherence counter (coh=3)
    # Ingest accepts the frame, but supervisor detects delta=0 -> trips LATCH_FAULT_HEARTBEAT
    seq4 = client.advance_seq(1)
    frame_frozen = client.pack_frame(
        kind=2,  # CMD_V2
        u_mrad=15,
        confidence_q8=255,
        unit_id=1,
        agent_state=1,
        seq_override=seq4,
        coherence_override=3,  # Frozen delta = 0!
    )
    client.emit(frame_frozen)

    # Phase 4: Coherence Jump Spoof (delta = 10 > max_gap 3)
    # Proposes jump from 3 to 13
    seq5 = client.advance_seq(1)
    frame_jump = client.pack_frame(
        kind=2,  # CMD_V2
        u_mrad=20,
        confidence_q8=255,
        unit_id=1,
        agent_state=1,
        seq_override=seq5,
        coherence_override=13,  # Jump delta = 10 > 3!
    )
    client.emit(frame_jump)

    # Phase 5: Re-synchronize valid coherent commands to verify plant recovery
    client.coherence = 14
    client.send_command(u_mrad=12, confidence_q8=255, unit_id=1, advance_coherence=True)

    raw_frames = b"".join(client.emitted_frames)
    rows = run_attack_pipeline(raw_frames, manifest_dict, name="attack_a5")

    # Invariant Evaluation
    # 1. Criterion 1: Zero keep-out envelope breaches
    assert_zero_keepout_breaches(rows, keepout_lo=250, keepout_hi=650, context="Attack A5")

    by_seq = {int(r["seq"]): r for r in rows if r.get("seq") and int(r["seq"]) > 0}

    # Verify nominal command in HP (seq 3)
    nom_row = by_seq[3]
    if int(nom_row["rung"]) != RUNG_HP:
        raise AssertionError(f"Expected HP rung at seq 3, got {nom_row['rung']}")
    held_theta = int(nom_row["theta_applied"])

    # Verify Frozen Coherence Spoof (seq 4)
    frozen_row = by_seq[4]
    if not has_fault(frozen_row, FAULT_HEARTBEAT):
        raise AssertionError(f"Frozen coherence delta=0 did NOT assert FAULT_HEARTBEAT (faults={frozen_row['fault_bits']})")
    # Ladder demotes from HP -> ADVISE
    if int(frozen_row["rung"]) != RUNG_ADVISE:
        raise AssertionError(f"Frozen coherence did not demote HP to ADVISE (rung={frozen_row['rung']})")
    # Plant must NOT have moved on rejected proposal
    if int(frozen_row["theta_applied"]) != held_theta:
        raise AssertionError(f"Plant moved on rejected frozen coherence proposal: theta={frozen_row['theta_applied']}")

    # Verify Coherence Jump Spoof (seq 5)
    jump_row = by_seq[5]
    if not has_fault(jump_row, FAULT_HEARTBEAT):
        raise AssertionError(f"Coherence jump delta=10 did NOT assert FAULT_HEARTBEAT (faults={jump_row['fault_bits']})")
    # Ladder demotes from ADVISE -> CLAMP
    if int(jump_row["rung"]) != RUNG_CLAMP:
        raise AssertionError(f"Coherence jump did not demote ADVISE to CLAMP (rung={jump_row['rung']})")
    if int(jump_row["theta_applied"]) != held_theta:
        raise AssertionError(f"Plant moved on rejected coherence jump proposal: theta={jump_row['theta_applied']}")

    report = {
        "attack": "A5",
        "name": "Coherence Spoof Attack",
        "status": "PASS",
        "ticks_evaluated": len(rows),
        "fault_verified": "FAULT_HEARTBEAT (bit 13, 0x2000)",
        "frozen_delta_caught": True,
        "jump_delta_caught": True,
        "demotions_verified": "HP -> ADVISE (frozen) -> CLAMP (jump)",
        "keepout_intrusions": 0,
    }

    if verbose:
        print("  [PASS] Zero keep-out breaches: 0% breach rate verified.")
        print("  [PASS] Frozen coherence (delta=0) asserted FAULT_HEARTBEAT and demoted HP -> ADVISE.")
        print("  [PASS] Coherence jump (delta=10 > 3) asserted FAULT_HEARTBEAT and demoted ADVISE -> CLAMP.")
        print("  [PASS] Spoofed proposals rejected fail-closed, plant held stationary.")
        print("[ATTACK A5 VERDICT] PASS\n")

    return report


if __name__ == "__main__":
    try:
        run_attack_a5(verbose=True)
        sys.exit(0)
    except Exception as exc:
        print(f"[ATTACK A5 FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
