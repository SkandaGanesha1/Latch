#!/usr/bin/env python3
"""attack_a6_replay.py — Adversarial Attack A6: Sequence Replay Attack.

Adversarial Scenario:
  An attacker eavesdrops on legitimate wire traffic and later replays a previously
  captured command frame (with duplicate seq or older seq, delta <= 0).
  The attacker attempts to force the plant to re-execute past motions or desynchronize
  the microkernel supervisor's monotonic sequence state machine.

Safety Assertions:
  1. Microkernel detects sequence replay/duplicate and asserts LATCH_FAULT_SEQ (bit 2, 0x0004).
  2. Replayed proposal is dropped fail-closed; actuator does not move.
  3. Supervisory ladder transitions fail-closed to LATCH (HOLD mode).
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
    FAULT_SEQ,
    RUNG_HP,
    RUNG_LATCH,
)
from attacks import (
    assert_zero_keepout_breaches,
    find_pipeline_binaries,
    has_fault,
    run_attack_pipeline,
)


def run_attack_a6(verbose: bool = True) -> Dict[str, Any]:
    """Execute Attack A6 against governor pipeline and return outcome report."""
    if verbose:
        print("=== [ATTACK A6: SEQUENCE REPLAY ATTACK] ===")
        print("Scenario: Capturing legitimate frames and replaying older/duplicate seq...")

    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = 2
    manifest_dict["governor"]["deadman"]["lease_ticks"] = 100
    manifest_dict["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)

    client = GovernorClient()

    # Phase 1: Warmup heartbeats -> HP
    client.send_heartbeat(advance_coherence=True)  # seq 1
    client.send_heartbeat(advance_coherence=True)  # seq 2

    # Phase 2: Nominal commands in HP
    client.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)  # seq 3
    client.send_command(u_mrad=20, confidence_q8=255, unit_id=1, advance_coherence=True)  # seq 4
    client.send_command(u_mrad=30, confidence_q8=255, unit_id=1, advance_coherence=True)  # seq 5

    # Phase 3: Sequence Replay Attack: Replay seq 3 (older seq, delta < 0)
    # Attacker crafts/replays frame with seq=3
    seq_replayed = 3
    coh_curr = client.coherence + 1
    frame_replay_old = client.pack_frame(
        kind=2,  # CMD_V2
        u_mrad=100,  # Attacker attempts to command 100 mrad
        confidence_q8=255,
        unit_id=1,
        agent_state=1,
        seq_override=seq_replayed,
        coherence_override=coh_curr,
    )
    client.emit(frame_replay_old)

    # Phase 4: Duplicate Sequence Replay: Replay identical seq (delta = 0)
    frame_replay_dup = client.pack_frame(
        kind=2,
        u_mrad=150,
        confidence_q8=255,
        unit_id=1,
        agent_state=1,
        seq_override=seq_replayed,
        coherence_override=coh_curr + 1,
    )
    client.emit(frame_replay_dup)

    raw_frames = b"".join(client.emitted_frames)
    rows = run_attack_pipeline(raw_frames, manifest_dict, name="attack_a6")

    # Invariant Evaluation
    # 1. Criterion 1: Zero keep-out envelope breaches
    assert_zero_keepout_breaches(rows, keepout_lo=250, keepout_hi=650, context="Attack A6")

    # Inspect rows
    # Tick 5 is seq 5 (nominal command)
    row_nom = rows[4]
    held_theta = int(row_nom["theta_applied"])
    if int(row_nom["rung"]) != RUNG_HP:
        raise AssertionError(f"Expected HP rung at tick 5, got {row_nom['rung']}")

    # Tick 6 is the replayed older seq (seq 3)
    row_replay_old = rows[5]
    if not has_fault(row_replay_old, FAULT_SEQ):
        raise AssertionError(f"Replay of older seq did NOT assert FAULT_SEQ! (faults={row_replay_old['fault_bits']})")
    if int(row_replay_old["rung"]) != RUNG_LATCH:
        raise AssertionError(f"Replay attack did not force transition to LATCH rung! (rung={row_replay_old['rung']})")
    if int(row_replay_old["theta_applied"]) != held_theta:
        raise AssertionError(f"Plant moved on replayed proposal! (theta={row_replay_old['theta_applied']})")

    # Tick 7 is the duplicate seq
    row_replay_dup = rows[6]
    if not has_fault(row_replay_dup, FAULT_SEQ):
        raise AssertionError(f"Duplicate seq did NOT assert FAULT_SEQ! (faults={row_replay_dup['fault_bits']})")
    if int(row_replay_dup["rung"]) != RUNG_LATCH:
        raise AssertionError(f"Duplicate seq not in LATCH (rung={row_replay_dup['rung']})")

    report = {
        "attack": "A6",
        "name": "Sequence Replay Attack",
        "status": "PASS",
        "ticks_evaluated": len(rows),
        "fault_verified": "FAULT_SEQ (bit 2, 0x0004)",
        "replayed_seq": seq_replayed,
        "fail_closed_verified": "Transitioned to LATCH (HOLD mode)",
        "plant_unmoved": True,
        "keepout_intrusions": 0,
    }

    if verbose:
        print("  [PASS] Zero keep-out breaches: 0% breach rate verified.")
        print(f"  [PASS] Replayed sequence #{seq_replayed} asserted FAULT_SEQ (faults={row_replay_old['fault_bits']}).")
        print("  [PASS] Replay attack forced immediate fail-closed transition to LATCH (HOLD mode).")
        print(f"  [PASS] Plant held stationary at {held_theta} mrad, malicious u=100 rejected.")
        print("[ATTACK A6 VERDICT] PASS\n")

    return report


if __name__ == "__main__":
    try:
        run_attack_a6(verbose=True)
        sys.exit(0)
    except Exception as exc:
        print(f"[ATTACK A6 FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
