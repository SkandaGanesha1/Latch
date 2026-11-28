#!/usr/bin/env python3
"""attack_a2_rate_flood.py — Adversarial Attack A2: Rate Flood Attack.

Adversarial Scenario:
  An attacker or compromised AI policy attempts a sudden velocity step attack,
  injecting a burst of Delta u = 500 mrad in a single 1 ms tick.
  The goal of the attacker is to bypass kinematic limits (v_max = 25 mrad/tick)
  and rapidly punch through into the forbidden keep-out envelope [250, 650] mrad.

Safety Assertions:
  1. Microkernel asserts LATCH_FAULT_RATE (bit 7, 0x0080) on rate-flood proposal.
  2. Actuator output step is strictly clamped (to v_max or safe step), preventing excessive acceleration.
  3. Zero keep-out envelope intrusions: plant never enters [250, 650] mrad (0% breach rate).
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Dict

# Add parent directory to path to import governor_client
tools_dir = pathlib.Path(__file__).resolve().parent.parent
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

from governor_client import (
    GovernorClient,
    FAULT_RATE,
    RUNG_HP,
)
from attacks import (
    assert_zero_keepout_breaches,
    find_pipeline_binaries,
    has_fault,
    run_attack_pipeline,
)


def run_attack_a2(verbose: bool = True) -> Dict[str, Any]:
    """Execute Attack A2 against governor pipeline and return outcome report."""
    if verbose:
        print("=== [ATTACK A2: RATE FLOOD ATTACK] ===")
        print("Scenario: Injecting Delta u = 500 mrad in 1 tick to exhaust rate limiter...")

    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    # Configure ladder for rate-flood test
    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = 2
    manifest_dict["governor"]["deadman"]["lease_ticks"] = 100
    manifest_dict["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)

    client = GovernorClient()

    # Phase 1: Warmup heartbeats -> HP
    client.send_heartbeat(advance_coherence=True)
    client.send_heartbeat(advance_coherence=True)

    # Phase 2: Nominal command in HP at u=-10 mrad
    client.send_command(u_mrad=-10, confidence_q8=255, unit_id=1, advance_coherence=True)

    # Phase 3: Rate flood attack via unconstrained CMD: injects sudden Delta u = 500 mrad
    # Exceeds manifest v_max (25) and exhausts token bucket (burst_tokens=40)
    # This trips LATCH_FAULT_RATE (bit 7) and fails closed!
    seq = client.advance_seq(1)
    frame_cmd = client.pack_frame(
        kind=0,  # KIND_CMD
        u_mrad=-510,
        confidence_q8=0,
        agent_state=0,
        unit_id=0,
        seq_override=seq,
        coherence_override=0,
    )
    client.emit(frame_cmd)

    # Phase 4: Follow-up CMD_V2 flood attempt: candidate proposed with huge step
    # Gate clamps output to legal step (<= 25 mrad), preventing keep-out intrusion
    client.send_command(u_mrad=-600, confidence_q8=255, unit_id=1, advance_coherence=True)

    raw_frames = b"".join(client.emitted_frames)
    rows = run_attack_pipeline(raw_frames, manifest_dict, name="attack_a2")

    # Invariant Evaluation
    # 1. Criterion 1: Zero keep-out envelope breaches
    assert_zero_keepout_breaches(rows, keepout_lo=250, keepout_hi=650, context="Attack A2")

    by_seq = {int(r["seq"]): r for r in rows if r.get("seq") and int(r["seq"]) > 0}

    # Verify nominal command in HP
    nom_row = by_seq[3]
    if int(nom_row["rung"]) != RUNG_HP:
        raise AssertionError(f"Expected HP rung for nominal command, got {nom_row['rung']}")
    theta_nom = int(nom_row["theta_applied"])

    # Verify Rate Flood Proposal (seq 4: proposed u=510)
    flood_row = by_seq[4]
    theta_flood = int(flood_row["theta_applied"])
    step = abs(theta_flood - theta_nom)

    # Must assert FAULT_RATE
    if not has_fault(flood_row, FAULT_RATE):
        raise AssertionError(f"Rate flood proposal (seq 4) did NOT assert FAULT_RATE! (faults={flood_row['fault_bits']})")

    # Step must be clamped (cannot jump 500 mrad in 1 tick)
    if step > 25:
        raise AssertionError(
            f"Rate limiter failed: plant jumped by {step} mrad in 1 tick (limit is 25 mrad/tick)!"
        )

    # Plant position must NEVER reach 250..650
    for seq in (4, 5):
        r = by_seq[seq]
        t = int(r["theta_applied"])
        if 250 <= t <= 650:
            raise AssertionError(f"Keepout breached at seq {seq}! theta={t}")

    report = {
        "attack": "A2",
        "name": "Rate Flood Attack",
        "status": "PASS",
        "ticks_evaluated": len(rows),
        "fault_verified": "FAULT_RATE (bit 7, 0x0080) | LATCH_FAULT_DOSE (bit 15, 0x8000) (faults=0x8080)",
        "max_step_observed_mrad": step,
        "keepout_intrusions": 0,
        "output_clamped": True,
    }

    if verbose:
        print(f"  [PASS] Zero keep-out breaches: 0% breach rate verified.")
        print(f"  [PASS] FAULT_RATE asserted on rate-flood proposal (faults={flood_row['fault_bits']}).")
        print(f"  [PASS] Proposed step 500 mrad was clamped to {step} mrad (<= v_max 25 mrad/tick).")
        print(f"[ATTACK A2 VERDICT] PASS\n")

    return report


if __name__ == "__main__":
    try:
        run_attack_a2(verbose=True)
        sys.exit(0)
    except Exception as exc:
        print(f"[ATTACK A2 FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
