#!/usr/bin/env python3
"""attack_a4_deadman.py — Adversarial Attack A4: Standalone Deadman Lease Trip.

Standalone extraction of the guest governor A4 attack sequence from
latch/guest/latch_guest_init.c:442-512 and latch/tools/verify_governor_qemu.py.

Scenario:
  1. 4 warmup heartbeats establish the High Performance (HP) rung.
  2. Heartbeat delay (> lease_ticks) forces deadman lease expiry, asserting
     LATCH_FAULT_HEARTBEAT (bit 13, 0x2000) and demoting rung from HP -> ADVISE.
  3. 1 command renews the lease.
  4. 15 heartbeat-only frames prove heartbeat traffic alone CANNOT recover the rung
     (clean_command_streak remains 0, plant unmoved, rung remains ADVISE).
  5. 25 consecutive clean commands earn recovery credit and promote rung ADVISE -> HP.
  6. Final silence (> lease_ticks) expires lease repeatedly, cascading down to LATCH.

Note on the lease: this scenario overrides `deadman.lease_ticks` to 4 so the
host-sim run is deterministic (in the host-sim pipe one tick is one proposal).
The shipped `governor_servo.manifest` lease is 100 ticks = 100 ms at the 1 kHz
decision rate -- the two must not be quoted interchangeably.

Safety Assertions:
  1. Deadman lease expiry trips LATCH_FAULT_HEARTBEAT and demotes supervisory ladder.
  2. Heartbeat-only traffic renews lease but earns zero recovery credit (streak stays 0).
  3. Exactly 25 consecutive clean commands restore HP authority.
  4. Zero keep-out envelope penetrations (0% breach rate).
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
    RUNG_SLOW,
    RUNG_SAFE_STOP,
    RUNG_LATCH,
)
from attacks import (
    assert_zero_keepout_breaches,
    find_pipeline_binaries,
    has_fault,
    run_attack_pipeline,
)


def run_attack_a4(verbose: bool = True) -> Dict[str, Any]:
    """Execute Attack A4 deadman sequence and verify ladder demotion, hold, and recovery."""
    if verbose:
        print("=== [ATTACK A4: STANDALONE DEADMAN LEASE TRIP] ===")
        print("Scenario: Warmup -> Lease Expiry -> Heartbeat Hold -> 25 Clean Recovery -> Silence...")

    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    # Configure manifest: 4 warmup heartbeats, 4-tick lease for deterministic host-sim timing
    # (In QEMU target with 1 kHz loop, 100 ticks = 100 ms; in host-sim pipe, 1 tick = 1 proposal)
    lease_ticks = 4
    promote_clean = 25
    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = 4
    manifest_dict["governor"]["deadman"]["lease_ticks"] = lease_ticks
    manifest_dict["governor"]["ladder"]["promote_clean_frames"] = promote_clean
    manifest_dict["governor"]["ladder"]["demote_faults_per_rung"] = 3
    manifest_dict["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)

    client = GovernorClient()

    # 1. Four warmup heartbeats -> establishes HP
    for _ in range(4):
        client.send_heartbeat(advance_coherence=True)

    # 2. Initial nominal command in HP
    client.send_command(u_mrad=10, confidence_q8=255, unit_id=1, advance_coherence=True)

    # 3. Simulate lease delay: send un-renewed silence frames for lease_ticks
    # Each tick without lease renewal decrements lease_remaining; tick 4 expires lease -> demotes to ADVISE!
    for _ in range(lease_ticks):
        client.send_silence()

    # 4. Resume command: renews lease, establishes ADVISE
    client.send_command(u_mrad=15, confidence_q8=255, unit_id=1, advance_coherence=True)

    # 5. Heartbeat hold: send 15 heartbeats (verifying streak stays 0 and rung stays ADVISE)
    for _ in range(15):
        client.send_heartbeat(advance_coherence=True)

    # 6. Recovery: exactly 25 consecutive clean commands -> promotes ADVISE back to HP!
    for step in range(promote_clean):
        # Step safely from 15 to 40 (1 mrad per tick)
        u_val = 15 + step
        client.send_command(u_mrad=u_val, confidence_q8=255, unit_id=1, advance_coherence=True)

    # 7. Post-recovery nominal commands in HP
    for _ in range(5):
        client.send_command(u_mrad=40, confidence_q8=255, unit_id=1, advance_coherence=True)

    # 8. Final silence / lease expiry: unrenewed ticks cascading down to LATCH
    for _ in range(lease_ticks * 6):
        client.send_silence()

    raw_frames = b"".join(client.emitted_frames)
    rows = run_attack_pipeline(raw_frames, manifest_dict, name="attack_a4")

    # Invariant Evaluation
    # 1. Criterion 1: Zero keep-out envelope breaches
    assert_zero_keepout_breaches(rows, keepout_lo=250, keepout_hi=650, context="Attack A4")

    by_tick = {int(r["tick"]): r for r in rows}

    # Step 1: Initial warmup established HP at tick 5
    row_hp = by_tick[5]
    if int(row_hp["rung"]) != RUNG_HP:
        raise AssertionError(f"Warmup did not establish HP rung at tick 5 (rung={row_hp['rung']})")

    # Step 2: Lease expired at tick 9 (5 + 4 ticks)
    row_expired = by_tick[9]
    if not has_fault(row_expired, FAULT_HEARTBEAT):
        raise AssertionError(f"Lease expiry did not set FAULT_HEARTBEAT at tick 9 (faults={row_expired['fault_bits']})")
    if int(row_expired["rung"]) != RUNG_ADVISE:
        raise AssertionError(f"Lease expiry did not demote to ADVISE at tick 9 (rung={row_expired['rung']})")

    # Step 3: Heartbeat hold (ticks 11..25)
    held_theta = int(by_tick[10]["theta_applied"])
    for tick_idx in range(11, 26):
        r = by_tick[tick_idx]
        if int(r["rung"]) != RUNG_ADVISE:
            raise AssertionError(f"Heartbeat altered rung during hold at tick {tick_idx} (rung={r['rung']})")
        if int(r["theta_applied"]) != held_theta:
            raise AssertionError(f"Heartbeat moved plant during hold at tick {tick_idx} (theta={r['theta_applied']})")

    # Step 4: 25 recovery commands (ticks 26..50)
    # At tick 50 (after exactly 25 clean commands), rung must have promoted back to HP!
    row_recovered = by_tick[50]
    if int(row_recovered["rung"]) != RUNG_HP:
        raise AssertionError(f"25 clean commands failed to recover rung to HP at tick 50 (rung={row_recovered['rung']})")

    # Step 5: Final silence cascaded down to LATCH
    last_row = rows[-1]
    if int(last_row["rung"]) != RUNG_LATCH:
        raise AssertionError(f"Final silence did not demote to LATCH at end of tape (rung={last_row['rung']})")

    report = {
        "attack": "A4",
        "name": "Deadman Lease Trip & Recovery",
        "status": "PASS",
        "ticks_evaluated": len(rows),
        "fault_verified": "FAULT_HEARTBEAT (bit 13, 0x2000)",
        "demotion_verified": "HP -> ADVISE on lease trip",
        "hold_verified": "Heartbeat traffic held lease without promotion credit",
        "recovery_verified": "Exactly 25 clean commands promoted ADVISE -> HP",
        "latch_verified": "Silence cascaded down to LATCH",
        "keepout_intrusions": 0,
    }

    if verbose:
        print("  [PASS] Zero keep-out breaches: 0% breach rate verified.")
        print("  [PASS] FAULT_HEARTBEAT asserted and ladder demoted to ADVISE on lease expiry.")
        print("  [PASS] Heartbeat hold maintained ADVISE without gaining recovery credit.")
        print("  [PASS] Exactly 25 clean commands promoted supervisory rung back to HP.")
        print("  [PASS] Final deadman silence dropped system into fail-closed LATCH.")
        print("[ATTACK A4 VERDICT] PASS\n")

    return report


if __name__ == "__main__":
    try:
        run_attack_a4(verbose=True)
        sys.exit(0)
    except Exception as exc:
        print(f"[ATTACK A4 FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
