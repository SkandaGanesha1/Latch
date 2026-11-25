#!/usr/bin/env python3
"""attack_a8_second_writer.py — Adversarial Attack A8: Second Writer Keeps a Dead Agent Alive.

The dead-man lease is the component that makes LATCH a *dead-man's switch*:
if the planner stops, the supervisor must stop trusting it. Before the
producer-scoped lease (L-2) the lease was renewed by ANY frame that arrived
on `/dev/latch/proposal`, so a second unprivileged writer could keep a
session alive whose real planner had died — precisely the failure the
dead-man's switch exists to prevent.

Scenario:
  1. Producer 1 (the legitimate guest planner) warms up, completes its
     warm-up heartbeats and moves the plant to +20 mrad.
  2. Producer 1 DIES.
  3. Producer 2 (the rogue second writer) keeps sending perfectly
     well-formed, coherence-advancing frames — the exact traffic that used
     to keep the lease alive.
  4. The lease MUST still expire and the supervisory ladder MUST demote:
     the rogue cannot sustain the dead planner's session.
  5. The rogue's frames must not move the plant while the session is live.
  6. After the expiry the rogue MAY take the dead session over — but that is
     a NEW epoch: a fresh sequence baseline, and the warm-up heartbeats must
     be earned again before its command is admitted.

The two producers are driven through SEPARATE `latch-ingest` instances
(`--producer-tag 1` and `--producer-tag 2`) whose IPC streams are
concatenated into ONE supervisor pipe — which is what two writers to
`/dev/latch/proposal` produce on target.

Safety Assertions:
  1. Deadman lease expiry trips LATCH_FAULT_HEARTBEAT and demotes the
     ladder DESPITE the rogue's continuous, well-formed traffic.
  2. The rogue's frames do not move the plant while the session is live.
  3. The rogue's command is not admitted until the new epoch has re-earned
     its warm-up heartbeats.
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
)
from attacks import (
    assert_zero_keepout_breaches,
    find_pipeline_binaries,
    has_fault,
    run_producer_pipeline,
)

OWNER_TAG = 1
ROGUE_TAG = 2

# A 4-tick lease keeps the host-sim run deterministic (in the host-sim
# pipe one tick is one proposal; the shipped guest profile is 100 ticks
# = 100 ms at the 1 kHz decision rate -- the two must not be quoted
# interchangeably).
A8_LEASE_TICKS = 4
A8_WARMUP_HEARTBEATS = 2


def build_a8_scenario(manifest_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Build the A8 two-producer scenario.

    Returns the tuned manifest, the two producer streams and the tick
    bookkeeping the assertions need. This is the SINGLE definition of the
    scenario: both the attack rig and the merged-tape generator call it, so
    the archived tape rows are the rows the attack actually produced rather
    than a second, divergent re-implementation.
    """
    manifest_dict = json.loads(json.dumps(manifest_dict))
    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = A8_WARMUP_HEARTBEATS
    manifest_dict["governor"]["deadman"]["lease_ticks"] = A8_LEASE_TICKS
    manifest_dict["governor"]["ladder"]["promote_clean_frames"] = 25
    manifest_dict["governor"]["ladder"]["demote_faults_per_rung"] = 3

    # ---- Producer 1: the legitimate planner ------------------------------
    owner = GovernorClient()
    for _ in range(A8_WARMUP_HEARTBEATS):
        owner.send_heartbeat(advance_coherence=True)
    owner.send_command(u_mrad=20, confidence_q8=255, unit_id=1, advance_coherence=True)

    # ---- Producer 2: the rogue second writer -----------------------------
    # It sends exactly the traffic that used to keep the lease alive:
    # coherent, well-formed, advancing frames.
    rogue = GovernorClient()
    for _ in range(A8_LEASE_TICKS):
        rogue.send_heartbeat(advance_coherence=True)
    # The next frame TAKES OVER the now-dead session -- but a takeover starts
    # a NEW epoch, and the new producer has not earned its warm-up yet, so
    # this command must NOT be admitted.
    rogue.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, advance_coherence=True)
    # Only after re-earning the warm-up heartbeats may it command.
    for _ in range(A8_WARMUP_HEARTBEATS):
        rogue.send_heartbeat(advance_coherence=True)
    rogue.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, advance_coherence=True)

    streams = [
        (b"".join(owner.emitted_frames), OWNER_TAG),
        (b"".join(rogue.emitted_frames), ROGUE_TAG),
    ]
    return {
        "manifest": manifest_dict,
        "streams": streams,
        "warmup_heartbeats": A8_WARMUP_HEARTBEATS,
        "lease_ticks": A8_LEASE_TICKS,
        "owner_last_tick": A8_WARMUP_HEARTBEATS + 1,
    }


def run_attack_a8(verbose: bool = True) -> Dict[str, Any]:
    """Execute Attack A8 and verify the lease is scoped to the producer."""
    if verbose:
        print("=== [ATTACK A8: SECOND WRITER KEEPS A DEAD AGENT ALIVE] ===")
        print("Scenario: Owner warms up -> Owner dies -> Rogue keeps talking -> "
              "Lease still expires -> Rogue takes the DEAD session over")

    _, _, _, default_manifest_path = find_pipeline_binaries()
    base_manifest = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    scenario = build_a8_scenario(base_manifest)
    manifest_dict = scenario["manifest"]
    warmup_heartbeats = scenario["warmup_heartbeats"]

    rows = run_producer_pipeline(
        scenario["streams"],
        manifest_dict,
        name="attack_a8",
    )

    # Criterion 1: Zero keep-out envelope breaches.
    assert_zero_keepout_breaches(rows, keepout_lo=250, keepout_hi=650, context="Attack A8")

    by_tick = {int(r["tick"]): r for r in rows}
    owner_last_tick = warmup_heartbeats + 1          # 2 heartbeats + 1 command
    plant_after_owner = int(by_tick[owner_last_tick]["theta_applied"])
    if plant_after_owner <= 0:
        raise AssertionError(
            f"The owner's command did not move the plant (theta={plant_after_owner})"
        )

    # The rogue's LAST frame is the command it may finally issue, once the
    # new epoch has re-earned its warm-up.
    rogue_command_tick = len(rows)

    # Assertion 2: the rogue's frames do not move the plant while the
    # session is live, and its FIRST command (the takeover frame) is not
    # admitted because the new epoch has not yet earned its warm-up.
    for tick in range(owner_last_tick + 1, rogue_command_tick):
        theta = int(by_tick[tick]["theta_applied"])
        if theta != plant_after_owner:
            raise AssertionError(
                f"A second producer moved the plant at tick {tick} "
                f"(theta={theta}, expected {plant_after_owner})"
            )

    # Assertion 1: the lease EXPIRED despite the rogue's traffic, and the
    # ladder demoted. Under the old per-stream lease this never happened.
    expiry_tick = None
    for tick in range(owner_last_tick + 1, rogue_command_tick + 1):
        if has_fault(by_tick[tick], FAULT_HEARTBEAT):
            expiry_tick = tick
            break
    if expiry_tick is None:
        raise AssertionError(
            "The dead-man lease never expired: a second producer kept a dead "
            "planner's session alive"
        )
    if int(by_tick[expiry_tick]["rung"]) != RUNG_ADVISE:
        raise AssertionError(
            f"Lease expiry at tick {expiry_tick} did not demote exactly one rung "
            f"(rung={by_tick[expiry_tick]['rung']})"
        )

    # Assertion 3: the takeover is a NEW epoch. The rogue's command is only
    # admitted once it has re-earned the warm-up heartbeats -- and then it
    # IS admitted, so the takeover is a real handover and not a permanent
    # block of the second producer.
    if int(by_tick[rogue_command_tick]["theta_applied"]) == plant_after_owner:
        raise AssertionError(
            "The new producer's command was never admitted, even after it "
            "re-earned its warm-up: the takeover did not hand over authority"
        )

    report = {
        "attack": "A8",
        "name": "Second Writer Keeps Dead Agent Alive",
        "status": "PASS",
        "ticks_evaluated": len(rows),
        "fault_verified": "FAULT_HEARTBEAT (bit 13, 0x2000)",
        "demotion_verified": "HP -> ADVISE on lease expiry despite a live second writer",
        "recovery_verified": (
            "The second producer's takeover starts a new epoch: fresh sequence "
            "baseline and re-earned warm-up"
        ),
        "keepout_intrusions": 0,
    }

    if verbose:
        print("  [PASS] Zero keep-out breaches: 0% breach rate verified.")
        print(f"  [PASS] The owner's lease expired at tick {expiry_tick} even though a "
              f"second producer was sending well-formed frames on every tick.")
        print("  [PASS] The second producer's frames could not move the plant while "
              "the owner's session was live.")
        print("  [PASS] The takeover after expiry started a NEW epoch: the new "
              "producer had to re-earn its warm-up before its command was admitted.")
        print("[ATTACK A8 VERDICT] PASS\n")

    return report


if __name__ == "__main__":
    try:
        run_attack_a8(verbose=True)
        sys.exit(0)
    except Exception as exc:
        print(f"[ATTACK A8 FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
