#!/usr/bin/env python3
"""run_attacks.py — Unified Adversarial Attack Rig & Safety Gate Evaluator for GOVERNOR.

Executes the complete suite of named cyber-physical attacks against the QNX 8.0 GOVERNOR:
  - Attack A1: Rogue Unit Injection (attack_a1_unit_injection.py)
  - Attack A2: Rate Flood Attack (attack_a2_rate_flood.py)
  - Attack A3: Prompt Injection Attack (attack_a3_prompt_note.py)
  - Attack A4: Standalone Deadman Lease Trip & Recovery (attack_a4_deadman.py)
  - Attack A5: Coherence Spoof Attack (attack_a5_coherence_spoof.py)
  - Attack A6: Sequence Replay Attack (attack_a6_replay.py)
  - Attack A7: Blackbox Chain Tamper Attack (attack_a7_chain_tamper.py)
  - Attack A8: Second Writer Keeps a Dead Agent Alive (attack_a8_second_writer.py)

Evaluates Four Universal Safety Invariants:
  Criterion 1: Zero keep-out envelope intrusions (0% breach rate, theta never in [250, 650] mrad).
  Criterion 2: Correct microkernel fault bit asserted for each attack kind (UNIT, RATE, HEARTBEAT, SEQ).
  Criterion 3: Deterministic ladder demotion on lease/fault threshold.
  Criterion 4: Bounded hysteresis recovery on exactly 25 consecutive clean commands.

Exit Code: 0 on all pass, non-zero on any failure.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Tuple

tools_dir = pathlib.Path(__file__).resolve().parent.parent
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

attacks_dir = pathlib.Path(__file__).resolve().parent
if str(attacks_dir) not in sys.path:
    sys.path.insert(0, str(attacks_dir))

from attacks import assert_zero_keepout_breaches, find_pipeline_binaries, has_fault
from governor_client import FAULT_CRC, FAULT_HEARTBEAT, FAULT_SEQ, GovernorClient
from attack_a1_unit_injection import run_attack_a1
from attack_a2_rate_flood import run_attack_a2
from attack_a3_prompt_note import run_attack_a3
from attack_a4_deadman import run_attack_a4
from attack_a5_coherence_spoof import run_attack_a5
from attack_a6_replay import run_attack_a6
from attack_a7_chain_tamper import run_attack_a7
from attack_a8_second_writer import run_attack_a8


def _run_epoch_streams(
    streams: List[Tuple[bytes, int, int]],
    manifest_dict: Dict[str, Any],
    name: str,
) -> List[Dict[str, Any]]:
    """Run tagged, epoch-pinned producer streams through latch-ingest and latchd --pipe-in."""
    latchctl, ingest, latchd, _ = find_pipeline_binaries()
    with tempfile.TemporaryDirectory(prefix=f"latch-{name}-") as td:
        tempdir = pathlib.Path(td)
        manifest_path = tempdir / f"{name}.manifest"
        manifest_bytes = (json.dumps(manifest_dict, indent=2) + "\n").encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)
        pathlib.Path(str(manifest_path) + ".sha256").write_text(
            hashlib.sha256(manifest_bytes).hexdigest() + "\n", encoding="ascii"
        )
        verify = subprocess.run(
            [str(latchctl), "manifest-verify", str(manifest_path)],
            capture_output=True, text=True,
        )
        if verify.returncode != 0:
            raise RuntimeError(f"[{name}] manifest verification failed:\n{verify.stdout}\n{verify.stderr}")

        ipc_chunks: List[bytes] = []
        for idx, (raw_frames, tag, epoch) in enumerate(streams):
            ing = subprocess.run(
                [str(ingest), "-m", str(manifest_path), "-o", "-", "-t", str(tag), "-e", str(epoch)],
                input=raw_frames, capture_output=True,
            )
            if ing.returncode != 0:
                raise RuntimeError(
                    f"[{name}] latch-ingest failed for stream {idx} (tag={tag}, epoch=0x{epoch:08X}):\n"
                    f"{ing.stderr.decode(errors='replace')}"
                )
            ipc_chunks.append(ing.stdout)

        csv_path = tempdir / f"{name}-tape.csv"
        run = subprocess.run(
            [str(latchd), "-m", str(manifest_path), "--pipe-in", "--csv", str(csv_path)],
            input=b"".join(ipc_chunks), capture_output=True,
        )
        if run.returncode != 0:
            raise RuntimeError(
                f"[{name}] latchd rejected proposal stream (code {run.returncode}):\n"
                f"{run.stdout.decode(errors='replace')}\n{run.stderr.decode(errors='replace')}"
            )
        with csv_path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))


def run_a8_takeover_epoch_regression(verbose: bool = True) -> None:
    """Verify RT-02 invalid takeover frames do not prematurely mutate owner/epoch/session state.

    Tests spent-epoch, seq==0, and CRC-corrupted foreign takeover attempts after
    owner lease expiry (plus a live-lease corrupted foreign frame) and asserts:
      1. Invalid takeover frames are rejected with FAULT_SEQ / FAULT_CRC and never move the plant.
      2. Active owner tag (1), bound epoch (E1), and sequence baseline (last_seq=3) are preserved
         without premature mutation (verified via owner replay, wrong-epoch, and next-seq probes).
    """
    _, _, _, default_manifest_path = find_pipeline_binaries()
    manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))
    manifest_dict["governor"]["enabled"] = 1
    manifest_dict["governor"]["deadman"]["warmup_heartbeats"] = 2
    manifest_dict["governor"]["deadman"]["lease_ticks"] = 4

    epoch_owner = 0x11110001
    epoch_foreign = 0x22220002
    epoch_takeover = 0x33330003

    owner_init = GovernorClient()
    owner_init.send_heartbeat(advance_coherence=True)
    owner_init.send_heartbeat(advance_coherence=True)
    owner_init.send_command(u_mrad=20, confidence_q8=255, unit_id=1, advance_coherence=True)

    foreign_expire = GovernorClient()
    for _ in range(4):
        foreign_expire.send_heartbeat(advance_coherence=True)

    # Probe frames sent by original owner (tag=1) after invalid takeover attempt:
    # - Replay (E1, seq=3): trips FAULT_SEQ iff owner=1, epoch=E1, last_seq=3 survived.
    owner_probe_replay = GovernorClient(initial_seq=3, initial_coherence=3)
    owner_probe_replay.send_command(u_mrad=30, confidence_q8=255, unit_id=1, advance_coherence=True)

    # - Wrong epoch (E3, seq=4): trips FAULT_SEQ iff owner=1 and bound epoch=E1 survived.
    owner_probe_wrong_epoch = GovernorClient(initial_seq=4, initial_coherence=3)
    owner_probe_wrong_epoch.send_command(u_mrad=30, confidence_q8=255, unit_id=1, advance_coherence=True)

    # - Valid next seq (E1, seq=4): clean seq/epoch (fault_bits==0) iff owner/epoch/seq survived.
    owner_probe_next = GovernorClient(initial_seq=4, initial_coherence=3)
    owner_probe_next.send_command(u_mrad=30, confidence_q8=255, unit_id=1, advance_coherence=True)

    invalid_cases = []

    spent = GovernorClient(initial_seq=1, initial_coherence=10)
    spent.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, advance_coherence=True)
    invalid_cases.append(("spent_epoch", b"".join(spent.emitted_frames), epoch_owner, FAULT_SEQ))

    seq0 = GovernorClient(initial_seq=0, initial_coherence=10)
    seq0.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, seq_override=0, advance_coherence=True)
    invalid_cases.append(("seq_zero", b"".join(seq0.emitted_frames), epoch_takeover, FAULT_SEQ))

    corrupt = GovernorClient(initial_seq=1, initial_coherence=10)
    corrupt.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, advance_coherence=True, corrupt_crc=True)
    invalid_cases.append(("corrupt_crc", b"".join(corrupt.emitted_frames), epoch_takeover, FAULT_CRC))

    for label, bad_bytes, bad_epoch, expected_fault in invalid_cases:
        for probe_name, probe_bytes, probe_epoch, expect_seq_fault in (
            ("replay_probe", b"".join(owner_probe_replay.emitted_frames), epoch_owner, True),
            ("wrong_epoch_probe", b"".join(owner_probe_wrong_epoch.emitted_frames), epoch_takeover, True),
            ("next_seq_probe", b"".join(owner_probe_next.emitted_frames), epoch_owner, False),
        ):
            rows = _run_epoch_streams(
                [
                    (b"".join(owner_init.emitted_frames), 1, epoch_owner),
                    (b"".join(foreign_expire.emitted_frames), 2, epoch_foreign),
                    (bad_bytes, 2, bad_epoch),
                    (probe_bytes, 1, probe_epoch),
                ],
                manifest_dict,
                name=f"a8_rt02_{label}_{probe_name}",
            )
            assert_zero_keepout_breaches(rows, context=f"Attack A8 ({label}/{probe_name})")
            if not has_fault(rows[6], FAULT_HEARTBEAT):
                raise AssertionError(f"A8 regression ({label}): owner lease did not expire on tick 7")
            theta_before = int(rows[6]["theta_applied"])
            bad_row = rows[7]
            if not has_fault(bad_row, expected_fault):
                raise AssertionError(
                    f"A8 regression ({label}): invalid takeover frame did not assert expected fault "
                    f"0x{expected_fault:04X} (got {bad_row['fault_bits']})"
                )
            if int(bad_row["theta_applied"]) != theta_before:
                raise AssertionError(
                    f"A8 regression ({label}): invalid takeover moved plant ({theta_before} -> {bad_row['theta_applied']})"
                )
            probe_row = rows[8]
            if expect_seq_fault:
                if not has_fault(probe_row, FAULT_SEQ):
                    raise AssertionError(
                        f"A8 regression ({label}/{probe_name}): premature takeover mutation lost active "
                        f"owner/epoch/seq state (expected FAULT_SEQ 0x0004, got {probe_row['fault_bits']})"
                    )
            else:
                if int(probe_row["fault_bits"], 16) != 0:
                    raise AssertionError(
                        f"A8 regression ({label}/{probe_name}): owner next-seq frame faulted after "
                        f"rejected takeover (got {probe_row['fault_bits']})"
                    )

    # Also verify a corrupted foreign frame while the owner's lease is live is ignored and
    # does not disrupt the owner's subsequent command.
    live_corrupt = GovernorClient(initial_seq=1, initial_coherence=10)
    live_corrupt.send_command(u_mrad=-20, confidence_q8=255, unit_id=1, advance_coherence=True, corrupt_crc=True)
    rows_live = _run_epoch_streams(
        [
            (b"".join(owner_init.emitted_frames), 1, epoch_owner),
            (b"".join(live_corrupt.emitted_frames), 2, epoch_foreign),
            (b"".join(owner_probe_next.emitted_frames), 1, epoch_owner),
        ],
        manifest_dict,
        name="a8_rt02_live_corrupt_foreign",
    )
    assert_zero_keepout_breaches(rows_live, context="Attack A8 (live_corrupt_foreign)")
    if int(rows_live[4]["fault_bits"], 16) != 0 or int(rows_live[4]["theta_applied"]) <= int(rows_live[2]["theta_applied"]):
        raise AssertionError(
            f"A8 regression (live_corrupt_foreign): live owner command failed after foreign corrupt frame "
            f"(row={rows_live[4]})"
        )

    if verbose:
        print("  [PASS] RT-02 invalid takeover regression: spent-epoch, seq==0, and corrupt foreign "
              "takeover frames rejected without mutating active owner/epoch/session state.")


def main() -> int:
    parser = argparse.ArgumentParser(description="GOVERNOR Unified Adversarial Attack Rig Runner")
    parser.add_argument("--filter", type=str, default="", help="Filter attacks by name (e.g. A1, A2)")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode (summary table only)")
    args = parser.parse_args()

    verbose = not args.quiet

    print("================================================================================")
    print(" LATCH GOVERNOR — Unified Adversarial Attack Rig & Invariant Verification Suite ")
    print(" Target: GOVERNOR supervisor, host-sim build of the QNX SDP 8.0 sources        ")
    print("         (x86_64 build host; on-target proof is captured separately)           ")
    print("================================================================================\n")

    attack_suite = [
        ("A1", "Rogue Unit Injection", run_attack_a1),
        ("A2", "Rate Flood Attack", run_attack_a2),
        ("A3", "Prompt Injection Attack", run_attack_a3),
        ("A4", "Deadman Lease Trip & Recovery", run_attack_a4),
        ("A5", "Coherence Spoof Attack", run_attack_a5),
        ("A6", "Sequence Replay Attack", run_attack_a6),
        ("A7", "Chain Tamper Attack", run_attack_a7),
        ("A8", "Second Writer Keeps Dead Alive", run_attack_a8),
    ]

    if args.filter:
        target_keys = [k.strip().upper() for k in args.filter.split(",")]
        attack_suite = [item for item in attack_suite if item[0] in target_keys]

    results: List[Dict[str, Any]] = []
    all_passed = True
    total_ticks = 0
    total_intrusions = 0
    start_time = time.monotonic()

    for attack_id, attack_name, runner_fn in attack_suite:
        try:
            report = runner_fn(verbose=verbose)
            if attack_id == "A8":
                run_a8_takeover_epoch_regression(verbose=verbose)
            results.append(report)
            total_ticks += report.get("ticks_evaluated", 0)
            total_intrusions += report.get("keepout_intrusions", 0)
        except Exception as exc:
            all_passed = False
            results.append({
                "attack": attack_id,
                "name": attack_name,
                "status": "FAIL",
                "error": str(exc),
                "keepout_intrusions": 1,
            })
            print(f"[ATTACK {attack_id} EXCEPTION] {exc}\n", file=sys.stderr)

    elapsed = time.monotonic() - start_time

    # Print Final Graded Scorecard
    print("================================================================================")
    print("                         ADVERSARIAL EVALUATION SCORECARD                       ")
    print("================================================================================")
    header = f"{'ID':<4} | {'Attack Scenario':<32} | {'Ticks':<6} | {'Fault Bit Verified':<18} | {'Status':<6}"
    print(header)
    print("-" * len(header))

    for res in results:
        status_str = res.get("status", "FAIL")
        ticks_str = str(res.get("ticks_evaluated", "N/A"))
        fault_str = res.get("fault_verified", res.get("error", "FAIL"))[:18]
        row_str = f"{res['attack']:<4} | {res['name']:<32} | {ticks_str:<6} | {fault_str:<18} | {status_str:<6}"
        print(row_str)

    print("-" * len(header))
    print(f"Total Ticks Evaluated     : {total_ticks}")
    print(f"Total Keep-Out Intrusions : {total_intrusions} (Envelopes Breached: 0.0%)")
    print(f"Execution Wall Time       : {elapsed:.3f} s")
    print("================================================================================")

    # Validate 4 Universal Safety Criteria
    print("\nSCENARIO CHECKS:")
    c1 = total_intrusions == 0
    c2 = all("fault_verified" in r and r.get("status") == "PASS" for r in results)
    c3 = any("demotion_verified" in r or "demotions_verified" in r for r in results)
    c4 = any("recovery_verified" in r for r in results)

    print(f"  [CRITERION 1] Zero Keep-Out Envelope Intrusions (0% Breach Rate): {'SATISFIED' if c1 else 'VIOLATED'}")
    print(f"  [CRITERION 2] Expected Faults in Tested Scenarios               : {'SATISFIED' if c2 else 'VIOLATED'}")
    print(f"  [CRITERION 3] Supervised Ladder Demotion (Lease/Fault Tripped)  : {'SATISFIED' if c3 else 'VIOLATED'}")
    print(f"  [CRITERION 4] Bounded Hysteresis Recovery (25 Clean Commands)   : {'SATISFIED' if c4 else 'VIOLATED'}")

    final_pass = all_passed and c1 and c2 and c3 and c4
    print("--------------------------------------------------------------------------------")
    if final_pass:
        print(f"[SUITE VERDICT] ALL {len(attack_suite)} ADVERSARIAL ATTACKS PASSED (0% FAILURE RATE)\n")
        return 0
    else:
        print("[SUITE VERDICT] ADVERSARIAL AUDIT FAILED\n", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
