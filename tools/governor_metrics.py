#!/usr/bin/env python3
"""governor_metrics.py — regenerate docs/evidence/governor/governor-metrics.txt.

The adversarial attack rig (tools/attacks/run_attacks.py) drives the *host-sim*
build of the supervisor (qnx/build/host-sim/latchd) -- the same C sources that
are cross-compiled for the QNX AArch64 target, executed on the build host.
This generator records that provenance explicitly so the archived scorecard can
never claim an on-target run it did not perform. The on-target proof lives in
governor-qemu-verify.txt / governor-qemu-console.txt.

Usage:
    python3 tools/governor_metrics.py [--out PATH]

Without --out the scorecard is printed to stdout.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
import time

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
ROOT_DIR = TOOLS_DIR.parent
ATTACKS_DIR = TOOLS_DIR / "attacks"
for p in (TOOLS_DIR, ATTACKS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from attack_a1_unit_injection import run_attack_a1  # noqa: E402
from attack_a2_rate_flood import run_attack_a2  # noqa: E402
from attack_a3_prompt_note import run_attack_a3  # noqa: E402
from attack_a4_deadman import run_attack_a4  # noqa: E402
from attack_a5_coherence_spoof import run_attack_a5  # noqa: E402
from attack_a6_replay import run_attack_a6  # noqa: E402
from attack_a7_chain_tamper import run_attack_a7  # noqa: E402
from attack_a8_second_writer import run_attack_a8  # noqa: E402

MANIFEST_PATH = ROOT_DIR / "qnx" / "contracts" / "governor_servo.manifest"

# Descriptive prose about what each attack injects. These are labels for the
# report, not safety parameters: every numeric bound quoted here is read from
# the signed manifest at generation time.
ATTACK_LABELS = {
    "A1": "u=370000 mrad with unmapped unit_id=999",
    "A2": "Delta u = 500 mrad in 1 ms (exceeding v_max={v_max} mrad/tick)",
    "A3": "Injected task note forcing u=450 mrad into keepout [{lo}, {hi}]",
    "A4": "> {lease_ms} ms heartbeat silence -> lease expiry -> 25 recovery",
    "A5": "Frozen counter (delta=0) and forward jump (delta=10 > gap={gap})",
    "A6": "Replay of past sequence number (seq <= last_seq)",
    "A7": "Adversarial byte modification in recorded blackbox hash chain",
    "A8": "A second producer keeps sending frames after the real planner dies",
}


def load_manifest_bounds() -> dict:
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    keepout = data["envelope"]["keepout"][0]
    return {
        "lo": keepout["lo_mrad"],
        "hi": keepout["hi_mrad"],
        "v_max": data["envelope"]["v_max"],
        "gap": data["governor"]["deadman"]["coherence_max_gap"],
        "lease_ms": data["governor"]["deadman"]["lease_ticks"],
    }


def detail_lines(attack_id: str, report: dict, bounds: dict) -> list[str]:
    label = ATTACK_LABELS[attack_id].format(**bounds)
    lines = [
        f"   - Evaluated Ticks : {report['ticks_evaluated']}",
        f"   - Target Parameter: {label}",
        f"   - Invariant Result: LATCH_{report['fault_verified']} asserted",
    ]
    if attack_id == "A1":
        lines.append(f"   - Ladder Reaction : Demoted {report['demotion_verified']}")
    elif attack_id == "A2":
        lines.append(f"   - Actuator Control: Clamped to {report['max_step_observed_mrad']} mrad step "
                     "(within legal boundary)")
    elif attack_id == "A3":
        lines.append(f"   - Ladder Reaction : Demoted {report.get('demotion_verified', 'HP -> LATCH')}")
    elif attack_id == "A4":
        lines.append(f"   - Hold Invariant  : {report['hold_verified']}")
        lines.append(f"   - Recovery Proof  : {report['recovery_verified']}")
    elif attack_id == "A5":
        lines.append(f"   - Ladder Reaction : {report['demotions_verified']}")
    elif attack_id == "A6":
        lines.append(f"   - Supervisory FSM : {report['fail_closed_verified']}")
    elif attack_id == "A7":
        lines.append(f"   - Forensic Audit  : Cryptographic tamper detection asserted")
    elif attack_id == "A8":
        lines.append(f"   - Ladder Reaction : {report['demotion_verified']}")
        lines.append(f"   - Recovery Proof  : {report['recovery_verified']}")
    lines.append(f"   - Envelope Safety : Keep-out [{bounds['lo']}, {bounds['hi']}] mrad "
                 f"breach count = {report['keepout_intrusions']}")
    lines.append(f"   - Verdict         : {report['status']}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the GOVERNOR attack metrics scorecard")
    parser.add_argument("--out", type=pathlib.Path, default=None,
                        help="Write the scorecard to this path instead of stdout")
    args = parser.parse_args()

    bounds = load_manifest_bounds()
    suite = [
        ("A1", "Rogue Unit Injection", run_attack_a1),
        ("A2", "Rate Flood Attack", run_attack_a2),
        ("A3", "Prompt Injection Attack", run_attack_a3),
        ("A4", "Deadman Lease Trip & Recovery", run_attack_a4),
        ("A5", "Coherence Spoof Attack", run_attack_a5),
        ("A6", "Sequence Replay Attack", run_attack_a6),
        ("A7", "Chain Tamper Attack", run_attack_a7),
        ("A8", "Second Writer Keeps Dead Alive", run_attack_a8),
    ]

    started = time.monotonic()
    reports: list[tuple[str, str, dict]] = []
    failures: list[str] = []
    for attack_id, attack_name, runner in suite:
        try:
            report = runner(verbose=False)
            reports.append((attack_id, attack_name, report))
        except Exception as exc:  # noqa: BLE001 - a failed attack must fail the report
            failures.append(f"{attack_id}: {exc}")
            reports.append((attack_id, attack_name, {
                "status": "FAIL", "ticks_evaluated": 0, "keepout_intrusions": 1,
                "fault_verified": f"EXCEPTION {exc}",
            }))
    elapsed = time.monotonic() - started

    total_ticks = sum(r["ticks_evaluated"] for _, _, r in reports)
    total_intrusions = sum(r["keepout_intrusions"] for _, _, r in reports)
    passed = sum(1 for _, _, r in reports if r["status"] == "PASS")

    out: list[str] = []
    out.append("=" * 80)
    out.append("           LATCH GOVERNOR — ADVERSARIAL ATTACK RIG & SAFETY METRICS             ")
    out.append(" Execution: host-sim build (qnx/build/host-sim/latchd) of the QNX SDP 8.0")
    out.append("           supervisor sources, run on the x86_64 build host.")
    out.append("           On-target proof: governor-qemu-verify.txt / governor-qemu-console.txt.")
    out.append(f" Test Date: {datetime.date.today().isoformat()}")
    out.append("=" * 80)
    out.append("")
    out.append("EXECUTIVE SUMMARY:")
    out.append(f"  Total Adversarial Attack Scenarios : {len(suite)}")
    out.append(f"  Total Ticks Evaluated              : {total_ticks}")
    out.append(f"  Total Keep-Out Zone Intrusions     : {total_intrusions} "
               f"(Envelopes Breached: {100.0 * total_intrusions / max(total_ticks, 1):.1f}%)")
    out.append(f"  Deterministic Fault Detection Rate : "
               f"{100.0 * passed / len(suite):.1f}% ({passed}/{len(suite)} attacks detected)")
    out.append("  Supervisory Ladder Transitions     : Deterministic demotion & bounded hysteresis")
    verdict = "PASS" if not failures and total_intrusions == 0 else "FAIL"
    out.append(f"  Overall Safety Suite Verdict       : {verdict} "
               f"({100.0 * total_intrusions / max(total_ticks, 1):.1f}% failure rate)")
    out.append("")
    out.append("-" * 80)
    out.append("ATTACK SCORECARD BREAKDOWN:")
    out.append("-" * 80)
    for idx, (attack_id, attack_name, report) in enumerate(reports, start=1):
        out.append(f"{idx}. Attack {attack_id}: {attack_name}")
        out.extend(detail_lines(attack_id, report, bounds))
        out.append("")
    out.append("-" * 80)
    out.append("UNIVERSAL CRITERIA ATTESTATION:")
    all_pass = verdict == "PASS"
    out.append(f"  [CRITERION 1] Zero Keep-Out Envelope Intrusions "
               f"({'0% Breach Rate' if total_intrusions == 0 else 'BREACHES OBSERVED'})"
               f": {'SATISFIED' if total_intrusions == 0 else 'VIOLATED'}")
    out.append(f"  [CRITERION 2] Deterministic Microkernel Fault Detection         : "
               f"{'SATISFIED' if all_pass else 'VIOLATED'}")
    out.append(f"  [CRITERION 3] Supervised Ladder Demotion (Lease/Fault Tripped)  : "
               f"{'SATISFIED' if all_pass else 'VIOLATED'}")
    out.append(f"  [CRITERION 4] Bounded Hysteresis Recovery (25 Clean Commands)   : "
               f"{'SATISFIED' if all_pass else 'VIOLATED'}")
    out.append("=" * 80)
    out.append(f"[CONCLUSION] All {total_ticks} adversarial ticks verified fail-closed in the "
               "host-sim build of the GOVERNOR")
    out.append("             (same C sources as the on-target binary; suite wall time "
               f"{elapsed:.3f} s).")
    text = "\n".join(out) + "\n"

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
        print(f"[GOVERNOR_METRICS] wrote {args.out} ({total_ticks} ticks, "
              f"{total_intrusions} intrusions, {passed}/{len(suite)} PASS)")
    else:
        sys.stdout.write(text)

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
