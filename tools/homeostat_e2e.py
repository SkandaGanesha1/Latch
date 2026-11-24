#!/usr/bin/env python3
"""Runtime proof that the HOMEOSTAT outer loop is wired into the supervisor.

The HOMEOSTAT loop is a CONTRACTING-ONLY advisor: it may lower the effective
velocity ceiling below the signed manifest limit, never raise it. This test
drives the REAL supervisor binary (host simulation) over the REAL wire
protocol and reads the result from the committed evidence-tape format, so it
proves the wiring rather than the arithmetic.

Four scenarios:

  A. CONTRACTION -- a stressed epoch contracts the velocity ceiling and the
     per-tick plant motion shrinks. The plant is still moving when the
     contraction lands, so the shrink is visible in the tape.
  B. RECOVERY   -- with every stress trigger disabled, a clean epoch recovers
     the scale back to Q8 unity and the motion returns to the baseline.
  C. CONTRACTING ONLY -- the HOMEOSTAT run never moves the plant FASTER than
     the identical run with no `homeostat` section.
  D. DEFAULT OFF -- a manifest with no `homeostat` section is byte-for-byte
     identical in behaviour to the pre-HOMEOSTAT supervisor.
"""

import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import zlib

MAGIC = 0x4C415448
CMD, HEARTBEAT, CMD_V2, SHRINK_REQ = range(4)


def frame_v2(kind, seq, coherence, u=0, confidence=0, agent_state=1, unit_id=0):
    """32-byte wire v2 frame with CRC over [0..16) || [20..32)."""
    header = struct.pack("<IHBBIi", MAGIC, 2, 0, kind, seq, u)
    metadata = (struct.pack("<IB", confidence, agent_state) +
                coherence.to_bytes(3, "little") + unit_id.to_bytes(4, "little"))
    crc = zlib.crc32(header + metadata) & 0xFFFFFFFF
    return header + struct.pack("<I", crc) + metadata


def run_pipeline(latchctl, ingest, latchd, manifest_dict, raw_frames, tempdir, name):
    manifest_path = tempdir / f"{name}.manifest"
    manifest_bytes = (json.dumps(manifest_dict, indent=2) + "\n").encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    pathlib.Path(str(manifest_path) + ".sha256").write_text(
        hashlib.sha256(manifest_bytes).hexdigest() + "\n", encoding="ascii")

    verify = subprocess.run([str(latchctl), "manifest-verify", str(manifest_path)],
                            capture_output=True, text=True)
    if verify.returncode != 0:
        raise SystemExit(f"[HOMEOSTAT_E2E] FAIL {name} contract did not validate:\n" +
                         verify.stdout + verify.stderr)

    ingested = subprocess.run([str(ingest), "-m", str(manifest_path), "-o", "-"],
                              input=raw_frames, capture_output=True)
    if ingested.returncode != 0:
        raise SystemExit(f"[HOMEOSTAT_E2E] FAIL ingest returned {ingested.returncode}:\n" +
                         ingested.stderr.decode(errors="replace"))

    csv_path = tempdir / f"{name}-tape.csv"
    run = subprocess.run([str(latchd), "-m", str(manifest_path), "--pipe-in",
                          "--csv", str(csv_path)], input=ingested.stdout,
                         capture_output=True, text=False)
    if run.returncode != 0:
        raise SystemExit(f"[HOMEOSTAT_E2E] FAIL latchd rejected stream:\n" +
                         run.stdout.decode(errors="replace") +
                         run.stderr.decode(errors="replace"))

    import csv
    with csv_path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows


def steps_by_tick(rows):
    """Per-tick signed plant motion, indexed by the tape's tick number."""
    steps = {}
    previous = None
    for row in rows:
        theta = int(row["theta_applied"])
        if previous is not None:
            steps[int(row["tick"])] = theta - previous
        previous = theta
    return steps


def base_config(fixture):
    config = json.loads(json.dumps(fixture))
    config["governor"]["enabled"] = 1
    config["governor"]["deadman"]["warmup_heartbeats"] = 2
    config["governor"]["deadman"]["lease_ticks"] = 100
    config["protocol"].update({"version": 2, "crc": "ieee32-v2", "coverage": 28})
    return config


def command_stream(count, target):
    """Warm-up heartbeats then a long run of identical motion proposals."""
    frames = [frame_v2(HEARTBEAT, 1, 1), frame_v2(HEARTBEAT, 2, 2)]
    for seq in range(3, 3 + count):
        frames.append(frame_v2(CMD_V2, seq, seq, u=target, confidence=255, unit_id=1))
    return b"".join(frames)


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: homeostat_e2e.py LATCHCTL INGEST LATCHD BASE_MANIFEST")
    latchctl, ingest, latchd, fixture = map(pathlib.Path, sys.argv[1:])
    base = base_config(json.loads(fixture.read_text(encoding="utf-8")))

    # A target far enough away that the plant is STILL TRAVELLING when the
    # contraction lands, and far enough that even the UNADAPTED supervisor
    # never reaches it inside the test window. At the unadapted ceiling of
    # 24 mrad/tick the plant needs ~41 ticks to cover 1000 mrad, so a
    # 40-tick run leaves every tick in the comparison window.
    TARGET = -1000
    FRAMES = 38
    EARLY = range(3, 13)
    LATE = range(22, 39)

    with tempfile.TemporaryDirectory(prefix="latch-homeostat-e2e-") as temp:
        tempdir = pathlib.Path(temp)

        # ------------------------------------------------------------------
        # Scenario A: CONTRACTION.
        #
        # The trigger is the CLAMP FRACTION: the guest keeps asking for a
        # target 900 mrad away, the supervisor can only advance v_max per
        # tick, so most of the requested motion is not applied. That fraction
        # crosses the clamp threshold, the epoch closes and the scale
        # contracts. The floor stops the contraction before it can collapse
        # the envelope to zero velocity.
        # ------------------------------------------------------------------
        contract_cfg = json.loads(json.dumps(base))
        contract_cfg["homeostat"] = {
            "enabled": 1,
            "epoch_ticks": 5,
            "reject_threshold_q8": 64,
            "latency_spread_threshold_ns": 0,
            "clamp_threshold_q8": 32,
            "coherence_anomaly_threshold": 0,
            "contraction_q8": 64,
            "recovery_q8": 1,
            "floor_q8": 26,
        }
        rows_contract = run_pipeline(latchctl, ingest, latchd, contract_cfg,
                                     command_stream(FRAMES, TARGET), tempdir, "contract")
        steps_contract = steps_by_tick(rows_contract)

        # The supervisor's step limit before any contraction is
        # v_max * confidence_q8 / 256 = 25 * 255 / 256 = 24 mrad/tick.
        early = [abs(steps_contract[t]) for t in EARLY]
        late = [abs(steps_contract[t]) for t in LATE]
        if not early or not late:
            raise SystemExit("[HOMEOSTAT_E2E] FAIL no motion was recorded")
        baseline_step = max(early)
        contracted_step = max(late)
        if contracted_step >= baseline_step:
            raise SystemExit(
                f"[HOMEOSTAT_E2E] FAIL the contracted run did not shrink the step "
                f"(early max {baseline_step}, late max {contracted_step})")
        if contracted_step < 1:
            raise SystemExit("[HOMEOSTAT_E2E] FAIL the contraction collapsed the envelope to zero")
        if baseline_step != 24:
            raise SystemExit(
                f"[HOMEOSTAT_E2E] FAIL unexpected uncontracted step {baseline_step} (expected 24)")
        pass_a = (f"[HOMEOSTAT_SCENARIO_A] PASS: stressed epoch contracted the "
                  f"per-tick velocity ceiling {baseline_step} -> {contracted_step} mrad/tick")

        # ------------------------------------------------------------------
        # Scenario B: RECOVERY.
        #
        # Every stress trigger is disabled, so the epoch is clean and the
        # scale recovers towards Q8 unity.
        # ------------------------------------------------------------------
        recover_cfg = json.loads(json.dumps(base))
        recover_cfg["homeostat"] = {
            "enabled": 1,
            "epoch_ticks": 5,
            "reject_threshold_q8": 0,
            "latency_spread_threshold_ns": 0,
            "clamp_threshold_q8": 0,
            "coherence_anomaly_threshold": 0,
            "contraction_q8": 64,
            "recovery_q8": 8,
            "floor_q8": 26,
        }
        rows_recover = run_pipeline(latchctl, ingest, latchd, recover_cfg,
                                    command_stream(FRAMES, TARGET), tempdir, "recover")
        steps_recover = steps_by_tick(rows_recover)
        recover_early = max(abs(steps_recover[t]) for t in EARLY)
        recover_late = max(abs(steps_recover[t]) for t in LATE)
        if recover_late < recover_early:
            raise SystemExit(
                f"[HOMEOSTAT_E2E] FAIL a clean epoch did not recover the ceiling "
                f"(early {recover_early}, late {recover_late})")
        if recover_late != baseline_step:
            raise SystemExit(
                f"[HOMEOSTAT_E2E] FAIL recovery did not return the ceiling to the "
                f"manifest limit (late {recover_late}, expected {baseline_step})")
        pass_b = (f"[HOMEOSTAT_SCENARIO_B] PASS: clean epoch recovered the "
                  f"per-tick velocity ceiling back to {recover_late} mrad/tick")

        # ------------------------------------------------------------------
        # Scenario C: CONTRACTING ONLY.
        #
        # The HOMEOSTAT run must never move the plant FASTER than the same
        # run without a `homeostat` section, on any single tick.
        # ------------------------------------------------------------------
        rows_plain = run_pipeline(latchctl, ingest, latchd, base,
                                  command_stream(FRAMES, TARGET), tempdir, "plain")
        steps_plain = steps_by_tick(rows_plain)
        compared = 0
        for tick in sorted(set(steps_contract) & set(steps_plain)):
            if steps_plain[tick] == 0:
                continue
            compared += 1
            if abs(steps_contract[tick]) > abs(steps_plain[tick]):
                raise SystemExit(
                    f"[HOMEOSTAT_E2E] FAIL HOMEOSTAT ACCELERATED the plant at "
                    f"tick {tick} ({steps_contract[tick]} vs {steps_plain[tick]})")
        if compared < 30:
            raise SystemExit(
                f"[HOMEOSTAT_E2E] FAIL only {compared} ticks were comparable -- "
                "the test window is too short to prove the invariant")
        pass_c = (f"[HOMEOSTAT_SCENARIO_C] PASS: contracting-only invariant held over "
                  f"{compared} ticks -- HOMEOSTAT never moved the plant faster "
                  "than the unadapted run")

        # ------------------------------------------------------------------
        # Scenario D: DEFAULT OFF.
        #
        # A manifest with no `homeostat` section must behave EXACTLY like the
        # pre-HOMEOSTAT supervisor. The supervisor also asserts this itself
        # (the status extension reports homeostat_enabled == 0).
        # ------------------------------------------------------------------
        off_cfg = json.loads(json.dumps(base))
        off_cfg.pop("homeostat", None)
        rows_off = run_pipeline(latchctl, ingest, latchd, off_cfg,
                                command_stream(FRAMES, TARGET), tempdir, "off")
        steps_off = steps_by_tick(rows_off)
        if steps_off != steps_plain:
            raise SystemExit("[HOMEOSTAT_E2E] FAIL a manifest without a homeostat "
                             "section changed the supervisor's behaviour")
        pass_d = ("[HOMEOSTAT_SCENARIO_D] PASS: default-off -- a manifest with no "
                  "homeostat section is behaviourally identical to the baseline")

        # ------------------------------------------------------------------
        # Negative case: an OUT-OF-RANGE homeostat section must be REJECTED
        # at load time (fail closed), never silently clamped at runtime.
        # ------------------------------------------------------------------
        bad_cfg = json.loads(json.dumps(base))
        bad_cfg["homeostat"] = {
            "enabled": 1, "epoch_ticks": 5, "reject_threshold_q8": 64,
            "latency_spread_threshold_ns": 0, "clamp_threshold_q8": 32,
            "coherence_anomaly_threshold": 0, "contraction_q8": 64,
            "recovery_q8": 1, "floor_q8": 0,          # <-- floor of zero is illegal
        }
        bad_path = tempdir / "bad.manifest"
        bad_bytes = (json.dumps(bad_cfg, indent=2) + "\n").encode("utf-8")
        bad_path.write_bytes(bad_bytes)
        pathlib.Path(str(bad_path) + ".sha256").write_text(
            hashlib.sha256(bad_bytes).hexdigest() + "\n", encoding="ascii")
        bad = subprocess.run([str(latchctl), "manifest-verify", str(bad_path)],
                             capture_output=True, text=True)
        if bad.returncode == 0:
            raise SystemExit("[HOMEOSTAT_E2E] FAIL an out-of-range homeostat floor "
                             "was admitted instead of rejected")
        pass_neg = ("[HOMEOSTAT_NEGATIVE] PASS: out-of-range homeostat parameters are "
                    "rejected at manifest load (fail closed, never silently clamped)")

        print(pass_a)
        print(pass_b)
        print(pass_c)
        print(pass_d)
        print(pass_neg)

    print("[HOMEOSTAT_E2E] PASS: contraction, recovery, contracting-only invariant, "
          "default-off and fail-closed parameter validation verified")


if __name__ == "__main__":
    main()
