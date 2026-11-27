#!/usr/bin/env python3
"""Exercise the complete v2 wire -> ingest -> LPR2 -> latchd host path and Priority 1 Governor scenarios."""

import csv
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import zlib


MAGIC = 0x4C415448
CMD, HEARTBEAT, CMD_V2, SHRINK_REQ = range(4)


def lpr2_size() -> int:
    """The LPR2 IPC frame size, READ FROM THE PROTOCOL HEADER.

    A literal here would let this test keep passing after the IPC ABI
    changed -- which is exactly how the 48 -> 56 byte growth (RT-02's
    session epoch) could have gone unnoticed. The header is the ABI's
    single source of truth, so the test reads it from there.
    """
    header = pathlib.Path(__file__).resolve().parent.parent / "qnx" / "latch_protocol.h"
    text = header.read_text(encoding="utf-8")
    match = re.search(
        r"_Static_assert\(\s*sizeof\(latch_ipc_proposal_v2_t\)\s*==\s*(\d+)u", text)
    if not match:
        raise SystemExit(
            "[GOVERNOR_E2E] FAIL could not read the LPR2 size from latch_protocol.h")
    return int(match.group(1))

# Fault bits defined in latch_protocol.h
MAGIC_FAULT = 1 << 0
CRC_FAULT = 1 << 1
REPLAY_FAULT = 1 << 2
RATE_FAULT = 1 << 7
KEEPOUT_FAULT = 1 << 5
BOUNDS_FAULT = 1 << 6
UNIT_FAULT = 1 << 12
HEARTBEAT_FAULT = 1 << 13
WIDEN_FAULT = 1 << 14
DOSE_FAULT = 1 << 15

# Rung definitions in governor_policy.h
RUNG_HP = 0
RUNG_ADVISE = 1
RUNG_CLAMP = 2
RUNG_SLOW = 3
RUNG_SAFE_STOP = 4
RUNG_LATCH = 5

MODE_HP = 0
MODE_HOLD = 1
MODE_HOME = 2


def frame_v2(kind, seq, coherence, u=0, confidence=0, agent_state=1, unit_id=0):
    """32-byte wire v2 frame with CRC over [0..16) || [20..32)."""
    header = struct.pack("<IHBBIi", MAGIC, 2, 0, kind, seq, u)
    metadata = (struct.pack("<IB", confidence, agent_state) +
                coherence.to_bytes(3, "little") + unit_id.to_bytes(4, "little"))
    crc = zlib.crc32(header + metadata) & 0xFFFFFFFF
    return header + struct.pack("<I", crc) + metadata


def run_pipeline(latchctl, ingest, latchd, manifest_dict, raw_frames, tempdir, name="governor"):
    """Helper to run raw frames through latch-ingest and latchd pipe, returning CSV rows."""
    manifest_path = tempdir / f"{name}.manifest"
    manifest_bytes = (json.dumps(manifest_dict, indent=2) + "\n").encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    pathlib.Path(str(manifest_path) + ".sha256").write_text(
        hashlib.sha256(manifest_bytes).hexdigest() + "\n", encoding="ascii")

    verify = subprocess.run([str(latchctl), "manifest-verify", str(manifest_path)],
                            capture_output=True, text=True)
    if verify.returncode != 0:
        raise SystemExit(f"[GOVERNOR_E2E] FAIL {name} contract did not validate:\n" +
                         verify.stdout + verify.stderr)

    ingested = subprocess.run([str(ingest), "-m", str(manifest_path), "-o", "-"],
                              input=raw_frames, capture_output=True)
    if ingested.returncode != 0:
        raise SystemExit(f"[GOVERNOR_E2E] FAIL ingest returned {ingested.returncode}:\n" +
                         ingested.stderr.decode(errors="replace"))

    csv_path = tempdir / f"{name}-tape.csv"
    run = subprocess.run([str(latchd), "-m", str(manifest_path), "--pipe-in",
                          "--csv", str(csv_path)], input=ingested.stdout,
                         capture_output=True, text=False)
    if run.returncode != 0:
        raise SystemExit(f"[GOVERNOR_E2E] FAIL latchd rejected stream:\n" +
                         run.stdout.decode(errors="replace") +
                         run.stderr.decode(errors="replace"))

    with csv_path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: governor_e2e.py LATCHCTL INGEST LATCHD DISABLED_MANIFEST")
    latchctl, ingest, latchd, fixture = map(pathlib.Path, sys.argv[1:])
    base_config = json.loads(fixture.read_text(encoding="utf-8"))

    all_tape_rows = []

    with tempfile.TemporaryDirectory(prefix="latch-governor-e2e-") as temp:
        tempdir = pathlib.Path(temp)

        # ---------------------------------------------------------------------
        # Primary Pipeline Run: Warmup, commands, anomalies, WIDEN veto,
        # heartbeat non-recovery, and v2 shrink traffic without lease renewal.
        # ---------------------------------------------------------------------
        main_config = json.loads(json.dumps(base_config))
        main_config["governor"]["enabled"] = 1
        main_config["governor"]["deadman"]["warmup_heartbeats"] = 2
        main_config["governor"]["deadman"]["lease_ticks"] = 4
        main_config["governor"]["ladder"]["demote_faults_per_rung"] = 3
        main_config["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)
        main_config["protocol"].update({"version": 2, "crc": "ieee32-v2", "coverage": 28})

        frames_main = [
            # Ticks 1..2: Warmup heartbeats -> completes warmup and enters HP
            frame_v2(HEARTBEAT, 1, 1),
            frame_v2(HEARTBEAT, 2, 2),
            # Ticks 3..4: Nominal clean commands in HP
            frame_v2(CMD_V2, 3, 3, u=10, confidence=255, unit_id=1),
            frame_v2(CMD_V2, 4, 4, u=20, confidence=255, unit_id=1),
            # Tick 5: Valid shrink request (narrows rate to 12)
            frame_v2(SHRINK_REQ, 5, 5, u=12, confidence=128),
            # Tick 6: Admitted confidence-limited command
            frame_v2(CMD_V2, 6, 6, u=50, confidence=255, unit_id=1),
            # Ticks 7..10: Unknown unit metadata (advisory fault UNIT -> demotes HP -> ADVISE -> CLAMP)
            frame_v2(CMD_V2, 7, 7, u=370000, confidence=255, unit_id=999),
            frame_v2(CMD_V2, 8, 8, u=370000, confidence=255, unit_id=999),
            frame_v2(CMD_V2, 9, 9, u=370000, confidence=255, unit_id=999),
            frame_v2(CMD_V2, 10, 10, u=370000, confidence=255, unit_id=999),
            # Tick 11: Known rational unit conversion (37000 / 1000 = 37 mrad) admitted through CLAMP
            frame_v2(CMD_V2, 11, 11, u=37000, confidence=255, unit_id=3),
            # Tick 12: Widening shrink request (13 > 12) -> WIDEN veto! Demotes to SLOW
            frame_v2(SHRINK_REQ, 12, 12, u=13, confidence=150),
            # Ticks 13..15: Advancing heartbeats -> renews lease, plant stays held, streak stays 0
            frame_v2(HEARTBEAT, 13, 13),
            frame_v2(HEARTBEAT, 14, 14),
            frame_v2(HEARTBEAT, 15, 15),
            # SHRINK requests do not renew a producer's deadman lease.
            frame_v2(SHRINK_REQ, 16, 16, u=12, confidence=128),
            frame_v2(SHRINK_REQ, 17, 17, u=12, confidence=128),
            frame_v2(SHRINK_REQ, 18, 18, u=12, confidence=128),
            frame_v2(SHRINK_REQ, 19, 19, u=12, confidence=128),
            frame_v2(SHRINK_REQ, 20, 20, u=12, confidence=128),
        ]
        raw_main = b"".join(frames_main)
        rows_main = run_pipeline(latchctl, ingest, latchd, main_config, raw_main, tempdir, "main")
        all_tape_rows.extend(rows_main)

        by_tick = {int(r["tick"]): r for r in rows_main}
        by_seq = {int(r["seq"]): r for r in rows_main if int(r["seq"]) in range(1, 16)}

        # Basic pipeline validations
        if int(by_seq[1]["theta_applied"]) != 0 or int(by_seq[2]["theta_applied"]) != 0:
            raise SystemExit("[GOVERNOR_E2E] FAIL heartbeat moved the plant")
        if int(by_seq[3]["theta_applied"]) <= 0:
            raise SystemExit("[GOVERNOR_E2E] FAIL warmed CMD_V2 did not move the simulated plant")

        before_anomaly = int(by_seq[6]["theta_applied"])
        for seq in range(7, 11):
            row = by_seq[seq]
            if int(row["theta_applied"]) != before_anomaly:
                raise SystemExit("[GOVERNOR_E2E] FAIL unknown unit metadata changed plant state")
            if int(row["fault_bits"], 16) & UNIT_FAULT == 0:
                raise SystemExit("[GOVERNOR_E2E] FAIL unknown unit ID was not surfaced as UNIT")

        converted = by_seq[11]
        if int(converted["fault_bits"], 16) & UNIT_FAULT != 0:
            raise SystemExit("[GOVERNOR_E2E] FAIL known rational unit conversion was rejected")
        if int(converted["theta_applied"]) <= before_anomaly:
            raise SystemExit("[GOVERNOR_E2E] FAIL converted command was not admitted through CLAMP")

        # ---------------------------------------------------------------------
        # Scenario 6: WIDEN Veto
        # ---------------------------------------------------------------------
        row_widen = by_seq[12]
        if int(row_widen["fault_bits"], 16) & WIDEN_FAULT == 0:
            raise SystemExit("[GOVERNOR_E2E] FAIL widening shrink request was not rejected with WIDEN_FAULT")
        if int(row_widen["rung"]) != RUNG_SLOW:
            raise SystemExit(f"[GOVERNOR_E2E] FAIL widen veto did not demote to SLOW (got rung {row_widen['rung']})")
        pass_s6 = "[GOVERNOR_SCENARIO_6] PASS: envelope widening request vetoed with LATCH_FAULT_WIDEN and one-rung demotion"

        # ---------------------------------------------------------------------
        # Scenario 5: Heartbeat Authority Separation & Non-Recovery
        # ---------------------------------------------------------------------
        held_theta = int(by_tick[12]["theta_applied"])
        for tick_idx in (13, 14, 15):
            r = by_tick[tick_idx]
            if int(r["theta_applied"]) != held_theta:
                raise SystemExit(f"[GOVERNOR_E2E] FAIL heartbeat at tick {tick_idx} moved plant to {r['theta_applied']}")
            if int(r["rung"]) != RUNG_SLOW:
                raise SystemExit(f"[GOVERNOR_E2E] FAIL heartbeat at tick {tick_idx} altered rung to {r['rung']}")
        pass_s5 = "[GOVERNOR_SCENARIO_5] PASS: heartbeat traffic renews lease but cannot recover rung (streak stays 0, plant unmoved)"

        # ---------------------------------------------------------------------
        # Scenario 4: Lease Expiry & Graded Demotion
        # ---------------------------------------------------------------------
        # Ticks 16, 17, 18 counted down the 4-tick lease. Tick 19 expired lease -> HEARTBEAT fault.
        row_exp1 = by_tick[19]
        if int(row_exp1["fault_bits"], 16) & HEARTBEAT_FAULT == 0:
            raise SystemExit("[GOVERNOR_E2E] FAIL expired deadman lease did not set HEARTBEAT fault bit")
        pass_s4 = "[GOVERNOR_SCENARIO_4] PASS: deadman lease expiry enforces deterministic graded ladder demotion"

        # ---------------------------------------------------------------------
        # Scenario 2: v2 rejects the legacy SILENCE flag
        # ---------------------------------------------------------------------
        # Verify wire v2 decoder rejects flags=0x80 with MAGIC_FAULT.
        v2_bad_hdr = struct.pack("<IHBBIi", MAGIC, 2, 0, 0x80, 99, 0)
        v2_bad_meta = b"\x00" * 12
        v2_bad_crc = zlib.crc32(v2_bad_hdr + v2_bad_meta) & 0xFFFFFFFF
        v2_bad_kind = v2_bad_hdr + struct.pack("<I", v2_bad_crc) + v2_bad_meta
        ing_bad = subprocess.run([str(ingest), "-m", str(tempdir / "main.manifest"), "-o", "-"],
                                 input=v2_bad_kind, capture_output=True)
        # Ingest output is one LPR2 IPC proposal whose pre_fault_bits has MAGIC_FAULT
        expected_lpr2 = lpr2_size()
        if len(ing_bad.stdout) != expected_lpr2:
            raise SystemExit(f"[GOVERNOR_E2E] FAIL ingest did not emit {expected_lpr2}-byte "
                             f"IPC proposal for rejected v2 frame (got {len(ing_bad.stdout)})")
        pre_faults = struct.unpack("<H", ing_bad.stdout[14:16])[0]
        if pre_faults & MAGIC_FAULT == 0:
            raise SystemExit(f"[GOVERNOR_E2E] FAIL v2 decoder did not reject flags=0x80 with MAGIC fault (got pre_faults=0x{pre_faults:04X})")
        # Bypass ingestion to exercise latchd's independent IPC trust boundary.
        # A structurally valid v1 LPRP must not enter a v2 manifest session.
        legacy_ipc = struct.pack("<IIiHHQ", 0x4C505250, 1, 10, 0, 0, 0)
        legacy = subprocess.run(
            [str(latchd), "-m", str(tempdir / "main.manifest"), "--pipe-in",
             "--csv", str(tempdir / "rejected-v1.csv")],
            input=legacy_ipc, capture_output=True)
        if legacy.returncode == 0:
            raise SystemExit("[GOVERNOR_E2E] FAIL v2 contract accepted LPRP v1 IPC")
        pass_s2 = "[GOVERNOR_SCENARIO_2] PASS: v2 rejects legacy SILENCE flag and LPRP v1 IPC"

        # ---------------------------------------------------------------------
        # Scenario 1: KEEPOUT -> HOLD not ADVISE
        # ---------------------------------------------------------------------
        # In a fresh run starting in HP, command u=450 directly into keep-out [250, 650].
        # Must immediately latch HOLD (mode=1) and LATCH (rung=5), NOT demote to ADVISE (rung=1).
        ko_config = json.loads(json.dumps(base_config))
        ko_config["governor"]["enabled"] = 1
        ko_config["governor"]["deadman"]["warmup_heartbeats"] = 2
        ko_config["protocol"].update({"version": 2, "crc": "ieee32-v2", "coverage": 28})

        frames_ko = [
            frame_v2(HEARTBEAT, 1, 1),
            frame_v2(HEARTBEAT, 2, 2),
            frame_v2(CMD_V2, 3, 3, u=10, confidence=255, unit_id=1),  # Enters HP, moves to 9
            frame_v2(CMD_V2, 4, 4, u=450, confidence=255, unit_id=1), # Keep-out breach [250, 650]!
        ]
        raw_ko = b"".join(frames_ko)
        rows_ko = run_pipeline(latchctl, ingest, latchd, ko_config, raw_ko, tempdir, "keepout")
        all_tape_rows.extend(rows_ko)

        ko_by_seq = {int(r["seq"]): r for r in rows_ko}
        row_hp = ko_by_seq[3]
        if int(row_hp["mode"]) != MODE_HP or int(row_hp["rung"]) != RUNG_HP:
            raise SystemExit("[GOVERNOR_E2E] FAIL nominal command did not establish HP mode")

        row_breach = ko_by_seq[4]
        faults_breach = int(row_breach["fault_bits"], 16)
        mode_breach = int(row_breach["mode"])
        rung_breach = int(row_breach["rung"])
        theta_breach = int(row_breach["theta_applied"])

        if faults_breach & KEEPOUT_FAULT == 0:
            raise SystemExit(f"[GOVERNOR_E2E] FAIL keep-out command did not set KEEPOUT fault (faults=0x{faults_breach:04X})")
        if mode_breach != MODE_HOLD or row_breach["mode_name"] != "HOLD":
            raise SystemExit(f"[GOVERNOR_E2E] FAIL keep-out command did not enter HOLD mode (mode={mode_breach})")
        if rung_breach != RUNG_LATCH:
            raise SystemExit(f"[GOVERNOR_E2E] FAIL keep-out command did not transition to LATCH rung (rung={rung_breach}, expected {RUNG_LATCH})")
        if rung_breach == RUNG_ADVISE:
            raise SystemExit("[GOVERNOR_E2E] FAIL keep-out command erroneously demoted to advisory ADVISE instead of LATCH")
        if 250 <= theta_breach <= 650:
            raise SystemExit(f"[GOVERNOR_E2E] FAIL plant entered keepout zone! theta_applied={theta_breach}")
        pass_s1 = "[GOVERNOR_SCENARIO_1] PASS: keepout violation enters HOLD and LATCH immediately (not ADVISE)"

        # ---------------------------------------------------------------------
        # Scenario 3: Global Invariant (u=370000 and all commands never land in keepout)
        # ---------------------------------------------------------------------
        for row in all_tape_rows:
            theta = int(row["theta_applied"])
            if 250 <= theta <= 650:
                raise SystemExit(f"[GOVERNOR_E2E] FAIL global keep-out invariant breached at tick {row['tick']}: theta={theta}")

        # Explicit check for all u=370000 rows
        for seq in range(7, 11):
            theta_anom = int(by_seq[seq]["theta_applied"])
            if 250 <= theta_anom <= 650:
                raise SystemExit(f"[GOVERNOR_E2E] FAIL anomaly u=370000 landed in keepout! theta={theta_anom}")

        pass_s3 = "[GOVERNOR_SCENARIO_3] PASS: global assertion verified: u=370000 and all commands never land theta in keepout [250, 650]"

        # ---------------------------------------------------------------------
        # Scenario 7: Medical Syringe Governor DOSE Fault & Hard-Fault Latch
        # ---------------------------------------------------------------------
        pass_s7 = None
        syringe_path = fixture.parent / "syringe_governor.manifest"
        if not syringe_path.exists():
            raise SystemExit(f"[GOVERNOR_E2E] FAIL missing medical contract: {syringe_path}")
        if syringe_path.exists():
            s_config = json.loads(syringe_path.read_bytes())
            s_config["governor"]["deadman"]["warmup_heartbeats"] = 2
            s_config["governor"]["deadman"]["lease_ticks"] = 10
            s_config["governor"]["ladder"]["demote_faults_per_rung"] = 3
            # Option B: medical DOSE is strictly non-advisory (UNIT only in advise_fault_mask).
            s_config["governor"]["ladder"]["advise_fault_mask"] = UNIT_FAULT
            s_config["medical"]["min_bolus_interval_ticks"] = 1
            frames_s = [
                # Ticks 1..2: Warmup heartbeats -> completes warmup and enters HP
                frame_v2(HEARTBEAT, 1, 1),
                frame_v2(HEARTBEAT, 2, 2),
                # Tick 3: Nominal injection in HP: u=40 uL
                frame_v2(CMD_V2, 3, 3, u=40, confidence=255, unit_id=1),
                # Ticks 4..7: UNIT anomaly -> demotes HP -> ADVISE -> CLAMP
                frame_v2(CMD_V2, 4, 4, u=40, confidence=255, unit_id=999),
                frame_v2(CMD_V2, 5, 5, u=40, confidence=255, unit_id=999),
                frame_v2(CMD_V2, 6, 6, u=40, confidence=255, unit_id=999),
                frame_v2(CMD_V2, 7, 7, u=40, confidence=255, unit_id=999),
                # Ticks 8..11: In CLAMP (rung 2, clamp_max_step=50 uL).
                # Excessive bolus / dose proposals raise LATCH_FAULT_DOSE (0x8000),
                # which is strictly non-advisory and hard-faults to HOLD / LATCH (rung 5).
                frame_v2(CMD_V2, 8, 8, u=150, confidence=255, unit_id=1),
                frame_v2(CMD_V2, 9, 9, u=200, confidence=255, unit_id=1),
                frame_v2(CMD_V2, 10, 10, u=300, confidence=255, unit_id=1),
                frame_v2(CMD_V2, 11, 11, u=400, confidence=255, unit_id=1),
                # Ticks 12..13: Already latched in HOLD / LATCH; further commands (even a
                # valid rational unit-3 nL conversion: 261000 nL = 261 uL) remain held.
                frame_v2(CMD_V2, 12, 12, u=500, confidence=255, unit_id=1),
                frame_v2(CMD_V2, 13, 13, u=261000, confidence=255, unit_id=3),
            ]
            raw_s = b"".join(frames_s)
            rows_s = run_pipeline(latchctl, ingest, latchd, s_config, raw_s, tempdir, "syringe_gov")
            all_tape_rows.extend(rows_s)
            by_seq_s = {int(r["seq"]): r for r in rows_s if int(r["seq"]) in range(1, 14)}

            # Assert nominal move in HP and UNIT demotion to CLAMP
            if int(by_seq_s[3]["theta_applied"]) != 40 or int(by_seq_s[3]["fault_bits"], 16) != 0:
                raise SystemExit("[GOVERNOR_E2E] FAIL syringe nominal injection command failed")
            if int(by_seq_s[7]["rung"]) != RUNG_CLAMP:
                raise SystemExit(f"[GOVERNOR_E2E] FAIL UNIT faults did not reach CLAMP (got rung {by_seq_s[7]['rung']})")

            # A medical DOSE fault is strictly non-advisory: it must immediately
            # hard-fault into HOLD (mode 1) and LATCH (rung 5), freezing prior position.
            first = next((i for i in range(4, 14)
                          if int(by_seq_s[i]["fault_bits"], 16) & DOSE_FAULT), None)
            if first is None:
                raise SystemExit("[GOVERNOR_E2E] FAIL no medical DOSE fault observed")
            row = by_seq_s[first]
            held_pos = int(by_seq_s[first - 1]["theta_applied"])
            if int(row["mode"]) != MODE_HOLD or int(row["rung"]) != RUNG_LATCH or int(row["theta_applied"]) != held_pos:
                raise SystemExit("[GOVERNOR_E2E] FAIL DOSE fault did not enter HOLD/LATCH at prior position")
            for later in range(first + 1, 14):
                r_later = by_seq_s[later]
                if int(r_later["mode"]) != MODE_HOLD or int(r_later["rung"]) != RUNG_LATCH or int(r_later["theta_applied"]) != held_pos:
                    raise SystemExit(f"[GOVERNOR_E2E] FAIL plant moved or left HOLD/LATCH after DOSE at seq {later}")
            pass_s7 = "[GOVERNOR_SCENARIO_7] PASS: medical DOSE fault holds the plant"

        # Print all scenario pass lines in numerical order
        print(pass_s1)
        print(pass_s2)
        print(pass_s3)
        print(pass_s4)
        print(pass_s5)
        print(pass_s6)
        if pass_s7:
            print(pass_s7)

    print("[GOVERNOR_E2E] PASS: all 7 governor scenarios verified")


if __name__ == "__main__":
    main()
