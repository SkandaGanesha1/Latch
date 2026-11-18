#!/usr/bin/env python3
"""
gov_replay.py — Tamper-Evident Blackbox Event Replay & Forensics Engine
GOVERNOR Subsystem (QNX SDP 8.0 & Host Simulation)

Specifications:
  H_0 = SHA-256("GOVERNOR_CHAIN_GENESIS:" || manifest_sha256)
  H_i = SHA-256(H_{i-1} || packed_62_bytes(event_i))

Capabilities:
  --verify   Recomputes SHA-256 chain from genesis, checks cryptographic
             continuity, detects any bit flip, sequence gap, or truncation.
  --replay   Simulates supervisor state machine from events, asserts ladder
             invariants (rungs descend on fault/expiry, only promote on
             consecutive clean commands, plant never moves on heartbeat).
  --test     Standalone self-test verifying genuine tamper detection.
  --json     Output enriched event stream with SHA-256 hash chain annotations.
"""

import argparse
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile


# 62-byte packed latch_gov_event_t layout
# _Static_assert(sizeof(latch_gov_event_t) == 62u, ...)
EVENT_STRUCT_FORMAT = '<QQQIiiiIIIHBBBBBBBB'
assert struct.calcsize(EVENT_STRUCT_FORMAT) == 62

# Supervisory Rungs (governor_policy.h)
RUNG_HP = 0
RUNG_ADVISE = 1
RUNG_CLAMP = 2
RUNG_SLOW = 3
RUNG_SAFE_STOP = 4
RUNG_LATCH = 5

RUNG_NAMES = {
    RUNG_HP: "HP",
    RUNG_ADVISE: "ADVISE",
    RUNG_CLAMP: "CLAMP",
    RUNG_SLOW: "SLOW",
    RUNG_SAFE_STOP: "SAFE_STOP",
    RUNG_LATCH: "LATCH"
}

# Wire Frame Kinds (governor_wire.h)
KIND_CMD = 0
KIND_HEARTBEAT = 1
KIND_CMD_V2 = 2
KIND_SHRINK_REQ = 3

KIND_NAMES = {
    KIND_CMD: "CMD",
    KIND_HEARTBEAT: "HEARTBEAT",
    KIND_CMD_V2: "CMD_V2",
    KIND_SHRINK_REQ: "SHRINK_REQ"
}

# Event Verdicts
VERDICT_NONE = 0
VERDICT_ACCEPT = 1
VERDICT_HEARTBEAT = 2
VERDICT_SHRINK = 3
VERDICT_REJECT = 4

VERDICT_NAMES = {
    VERDICT_NONE: "NONE",
    VERDICT_ACCEPT: "ACCEPT",
    VERDICT_HEARTBEAT: "HEARTBEAT",
    VERDICT_SHRINK: "SHRINK",
    VERDICT_REJECT: "REJECT"
}

# Fault Bits (latch_protocol.h)
FAULT_MAGIC = 1 << 0
FAULT_CRC = 1 << 1
FAULT_SEQ = 1 << 2
FAULT_RATE = 1 << 3
FAULT_NAN = 1 << 4
FAULT_KEEPOUT = 1 << 5
FAULT_BOUNDS = 1 << 6
FAULT_WATCHDOG = 1 << 8
FAULT_I2C = 1 << 9
FAULT_OPERATOR = 1 << 10
FAULT_EPERM = 1 << 11
FAULT_UNIT = 1 << 12
FAULT_HEARTBEAT = 1 << 13
FAULT_WIDEN = 1 << 14
FAULT_DOSE = 1 << 15

# Default Advisory allowed mask (RATE, UNIT, DOSE)
DEFAULT_ADVISORY_MASK = (1 << 7) | (1 << 12) | (1 << 15)


def pack_event(ev: dict) -> bytes:
    """Packs an event dictionary into canonical 62-byte binary format.
    Validates that bytes_hex (if present) matches the packed fields.
    """
    packed = struct.pack(
        EVENT_STRUCT_FORMAT,
        int(ev["event_index"]),
        int(ev["tick"]),
        int(ev["cycles"]),
        int(ev["seq"]),
        int(ev["raw_u_mrad"]),
        int(ev["normalized_u_mrad"]),
        int(ev["theta_applied_mrad"]),
        int(ev["unit_id"]),
        int(ev["coherence_ctr"]),
        int(ev["lease_remaining"]),
        int(ev["fault_bits"]),
        int(ev["mode"]),
        int(ev["rung_before"]),
        int(ev["rung_after"]),
        int(ev["kind"]),
        int(ev["verdict"]),
        int(ev["agent_state"]),
        int(ev["confidence_q8"]),
        int(ev["coherence_valid"])
    )
    if "bytes_hex" in ev and ev["bytes_hex"] is not None:
        raw = bytes.fromhex(ev["bytes_hex"])
        if len(raw) != 62:
            raise ValueError(f"bytes_hex length invalid: expected 62 bytes (124 hex chars), got {len(raw)} bytes")
        if raw != packed:
            raise ValueError(
                f"Payload mismatch at event {ev.get('event_index')}: "
                f"bytes_hex does not match dictionary fields"
            )
    return packed


def unpack_event(raw_bytes: bytes) -> dict:
    """Unpacks 62-byte binary format into an event dictionary."""
    if len(raw_bytes) != 62:
        raise ValueError(f"Expected 62 bytes, got {len(raw_bytes)}")
    v = struct.unpack(EVENT_STRUCT_FORMAT, raw_bytes)
    return {
        "event_index": v[0],
        "tick": v[1],
        "cycles": v[2],
        "seq": v[3],
        "raw_u_mrad": v[4],
        "normalized_u_mrad": v[5],
        "theta_applied_mrad": v[6],
        "unit_id": v[7],
        "coherence_ctr": v[8],
        "lease_remaining": v[9],
        "fault_bits": v[10],
        "mode": v[11],
        "rung_before": v[12],
        "rung_after": v[13],
        "kind": v[14],
        "verdict": v[15],
        "agent_state": v[16],
        "confidence_q8": v[17],
        "coherence_valid": v[18],
        "bytes_hex": raw_bytes.hex()
    }


def compute_genesis_hash(manifest_sha256: str | bytes) -> bytes:
    """H_0 = SHA-256("GOVERNOR_CHAIN_GENESIS:" || manifest_sha256)"""
    if isinstance(manifest_sha256, str):
        manifest_bytes = bytes.fromhex(manifest_sha256)
    else:
        manifest_bytes = manifest_sha256
    return hashlib.sha256(b"GOVERNOR_CHAIN_GENESIS:" + manifest_bytes).digest()


def build_hash_chain(manifest_sha256: str | bytes, events: list[dict]) -> tuple[bytes, list[dict]]:
    """Builds and attaches rolling SHA-256 hash chain to event sequence.
    H_0 = SHA-256("GOVERNOR_CHAIN_GENESIS:" || manifest_sha256)
    H_i = SHA-256(H_{i-1} || packed_62_bytes(event_i))
    """
    genesis_hash = compute_genesis_hash(manifest_sha256)
    curr_hash = genesis_hash

    chained_events = []
    for ev in events:
        ev_copy = dict(ev)
        ev_bytes = pack_event(ev_copy)
        ev_copy["bytes_hex"] = ev_bytes.hex()
        ev_copy["prev_hash"] = curr_hash.hex()
        curr_hash = hashlib.sha256(curr_hash + ev_bytes).digest()
        ev_copy["hash"] = curr_hash.hex()
        chained_events.append(ev_copy)

    return genesis_hash, chained_events


def verify_hash_chain(
    manifest_sha256: str | bytes,
    events: list[dict],
    expected_terminal_hash: str | None = None,
    expected_count: int | None = None,
    expected_genesis_hash: str | None = None
) -> tuple[bool, str]:
    """Recomputes SHA-256 chain from genesis, checks cryptographic continuity,
    detects any bit flip, sequence gap, payload mismatch, unhashed event, or truncation.
    """
    if not events:
        if expected_count is not None and expected_count > 0:
            return False, f"TAMPER DETECTED: Truncation (expected {expected_count} events, found 0)"
        return True, "No events to verify"

    if expected_count is not None and len(events) != expected_count:
        return False, f"TAMPER DETECTED: event count mismatch (header count={expected_count} != actual={len(events)})"

    try:
        genesis_hash = compute_genesis_hash(manifest_sha256)
    except Exception as exc:
        return False, f"TAMPER DETECTED: invalid manifest SHA-256: {exc}"

    if expected_genesis_hash is not None:
        if genesis_hash.hex() != expected_genesis_hash.lower():
            return False, (f"TAMPER DETECTED: root genesis_hash mismatch "
                           f"(expected {expected_genesis_hash} != computed {genesis_hash.hex()})")

    curr_hash = genesis_hash

    for i, ev in enumerate(events):
        curr_idx = ev.get("event_index", i)
        expected_prev = ev.get("prev_hash")
        expected_curr = ev.get("hash")

        # Check sequence continuity
        if i > 0:
            prev_idx = events[i - 1].get("event_index", i - 1)
            if curr_idx != prev_idx + 1:
                return False, f"TAMPER DETECTED: sequence gap between event {prev_idx} and {curr_idx}"
            if ev.get("tick", 0) < events[i - 1].get("tick", 0):
                return False, f"TAMPER DETECTED: non-monotonic tick at event index {curr_idx}"

        # Every event in a verified chain must have explicit cryptographic hashes
        if expected_prev is None or expected_curr is None:
            return False, f"TAMPER DETECTED at event index {curr_idx}: unhashed event in chain (missing hash/prev_hash)"

        if curr_hash.hex() != expected_prev.lower():
            return False, (f"TAMPER DETECTED at event index {curr_idx}: "
                           f"prev_hash mismatch: expected {expected_prev} != computed {curr_hash.hex()}")

        try:
            ev_bytes = pack_event(ev)
        except ValueError as exc:
            return False, f"TAMPER DETECTED at event index {curr_idx}: {exc}"

        curr_hash = hashlib.sha256(curr_hash + ev_bytes).digest()

        if curr_hash.hex() != expected_curr.lower():
            return False, (f"TAMPER DETECTED at event index {curr_idx}: "
                           f"event payload altered (computed {curr_hash.hex()} != expected {expected_curr})")

    if expected_terminal_hash is not None:
        if curr_hash.hex() != expected_terminal_hash.lower():
            return False, (f"TAMPER DETECTED: terminal hash mismatch "
                           f"(expected {expected_terminal_hash} != computed {curr_hash.hex()})")

    return True, f"Cryptographic continuity verified across {len(events)} events (terminal hash {curr_hash.hex()})"


def replay_events(
    events: list[dict],
    advisory_mask: int = DEFAULT_ADVISORY_MASK,
    hysteresis_clean_frames: int = 25
) -> tuple[bool, str, dict]:
    """Simulates supervisor state machine from events and asserts ladder invariants:
    - Rungs descend on fault or lease expiry
    - Rungs only promote on consecutive clean commands matching hysteresis_clean_frames
    - Plant never moves on heartbeat (both at initial event and subsequent events)
    - Heartbeat never promotes ladder
    - LATCH requires operator release
    """
    stats = {
        "total_events": len(events),
        "heartbeats": 0,
        "commands": 0,
        "demotions": 0,
        "promotions": 0,
        "hard_faults": 0,
        "transitions": []
    }

    if not events:
        return True, "No events to replay", stats

    clean_streak = 0

    for i, ev in enumerate(events):
        idx = ev.get("event_index", i)
        r_before = ev.get("rung_before", RUNG_HP)
        r_after = ev.get("rung_after", RUNG_HP)
        kind = ev.get("kind", KIND_CMD)
        verdict = ev.get("verdict", VERDICT_NONE)
        fault_bits = ev.get("fault_bits", 0)
        theta_applied = ev.get("theta_applied_mrad", 0)

        # Invariant 1: Valid rung bounds
        if not (0 <= r_before <= 5 and 0 <= r_after <= 5):
            return False, f"INVARIANT VIOLATION: Invalid rung out of [0..5] at event {idx} ({r_before}->{r_after})", stats

        # Invariant 2: Inter-event rung continuity
        if i > 0:
            prev_after = events[i - 1].get("rung_after", RUNG_HP)
            prev_idx = events[i - 1].get("event_index", i - 1)
            if idx == prev_idx + 1 and r_before != prev_after:
                return False, (f"INVARIANT VIOLATION: Rung discontinuity between event {prev_idx} "
                               f"(rung_after={RUNG_NAMES.get(prev_after)}) and event {idx} "
                               f"(rung_before={RUNG_NAMES.get(r_before)})"), stats

        # Invariant 3: Heartbeat invariant (plant never moves on heartbeat, heartbeat never promotes)
        if kind == KIND_HEARTBEAT:
            stats["heartbeats"] += 1
            if r_after < r_before:
                return False, (f"INVARIANT VIOLATION: Heartbeat promoted ladder from "
                               f"{RUNG_NAMES.get(r_before)} to {RUNG_NAMES.get(r_after)} at event {idx}"), stats
            if i > 0:
                prev_theta = events[i - 1].get("theta_applied_mrad", 0)
                if theta_applied != prev_theta:
                    return False, (f"INVARIANT VIOLATION: Plant moved on heartbeat at event {idx}: "
                                   f"theta changed from {prev_theta} to {theta_applied} mrad"), stats
            else:
                if theta_applied != 0:
                    return False, (f"INVARIANT VIOLATION: Plant moved on initial heartbeat at event 0: "
                                   f"theta_applied_mrad is {theta_applied} != 0"), stats
        else:
            stats["commands"] += 1

        # Invariant 4: Ladder promotion rules
        if r_after < r_before:
            stats["promotions"] += 1
            stats["transitions"].append((r_before, r_after))
            if r_after != r_before - 1:
                return False, (f"INVARIANT VIOLATION: Promotion jumped multiple rungs at event {idx}: "
                               f"{RUNG_NAMES.get(r_before)} -> {RUNG_NAMES.get(r_after)}"), stats
            if verdict != VERDICT_ACCEPT:
                return False, (f"INVARIANT VIOLATION: Promotion without accepted command verdict at event {idx} "
                               f"(verdict={VERDICT_NAMES.get(verdict)})"), stats
            if ev.get("coherence_valid", 0) == 0:
                return False, f"INVARIANT VIOLATION: Promotion with invalid coherence at event {idx}", stats
            if fault_bits != 0:
                return False, f"INVARIANT VIOLATION: Promotion with active fault bits 0x{fault_bits:04X} at event {idx}", stats
            # Invariant: 25-frame (configured) hysteresis recovery
            if clean_streak + 1 < hysteresis_clean_frames:
                return False, (f"INVARIANT VIOLATION: Premature promotion at event {idx}: "
                               f"clean streak {clean_streak + 1} < {hysteresis_clean_frames} required"), stats
            clean_streak = 0
        elif (kind in (KIND_CMD, KIND_CMD_V2) and
              verdict == VERDICT_ACCEPT and
              ev.get("coherence_valid", 0) == 1 and
              fault_bits == 0):
            clean_streak += 1
        else:
            clean_streak = 0

        # Invariant 5: Ladder demotion rules
        if r_after > r_before:
            stats["demotions"] += 1
            stats["transitions"].append((r_before, r_after))
            clean_streak = 0
            hard_faults = fault_bits & ~advisory_mask
            if hard_faults != 0:
                stats["hard_faults"] += 1
                if r_after != RUNG_LATCH:
                    return False, (f"INVARIANT VIOLATION: Hard fault 0x{hard_faults:04X} did not enter LATCH "
                                   f"at event {idx} (entered {RUNG_NAMES.get(r_after)})"), stats
            else:
                if r_after != r_before + 1:
                    return False, (f"INVARIANT VIOLATION: Demotion skipped rung without hard fault at event {idx}: "
                                   f"{RUNG_NAMES.get(r_before)} -> {RUNG_NAMES.get(r_after)}"), stats

        # Invariant 6: Hard fault fallback rule
        hard_faults = fault_bits & ~advisory_mask
        if hard_faults != 0 and r_after != RUNG_LATCH:
            return False, f"INVARIANT VIOLATION: Hard fault present but rung is {RUNG_NAMES.get(r_after)} at event {idx}", stats

    return True, f"All ladder invariants verified across {len(events)} events", stats


def run_selftest() -> bool:
    """Feature 3: Standalone self-test testing genuine tamper detection and CLI integration.
    Mutates bits in events, manifests, and sequences to assert tamper detection.
    """
    print("[GOV_REPLAY_TEST] Running Standalone Tamper Detection & Replay Self-Tests...")

    # Bind the synthetic chain's genesis to the real contract's SHA-256 so the
    # self-test can never drift from the manifest it claims to attest. Falls
    # back to a fixed seed only if the contract is absent from the tree.
    default_manifest_sha256 = "0c36e2f338e31ef29c84d3fb66d06860a02e86c99b0e8ea8af2d070373e92ad0"
    contract = pathlib.Path(__file__).resolve().parent.parent / "qnx" / "contracts" / "governor_servo.manifest"
    if contract.is_file():
        manifest_sha256 = hashlib.sha256(contract.read_bytes()).hexdigest()
    else:
        manifest_sha256 = default_manifest_sha256

    # 1. Synthesize realistic event stream adhering strictly to 25-clean-frame hysteresis
    raw_events = []
    # 4 warm-up heartbeats (ticks 1..4)
    for i in range(4):
        raw_events.append({
            "event_index": i, "tick": i + 1, "cycles": 1000 * (i + 1), "seq": i + 1,
            "raw_u_mrad": 0, "normalized_u_mrad": 0, "theta_applied_mrad": 0,
            "unit_id": 1, "coherence_ctr": i + 1, "lease_remaining": 100,
            "fault_bits": 0, "mode": 1, "rung_before": RUNG_HP, "rung_after": RUNG_HP,
            "kind": KIND_HEARTBEAT, "verdict": VERDICT_HEARTBEAT, "agent_state": 0,
            "confidence_q8": 0, "coherence_valid": 1
        })
    # 4 clean commands in HP (ticks 5..8)
    for i in range(4, 8):
        raw_events.append({
            "event_index": i, "tick": i + 1, "cycles": 1000 * (i + 1), "seq": i + 1,
            "raw_u_mrad": 25, "normalized_u_mrad": 25, "theta_applied_mrad": 25,
            "unit_id": 1, "coherence_ctr": i + 1, "lease_remaining": 100,
            "fault_bits": 0, "mode": 1, "rung_before": RUNG_HP, "rung_after": RUNG_HP,
            "kind": KIND_CMD_V2, "verdict": VERDICT_ACCEPT, "agent_state": 1,
            "confidence_q8": 255, "coherence_valid": 1
        })
    # Event 8: Advisory UNIT fault -> Demote HP to ADVISE (tick 9)
    raw_events.append({
        "event_index": 8, "tick": 9, "cycles": 9000, "seq": 9,
        "raw_u_mrad": 370000, "normalized_u_mrad": 25, "theta_applied_mrad": 25,
        "unit_id": 99, "coherence_ctr": 9, "lease_remaining": 100,
        "fault_bits": FAULT_UNIT, "mode": 1, "rung_before": RUNG_HP, "rung_after": RUNG_ADVISE,
        "kind": KIND_CMD_V2, "verdict": VERDICT_REJECT, "agent_state": 1,
        "confidence_q8": 255, "coherence_valid": 1
    })
    # Events 9..32 (24 clean commands in ADVISE): building hysteresis streak
    for j in range(24):
        idx = len(raw_events)
        raw_events.append({
            "event_index": idx, "tick": idx + 1, "cycles": 1000 * (idx + 1), "seq": idx + 1,
            "raw_u_mrad": 25, "normalized_u_mrad": 25, "theta_applied_mrad": 25,
            "unit_id": 1, "coherence_ctr": idx + 1, "lease_remaining": 100,
            "fault_bits": 0, "mode": 1, "rung_before": RUNG_ADVISE, "rung_after": RUNG_ADVISE,
            "kind": KIND_CMD_V2, "verdict": VERDICT_ACCEPT, "agent_state": 1,
            "confidence_q8": 255, "coherence_valid": 1
        })
    # Event 33: 25th clean command promotes ADVISE back to HP
    idx = len(raw_events)
    raw_events.append({
        "event_index": idx, "tick": idx + 1, "cycles": 1000 * (idx + 1), "seq": idx + 1,
        "raw_u_mrad": 25, "normalized_u_mrad": 25, "theta_applied_mrad": 25,
        "unit_id": 1, "coherence_ctr": idx + 1, "lease_remaining": 100,
        "fault_bits": 0, "mode": 1, "rung_before": RUNG_ADVISE, "rung_after": RUNG_HP,
        "kind": KIND_CMD_V2, "verdict": VERDICT_ACCEPT, "agent_state": 1,
        "confidence_q8": 255, "coherence_valid": 1
    })
    # Event 34: Hard fault KEEPOUT -> Immediate LATCH
    idx = len(raw_events)
    raw_events.append({
        "event_index": idx, "tick": idx + 1, "cycles": 1000 * (idx + 1), "seq": idx + 1,
        "raw_u_mrad": 660, "normalized_u_mrad": 660, "theta_applied_mrad": 25,
        "unit_id": 1, "coherence_ctr": idx + 1, "lease_remaining": 100,
        "fault_bits": FAULT_KEEPOUT, "mode": 2, "rung_before": RUNG_HP, "rung_after": RUNG_LATCH,
        "kind": KIND_CMD_V2, "verdict": VERDICT_REJECT, "agent_state": 1,
        "confidence_q8": 255, "coherence_valid": 1
    })

    # Build valid cryptographic hash chain
    genesis_hash, chained_events = build_hash_chain(manifest_sha256, raw_events)

    # Sub-test 1: Verify pristine hash chain
    ok, msg = verify_hash_chain(manifest_sha256, chained_events)
    if not ok:
        print(f"[FAIL] Sub-test 1 pristine verification failed: {msg}")
        return False
    print("  [PASS] Sub-test 1: Pristine hash chain cryptographic continuity verified")

    # Sub-test 2: Replay pristine events
    ok, msg, stats = replay_events(chained_events)
    if not ok:
        print(f"[FAIL] Sub-test 2 replay failed: {msg}")
        return False
    if stats["heartbeats"] != 4 or stats["demotions"] != 2 or stats["promotions"] != 1 or stats["hard_faults"] != 1:
        print(f"[FAIL] Sub-test 2 unexpected stats: {stats}")
        return False
    print("  [PASS] Sub-test 2: Supervisor state machine replay and ladder invariants verified (25-frame hysteresis)")

    # Sub-test 3: Single bit flip tamper detection in event payload
    tampered_events = [dict(e) for e in chained_events]
    tampered_events[5]["theta_applied_mrad"] ^= 1
    tampered_events[5].pop("bytes_hex", None)
    ok, msg = verify_hash_chain(manifest_sha256, tampered_events)
    if ok or "TAMPER DETECTED" not in msg or "event index 5" not in msg:
        print(f"[FAIL] Sub-test 3 expected TAMPER DETECTED at event index 5, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 3: Single bit flip caught: '{msg}'")

    # Sub-test 4: Manifest swap tamper detection
    wrong_manifest = "11" * 32
    ok, msg = verify_hash_chain(wrong_manifest, chained_events)
    if ok or "TAMPER DETECTED" not in msg:
        print(f"[FAIL] Sub-test 4 expected TAMPER DETECTED on manifest swap, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 4: Manifest substitution caught: '{msg}'")

    # Sub-test 5: Sequence gap / truncation detection
    truncated_events = [dict(e) for e in chained_events[:6]] + [dict(e) for e in chained_events[7:]]
    ok, msg = verify_hash_chain(manifest_sha256, truncated_events)
    if ok or "TAMPER DETECTED" not in msg:
        print(f"[FAIL] Sub-test 5 expected TAMPER DETECTED on sequence truncation, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 5: Event truncation / gap caught: '{msg}'")

    # Sub-test 6: Heartbeat promotion invariant violation caught
    illegal_events = [dict(e) for e in raw_events]
    illegal_events[2]["rung_before"] = RUNG_ADVISE
    illegal_events[2]["rung_after"] = RUNG_HP
    ok, msg, _ = replay_events(illegal_events)
    if ok or "INVARIANT VIOLATION" not in msg:
        print(f"[FAIL] Sub-test 6 expected INVARIANT VIOLATION on heartbeat promotion, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 6: Heartbeat promotion invariant violation caught: '{msg}'")

    # Sub-test 7: Plant motion during heartbeat caught in replay
    moving_hb = [dict(e) for e in raw_events]
    moving_hb[2]["theta_applied_mrad"] = 999
    ok, msg, _ = replay_events(moving_hb)
    if ok or "Plant moved on heartbeat" not in msg:
        print(f"[FAIL] Sub-test 7 expected plant move violation, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 7: Plant motion during heartbeat caught: '{msg}'")

    # Sub-test 8: Initial heartbeat movement caught at event 0
    init_hb = [dict(e) for e in raw_events]
    init_hb[0]["theta_applied_mrad"] = 50
    ok, msg, _ = replay_events(init_hb)
    if ok or "Plant moved on initial heartbeat" not in msg:
        print(f"[FAIL] Sub-test 8 expected initial plant move violation, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 8: Initial plant motion at event 0 caught: '{msg}'")

    # Sub-test 9: Premature ladder recovery (< 25 clean frames) rejected
    premature_events = [dict(e) for e in raw_events[:10]]
    # Event 8 demoted HP -> ADVISE. Try promoting at event 9 after only 1 clean command:
    premature_events[9]["rung_before"] = RUNG_ADVISE
    premature_events[9]["rung_after"] = RUNG_HP
    ok, msg, _ = replay_events(premature_events)
    if ok or "Premature promotion" not in msg:
        print(f"[FAIL] Sub-test 9 expected Premature promotion rejection, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 9: Premature promotion (< 25 clean frames) caught: '{msg}'")

    # Sub-test 10: Payload mismatch between bytes_hex and dictionary fields
    desync_events = [dict(e) for e in chained_events]
    desync_events[5]["theta_applied_mrad"] = 888
    # bytes_hex remains unmodified (contains 25 mrad)
    ok, msg = verify_hash_chain(manifest_sha256, desync_events)
    if ok or "TAMPER DETECTED" not in msg or "bytes_hex does not match dictionary fields" not in msg:
        print(f"[FAIL] Sub-test 10 expected bytes_hex mismatch caught, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 10: bytes_hex vs dictionary desync caught: '{msg}'")

    # Sub-test 11: Unhashed event in chain rejected
    unhashed_events = [dict(e) for e in chained_events]
    unhashed_events.append({
        "event_index": len(unhashed_events), "tick": 999, "cycles": 999000, "seq": 999,
        "raw_u_mrad": 0, "normalized_u_mrad": 0, "theta_applied_mrad": 0,
        "unit_id": 1, "coherence_ctr": 999, "lease_remaining": 100,
        "fault_bits": 0, "mode": 1, "rung_before": 0, "rung_after": 0,
        "kind": 1, "verdict": 2, "agent_state": 0, "confidence_q8": 0, "coherence_valid": 1
    })
    ok, msg = verify_hash_chain(manifest_sha256, unhashed_events)
    if ok or "unhashed event in chain" not in msg:
        print(f"[FAIL] Sub-test 11 expected unhashed event rejection, got: ok={ok}, msg='{msg}'")
        return False
    print(f"  [PASS] Sub-test 11: Unhashed appended event caught: '{msg}'")

    # Sub-test 12: End-to-end CLI regression suite via subprocess
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = os.path.join(tmpdir, "raw.json")
        chained_path = os.path.join(tmpdir, "chained.json")
        tampered_path = os.path.join(tmpdir, "tampered.json")
        swapped_manifest_path = os.path.join(tmpdir, "swapped_manifest.json")
        tampered_prev_hash_path = os.path.join(tmpdir, "tampered_prev_hash.json")
        unhashed_path = os.path.join(tmpdir, "unhashed.json")
        bytes_mismatch_path = os.path.join(tmpdir, "bytes_mismatch.json")
        premature_path = os.path.join(tmpdir, "premature.json")

        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump({"manifest_sha256": manifest_sha256, "events": raw_events}, f)

        # 12a. CLI --file raw.json --json generates chained JSON
        res = subprocess.run(
            [sys.executable, __file__, "--file", raw_path, "--json"],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            print(f"[FAIL] Sub-test 12a CLI --json failed: {res.stderr}")
            return False
        chained_data = json.loads(res.stdout)
        with open(chained_path, "w", encoding="utf-8") as f:
            json.dump(chained_data, f)

        # 12b. CLI --verify on pristine chained file exits 0 with [VERIFY PASS]
        res = subprocess.run(
            [sys.executable, __file__, "--file", chained_path, "--verify"],
            capture_output=True, text=True
        )
        if res.returncode != 0 or "[VERIFY PASS]" not in res.stdout:
            print(f"[FAIL] Sub-test 12b CLI --verify pristine failed: exit={res.returncode}, out={res.stdout}, err={res.stderr}")
            return False

        # 12c. CLI --replay on pristine chained file exits 0 with [REPLAY PASS]
        res = subprocess.run(
            [sys.executable, __file__, "--file", chained_path, "--replay"],
            capture_output=True, text=True
        )
        if res.returncode != 0 or "[REPLAY PASS]" not in res.stdout:
            print(f"[FAIL] Sub-test 12c CLI --replay pristine failed: exit={res.returncode}, out={res.stdout}, err={res.stderr}")
            return False

        # 12d. CLI --verify on tampered payload exits 1 with TAMPER DETECTED
        tampered_data = json.loads(json.dumps(chained_data))
        tampered_data["events"][5]["theta_applied_mrad"] ^= 1
        tampered_data["events"][5].pop("bytes_hex", None)
        with open(tampered_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data, f)
        res = subprocess.run(
            [sys.executable, __file__, "--file", tampered_path, "--verify"],
            capture_output=True, text=True
        )
        if res.returncode != 1 or "TAMPER DETECTED" not in (res.stdout + res.stderr):
            print(f"[FAIL] Sub-test 12d CLI --verify failed to detect payload tampering! exit={res.returncode}")
            return False

        # 12e. CLI --verify on swapped manifest exits 1 with TAMPER DETECTED
        swapped_data = json.loads(json.dumps(chained_data))
        swapped_data["manifest_sha256"] = "11" * 32
        with open(swapped_manifest_path, "w", encoding="utf-8") as f:
            json.dump(swapped_data, f)
        res = subprocess.run(
            [sys.executable, __file__, "--file", swapped_manifest_path, "--verify"],
            capture_output=True, text=True
        )
        if res.returncode != 1 or "TAMPER DETECTED" not in (res.stdout + res.stderr):
            print(f"[FAIL] Sub-test 12e CLI --verify failed to detect manifest swap! exit={res.returncode}")
            return False

        # 12f. CLI --verify on tampered prev_hash exits 1 with TAMPER DETECTED
        prev_data = json.loads(json.dumps(chained_data))
        prev_data["events"][5]["prev_hash"] = "aa" * 32
        with open(tampered_prev_hash_path, "w", encoding="utf-8") as f:
            json.dump(prev_data, f)
        res = subprocess.run(
            [sys.executable, __file__, "--file", tampered_prev_hash_path, "--verify"],
            capture_output=True, text=True
        )
        if res.returncode != 1 or "TAMPER DETECTED" not in (res.stdout + res.stderr):
            print(f"[FAIL] Sub-test 12f CLI --verify failed to detect prev_hash tampering! exit={res.returncode}")
            return False

        # 12g. CLI --verify on bytes_hex mismatch exits 1 with TAMPER DETECTED
        mismatch_data = json.loads(json.dumps(chained_data))
        mismatch_data["events"][5]["theta_applied_mrad"] ^= 1
        with open(bytes_mismatch_path, "w", encoding="utf-8") as f:
            json.dump(mismatch_data, f)
        res = subprocess.run(
            [sys.executable, __file__, "--file", bytes_mismatch_path, "--verify"],
            capture_output=True, text=True
        )
        if res.returncode != 1 or "TAMPER DETECTED" not in (res.stdout + res.stderr):
            print(f"[FAIL] Sub-test 12g CLI --verify failed to detect bytes_hex desync! exit={res.returncode}")
            return False

        # 12h. CLI --verify on unhashed appended event exits 1 with TAMPER DETECTED
        unhashed_data = json.loads(json.dumps(chained_data))
        unhashed_data["events"].append({
            "event_index": len(unhashed_data["events"]), "tick": 999, "cycles": 999000, "seq": 999,
            "raw_u_mrad": 0, "normalized_u_mrad": 0, "theta_applied_mrad": 0,
            "unit_id": 1, "coherence_ctr": 999, "lease_remaining": 100,
            "fault_bits": 0, "mode": 1, "rung_before": 0, "rung_after": 0,
            "kind": 1, "verdict": 2, "agent_state": 0, "confidence_q8": 0, "coherence_valid": 1
        })
        with open(unhashed_path, "w", encoding="utf-8") as f:
            json.dump(unhashed_data, f)
        res = subprocess.run(
            [sys.executable, __file__, "--file", unhashed_path, "--verify"],
            capture_output=True, text=True
        )
        if res.returncode != 1 or "TAMPER DETECTED" not in (res.stdout + res.stderr):
            print(f"[FAIL] Sub-test 12h CLI --verify failed to detect unhashed event! exit={res.returncode}")
            return False

        # 12i. CLI --replay on premature promotion exits 1 with INVARIANT VIOLATION
        premature_data = {
            "manifest_sha256": manifest_sha256,
            "events": [
                {"event_index": 0, "tick": 1, "cycles": 1000, "seq": 1,
                 "raw_u_mrad": 25, "normalized_u_mrad": 25, "theta_applied_mrad": 25,
                 "unit_id": 1, "coherence_ctr": 1, "lease_remaining": 100,
                 "fault_bits": FAULT_UNIT, "mode": 1, "rung_before": RUNG_HP, "rung_after": RUNG_ADVISE,
                 "kind": KIND_CMD_V2, "verdict": VERDICT_REJECT, "agent_state": 1,
                 "confidence_q8": 255, "coherence_valid": 1},
                {"event_index": 1, "tick": 2, "cycles": 2000, "seq": 2,
                 "raw_u_mrad": 25, "normalized_u_mrad": 25, "theta_applied_mrad": 25,
                 "unit_id": 1, "coherence_ctr": 2, "lease_remaining": 100,
                 "fault_bits": 0, "mode": 1, "rung_before": RUNG_ADVISE, "rung_after": RUNG_HP,
                 "kind": KIND_CMD_V2, "verdict": VERDICT_ACCEPT, "agent_state": 1,
                 "confidence_q8": 255, "coherence_valid": 1}
            ]
        }
        with open(premature_path, "w", encoding="utf-8") as f:
            json.dump(premature_data, f)
        res = subprocess.run(
            [sys.executable, __file__, "--file", premature_path, "--replay"],
            capture_output=True, text=True
        )
        if res.returncode != 1 or "INVARIANT VIOLATION" not in (res.stdout + res.stderr):
            print(f"[FAIL] Sub-test 12i CLI --replay failed to detect premature promotion! exit={res.returncode}")
            return False

        print("  [PASS] Sub-test 12: CLI subprocess end-to-end regression tests (tamper detection & replay) verified")

    print("[GOV_REPLAY_TEST] ALL TESTS PASSED: Genesis, rolling SHA-256, ladder replay, and genuine tamper detection verified.")
    return True


def load_events_source(args) -> tuple[str, list[dict], dict]:
    """Loads manifest_sha256, events, and root data dict from --file, --dev, or stdin."""
    if args.dev:
        # Query device via latchctl
        latchctl_path = os.environ.get("LATCHCTL_BIN", "./qnx/build/host-sim/latchctl")
        if not os.path.exists(latchctl_path):
            latchctl_path = "build/host-sim/latchctl"
        res = subprocess.run([latchctl_path, "-d", args.dev, "events", "--json"],
                             capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif not sys.stdin.isatty():
        content = sys.stdin.read().strip()
        if not content:
            raise ValueError("No input provided via stdin")
        data = json.loads(content)
    else:
        raise ValueError("Must specify --file, --dev, or pipe JSON via stdin")

    manifest_sha256 = data.get("manifest_sha256", "0" * 64)
    events = data.get("events", [])
    return manifest_sha256, events, data


def main():
    parser = argparse.ArgumentParser(
        description="Tamper-Evident Blackbox Event Replay & Forensics Engine for GOVERNOR"
    )
    parser.add_argument("--test", action="store_true", help="Run standalone self-test with genuine tamper detection")
    parser.add_argument("--verify", action="store_true", help="Verify cryptographic hash chain continuity and integrity")
    parser.add_argument("--replay", action="store_true", help="Replay events and assert supervisor ladder invariants")
    parser.add_argument("--hysteresis", type=int, default=25, help="Consecutive clean frames required for ladder promotion (default: 25)")
    parser.add_argument("--json", action="store_true", help="Output JSON with rolling hash chain attached")
    parser.add_argument("--file", type=str, help="Path to input JSON file from latchctl events --json")
    parser.add_argument("--dev", type=str, help="Device node to query via latchctl (e.g. /dev/latch/actuator)")

    args = parser.parse_args()

    if args.test:
        if not run_selftest():
            sys.exit(1)
        sys.exit(0)

    try:
        manifest_sha256, events, root_data = load_events_source(args)
    except Exception as exc:
        print(f"Error loading event source: {exc}", file=sys.stderr)
        sys.exit(1)

    exit_code = 0

    if args.verify:
        expected_terminal = root_data.get("terminal_hash")
        expected_count = root_data.get("count")
        expected_genesis = root_data.get("genesis_hash")
        ok, msg = verify_hash_chain(
            manifest_sha256,
            events,
            expected_terminal_hash=expected_terminal,
            expected_count=expected_count,
            expected_genesis_hash=expected_genesis
        )
        if ok:
            print(f"[VERIFY PASS] {msg}")
        else:
            print(f"[VERIFY FAIL] {msg}", file=sys.stderr)
            exit_code = 1

    if args.replay:
        ok, msg, stats = replay_events(events, hysteresis_clean_frames=args.hysteresis)
        if ok:
            print(f"[REPLAY PASS] {msg}")
            print(f"Replay Summary: {stats['total_events']} events | {stats['commands']} commands | "
                  f"{stats['heartbeats']} heartbeats | {stats['demotions']} demotions | "
                  f"{stats['promotions']} promotions | {stats['hard_faults']} hard faults")
        else:
            print(f"[REPLAY FAIL] {msg}", file=sys.stderr)
            exit_code = 1

    if args.json or (not args.verify and not args.replay):
        genesis_hash, chained_events = build_hash_chain(manifest_sha256, events)
        output = {
            "manifest_sha256": manifest_sha256,
            "genesis_hash": genesis_hash.hex(),
            "count": len(chained_events),
            "terminal_hash": chained_events[-1]["hash"] if chained_events else genesis_hash.hex(),
            "events": chained_events
        }
        print(json.dumps(output, indent=2))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
