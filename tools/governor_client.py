#!/usr/bin/env python3
"""governor_client.py — Python Client SDK for GOVERNOR on QNX 8.0.

Pure Python standard library SDK (no external dependencies).
Implements Wire Protocol v2 encoding/decoding, IEEE 802.3 CRC-32 checksums,
advancing coherence leases, Anthropic poka-yoke actuation proposal,
and comprehensive cyber-physical fault injection capabilities.
"""

from __future__ import annotations

import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import zlib


# =============================================================================
# Protocol Constants (aligned with latch/qnx/latch_protocol.h & governor_wire.h)
# =============================================================================

WIRE_MAGIC: int = 0x4C415448  # 'LATH' (LE)
WIRE_VERSION_V1: int = 1
WIRE_VERSION_V2: int = 2
WIRE_DEFAULT_JOINT: int = 0
WIRE_FRAME_SIZE: int = 32

# Wire Kind definitions
KIND_CMD: int = 0          # Legacy/v1 command payload
KIND_HEARTBEAT: int = 1    # Liveness heartbeat renewal frame
KIND_CMD_V2: int = 2       # Supervised command frame with unit metadata
KIND_SHRINK_REQ: int = 3   # Dynamic envelope constraint tighten request

# Agent State definitions (uint8)
AGENT_STATE_BOOT: int = 0
AGENT_STATE_NOMINAL: int = 1
AGENT_STATE_DEGRADED: int = 2
AGENT_STATE_RECOVERING: int = 3
AGENT_STATE_UNKNOWN: int = 4

# Fault Bit definitions (latch_protocol.h:145-161)
FAULT_NONE: int = 0
FAULT_MAGIC: int = 1 << 0       # 0x0001: Bad magic, version, or joint
FAULT_CRC: int = 1 << 1         # 0x0002: IEEE 802.3 CRC32 mismatch
FAULT_SEQ: int = 1 << 2         # 0x0004: Sequence gap or replay
FAULT_NAN: int = 1 << 3         # 0x0008: u_mrad == INT32_MIN (-2147483648)
FAULT_RESERVED: int = 1 << 4    # 0x0010: Illegal field combination / reserved bits
FAULT_KEEPOUT: int = 1 << 5     # 0x0020: Enters or crosses keep-out zone
FAULT_BOUNDS: int = 1 << 6      # 0x0040: Outside manifest envelope limits
FAULT_RATE: int = 1 << 7        # 0x0080: Exceeds rate limit (v_max / token bucket)
FAULT_WATCHDOG: int = 1 << 8    # 0x0100: Channel silent past watchdog ticks
FAULT_I2C: int = 1 << 9         # 0x0200: Actuator bus failure
FAULT_OPERATOR: int = 1 << 10   # 0x0400: Operator emergency hold
FAULT_EPERM: int = 1 << 11      # 0x0800: Unauthorized actuator devctl
FAULT_UNIT: int = 1 << 12       # 0x1000: Unknown or unmapped unit ID
FAULT_HEARTBEAT: int = 1 << 13  # 0x2000: Deadman lease expiry or frozen coherence
FAULT_WIDEN: int = 1 << 14      # 0x4000: Envelope widening veto
FAULT_DOSE: int = 1 << 15       # 0x8000: Dose rate exceeds rung limit or envelope

FAULT_WIRE_MASK: int = (FAULT_MAGIC | FAULT_CRC | FAULT_SEQ | FAULT_NAN | FAULT_RESERVED)
FAULT_ENVELOPE_MASK: int = (FAULT_KEEPOUT | FAULT_BOUNDS | FAULT_RATE)

# Governor Supervisory Ladder Rungs (governor_policy.h:46-53)
RUNG_HP: int = 0         # High Performance (Full authority)
RUNG_ADVISE: int = 1     # Advisory (Logged deviations, nominal motion)
RUNG_CLAMP: int = 2      # Clamped velocity (e.g. clamp_max_step)
RUNG_SLOW: int = 3       # Scaled velocity (25% nominal limit)
RUNG_SAFE_STOP: int = 4  # Controlled deceleration to safe standstill
RUNG_LATCH: int = 5      # Hard latch (HOLD mode, zero motion, manual release required)

RUNG_NAMES: Dict[int, str] = {
    RUNG_HP: "HP",
    RUNG_ADVISE: "ADVISE",
    RUNG_CLAMP: "CLAMP",
    RUNG_SLOW: "SLOW",
    RUNG_SAFE_STOP: "SAFE_STOP",
    RUNG_LATCH: "LATCH",
}

# Modulo 2^24 coherence constant
COHERENCE_MODULO: int = 1 << 24  # 16,777,216


# =============================================================================
# CRC-32 & Framing Primitives
# =============================================================================

def compute_wire_v2_crc(header_16: bytes, metadata_12: bytes) -> int:
    """Compute IEEE 802.3 CRC-32 over [0..16) || [20..32) (28 bytes total).

    Uses reflected polynomial 0xEDB88320 (identical to standard zlib.crc32).
    """
    if len(header_16) != 16 or len(metadata_12) != 12:
        raise ValueError(
            f"CRC input lengths mismatch: header={len(header_16)} (expected 16), "
            f"metadata={len(metadata_12)} (expected 12)"
        )
    return zlib.crc32(header_16 + metadata_12) & 0xFFFFFFFF


def pack_wire_v2_frame(
    kind: int,
    seq: int,
    coherence: int,
    u_mrad: int = 0,
    confidence_q8: int = 255,
    agent_state: int = AGENT_STATE_NOMINAL,
    unit_id: int = 0,
    *,
    corrupt_crc: bool = False,
    crc_override: Optional[int] = None,
    corrupt_reserved: bool = False,
    magic_override: Optional[int] = None,
    version_override: Optional[int] = None,
    joint_override: Optional[int] = None,
) -> bytes:
    """Packs exactly 32 bytes according to docs/GOVERNOR_PROTOCOL_V2.md.

    Layout:
      [0..4)   uint32 LE magic (0x4C415448)
      [4..6)   uint16 LE version (2)
      [6]      uint8     joint index (0)
      [7]      uint8     kind (0=CMD, 1=HEARTBEAT, 2=CMD_V2, 3=SHRINK_REQ)
      [8..12)  uint32 LE sequence number
      [12..16) int32  LE payload (u_mrad or shrink_v)
      [16..20) uint32 LE IEEE 802.3 CRC-32 over [0..16) || [20..32)
      [20..24) uint32 LE confidence_q8 (0..255)
      [24]     uint8     agent_state
      [25..28) uint24 LE coherence_ctr (modulo 2^24)
      [28..32) uint32 LE unit_id (for CMD_V2 non-zero)
    """
    magic = WIRE_MAGIC if magic_override is None else magic_override
    version = WIRE_VERSION_V2 if version_override is None else version_override
    joint = WIRE_DEFAULT_JOINT if joint_override is None else joint_override

    header = struct.pack(
        "<IHBBIi",
        magic & 0xFFFFFFFF,
        version & 0xFFFF,
        joint & 0xFF,
        kind & 0xFF,
        seq & 0xFFFFFFFF,
        u_mrad,
    )

    coh_bytes = (coherence & 0xFFFFFF).to_bytes(3, "little")
    unit_bytes = (unit_id & 0xFFFFFFFF).to_bytes(4, "little")
    metadata = struct.pack("<IB", confidence_q8 & 0xFF, agent_state & 0xFF) + coh_bytes + unit_bytes

    if corrupt_reserved:
        # Corrupt the 3 high bytes of confidence (must be 0)
        metadata = struct.pack("<I", (confidence_q8 & 0xFF) | 0xFF000000) + metadata[4:]

    if crc_override is not None:
        crc = crc_override & 0xFFFFFFFF
    else:
        crc = compute_wire_v2_crc(header, metadata)
        if corrupt_crc:
            crc ^= 0x00000001

    crc_bytes = struct.pack("<I", crc)
    frame = header + crc_bytes + metadata

    if len(frame) != WIRE_FRAME_SIZE:
        raise AssertionError(f"Packed frame size is {len(frame)} bytes, expected {WIRE_FRAME_SIZE}")
    return frame


def unpack_wire_v2_frame(frame: bytes) -> Dict[str, Any]:
    """Unpack a 32-byte Wire v2 frame and validate its fields and CRC-32."""
    if len(frame) != WIRE_FRAME_SIZE:
        return {
            "valid": False,
            "faults": FAULT_MAGIC,
            "error": f"Invalid frame length: {len(frame)} (expected {WIRE_FRAME_SIZE})",
        }

    magic, version, joint, kind, seq, u_mrad = struct.unpack("<IHBBIi", frame[0:16])
    crc = struct.unpack("<I", frame[16:20])[0]
    conf_raw, agent_state = struct.unpack("<IB", frame[20:25])
    coherence = int.from_bytes(frame[25:28], "little")
    unit_id = struct.unpack("<I", frame[28:32])[0]

    computed_crc = compute_wire_v2_crc(frame[0:16], frame[20:32])
    crc_ok = crc == computed_crc

    faults = FAULT_NONE
    if (
        magic != WIRE_MAGIC
        or version != WIRE_VERSION_V2
        or joint != WIRE_DEFAULT_JOINT
        or kind > KIND_SHRINK_REQ
    ):
        faults |= FAULT_MAGIC

    if not crc_ok:
        faults |= FAULT_CRC

    if conf_raw > 255 or agent_state > 4:
        faults |= FAULT_RESERVED

    # Structural kind constraints from governor_wire.c
    if kind == KIND_CMD:
        if conf_raw != 0 or agent_state != 0 or coherence != 0 or unit_id != 0:
            faults |= FAULT_RESERVED
    elif kind == KIND_HEARTBEAT:
        if u_mrad != 0 or conf_raw != 0 or unit_id != 0:
            faults |= FAULT_RESERVED
    elif kind == KIND_CMD_V2:
        if unit_id == 0:
            faults |= FAULT_RESERVED
    elif kind == KIND_SHRINK_REQ:
        if u_mrad < 0 or conf_raw == 0 or unit_id != 0:
            faults |= FAULT_RESERVED

    return {
        "valid": faults == FAULT_NONE,
        "faults": faults,
        "magic": magic,
        "version": version,
        "joint": joint,
        "kind": kind,
        "kind_name": {
            KIND_CMD: "CMD",
            KIND_HEARTBEAT: "HEARTBEAT",
            KIND_CMD_V2: "CMD_V2",
            KIND_SHRINK_REQ: "SHRINK_REQ",
        }.get(kind, "UNKNOWN"),
        "seq": seq,
        "u_mrad": u_mrad,
        "crc": crc,
        "crc_ok": crc_ok,
        "confidence_q8": conf_raw & 0xFF,
        "agent_state": agent_state,
        "coherence_ctr": coherence,
        "unit_id": unit_id,
        "raw_bytes": frame,
    }


def pack_wire_v1_silence_frame(seq: int = 0) -> bytes:
    """Pack a 32-byte wire v1 simulation harness silence frame (flags=0x80).

    Used in simulation pipelines to simulate elapsed idle ticks without byte traffic.
    """
    header = struct.pack("<IHBBii", WIRE_MAGIC, WIRE_VERSION_V1, WIRE_DEFAULT_JOINT, 0x80, seq, 0)
    crc = zlib.crc32(header) & 0xFFFFFFFF
    return header + struct.pack("<I", crc) + (b"\x00" * 12)


# =============================================================================
# GovernorClient SDK
# =============================================================================

class GovernorClient:
    """High-level Python SDK for sending Wire v2 frames to the QNX 8.0 Governor.

    Supports pluggable transports:
      - None / memory buffer
      - File or IO stream (e.g. sys.stdout.buffer, open file)
      - Integer file descriptor (os.write)
      - Named pipe / FIFO path or device (e.g. '/tmp/latch.pipe' or '/dev/hvc0')
      - TCP / UNIX socket (socket.socket or "host:port" / "unix:/path")
      - Subprocess stdin (subprocess.Popen)
      - Custom callable callback (fn(bytes))

    Adheres to the Anthropic poka-yoke actuation pattern:
    Actuators are proposed strictly via `propose()`, with monotonic sequence
    and advancing 24-bit coherence counter management handled automatically.
    """

    def __init__(
        self,
        transport: Any = None,
        *,
        initial_seq: int = 1,
        initial_coherence: int = 0,
        auto_flush: bool = True,
    ) -> None:
        self.seq: int = initial_seq
        self.coherence: int = initial_coherence & 0xFFFFFF
        self.auto_flush: bool = auto_flush
        self.transport_target: Any = transport
        self.transport: Any = None
        self._owns_transport: bool = False
        self.emitted_frames: List[bytes] = []
        self._lock: threading.Lock = threading.Lock()

        if transport is not None:
            self._init_transport(transport)

    def _init_transport(self, target: Any) -> None:
        """Resolve and open the requested transport."""
        if isinstance(target, (str, pathlib.Path)):
            path_str = str(target)
            if path_str.startswith("tcp://"):
                host_port = path_str[6:].split(":")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host_port[0], int(host_port[1])))
                self.transport = sock
                self._owns_transport = True
            elif path_str.startswith("unix://"):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(path_str[7:])
                self.transport = sock
                self._owns_transport = True
            else:
                # File, FIFO, or device
                fd = os.open(path_str, os.O_WRONLY | os.O_NONBLOCK if os.path.exists(path_str) else os.O_WRONLY)
                self.transport = fd
                self._owns_transport = True
        elif isinstance(target, socket.socket):
            self.transport = target
        elif isinstance(target, int):
            self.transport = target
        elif hasattr(target, "stdin") and target.stdin is not None:
            # Subprocess Popen
            self.transport = target.stdin
        elif hasattr(target, "write") or callable(target):
            self.transport = target
        else:
            raise TypeError(f"Unsupported transport type: {type(target)}")

    def connect(self) -> "GovernorClient":
        """Re-open or connect transport if needed."""
        if self.transport is None and self.transport_target is not None:
            self._init_transport(self.transport_target)
        return self

    def close(self) -> None:
        """Close opened transport resources."""
        if self._owns_transport and self.transport is not None:
            try:
                if isinstance(self.transport, int):
                    os.close(self.transport)
                elif hasattr(self.transport, "close"):
                    self.transport.close()
            except Exception:
                pass
            self.transport = None

    def __enter__(self) -> "GovernorClient":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def advance_coherence(self, step: int = 1) -> int:
        """Advance the 24-bit coherence counter modulo 2^24."""
        with self._lock:
            self.coherence = (self.coherence + step) & 0xFFFFFF
            return self.coherence

    def advance_seq(self, step: int = 1) -> int:
        """Advance the sequence number monotonically."""
        with self._lock:
            current = self.seq
            self.seq = (self.seq + step) & 0xFFFFFFFF
            return current

    def emit(self, frame: bytes) -> None:
        """Emit a 32-byte frame across the configured transport."""
        if len(frame) != WIRE_FRAME_SIZE:
            raise ValueError(f"Frame length {len(frame)} != {WIRE_FRAME_SIZE}")

        with self._lock:
            self.emitted_frames.append(frame)

            if self.transport is None:
                return

            if callable(self.transport) and not hasattr(self.transport, "write"):
                self.transport(frame)
            elif isinstance(self.transport, int):
                os.write(self.transport, frame)
            elif isinstance(self.transport, socket.socket):
                self.transport.sendall(frame)
            elif hasattr(self.transport, "write"):
                self.transport.write(frame)
                if self.auto_flush and hasattr(self.transport, "flush"):
                    self.transport.flush()

    def flush(self) -> None:
        """Flush the transport buffer if applicable."""
        with self._lock:
            if self.transport is not None and hasattr(self.transport, "flush"):
                try:
                    self.transport.flush()
                except Exception:
                    pass

    def pack_frame(
        self,
        kind: int,
        u_mrad: int = 0,
        confidence_q8: int = 255,
        agent_state: int = AGENT_STATE_NOMINAL,
        unit_id: int = 0,
        *,
        seq_override: Optional[int] = None,
        coherence_override: Optional[int] = None,
        corrupt_crc: bool = False,
        corrupt_reserved: bool = False,
        magic_override: Optional[int] = None,
        version_override: Optional[int] = None,
        joint_override: Optional[int] = None,
    ) -> bytes:
        """Pack a 32-byte Wire v2 frame with optional fault-injection overrides."""
        with self._lock:
            seq = self.seq if seq_override is None else seq_override
            coh = self.coherence if coherence_override is None else coherence_override

            return pack_wire_v2_frame(
                kind=kind,
                seq=seq,
                coherence=coh,
                u_mrad=u_mrad,
                confidence_q8=confidence_q8,
                agent_state=agent_state,
                unit_id=unit_id,
                corrupt_crc=corrupt_crc,
                corrupt_reserved=corrupt_reserved,
                magic_override=magic_override,
                version_override=version_override,
                joint_override=joint_override,
            )

    # -------------------------------------------------------------------------
    # High-Level Semantic Methods
    # -------------------------------------------------------------------------

    def send_silence(self, **pack_kwargs) -> bytes:
        """Send a simulation harness silence frame (flags=0x80) simulating an idle tick."""
        seq = pack_kwargs.pop("seq_override", None)
        if seq is None:
            seq = self.advance_seq(1)
        frame = pack_wire_v1_silence_frame(seq)
        self.emit(frame)
        return frame

    def send_heartbeat(
        self,
        agent_state: int = AGENT_STATE_NOMINAL,
        advance_coherence: bool = True,
        **pack_kwargs,
    ) -> bytes:
        """Send kind=1 HEARTBEAT frame.

        Advances the 24-bit coherence counter by default to refresh the deadman lease.
        Heartbeats do NOT count toward recovery streaks.
        """
        seq = pack_kwargs.pop("seq_override", None)
        if seq is None:
            seq = self.advance_seq(1)

        coh = pack_kwargs.pop("coherence_override", None)
        if coh is None and advance_coherence:
            coh = self.advance_coherence(1)

        frame = self.pack_frame(
            kind=KIND_HEARTBEAT,
            u_mrad=0,
            confidence_q8=0,
            agent_state=agent_state,
            unit_id=0,
            seq_override=seq,
            coherence_override=coh,
            **pack_kwargs,
        )
        self.emit(frame)
        return frame

    def send_command(
        self,
        u_mrad: int,
        confidence_q8: int = 255,
        unit_id: int = 1,
        agent_state: int = AGENT_STATE_NOMINAL,
        advance_coherence: bool = True,
        **pack_kwargs,
    ) -> bytes:
        """Send kind=2 CMD_V2 supervised command frame."""
        seq = pack_kwargs.pop("seq_override", None)
        if seq is None:
            seq = self.advance_seq(1)

        coh = pack_kwargs.pop("coherence_override", None)
        if coh is None and advance_coherence:
            coh = self.advance_coherence(1)

        frame = self.pack_frame(
            kind=KIND_CMD_V2,
            u_mrad=u_mrad,
            confidence_q8=confidence_q8,
            agent_state=agent_state,
            unit_id=unit_id,
            seq_override=seq,
            coherence_override=coh,
            **pack_kwargs,
        )
        self.emit(frame)
        return frame

    def send_shrink_request(
        self,
        shrink_v: int,
        shrink_scale_q8: int = 128,
        agent_state: int = AGENT_STATE_NOMINAL,
        advance_coherence: bool = True,
        **pack_kwargs,
    ) -> bytes:
        """Send kind=3 SHRINK_REQ request.

        Requests a tighter velocity/scale limit. Widening requests are vetoed.
        """
        seq = pack_kwargs.pop("seq_override", None)
        if seq is None:
            seq = self.advance_seq(1)

        coh = pack_kwargs.pop("coherence_override", None)
        if coh is None and advance_coherence:
            coh = self.advance_coherence(1)

        frame = self.pack_frame(
            kind=KIND_SHRINK_REQ,
            u_mrad=shrink_v,
            confidence_q8=shrink_scale_q8,
            agent_state=agent_state,
            unit_id=0,
            seq_override=seq,
            coherence_override=coh,
            **pack_kwargs,
        )
        self.emit(frame)
        return frame

    def propose(
        self,
        u_mrad: int,
        confidence_q8: int = 255,
        unit_id: int = 1,
        agent_state: int = AGENT_STATE_NOMINAL,
    ) -> bytes:
        """Anthropic poka-yoke pattern: high-level actuator propose method.

        The physical AI agent calls propose(u) instead of directly mutating hardware.
        """
        return self.send_command(
            u_mrad=u_mrad,
            confidence_q8=confidence_q8,
            unit_id=unit_id,
            agent_state=agent_state,
            advance_coherence=True,
        )


# =============================================================================
# Self-Test Verification
# =============================================================================

def self_test() -> None:
    """Run SDK self-tests to verify byte layout, CRC32, and framing invariants."""
    print("[GOVERNOR_CLIENT_TEST] Running SDK verification...")

    client = GovernorClient()

    # 1. Warmup heartbeat frame check
    hb = client.send_heartbeat()
    assert len(hb) == 32, f"Heartbeat length {len(hb)} != 32"
    parsed_hb = unpack_wire_v2_frame(hb)
    assert parsed_hb["valid"] is True, f"Heartbeat invalid: {parsed_hb}"
    assert parsed_hb["kind"] == KIND_HEARTBEAT
    assert parsed_hb["seq"] == 1
    assert parsed_hb["coherence_ctr"] == 1
    assert parsed_hb["crc_ok"] is True
    print("  [PASS] Heartbeat framing and IEEE 802.3 CRC32 verified")

    # 2. Command frame check
    cmd = client.send_command(u_mrad=150, confidence_q8=200, unit_id=1)
    assert len(cmd) == 32
    parsed_cmd = unpack_wire_v2_frame(cmd)
    assert parsed_cmd["valid"] is True
    assert parsed_cmd["kind"] == KIND_CMD_V2
    assert parsed_cmd["seq"] == 2
    assert parsed_cmd["coherence_ctr"] == 2
    assert parsed_cmd["u_mrad"] == 150
    assert parsed_cmd["confidence_q8"] == 200
    assert parsed_cmd["unit_id"] == 1
    print("  [PASS] Supervised CMD_V2 packing and unpacking verified")

    # 3. Shrink request frame check
    shrink = client.send_shrink_request(shrink_v=25, shrink_scale_q8=128)
    assert len(shrink) == 32
    parsed_shrink = unpack_wire_v2_frame(shrink)
    assert parsed_shrink["valid"] is True
    assert parsed_shrink["kind"] == KIND_SHRINK_REQ
    assert parsed_shrink["seq"] == 3
    assert parsed_shrink["coherence_ctr"] == 3
    assert parsed_shrink["u_mrad"] == 25
    assert parsed_shrink["confidence_q8"] == 128
    print("  [PASS] SHRINK_REQ packing and unpacking verified")

    # 4. Fault injection: CRC corruption
    corrupt_crc_frame = client.pack_frame(
        kind=KIND_CMD_V2, u_mrad=100, unit_id=1, corrupt_crc=True
    )
    parsed_crc_fault = unpack_wire_v2_frame(corrupt_crc_frame)
    assert parsed_crc_fault["valid"] is False
    assert parsed_crc_fault["faults"] & FAULT_CRC != 0
    print("  [PASS] CRC fault injection properly detected")

    # 5. Fault injection: Reserved bits corruption
    corrupt_res_frame = client.pack_frame(
        kind=KIND_CMD_V2, u_mrad=100, unit_id=1, corrupt_reserved=True
    )
    parsed_res_fault = unpack_wire_v2_frame(corrupt_res_frame)
    assert parsed_res_fault["valid"] is False
    assert parsed_res_fault["faults"] & FAULT_RESERVED != 0
    print("  [PASS] Reserved field corruption properly detected")

    # 6. Coherence 24-bit modulo wrap
    wrap_client = GovernorClient(initial_coherence=0xFFFFFF)
    wrap_client.advance_coherence(1)
    assert wrap_client.coherence == 0, f"Expected 0 on wrap, got {wrap_client.coherence}"
    wrap_client.advance_coherence(2)
    assert wrap_client.coherence == 2
    print("  [PASS] Modulo 2^24 coherence counter wrap verified")

    # 7. Anthropic poka-yoke propose
    prop = client.propose(u_mrad=-50, confidence_q8=255, unit_id=1)
    assert len(prop) == 32
    parsed_prop = unpack_wire_v2_frame(prop)
    assert parsed_prop["valid"] is True
    assert parsed_prop["u_mrad"] == -50
    print("  [PASS] Poka-yoke propose() verified")

    print("[GOVERNOR_CLIENT_TEST] All 7 tests PASSED.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        self_test()
    else:
        print("Usage: governor_client.py [--test]")
