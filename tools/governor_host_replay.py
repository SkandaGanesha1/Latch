#!/usr/bin/env python3
"""Bounded host-simulation adapter with supervisor-produced feedback.

Each step replays all prior wire frames through latch-ingest and latchd in a
fresh process and reads the final event. It is an offline deterministic
simulation, not a running QNX target, a live link, or a wall-clock watchdog.
"""
from __future__ import annotations

import json
import pathlib
import struct
import subprocess
import tempfile


class HostReplay:
    """Replay at most 64 wire frames through the real host-sim supervisor."""

    MAX_FRAMES = 64  # host-sim event dump exports at most the newest 64 records

    def __init__(self, manifest_path: str | pathlib.Path, timeout_seconds: float = 5.0):
        self.manifest_path = pathlib.Path(manifest_path).resolve(strict=True)
        self.timeout_seconds = float(timeout_seconds)
        if not 0 < self.timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be in (0, 60]")
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        governor = self.manifest.get("governor", {})
        if governor.get("enabled") != 1 or self.manifest.get("protocol", {}).get("version") != 2:
            raise ValueError("an enabled Governor v2 manifest is required")
        self.warmup_heartbeats = int(governor["deadman"]["warmup_heartbeats"])
        self.canonical_unit_id = int(governor["units"]["canonical_unit_id"])
        self.home = int(self.manifest["envelope"]["home_mrad"])
        self._frames: list[bytes] = []
        self._root = pathlib.Path(__file__).resolve().parent.parent
        self._ingest = self._root / "qnx/build/host-sim/latch-ingest"
        self._latchd = self._root / "qnx/build/host-sim/latchd"
        if not self._ingest.is_file() or not self._latchd.is_file():
            raise FileNotFoundError("build host-sim binaries with make -C qnx host-sim")

    def step(self, frame: bytes) -> dict:
        """Return the actual final supervisor event for one v2 frame.

        A failed or uncorrelated run leaves the accumulated transcript unchanged.
        """
        if not isinstance(frame, bytes) or len(frame) != 32:
            raise ValueError("expected exactly one 32-byte v2 wire frame")
        if len(self._frames) >= self.MAX_FRAMES:
            raise ValueError("host replay event window exhausted")
        magic, version, _, _, sequence = struct.unpack_from("<IHBBI", frame)
        if magic != 0x4C415448 or version != 2:
            raise ValueError("expected v2 LATH wire frame")
        if self._frames and sequence <= struct.unpack_from("<I", self._frames[-1], 8)[0]:
            raise ValueError("host replay requires strictly increasing non-wrapping sequences")
        raw = b"".join([*self._frames, frame])
        try:
            ingest = subprocess.run([str(self._ingest), "-m", str(self.manifest_path), "-o", "-"],
                                    input=raw, capture_output=True, timeout=self.timeout_seconds, check=True)
            with tempfile.TemporaryDirectory(prefix="latch-feedback-") as tmp:
                event_path = pathlib.Path(tmp) / "events.json"
                subprocess.run([str(self._latchd), "-m", str(self.manifest_path), "--pipe-in",
                                "--events-json", str(event_path)], input=ingest.stdout,
                               capture_output=True, timeout=self.timeout_seconds, check=True)
                payload = json.loads(event_path.read_text(encoding="utf-8"))
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"supervisor replay failed: {exc}") from exc
        events = payload.get("events")
        if not isinstance(events, list) or len(events) != len(self._frames) + 1:
            raise RuntimeError("supervisor did not return one event per proposal")
        event = events[-1]
        if event.get("seq") != sequence or event.get("event_index") != len(self._frames):
            raise RuntimeError("supervisor feedback sequence mismatch")
        self._frames.append(frame)
        return {
            "seq": sequence,
            "theta_applied": event["theta_applied_mrad"],
            "mode": event["mode"],
            "fault_bits": event["fault_bits"],
            "rung": event["rung_after"],
            "verdict": event["verdict"],
            "tick": event["tick"],
            "source": "host-sim replay; no real-time lease observation",
        }
