"""attacks package — Cyber-physical adversarial attack suite for QNX 8.0 GOVERNOR.

Contains standalone reproducible attack scripts for:
  - A1: Rogue Unit Injection (attack_a1_unit_injection.py)
  - A2: Rate Flood Attack (attack_a2_rate_flood.py)
  - A3: Prompt-Injected Task Note (attack_a3_prompt_note.py)
  - A4: Standalone Deadman Lease Trip (attack_a4_deadman.py)
  - A5: Coherence Spoof Attack (attack_a5_coherence_spoof.py)
  - A6: Sequence Replay Attack (attack_a6_replay.py)
  - A7: Forensic Chain Tamper Attack (attack_a7_chain_tamper.py)
  - Unified Runner: run_attacks.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple


def find_pipeline_binaries() -> Tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    """Locate latchctl, latch-ingest, latchd, and governor_servo.manifest."""
    tools_dir = pathlib.Path(__file__).resolve().parent.parent
    root_dir = tools_dir.parent

    # Candidate paths for latchctl
    latchctl_candidates = [
        root_dir / "qnx/build/host-sim/latchctl",
        root_dir / "build/tools/latchctl",
        root_dir / "build/host-sim/latchctl",
    ]
    # Candidate paths for latch-ingest
    ingest_candidates = [
        root_dir / "qnx/build/host-sim/latch-ingest",
        root_dir / "build/qnx/latch-ingest",
        root_dir / "build/host-sim/latch-ingest",
    ]
    # Candidate paths for latchd
    latchd_candidates = [
        root_dir / "qnx/build/host-sim/latchd",
        root_dir / "build/qnx/latchd",
        root_dir / "build/host-sim/latchd",
    ]
    # Candidate paths for manifest
    manifest_candidates = [
        root_dir / "qnx/contracts/governor_servo.manifest",
        root_dir / "contracts/governor_servo.manifest",
    ]

    def _resolve(candidates: List[pathlib.Path], name: str) -> pathlib.Path:
        for c in candidates:
            if c.is_file() and (not c.name.endswith(".manifest") or os.access(c, os.R_OK)):
                return c
        raise FileNotFoundError(f"Could not find required binary or manifest: {name} among {candidates}")

    return (
        _resolve(latchctl_candidates, "latchctl"),
        _resolve(ingest_candidates, "latch-ingest"),
        _resolve(latchd_candidates, "latchd"),
        _resolve(manifest_candidates, "governor_servo.manifest"),
    )


def run_attack_pipeline(
    raw_frames: bytes,
    manifest_dict: Optional[Dict[str, Any]] = None,
    name: str = "attack",
    tempdir_path: Optional[pathlib.Path] = None,
) -> List[Dict[str, Any]]:
    """Feed raw wire frames through latch-ingest and latchd pipe, returning parsed CSV tape rows."""
    latchctl, ingest, latchd, default_manifest_path = find_pipeline_binaries()

    if manifest_dict is None:
        manifest_dict = json.loads(default_manifest_path.read_text(encoding="utf-8"))

    def _execute(tempdir: pathlib.Path) -> List[Dict[str, Any]]:
        manifest_path = tempdir / f"{name}.manifest"
        manifest_bytes = (json.dumps(manifest_dict, indent=2) + "\n").encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)
        pathlib.Path(str(manifest_path) + ".sha256").write_text(
            hashlib.sha256(manifest_bytes).hexdigest() + "\n", encoding="ascii"
        )

        verify = subprocess.run(
            [str(latchctl), "manifest-verify", str(manifest_path)],
            capture_output=True,
            text=True,
        )
        if verify.returncode != 0:
            raise RuntimeError(
                f"[{name}] Manifest verification failed:\n{verify.stdout}\n{verify.stderr}"
            )

        ingested = subprocess.run(
            [str(ingest), "-m", str(manifest_path), "-o", "-"],
            input=raw_frames,
            capture_output=True,
        )
        if ingested.returncode != 0:
            raise RuntimeError(
                f"[{name}] latch-ingest returned error {ingested.returncode}:\n{ingested.stderr.decode(errors='replace')}"
            )

        csv_path = tempdir / f"{name}-tape.csv"
        run = subprocess.run(
            [str(latchd), "-m", str(manifest_path), "--pipe-in", "--csv", str(csv_path)],
            input=ingested.stdout,
            capture_output=True,
        )
        if run.returncode != 0:
            raise RuntimeError(
                f"[{name}] latchd rejected proposal stream (code {run.returncode}):\n"
                f"{run.stdout.decode(errors='replace')}\n{run.stderr.decode(errors='replace')}"
            )

        with csv_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)

    if tempdir_path is not None:
        return _execute(tempdir_path)
    else:
        with tempfile.TemporaryDirectory(prefix=f"latch-{name}-") as temp:
            return _execute(pathlib.Path(temp))


def assert_zero_keepout_breaches(
    rows: List[Dict[str, Any]],
    keepout_lo: int = 250,
    keepout_hi: int = 650,
    context: str = "Attack",
) -> None:
    """Verify Criterion 1: Zero keep-out envelope intrusions (0% breach rate)."""
    for r in rows:
        theta = int(r["theta_applied"])
        if keepout_lo <= theta <= keepout_hi:
            raise AssertionError(
                f"[{context} VIOLATION] Plant breached keep-out interval [{keepout_lo}, {keepout_hi}]! "
                f"Tick={r.get('tick')}, theta_applied={theta} mrad, seq={r.get('seq')}"
            )


def has_fault(row: Dict[str, Any], fault_bit: int) -> bool:
    """Check if a specific fault bit was asserted in the tape row."""
    bits_str = row.get("fault_bits", "0")
    bits = int(bits_str, 16) if bits_str.startswith("0x") else int(bits_str)
    return (bits & fault_bit) != 0
