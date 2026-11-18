#!/usr/bin/env python3
"""Negative parser tests for the opt-in, disabled schema-3 GOVERNOR contract."""

import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


def run(binary: pathlib.Path, path: pathlib.Path, should_pass: bool, label: str) -> None:
    result = subprocess.run([str(binary), "manifest-verify", str(path)],
                            capture_output=True, text=True)
    passed = result.returncode == 0
    if passed != should_pass:
        print(f"[GOVERNOR_MANIFEST] FAIL {label}: rc={result.returncode}\n"
              f"{result.stdout}{result.stderr}", file=sys.stderr)
        raise SystemExit(1)
    print(f"[GOVERNOR_MANIFEST] PASS {label}")


def write_case(directory: pathlib.Path, name: str, data: bytes) -> pathlib.Path:
    path = directory / f"{name}.manifest"
    path.write_bytes(data)
    sidecar = hashlib.sha256(data).hexdigest() + "\n"
    pathlib.Path(str(path) + ".sha256").write_text(sidecar, encoding="ascii")
    return path


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: governor_manifest_test.py LATCHCTL VALID_MANIFEST")
    binary = pathlib.Path(sys.argv[1]).resolve()
    original = pathlib.Path(sys.argv[2]).read_bytes()
    document = json.loads(original)

    with tempfile.TemporaryDirectory(prefix="latch-governor-manifest-") as temp:
        directory = pathlib.Path(temp)
        run(binary, write_case(directory, "enabled_valid", original),
            True, "enabled schema-3 contract with wire v2")

        disabled = copy.deepcopy(document)
        disabled["governor"]["enabled"] = 0
        disabled["protocol"].update({"version": 1, "crc": "ieee32", "coverage": 16})
        run(binary, write_case(directory, "disabled_valid",
                               json.dumps(disabled, indent=2).encode()),
            True, "disabled schema-3 contract with wire v1")

        mismatch = copy.deepcopy(document)
        mismatch["protocol"].update({"version": 1, "crc": "ieee32", "coverage": 16})
        run(binary, write_case(directory, "enabled_v1_mismatch",
                               json.dumps(mismatch, indent=2).encode()),
            False, "enabled contract rejects mismatched protocol v1")

        unknown = copy.deepcopy(document)
        unknown["governor"]["future_policy"] = 1
        run(binary, write_case(directory, "unknown",
                               json.dumps(unknown, indent=2).encode()),
            False, "unknown governor key rejected")

        duplicate = original.decode("utf-8").replace(
            '"enabled": 1,\n      "canonical_unit_id"',
            '"enabled": 1,\n      "enabled": 1,\n      "canonical_unit_id"', 1)
        run(binary, write_case(directory, "duplicate", duplicate.encode()),
            False, "duplicate governor key rejected")

        missing = copy.deepcopy(document)
        del missing["governor"]["deadman"]["warmup_heartbeats"]
        run(binary, write_case(directory, "missing",
                               json.dumps(missing, indent=2).encode()),
            False, "missing required governor setting rejected")

        bad_id = copy.deepcopy(document)
        bad_id["governor"]["units"]["canonical_unit_id"] = 0
        run(binary, write_case(directory, "unit_id",
                               json.dumps(bad_id, indent=2).encode()),
            False, "invalid canonical unit ID rejected")

        mismatched_units = copy.deepcopy(document)
        mismatched_units["governor"]["units"]["conversion_denominators"] = [57]
        run(binary, write_case(directory, "unit_arrays", json.dumps(mismatched_units).encode()),
            False, "mismatched unit conversion arrays rejected")

        disabled_v2 = copy.deepcopy(disabled)
        disabled_v2["protocol"].update({"version": 2, "crc": "ieee32-v2", "coverage": 28})
        run(binary, write_case(directory, "disabled_v2",
                               json.dumps(disabled_v2, indent=2).encode()),
            False, "disabled GOVERNOR cannot select protocol v2")

        overlapping_ko = copy.deepcopy(document)
        overlapping_ko["envelope"]["keepout"] = [
            {"lo_mrad": 250, "hi_mrad": 650, "label": "PERSON"},
            {"lo_mrad": 600, "hi_mrad": 800, "label": "OBSTACLE"},
        ]
        run(binary, write_case(directory, "overlapping_keepout",
                               json.dumps(overlapping_ko, indent=2).encode()),
            False, "overlapping keep-out intervals rejected")

        # Advisory mask: bit 15 (DOSE) is allowed (36864 = bit 12 UNIT + bit 15 DOSE)
        dose_mask = copy.deepcopy(document)
        dose_mask["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15)
        run(binary, write_case(directory, "dose_advisory_mask",
                               json.dumps(dose_mask, indent=2).encode()),
            True, "advisory mask with DOSE bit admitted")

        # Advisory mask: unauthorized bit (bit 5 KEEPOUT = 32) rejected
        bad_mask = copy.deepcopy(document)
        bad_mask["governor"]["ladder"]["advise_fault_mask"] = (1 << 12) | (1 << 15) | (1 << 5)
        run(binary, write_case(directory, "invalid_advisory_mask",
                               json.dumps(bad_mask, indent=2).encode()),
            False, "advisory mask with unauthorized bits rejected")

        # Syringe governor manifest contract verification if present
        syringe_path = pathlib.Path(sys.argv[2]).parent / "syringe_governor.manifest"
        if syringe_path.exists():
            run(binary, syringe_path, True, "syringe governor schema-3 contract verified")
            syringe_doc = json.loads(syringe_path.read_bytes())
            bad_syringe = copy.deepcopy(syringe_doc)
            bad_syringe["governor"]["ladder"]["clamp_max_step"] = 500  # > v_max (200)
            run(binary, write_case(directory, "bad_syringe_step",
                                   json.dumps(bad_syringe, indent=2).encode()),
                False, "syringe contract clamp_max_step exceeding v_max rejected")


if __name__ == "__main__":
    main()
