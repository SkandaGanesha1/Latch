#!/usr/bin/env python3
"""Regression checks for replay completeness and checkpoint handling."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import gov_replay as replay


class ReplayHardeningTest(unittest.TestCase):
    def test_empty_and_invalid_digest_fail(self):
        self.assertFalse(replay.verify_hash_chain("00" * 32, [])[0])
        with self.assertRaises(ValueError):
            replay.compute_genesis_hash("00")
        p = subprocess.run([sys.executable, replay.__file__, "--verify"],
                           input="{}", text=True, capture_output=True)
        self.assertNotEqual(p.returncode, 0)

    def test_independent_checkpoint_detects_resealed_tail(self):
        digest = "ab" * 32
        event = replay.unpack_event(bytes(62))
        _, chained = replay.build_hash_chain(digest, [event])
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.json"
            anchor = Path(tmp) / "checkpoint.json"
            source.write_text(json.dumps({"manifest_sha256": digest, "events": chained}))
            anchor.write_text(json.dumps({"manifest_sha256": digest, "count": 1,
                                          "terminal_hash": chained[-1]["hash"]}))
            command = [sys.executable, replay.__file__, "--verify", "--file", str(source),
                       "--checkpoint", str(anchor)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            altered = dict(event, tick=1)
            altered.pop("bytes_hex")
            _, resealed = replay.build_hash_chain(digest, [altered])
            source.write_text(json.dumps({"manifest_sha256": digest, "events": resealed}))
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_device_pagination_and_overwrite_detection(self):
        digest = "ab" * 32
        calls = []

        def fetch(command, **kwargs):
            self.assertEqual(command[3:6], ["--", "events", "--json"])
            start = int(command[-1])
            calls.append(start)
            page = {"start_index": start, "latest_index": 130, "record_version": 1,
                    "manifest_sha256": digest,
                    "events": [{"event_index": i} for i in range(start, min(start + 64, 130))]}
            page["count"] = len(page["events"])
            return SimpleNamespace(stdout=json.dumps(page))

        args = SimpleNamespace(dev="/dev/latch/actuator", file=None)
        with patch.dict(os.environ, {"LATCHCTL_BIN": "/fake/latchctl"}), patch.object(replay.subprocess, "run", side_effect=fetch):
            _, events, _ = replay.load_events_source(args)
        self.assertEqual(calls, [0, 64, 128])
        self.assertEqual(len(events), 130)

        def overwritten(command, **kwargs):
            response = fetch(command, **kwargs)
            page = json.loads(response.stdout)
            if int(command[-1]) > 0:
                page["start_index"] += 1
            return SimpleNamespace(stdout=json.dumps(page))

        with patch.dict(os.environ, {"LATCHCTL_BIN": "/fake/latchctl"}), patch.object(replay.subprocess, "run", side_effect=overwritten):
            with self.assertRaises(ValueError):
                replay.load_events_source(args)


if __name__ == "__main__":
    unittest.main()
