#!/usr/bin/env python3
"""Host-only tests for supervisor event correlation and replay isolation."""
import concurrent.futures
import json
import pathlib
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from governor_e2e import frame_v2, HEARTBEAT, CMD_V2
from governor_host_replay import HostReplay

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / 'qnx/contracts/governor_servo.manifest'


def warm(harness):
    for seq in range(1, harness.warmup_heartbeats + 1):
        result = harness.step(frame_v2(HEARTBEAT, seq, seq, agent_state=0))
        assert result['seq'] == seq and result['verdict'] == 2


class HostReplayTest(unittest.TestCase):
    def test_correlated_accept_and_keepout_veto(self):
        h = HostReplay(MANIFEST)
        warm(h)
        seq = h.warmup_heartbeats + 1
        accepted = h.step(frame_v2(CMD_V2, seq, seq, u=10, confidence=255,
                                   unit_id=h.canonical_unit_id))
        self.assertEqual((accepted['seq'], accepted['verdict'], accepted['fault_bits']), (seq, 1, 0))
        seq += 1
        rejected = h.step(frame_v2(CMD_V2, seq, seq, u=450, confidence=255,
                                   unit_id=h.canonical_unit_id))
        self.assertEqual(rejected['seq'], seq)
        self.assertEqual(rejected['verdict'], 4)
        self.assertTrue(rejected['fault_bits'] & (1 << 5))
        self.assertEqual(rejected['theta_applied'], accepted['theta_applied'])

    def test_invalid_frame_and_sequence_leave_transcript_unchanged(self):
        h = HostReplay(MANIFEST)
        frame = frame_v2(HEARTBEAT, 1, 1, agent_state=0)
        h.step(frame)
        with self.assertRaises(ValueError): h.step(frame)
        with self.assertRaises(ValueError): h.step(b'x')
        self.assertEqual(len(h._frames), 1)

    def test_timeout_and_mismatched_supervisor_event_fail_closed(self):
        h = HostReplay(MANIFEST)
        frame = frame_v2(HEARTBEAT, 1, 1, agent_state=0)
        with patch('governor_host_replay.subprocess.run', side_effect=subprocess.TimeoutExpired('ingest', 1)):
            with self.assertRaises(RuntimeError): h.step(frame)
        self.assertEqual(len(h._frames), 0)

        def mocked_run(args, **kwargs):
            if '--events-json' in args:
                pathlib.Path(args[args.index('--events-json') + 1]).write_text(
                    json.dumps({'events': [{'seq': 999, 'event_index': 0}]}))
            return SimpleNamespace(stdout=b'')
        with patch('governor_host_replay.subprocess.run', side_effect=mocked_run):
            with self.assertRaisesRegex(RuntimeError, 'sequence mismatch'): h.step(frame)
        self.assertEqual(len(h._frames), 0)

    def test_two_simulators_do_not_share_state_or_tempfiles(self):
        def run(target):
            h = HostReplay(MANIFEST)
            warm(h)
            seq = h.warmup_heartbeats + 1
            return h.step(frame_v2(CMD_V2, seq, seq, u=target, confidence=255,
                                   unit_id=h.canonical_unit_id))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            nominal, unsafe = list(pool.map(run, (10, 450)))
        self.assertEqual(nominal['verdict'], 1)
        self.assertEqual(unsafe['verdict'], 4)
        self.assertEqual(nominal['seq'], unsafe['seq'])


if __name__ == '__main__': unittest.main()
