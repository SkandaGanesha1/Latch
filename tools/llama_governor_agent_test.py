#!/usr/bin/env python3
"""Tests for untrusted model responses and feedback sequencing."""
import json
import unittest
from unittest.mock import patch

from governor_client import unpack_wire_v2_frame
from llama_governor_agent import run_iterations, validate_action


def command(value):
    return json.dumps({'tool': 'propose_motion', 'value': value, 'unit_id': 1, 'confidence_q8': 255})


class FakeModel:
    def __init__(self, outputs):
        self.outputs = iter(outputs)
        self.inputs = []

    def decide(self, task, observation):
        self.inputs.append(observation)
        value = next(self.outputs)
        if isinstance(value, Exception):
            raise value
        return value


class FakeSupervisor:
    warmup_heartbeats = 2

    def __init__(self, mismatch=False):
        self.frames = []
        self.mismatch = mismatch

    def step(self, frame):
        decoded = unpack_wire_v2_frame(frame)
        self.frames.append(decoded)
        return {'seq': decoded['seq'] + (1 if self.mismatch and len(self.frames) > 2 else 0),
                'theta_applied': decoded['u_mrad'], 'fault_bits': 0, 'mode': 0, 'rung': 0,
                'source': 'unit test fixture'}


class AgentTest(unittest.TestCase):
    def test_two_iterations_pass_real_observation_forward(self):
        model = FakeModel([command(5), command(10)])
        supervisor = FakeSupervisor()
        result = run_iterations(model, supervisor, 'demo', 2)
        self.assertEqual(len(supervisor.frames), 4)
        self.assertEqual(model.inputs[1]['current']['seq'], result[0]['frame_sequence'])
        self.assertEqual(model.inputs[1]['previous_action']['value'], 5)
        self.assertEqual(result[1]['supervisor_observation']['seq'], result[1]['frame_sequence'])

    def test_invalid_response_or_timeout_emits_no_extra_commands(self):
        for output in ('{"tool":"propose_motion","tool":"read_joint_state"}',
                       '{"tool":"propose_motion","value":true,"unit_id":1,"confidence_q8":255}',
                       '{"tool":"propose_motion","value":1,"unit_id":0,"confidence_q8":255}',
                       TimeoutError('planner expired')):
            supervisor = FakeSupervisor()
            with self.assertRaises((ValueError, TimeoutError)):
                run_iterations(FakeModel([output]), supervisor, 'demo', 1)
            self.assertEqual(len(supervisor.frames), 2)

    def test_mismatched_sequence_stops_before_second_call(self):
        model = FakeModel([command(1), command(2)])
        supervisor = FakeSupervisor(mismatch=True)
        with self.assertRaises(RuntimeError):
            run_iterations(model, supervisor, 'demo', 2)
        self.assertEqual(len(model.inputs), 1)

    def test_disabled_tool_fails_closed(self):
        model = FakeModel([command(1)])
        model.allowed_tools = {'read_joint_state'}
        supervisor = FakeSupervisor()
        with self.assertRaises(ValueError):
            run_iterations(model, supervisor, 'demo', 1)
        self.assertEqual(len(supervisor.frames), 2)

    def test_unknown_and_extra_fields_rejected(self):
        for raw in ('{"tool":"shell","value":0,"unit_id":0,"confidence_q8":0}',
                    '{"tool":"read_joint_state","value":0,"unit_id":0,"confidence_q8":0,"x":1}'):
            with self.assertRaises(ValueError):
                validate_action(raw)


if __name__ == '__main__':
    unittest.main()
