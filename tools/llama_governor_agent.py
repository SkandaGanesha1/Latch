#!/usr/bin/env python3
"""Experimental local LLM + deterministic Governor host simulation.

Each step replays all frames through fresh host-sim processes. It is not a live
QNX connection, a guest workload, or a real-time deadman demonstration.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from governor_client import GovernorClient, unpack_wire_v2_frame
from governor_host_replay import HostReplay

MAX_REPLY_BYTES = 16384
MAX_TASK_BYTES = 4096
MAX_ITERATIONS = 16
TOOLS = {'read_joint_state', 'propose_motion', 'request_envelope_shrink'}
ACTION_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'properties': {
        'tool': {'type': 'string', 'enum': sorted(TOOLS)},
        'value': {'type': 'integer', 'minimum': -2147483648, 'maximum': 2147483647},
        'unit_id': {'type': 'integer', 'minimum': 0, 'maximum': 4294967295},
        'confidence_q8': {'type': 'integer', 'minimum': 0, 'maximum': 255},
    },
    'required': ['tool', 'value', 'unit_id', 'confidence_q8'],
}


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON key')
        obj[key] = value
    return obj


def validate_action(raw: str) -> dict:
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_REPLY_BYTES:
        raise ValueError('model output missing or exceeds size limit')
    action = json.loads(raw, object_pairs_hook=_unique_pairs)
    if not isinstance(action, dict) or set(action) != {'tool', 'value', 'unit_id', 'confidence_q8'}:
        raise ValueError('model output must contain exactly tool, value, unit_id, confidence_q8')
    if not isinstance(action['tool'], str) or action['tool'] not in TOOLS:
        raise ValueError('unknown tool')
    for key, lo, hi in [('value', -2147483648, 2147483647), ('unit_id', 0, 4294967295), ('confidence_q8', 0, 255)]:
        v = action[key]
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f'invalid {key}')
    if action['tool'] == 'propose_motion' and action['unit_id'] == 0:
        raise ValueError('motion requires explicit nonzero unit_id')
    if action['tool'] == 'request_envelope_shrink' and (action['value'] <= 0 or action['unit_id'] != 0 or action['confidence_q8'] == 0):
        raise ValueError('shrink requires positive value and scale, unit_id zero')
    if action['tool'] == 'read_joint_state' and any(action[x] != 0 for x in ('value', 'unit_id', 'confidence_q8')):
        raise ValueError('read_joint_state arguments must be zero')
    return action


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


class LocalModel:
    """Start a private loopback server using exactly the requested model file."""
    def __init__(self, executable: Path, model: Path, timeout: float, context: int, allowed_tools=None):
        self.executable, self.model, self.timeout, self.context = executable, model, timeout, context
        self.allowed_tools = set(allowed_tools or TOOLS)
        self.process = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __enter__(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.url = f'http://127.0.0.1:{port}'
        self.process = subprocess.Popen([str(self.executable), '-m', str(self.model), '--host', '127.0.0.1', '--port', str(port), '--ctx-size', str(self.context), '--parallel', '1', '--no-webui'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.__exit__(None, None, None)
                raise RuntimeError('llama-server exited before it became ready')
            try:
                with self.opener.open(self.url + '/health', timeout=min(1, max(.1, deadline - time.monotonic()))) as res:
                    health = json.loads(res.read(MAX_REPLY_BYTES + 1))
                    if health.get('status') == 'ok':
                        return self
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
                time.sleep(.1)
        self.__exit__(None, None, None)
        raise TimeoutError('llama-server startup timed out')

    def __exit__(self, *_):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def decide(self, task: str, observation: dict) -> str:
        system = ('You are a proposal generator for a simulated physical supervisor. '
                  'Return JSON only with exactly tool, value, unit_id, confidence_q8. '
                  'Allowed tools: read_joint_state (all numeric values 0), propose_motion '
                  '(value=int32 target, nonzero unit_id, confidence_q8 0..255), '
                  'request_envelope_shrink (value positive velocity, unit_id 0, confidence_q8 1..255). '
                  'Every proposal is checked by an independent supervisor. Do not infer a verdict.')
        schema = copy.deepcopy(ACTION_SCHEMA)
        schema['properties']['tool']['enum'] = sorted(self.allowed_tools)
        if self.allowed_tools == {'propose_motion'}:
            schema['properties']['unit_id']['minimum'] = 1
        system += ' Available tools for this run: ' + ', '.join(sorted(self.allowed_tools)) + '.'
        payload = {'messages': [{'role': 'system', 'content': system},
                                {'role': 'user', 'content': json.dumps({'task': task, 'observation': observation})}],
                   'temperature': 0, 'max_tokens': 128,
                   'response_format': {'type': 'json_schema', 'json_schema': {'name': 'governor_tool', 'schema': schema}}}
        req = urllib.request.Request(self.url + '/v1/chat/completions', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        with self.opener.open(req, timeout=self.timeout) as response:
            body = response.read(MAX_REPLY_BYTES + 1)
        if len(body) > MAX_REPLY_BYTES:
            raise ValueError('model response exceeds size limit')
        result = json.loads(body, object_pairs_hook=_unique_pairs)
        return result['choices'][0]['message']['content']


def run_iterations(model, simulator, task: str, iterations: int) -> list[dict]:
    if not isinstance(task, str) or not task.strip() or len(task.encode('utf-8')) > MAX_TASK_BYTES:
        raise ValueError('task is empty or too long')
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError('iteration count out of range')
    client = GovernorClient()
    observation = None
    for _ in range(simulator.warmup_heartbeats):
        observation = simulator.step(client.send_heartbeat())
    if observation is None:
        raise ValueError('manifest must require at least one warmup heartbeat for this demo')
    log = []
    previous_action = None
    for index in range(iterations):
        request_time_ns = time.time_ns()
        started = time.monotonic_ns()
        raw = model.decide(task, {'current': observation, 'previous_action': previous_action,
                                  'iteration': index + 1})
        inference_ns = time.monotonic_ns() - started
        action = validate_action(raw)
        if action['tool'] not in getattr(model, 'allowed_tools', TOOLS):
            raise ValueError('model selected a tool disabled for this run')
        before = observation
        if action['tool'] == 'read_joint_state':
            frame = None
        elif action['tool'] == 'propose_motion':
            frame = client.send_command(action['value'], unit_id=action['unit_id'], confidence_q8=action['confidence_q8'])
        else:
            frame = client.send_shrink_request(action['value'], shrink_scale_q8=action['confidence_q8'])
        if frame is not None:
            seq = unpack_wire_v2_frame(frame)['seq']
            observation = simulator.step(frame)
            if int(observation['seq']) != seq:
                raise RuntimeError('supervisor response sequence mismatch')
        log.append({'iteration': index + 1, 'request_unix_ns': request_time_ns,
                    'inference_elapsed_ns': inference_ns, 'input_observation': before, 'model_output': raw,
                    'action': action, 'supervisor_observation': observation,
                    'frame_sequence': None if frame is None else seq})
        previous_action = action
    return log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, type=Path, help='local llama-server executable')
    parser.add_argument('--model', required=True, type=Path, help='local GGUF model')
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--task', required=True)
    parser.add_argument('--iterations', type=int, default=2)
    parser.add_argument('--timeout', type=float, default=30.0, help='per-inference/startup timeout seconds')
    parser.add_argument('--context', type=int, default=1024)
    parser.add_argument('--allowed-tool', action='append', choices=sorted(TOOLS),
                        help='restrict available model tools (repeatable; default all)')
    args = parser.parse_args()
    if not .1 <= args.timeout <= 120 or not 512 <= args.context <= 8192:
        parser.error('timeout or context out of range')
    if not args.server.is_file() or not os.access(args.server, os.X_OK) or not args.model.is_file():
        parser.error('server executable and model file must exist')
    try:
        version_result = subprocess.run([str(args.server), '--version'], check=True, capture_output=True, text=True, timeout=5)
        version = (version_result.stdout + version_result.stderr).strip()
        if not version:
            raise RuntimeError('llama-server did not report its version')
        simulator = HostReplay(args.manifest, timeout_seconds=args.timeout)
        with LocalModel(args.server, args.model, args.timeout, args.context, args.allowed_tool) as model:
            entries = run_iterations(model, simulator, args.task, args.iterations)
        print(json.dumps({'mode': 'host-simulation-replay', 'real_time_liveness_tested': False,
                          'task': args.task, 'allowed_tools': sorted(args.allowed_tool or TOOLS),
                          'model_sha256': sha256_file(args.model), 'llama_server_version': version,
                          'manifest_sha256': sha256_file(args.manifest), 'iterations': entries}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError, urllib.error.URLError) as exc:
        print(f'[LLAMA_GOVERNOR FAIL] {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
