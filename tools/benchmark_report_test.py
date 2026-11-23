#!/usr/bin/env python3
"""Regression tests for recorded-cycle reporting and fail-closed inputs."""
from __future__ import annotations
import subprocess
import sys
import tempfile
from pathlib import Path
from benchmark_qnx_vs_linux import summarize_tape

with tempfile.TemporaryDirectory() as directory:
    tape = Path(directory) / 'tape.csv'
    tape.write_text('cycles_in,cycles_out\n10,110\n200,500\n', encoding='utf-8')
    stats = summarize_tape(tape, 1_000_000)
    assert stats['count'] == 2 and stats['min_us'] == 100 and stats['max_us'] == 300
    tape.write_text('cycles_in,cycles_out\n100,99\n', encoding='utf-8')
    command = [sys.executable, str(Path(__file__).with_name('benchmark_qnx_vs_linux.py')),
               '--tape', str(tape), '--cycles-per-second', '1000000',
               '--platform', 'fixture', '--workload', 'fixture']
    assert subprocess.run(command, capture_output=True, check=False).returncode != 0
    tape.write_text('cycles_in,cycles_out\n', encoding='utf-8')
    assert subprocess.run(command, capture_output=True, check=False).returncode != 0
print('[BENCHMARK_REPORT] PASS: measured conversion and invalid evidence rejection')
