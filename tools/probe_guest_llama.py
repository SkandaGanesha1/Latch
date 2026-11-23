#!/usr/bin/env python3
"""Read-only inventory and Linux/AArch64 C++ link probe for guest inference.

This only measures prerequisites. A successful compiler probe is not evidence
that a model fits, a guest boots, or the supervisor has a feedback channel.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def binary_arch(path: Path) -> str:
    try:
        with path.open('rb') as stream:
            header = stream.read(20)
        if len(header) < 20 or header[:4] != b'\x7fELF' or header[5] not in (1, 2):
            return 'not ELF'
        machine = struct.unpack(('<' if header[5] == 1 else '>') + 'H', header[18:20])[0]
        return {62: 'x86_64', 183: 'aarch64'}.get(machine, f'ELF machine {machine}')
    except OSError:
        return 'missing'


def capture(command: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llama-source', type=Path, default=Path.home() / 'tools/llama.cpp')
    parser.add_argument('--model', type=Path, default=Path.home() / 'models/SmolLM2-135M-Instruct-Q8_0.gguf')
    parser.add_argument('--cross-cxx', default=os.environ.get('GOVERNOR_CROSS_CXX', 'aarch64-linux-gnu-g++'))
    parser.add_argument('--guest-sysroot', type=Path, help='Linux AArch64 sysroot for the C++ link test')
    args = parser.parse_args()

    source = args.llama_source.expanduser().resolve()
    model = args.model.expanduser().resolve()
    git_rc, revision = capture(['git', '-C', str(source), 'rev-parse', 'HEAD'])
    model_info: dict[str, object] = {'path': str(model), 'present': model.is_file()}
    if model.is_file():
        digest = hashlib.sha256()
        with model.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        model_info.update(bytes=model.stat().st_size, sha256=digest.hexdigest())

    compiler = shutil.which(args.cross_cxx)
    probe: dict[str, object] = {'compiler': args.cross_cxx, 'path': compiler, 'passed': False}
    if compiler:
        with tempfile.TemporaryDirectory(prefix='latch-guest-cxx-') as temporary:
            temp = Path(temporary)
            input_path = temp / 'probe.cpp'
            executable = temp / 'probe'
            input_path.write_text('#include <vector>\nint main() { std::vector<int> a{1}; return a[0] - 1; }\n', encoding='utf-8')
            cmd = [compiler]
            if args.guest_sysroot:
                cmd.append('--sysroot=' + str(args.guest_sysroot.resolve()))
            cmd += [str(input_path), '-o', str(executable)]
            rc, output = capture(cmd)
            arch = binary_arch(executable)
            probe.update(passed=(rc == 0 and arch == 'aarch64'), returncode=rc,
                         output=output, output_arch=arch)
    cli = source / 'build/bin/llama-cli'
    report = {
        'llama_source': str(source),
        'llama_revision': revision if git_rc == 0 else None,
        'llama_cli': {'path': str(cli), 'architecture': binary_arch(cli)},
        'model': model_info,
        'linux_aarch64_cxx_link_probe': probe,
        'note': 'Compiler link success alone does not verify target runtime, memory, guest execution, or feedback transport.',
    }
    print(json.dumps(report, indent=2))
    return 0 if git_rc == 0 and model.is_file() and probe['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
