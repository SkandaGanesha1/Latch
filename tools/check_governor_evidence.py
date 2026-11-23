#!/usr/bin/env python3
"""Check Governor archive contract digests and required host artifacts."""
from pathlib import Path
import csv
import hashlib
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
archive = root / 'docs/evidence/governor'
errors = []
try:
    manifest_evidence = (archive / 'governor-manifest-verify.txt').read_text(encoding='utf-8')
    for name in ('governor_servo', 'syringe_governor'):
        manifest = root / 'qnx/contracts' / (name + '.manifest')
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        sidecar = manifest.with_name(manifest.name + '.sha256').read_text(encoding='utf-8').split()[0]
        if digest != sidecar or digest not in manifest_evidence:
            errors.append(f'{name}: contract, sidecar or archived verification disagree')
    for name in ('governor-host-sim.txt', 'governor-tape.csv', 'governor-metrics.txt'):
        path = archive / name
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f'missing or empty {path}')
    with tempfile.TemporaryDirectory(prefix='latch-governor-evidence-') as temp:
        fresh = Path(temp) / 'tape.csv'
        result = subprocess.run([sys.executable, str(root / 'tools/generate_governor_tape.py'),
                                 '--out', str(fresh)], cwd=root, capture_output=True, text=True)
        if result.returncode:
            errors.append(f'fresh tape generation failed: {result.stderr.strip()}')
        else:
            def semantic_rows(path):
                with path.open(encoding='utf-8', newline='') as stream:
                    return [{k: v for k, v in row.items()
                             if k not in ('cycles_in', 'cycles_out', 'latency_cycles')}
                            for row in csv.DictReader(stream)]
            if semantic_rows(archive / 'governor-tape.csv') != semantic_rows(fresh):
                errors.append('archived Governor tape differs from current host simulation')
except (OSError, IndexError) as exc:
    errors.append(str(exc))
if errors:
    print('[GOVERNOR EVIDENCE FAIL] ' + '; '.join(errors), file=sys.stderr)
    sys.exit(1)
print('[GOVERNOR EVIDENCE PASS] contract digests and host tape behavior agree; QNX runtime freshness not established')
