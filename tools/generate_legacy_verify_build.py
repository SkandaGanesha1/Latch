#!/usr/bin/env python3
"""Create a disposable legacy QEMU image with a typed test launcher.

Normal policy and startup are unchanged; this adds one launcher started by
startup as latch_verify_t. The operator shell receives no type transition.
"""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
text = args.source.read_text(encoding='utf-8')
marker = '    # 7. Interactive operator shell on _cpu-1'
if text.count(marker) != 1:
    raise SystemExit('expected one operator-shell startup marker')
text = text.replace(marker, '    # TEST IMAGE ONLY: fixed verifier waits for test trigger\n'
                    '    on -T latch_verify_t /proc/boot/latch_verify_trigger &\n\n' + marker)
text += ('\n[uid=0 gid=0 perms=0750] /proc/boot/latch_verify_trigger = '
         'build/nto-aarch64-le/latch_verify_trigger\n')
args.output.write_text(text, encoding='utf-8')
