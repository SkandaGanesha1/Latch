#!/usr/bin/env python3
"""Generate the DISPOSABLE fbprobe image's security policy.

The feedback-transport experiment (W4) needs two things the deployment
policy does not grant: a feedback MAILBOX resource manager
(`latch_fb_sink`, which owns the two one-sided feedback nodes) and a
publisher that may write into the mailbox's write side.

The deployment policy `qnx/latch.secpol` is NOT modified.  It is the
policy the shipped images run under, and the written audit review
(`docs/secpol-audit-review.md`) states that it is untouched and that no
generated rule was accepted.  Widening it for a transport experiment would
be a policy change disguised as tooling -- and the fbprobe image is
disposable anyway, so its extra privileges should not be the deployed
system's.

So the policy is ASSEMBLED from two tracked files:

    qnx/latch.secpol              the deployment policy, unchanged
    qnx/latch_fbprobe.secpol.inc  the experiment's additions, appended

The result is a build artifact (`build/latch_fbprobe.secpol`) and is
compiled to `build/secpol_fbprobe.bin`, which only the fbprobe buildfile
references.

Usage:
    python3 tools/generate_fbprobe_secpol.py <out.secpol>
"""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(REPO_ROOT, "qnx", "latch.secpol")
INC = os.path.join(REPO_ROOT, "qnx", "latch_fbprobe.secpol.inc")

BANNER = """\
# ==============================================================================
# GENERATED FILE -- DO NOT EDIT.
#
# Assembled by tools/generate_fbprobe_secpol.py from
#   qnx/latch.secpol              (the deployment policy, unchanged)
#   qnx/latch_fbprobe.secpol.inc  (the W4 transport experiment's additions)
#
# This policy is used ONLY by the DISPOSABLE feedback-transport probe image.
# The deployment policy qnx/latch.secpol is not modified by the experiment.
# ==============================================================================

"""


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: generate_fbprobe_secpol.py <out.secpol>\n")
        return 2
    out = argv[1]
    try:
        with open(BASE, "r", encoding="utf-8") as f:
            base = f.read()
        with open(INC, "r", encoding="utf-8") as f:
            inc = f.read()
    except OSError as exc:
        sys.stderr.write("generate_fbprobe_secpol: %s\n" % exc)
        return 1

    text = BANNER + base.rstrip() + "\n\n" + inc.lstrip()
    parent = os.path.dirname(os.path.abspath(out))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print("[fbprobe-secpol] wrote %s (%d bytes)" % (out, len(text)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
