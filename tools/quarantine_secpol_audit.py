#!/usr/bin/env python3
"""Preserve the historical, unsubstantiated security audit and withdraw it.

THE ARCHIVED COPY CARRIES ITS OWN WITHDRAWAL BANNER.

The archived copy used to be a byte-for-byte copy of the original report,
which meant that a reader who opened
`docs/evidence/quarantine/REJECTED-secpol-audit.txt` on its own saw a
report that reads like a passed audit.  The withdrawal notice lived in
`docs/evidence/derived/secpol-audit.txt` -- one directory away -- and in
this tool's source.  A withdrawn artefact must say so IN ITS OWN FIRST
LINES, or somebody will quote it.

So the banner is prepended here, and the step that asserts it is
IDEMPOTENT: re-running this tool on an archive that already carries the
banner changes nothing, and re-running it on one that lost the banner
restores it.  `tools/consistency_check.py` checks both the archived file
and this source, so a banner that is quietly dropped fails the build.
"""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1] / 'docs' / 'evidence'
source = root / 'derived' / 'secpol-audit.txt'
archive = root / 'quarantine' / 'REJECTED-secpol-audit.txt'

# THE MARKER.  `tools/consistency_check.py` looks for this exact string in
# the archived file's first lines AND in this source, so the artefact and
# its generator cannot drift apart.
BANNER_MARKER = "WITHDRAWN -- NOT EVIDENCE"

BANNER = (
    "==============================================================================\n"
    "WITHDRAWN -- NOT EVIDENCE.  QUARANTINED ARTEFACT: retained for audit\n"
    "history only.  This historical report made unsupported claims about\n"
    "secpolgenerate coverage, least privilege and certification.  Do not\n"
    "quote it, do not cite it, and do not present it as evidence of a passed\n"
    "security audit.  The current, unrestricted secpolgenerate capture and\n"
    "its written review are docs/evidence/governor/secpol-audit.txt and\n"
    "docs/secpol-audit-review.md.\n"
    "==============================================================================\n"
    "\n"
)

notice = ("WITHDRAWN: This historical report made unsupported claims about "
          "secpolgenerate coverage, least privilege and certification.\n"
          "It is not evidence of a passed security audit. The original is "
          "preserved at ../quarantine/REJECTED-secpol-audit.txt.\n"
          "See ../../V12_GAP_LEDGER.md for the limited QEMU policy-generation "
          "run and outstanding review.\n")

if not archive.exists():
    if not source.is_file() or source.read_text(encoding='utf-8').startswith('WITHDRAWN:'):
        raise SystemExit('Original report missing; refusing to create a misleading archive')
    shutil.copyfile(source, archive)

# (Re-)assert the inline banner on the archived copy.  Idempotent: an
# archive that already carries the marker is left byte-for-byte alone.
archived = archive.read_text(encoding='utf-8')
if not archived.startswith(BANNER_MARKER):
    archive.write_text(BANNER + archived, encoding='utf-8')

source.write_text(notice, encoding='utf-8')
