#!/usr/bin/env python3
"""Preserve the historical, unsubstantiated security audit and withdraw it."""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1] / 'docs' / 'evidence'
source = root / 'derived' / 'secpol-audit.txt'
archive = root / 'quarantine' / 'REJECTED-secpol-audit.txt'
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
source.write_text(notice, encoding='utf-8')
