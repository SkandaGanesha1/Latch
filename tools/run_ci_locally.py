#!/usr/bin/env python3
"""Run every `run:` step of .github/workflows/ci.yml locally, in order.

This reproduces the GitHub Actions job exactly (same shell, same commands,
same working directory) so that every step is verified BEFORE the change is
pushed -- instead of discovering the next failure one push at a time.

Usage:
    python3 tools/run_ci_locally.py [--only <substring>] [--keep-going]
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# GitHub Actions runs `run:` blocks with `bash -e {0}`.
BASH_ARGS = ["bash", "-e"]


def parse_steps(text: str):
    """Yield (name, script) for each `- name:` step that has a `run:` block."""
    lines = text.splitlines()
    steps = []
    i = 0
    while i < len(lines):
        m = re.match(r"^      - name:\s*(.+?)\s*$", lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        # Find the `run:` key of this step (indented deeper than the `- name:`).
        j = i + 1
        run_indent = None
        while j < len(lines):
            line = lines[j]
            if re.match(r"^      - name:", line):
                break
            rm = re.match(r"^(\s+)run:\s*(\|.*|>.*|)$", line)
            if rm:
                run_indent = len(rm.group(1))
                block_style = rm.group(2)
                j += 1
                break
            j += 1
        if run_indent is None:
            i = j
            continue
        # A block scalar: collect the more-indented body.
        body = []
        body_indent = None
        while j < len(lines):
            line = lines[j]
            if line.strip() == "":
                body.append("")
                j += 1
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= run_indent:
                break
            if body_indent is None:
                body_indent = indent
            body.append(line[body_indent:] if len(line) >= body_indent else line.strip())
            j += 1
        steps.append((name, "\n".join(body).rstrip() + "\n"))
        i = j
    return steps


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="only run steps whose name contains this")
    ap.add_argument("--keep-going", action="store_true")
    args = ap.parse_args()

    steps = parse_steps(WORKFLOW.read_text(encoding="utf-8"))
    if not steps:
        print("[CI-LOCAL] no steps parsed -- the workflow layout changed", file=sys.stderr)
        return 2

    failures = []
    for index, (name, script) in enumerate(steps, start=1):
        if args.only and args.only.lower() not in name.lower():
            continue
        print(f"\n{'=' * 78}\n[CI-LOCAL] step {index}: {name}\n{'=' * 78}", flush=True)
        proc = subprocess.run(BASH_ARGS + ["-c", script], cwd=REPO_ROOT,
                              capture_output=True, text=True)
        out = (proc.stdout or "") + (proc.stderr or "")
        if out.strip():
            print(out.rstrip())
        print(f"[CI-LOCAL] -> exit {proc.returncode}")
        if proc.returncode != 0:
            failures.append((name, proc.returncode))
            if not args.keep_going:
                break

    print(f"\n{'=' * 78}\n[CI-LOCAL] SUMMARY: {len(steps)} step(s), {len(failures)} failure(s)")
    for name, rc in failures:
        print(f"  FAILED (exit {rc}): {name}")
    print("=" * 78)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
