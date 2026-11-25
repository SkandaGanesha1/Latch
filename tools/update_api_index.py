#!/usr/bin/env python3
"""update_api_index.py — Mechanically re-derive "Evidence of QNX use" line anchors.

WHY THIS EXISTS
---------------
The judge-facing "Evidence-of-QNX-Use" tables quote `file:line` anchors so a
reviewer can open a file and land on the exact line that proves a QNX-native
technique is really used.  Hand-maintained anchors rot the moment a function
moves, and a wrong anchor reads as "agent-generated documentation nobody
audited".  This tool makes the anchors *derived*, not *written*.

HOW IT WORKS (no hardcoded line numbers anywhere)
-------------------------------------------------
For every `path:line` or `path:start-end` reference found in a Markdown file:

  1. Resolve `path` against the repository (several prefixes are tried so that
     both `qnx/latchd.c` and `latch/qnx/latchd.c` work, and a bare file name
     is resolved against the directory of the other paths in the same row).
  2. Collect the *candidate symbols* from the surrounding text and rank them
     from most to least specific:
        a. `DCMD_*` macro names — they name one exact devctl command, and all
           of them named in a row are unioned, because a row that cites two
           devctls wants both anchors.
        b. Identifiers from the **first cell** of the Markdown table row (the
           "QNX 8.0 Subsystem / API" column), longest first.  A longer
           identifier is almost always the more specific one: `gov_medical_check`
           beats `gov_gate_precheck`.
        c. Literal configuration tokens named in the row (`virtio-console`,
           `_cpu-2`, `secpolpush`) — these are what anchor a *configuration*
           file, which has no function symbols to point at.
        d. Identifiers from the whole row, longest first.
  3. Re-scan the referenced source file for the winning symbol(s) and collect
     the line numbers where it is actually used.
  4. Rewrite the reference with the freshly derived line numbers.

A "use" is a line that mentions the symbol **outside** of a comment and
**outside** of a string literal.  That distinction matters: `perror("latchd:
resmgr_attach")` is a diagnostic message, not a call to `resmgr_attach()`, and
anchoring on it would send a reviewer to the wrong line.

DATA FILES ARE LEFT ALONE.  A citation such as
`docs/evidence/governor/governor-tape.csv:21-99` points at recorded data, not
at code, and there is no symbol to re-derive it from.

USAGE
-----
    python3 tools/update_api_index.py --check   # fail if any anchor drifted
    python3 tools/update_api_index.py --write   # rewrite the anchors in place
    python3 tools/update_api_index.py --write path/to/other.md ...

Exit codes: 0 = in sync (or successfully written), 1 = drift detected in
`--check` mode, 2 = a reference could not be resolved at all.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

DEFAULT_TARGETS = (
    "README.md",
    "docs/GOVERNOR_JUDGE_READINESS.md",
)

# A reference looks like `some/path.ext:12`, `some/path.ext:12, 15` or
# `some/path.ext:12-34`.  The path may itself contain dots and dashes.  The
# optional "(+N more)" tail is part of the reference: it must be consumed so
# that re-running the tool is idempotent.
REFERENCE_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_./+-]+\.[A-Za-z0-9_]+):"
    r"(?P<lines>\d+(?:\s*(?:,|-)\s*\d+)*(?:\s*,\s*\(\+\d+ more\))*)"
)

IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# A "special token" is a configuration key: it contains a separator or a digit
# and is therefore not an ordinary identifier.
SPECIAL_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*[A-Za-z0-9_]")

# Files that hold recorded data rather than code: their line citations are
# about the DATA, so there is no symbol to re-derive them from.
DATA_SUFFIXES = frozenset({
    ".csv", ".tsv", ".json", ".png", ".jpg", ".jpeg", ".svg", ".gif",
    ".pdf", ".mp4", ".webm", ".zip", ".gz", ".tar", ".wav", ".mp3",
})

# Identifiers that are never a useful anchor: English words that happen to
# appear in prose, plus generic glue.
STOPWORDS = frozenset(
    """
    a an and the of to in on for with without from by as at is are was were be
    been being this that these those it its their there here then than so if
    else not no nor but or yet we you they he she i us them our your their
    file files line lines source sources code api apis subsystem engineering
    role use used using uses exact citation index evidence qnx use proof prove
    proves function functions call calls callsite callsites quote quotes
    version versions note notes see also more most only such same other
    path paths type types mode modes case cases one two three four five
    six seven eight nine ten first second third next last new old
    """.split()
)

# How many anchors to print for one reference before truncating.
MAX_ANCHORS = 4

# File types whose comments start with '#'.
HASH_COMMENT_SUFFIXES = frozenset({
    ".py", ".sh", ".bash", ".yml", ".yaml", ".toml", ".ini",
    ".build", ".secpol", ".qvmconf", ".conf", ".cfg", ".mk", ".make",
})

# A backtick-quoted phrase of two or more words, e.g. `type latchd_t`.
PHRASE_RE = re.compile(r"`([^`\n]{3,})`")


class Reference:
    """One `path:lines` reference inside a Markdown document."""

    __slots__ = ("start", "end", "path", "lines_text")

    def __init__(self, start: int, end: int, path: str, lines_text: str) -> None:
        self.start = start
        self.end = end
        self.path = path
        self.lines_text = lines_text


def strip_literals(line: str) -> str:
    """Remove C/Shell string and character literals from a source line."""
    out: List[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            while i < n:
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def is_comment_line(line: str, suffix: str) -> bool:
    """True when the line is a comment and therefore cannot be an anchor."""
    stripped = line.strip()
    if stripped.startswith("*") or stripped.startswith("//") or stripped.startswith("/*"):
        return True
    if suffix in HASH_COMMENT_SUFFIXES:
        if stripped.startswith("#"):
            return True
    return False


def read_lines(path: pathlib.Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def symbol_use_sites(source: pathlib.Path, symbol: str,
                     require_call: bool = False) -> List[int]:
    """Line numbers (1-based) where `symbol` is genuinely used in `source`.

    A use is a whole-word mention on a line that is neither a comment nor a
    string literal.  With `require_call` the mention must also be the callee
    of a call (`symbol(`), which is what distinguishes a real invocation from
    an incidental mention of the same name.
    """
    lines = read_lines(source)
    if not lines:
        return []
    suffix = source.suffix.lower()
    pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])")
    call_pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"\s*\(")
    hits: List[int] = []
    for number, raw in enumerate(lines, start=1):
        if is_comment_line(raw, suffix):
            continue
        code = strip_literals(raw)
        if not pattern.search(code):
            continue
        if require_call and not call_pattern.search(code):
            continue
        hits.append(number)
    return hits


def literal_use_sites(source: pathlib.Path, token: str) -> List[int]:
    """Line numbers where the literal configuration token appears."""
    lines = read_lines(source)
    if not lines:
        return []
    suffix = source.suffix.lower()
    hits: List[int] = []
    for number, raw in enumerate(lines, start=1):
        if is_comment_line(raw, suffix):
            continue
        if token in raw:
            hits.append(number)
    return hits


def resolve_path(raw: str, doc_path: pathlib.Path,
                 sibling_dirs: Sequence[pathlib.Path] = ()) -> Optional[pathlib.Path]:
    """Resolve a documented path against the repository, tolerating prefixes."""
    raw = raw.strip().strip("`")
    if not raw:
        return None

    plain = pathlib.PurePosixPath(raw)
    candidates: List[pathlib.Path] = []
    candidates.append(REPO_ROOT / plain)
    candidates.append(doc_path.parent / plain)
    # The documentation often prefixes repository paths with the repository
    # directory name itself (`latch/qnx/latchd.c`).
    if plain.parts and plain.parts[0] == REPO_ROOT.name:
        candidates.append(REPO_ROOT / pathlib.PurePosixPath(*plain.parts[1:]))
    # And sometimes the path is relative to the parent of the repository.
    candidates.append(REPO_ROOT.parent / plain)
    if plain.parts and plain.parts[0] == REPO_ROOT.name:
        candidates.append(REPO_ROOT.parent / pathlib.PurePosixPath(*plain.parts[1:]))
    # A bare file name next to a fully qualified one: look beside it.
    if len(plain.parts) == 1:
        for directory in sibling_dirs:
            candidates.append(directory / plain)

    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue

    # Last resort: a unique file with this name anywhere in the repository.
    if len(plain.parts) == 1:
        matches = [p for p in REPO_ROOT.rglob(plain.name) if p.is_file()]
        if len(matches) == 1:
            return matches[0]
    return None


def row_cells(line: str) -> List[str]:
    """Split a Markdown table row into its cells (best effort)."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    parts = stripped.split("|")
    # parts[0] is empty (before the first '|'); parts[-1] may be empty too.
    if parts and not parts[0].strip():
        parts = parts[1:]
    if parts and not parts[-1].strip():
        parts = parts[:-1]
    return [p.strip() for p in parts]


def context_parts(text: str, ref_start: int, ref_end: int) -> Tuple[List[str], List[str]]:
    """Return (first-cell identifiers, whole-context identifiers) for a reference.

    For a Markdown table row the API-name cell is the primary source; for prose
    the enclosing sentence is used.
    """
    line_start = text.rfind("\n", 0, ref_start) + 1
    line_end = text.find("\n", ref_end)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]

    cells = row_cells(line)
    if cells:
        # The first cell names the API; it is the primary anchor intent.
        return cells[:1], cells

    # Prose: use the sentence containing the reference.
    left = max(
        text.rfind(".", 0, ref_start),
        text.rfind(";", 0, ref_start),
        text.rfind("\n", 0, ref_start),
    )
    right_candidates = [p for p in (text.find(".", ref_end), text.find(";", ref_end)) if p >= 0]
    right = min(right_candidates) if right_candidates else len(text)
    sentence = text[left + 1:right + 1]
    return [sentence], [sentence]


def ordered_unique(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def identifiers_in(texts: Sequence[str]) -> List[str]:
    """Identifiers named in the given texts, ignoring the file paths themselves.

    A path such as `qnx/gov_gate_precheck.c` names a FILE, not a symbol that
    lives in it, so it must not out-rank the symbol the row actually means.
    """
    out: List[str] = []
    for text in texts:
        scrubbed = re.sub(r"[A-Za-z0-9_./+-]+\.[A-Za-z0-9_]+", " ", text)
        out.extend(IDENTIFIER_RE.findall(scrubbed))
    return out


def special_tokens_in(texts: Sequence[str], excluded: Sequence[str]) -> List[str]:
    """Configuration-style tokens such as `virtio-console` or `_cpu-2`.

    Tokens that are part of a file path quoted in the same row are skipped:
    the path is already the reference, not the thing inside the file.
    """
    excluded_lower = {e.lower() for e in excluded}
    out: List[str] = []
    for text in texts:
        for path_like in re.findall(r"[A-Za-z0-9_./+-]+\.[A-Za-z0-9_]+", text):
            excluded_lower.add(path_like.lower())
        for token in SPECIAL_TOKEN_RE.findall(text):
            if len(token) < 4:
                continue
            if not any(ch in token for ch in "-._"):
                continue
            low = token.lower()
            if low in excluded_lower:
                continue
            if any(low in path for path in excluded_lower):
                continue
            if token.startswith((".", "/")):
                continue
            out.append(token)
    return out


def phrases_in(texts: Sequence[str]) -> List[str]:
    """Backtick-quoted phrases that name a concrete thing, in order of appearance.

    A phrase qualifies when it has two or more words (`type latchd_t`,
    `vdev virtio-console`) or when it is written as a call (`gov_medical_check()`),
    which is an explicit statement by the author that this is the function.
    """
    out: List[str] = []
    for text in texts:
        for phrase in PHRASE_RE.findall(text):
            phrase = phrase.strip()
            if len(phrase.split()) < 2 and not phrase.endswith("()"):
                continue
            out.append(phrase)
    return out


def resolve_anchor(source: pathlib.Path, primary: Sequence[str],
                    context: Sequence[str], excluded: Sequence[str]) -> Optional[List[int]]:
    """Find the line numbers in `source` that best match the documented intent.

    The stages are ordered from "names exactly one thing" to "names many
    things", because a row that cites `DCMD_LATCH_GET_GOV_STATUS` wants that
    devctl and not the word "devctl".
    """
    primary_ids = identifiers_in(primary)
    context_ids = identifiers_in(context)

    def ranked(ids: Sequence[str]) -> List[str]:
        return ordered_unique(
            sorted((i for i in ids
                    if i.lower() not in STOPWORDS and not i.isdigit() and len(i) > 2),
                   key=len, reverse=True)
        )

    # (a) DCMD_* macros: a row that names two devctls wants both anchors.
    dcmd = ordered_unique(i for i in context_ids if i.startswith("DCMD_"))
    if dcmd:
        union: List[int] = []
        for symbol in dcmd:
            for hit in symbol_use_sites(source, symbol):
                if hit not in union:
                    union.append(hit)
        if union:
            return sorted(union)

    # (b) Real call sites of the identifiers named in the API-name cell.
    for symbol in ranked(primary_ids):
        hits = symbol_use_sites(source, symbol, require_call=True)
        if hits:
            return hits

    # (c) An explicit backtick-quoted phrase: `type latchd_t`,
    #     `vdev virtio-console`, `gov_medical_check()`.
    for phrase in ordered_unique(phrases_in(context)):
        if phrase.endswith("()"):
            hits = symbol_use_sites(source, phrase[:-2], require_call=True)
        else:
            hits = literal_use_sites(source, phrase)
        if hits:
            return hits

    # (d) Real call sites of an identifier named anywhere in the row.
    for symbol in ranked(context_ids):
        hits = symbol_use_sites(source, symbol, require_call=True)
        if hits:
            return hits

    # (e) Configuration tokens named in the row, in the order the row names
    #     them: `virtio-console`, `_cpu-2`, `type latchd_t`, ...
    for token in ordered_unique(special_tokens_in(context, excluded)):
        hits = literal_use_sites(source, token)
        if hits:
            return hits

    # (f) Any mention of an identifier from the API-name cell.
    for symbol in ranked(primary_ids):
        hits = symbol_use_sites(source, symbol)
        if hits:
            return hits

    # (g) Any mention of an identifier from the whole row.
    for symbol in ranked(context_ids):
        hits = symbol_use_sites(source, symbol)
        if hits:
            return hits

    return None


def format_lines(hits: Sequence[int]) -> str:
    if not hits:
        return ""
    shown = list(hits[:MAX_ANCHORS])
    text = ", ".join(str(h) for h in shown)
    if len(hits) > len(shown):
        text += f", (+{len(hits) - len(shown)} more)"
    return text


def rewrite_document(doc_path: pathlib.Path, verbose: bool = False) -> Tuple[str, List[str], List[str]]:
    """Return (new_text, resolved_refs, unresolved_refs) for one document."""
    original = doc_path.read_text(encoding="utf-8")
    text = original
    resolved: List[str] = []
    unresolved: List[str] = []

    references: List[Reference] = []
    for match in REFERENCE_RE.finditer(original):
        references.append(
            Reference(match.start(), match.end(), match.group("path"), match.group("lines"))
        )

    # Group references by the line they live on so that a bare file name can be
    # resolved against the directory of its fully qualified siblings.
    sibling_dirs: Dict[int, List[pathlib.Path]] = {}
    for ref in references:
        line_no = original.count("\n", 0, ref.start)
        source = resolve_path(ref.path, doc_path)
        if source is not None:
            sibling_dirs.setdefault(line_no, []).append(source.parent)

    for ref in reversed(references):
        if pathlib.PurePosixPath(ref.path).suffix.lower() in DATA_SUFFIXES:
            continue
        line_no = original.count("\n", 0, ref.start)
        source = resolve_path(ref.path, doc_path, sibling_dirs.get(line_no, ()))
        if source is None:
            unresolved.append(f"{ref.path}: file not found")
            continue
        primary, context = context_parts(original, ref.start, ref.end)
        symbols = resolve_anchor(source, primary, context, [ref.path])
        if symbols is None:
            unresolved.append(f"{ref.path}: no symbol from the row matched")
            continue
        new_lines = format_lines(symbols)
        replacement = f"{ref.path}:{new_lines}"
        text = text[: ref.start] + replacement + text[ref.end :]
        resolved.append(f"{ref.path}: {ref.lines_text} -> {new_lines}")
        if verbose:
            print(f"  {doc_path}: {ref.path}: {ref.lines_text} -> {new_lines}")

    return text, resolved, unresolved


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Re-derive or verify Markdown source-line anchors."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="Fail (exit 1) when any anchor has drifted.")
    mode.add_argument("--write", action="store_true",
                      help="Rewrite the anchors in place (default).")
    parser.add_argument("--verbose", action="store_true", help="Print every anchor change.")
    parser.add_argument("targets", nargs="*", help="Markdown files (default: README.md, "
                                                   "docs/GOVERNOR_JUDGE_READINESS.md)")
    args = parser.parse_args(argv)

    targets = args.targets or list(DEFAULT_TARGETS)
    drift = False
    unresolved_total = 0

    for name in targets:
        doc_path = (REPO_ROOT / name) if not pathlib.Path(name).is_absolute() else pathlib.Path(name)
        if not doc_path.is_file():
            print(f"[ANCHORS] SKIP (not found): {doc_path}", file=sys.stderr)
            continue

        new_text, resolved, unresolved = rewrite_document(doc_path, verbose=args.verbose)
        unresolved_total += len(unresolved)
        for item in unresolved:
            print(f"[ANCHORS] UNRESOLVED {doc_path}: {item}", file=sys.stderr)

        if new_text != doc_path.read_text(encoding="utf-8"):
            drift = True
            if args.check:
                print(f"[ANCHORS] DRIFT: {doc_path} ({len(resolved)} reference(s) moved)")
            else:
                doc_path.write_text(new_text, encoding="utf-8")
                print(f"[ANCHORS] UPDATED: {doc_path} ({len(resolved)} reference(s) re-derived)")
        else:
            print(f"[ANCHORS] IN SYNC: {doc_path} ({len(resolved)} reference(s) verified)")

    if unresolved_total:
        print(f"[ANCHORS] {unresolved_total} reference(s) could not be resolved.",
              file=sys.stderr)
        return 2

    if args.check and drift:
        print("[ANCHORS] FAIL: source anchors have drifted. "
              "Run: python3 tools/update_api_index.py --write", file=sys.stderr)
        return 1

    print("[ANCHORS] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
