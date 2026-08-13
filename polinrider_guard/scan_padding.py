"""Scanner for the whitespace-padding hiding technique confirmed in a real
PolinRider/BeaverTail sample: a legitimate-looking file (e.g. an eslint
config) with a normal-looking ending, followed by hundreds of spaces to push
a malicious statement off the right edge of an editor's viewport, all on one
physical line.

This is structural, not byte-signature-based -- it doesn't need to know what
the hidden payload says, only that something is hidden this way. That makes
it complementary to scan_ioc.py, which needs to recognize specific bytes.
"""
from __future__ import annotations

import os
import re
import statistics
from dataclasses import dataclass
from pathlib import Path

from . import allowlist
from .progress import OnProgress, make_reporter
from .skip_lists import SKIP_DIR_NAMES, SKIP_FILENAME_SUFFIXES

# Real content, then 80+ consecutive spaces/tabs, then more content, all on
# one line, has no ordinary formatting purpose -- that's the actual
# PolinRider shape: legitimate code that ends normally, followed by a wall
# of spaces pushing a payload off the right edge of an editor. The leading
# \S is deliberate: it excludes pure leading indentation (deeply nested or
# hand-aligned continuation lines, e.g. in templated HTML/PHP), which is
# ordinary formatting and was previously a common false positive here --
# indentation has nothing *before* the gap on the same line, only after.
# This is the primary, high-confidence signal: it doesn't depend on
# comparing against other lines in the file. Public (no leading underscore)
# so polinrider_guard/recovery.py can reuse the exact same signal to strip
# the offending line during history surgery, instead of re-deriving it.
WHITESPACE_RUN_RE = re.compile(r"\S[ \t]{80,}\S")
# Same signal as bytes, for recovery.py's git-filter-repo blob callback,
# which operates on raw blob bytes rather than decoded text.
WHITESPACE_RUN_RE_BYTES = re.compile(rb"\S[ \t]{80,}\S")

# Secondary, softer signal: a line that's a massive outlier next to the
# file's own other lines, even without deliberate space-padding (e.g. a
# payload appended directly after existing code with no attempt to hide the
# seam). Comparing against the file's OWN median -- rather than a fixed
# threshold -- means a uniformly minified/bundled file (long lines
# throughout) doesn't trip this; only a line that stands out *within that
# file* does.
_MIN_LINES_FOR_OUTLIER = 5
_OUTLIER_ABSOLUTE_FLOOR = 2000
_OUTLIER_RATIO = 15

# A `data:` URI's length is fully explained by its encoded payload (an
# inlined image/font/icon, e.g. a CSS `background: url("data:image/gif;
# base64,...")`), independent of whatever code surrounds it on the line --
# collapsing it before the outlier check keeps that check aimed at
# anomalous *code* length (the thing an appended payload would cause), not
# anomalous *asset* length. Matches both base64 and plain/URL-encoded data
# URIs (the latter common for inlined `data:image/svg+xml,...` icons).
_DATA_URI_RE = re.compile(r"data:[^,\s\"')]+,[^\s\"')]+")


def _outlier_length(line: str) -> int:
    return len(_DATA_URI_RE.sub("<data-uri>", line))


# Widely-distributed minified libraries conventionally open with a
# "preserved" comment -- the `/*!` marker is a real, specific convention
# terser/uglify/rollup all honor to mean "keep this exact comment even
# though everything else is being stripped" -- naming a real license and
# copyright holder, e.g. Socket.IO's own bundle:
#   /*!
#    * Socket.IO v4.7.5
#    * (c) 2014-2024 Guillermo Rauch
#    * Released under the MIT License.
#    */
# That's a much stronger, more specific signal of "this is a distributed
# third-party library" than a ".min.js" filename convention alone -- an
# attacker embedding a payload wouldn't naturally carry a real license
# banner citing a real license and copyright holder. Deliberately only
# gates the softer line_length_outlier signal below, not the high-
# confidence whitespace-padding one: a real attack could tamper with a
# genuine vendor file (license banner intact) by appending a deliberately
# padded statement, and that shouldn't go unnoticed just because the file
# it landed in happens to be a legitimate library.
_LICENSE_KEYWORDS_RE = re.compile(r"copyright|license|\(c\)\s*\d{4}", re.IGNORECASE)


def _has_license_banner(text: str) -> bool:
    stripped = text.lstrip()
    if not stripped.startswith("/*!"):
        return False
    end = stripped.find("*/", 3)
    banner = stripped[:end] if end != -1 else stripped[:2000]
    return bool(_LICENSE_KEYWORDS_RE.search(banner))


@dataclass
class PaddingFinding:
    file: str
    line: int
    kind: str
    line_length: int
    severity: str
    context: str

    def to_dict(self) -> dict:
        return {
            "type": "hidden_payload_padding",
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "line_length": self.line_length,
            "severity": self.severity,
            "context": self.context,
        }


# The whitespace-padding hiding technique this scanner targets is a
# JS-ecosystem one specifically (see module docstring -- the confirmed
# sample was an eslint config). Restricting to JS-family source, rather
# than scanning every text file like scan_ioc.py does, keeps both signals
# aimed at files where this technique is actually plausible, instead of
# reacting to naturally-huge lines in vendored CSS/SVG/asset files that
# were never a realistic vector for it -- a source of persistent noise no
# length/whitespace heuristic can reliably tell apart from the real thing,
# since minified vendor code and an appended-with-no-gap payload are
# structurally identical.
_SCAN_EXTENSIONS = {".js", ".mjs", ".ts"}


def _iter_candidate_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            if name.lower().endswith(SKIP_FILENAME_SUFFIXES):
                continue
            yield path


def _whitespace_run_context(line: str, match: re.Match, before: int = 30, after: int = 60) -> str:
    ws_start = match.start() + 1  # skip the leading \S the regex anchors the gap on
    gap = (match.end() - 1) - ws_start  # exclude the trailing \S char from the count
    prefix = line[max(0, ws_start - before) : ws_start]
    suffix = line[match.end() - 1 : match.end() - 1 + after]
    return f"...{prefix!r} <{gap} whitespace chars> {suffix!r}..."


def scan_file(path: Path, root: Path) -> list[PaddingFinding]:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return []

    if b"\x00" in raw[:8192]:
        return []

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []

    lines = text.splitlines()
    if not lines:
        return []

    rel = str(path.relative_to(root))
    findings: list[PaddingFinding] = []
    lengths = [len(line) for line in lines]
    median_len = statistics.median(lengths)
    has_license_banner = _has_license_banner(text)

    for line_no, line in enumerate(lines, start=1):
        match = WHITESPACE_RUN_RE.search(line)
        if match:
            findings.append(
                PaddingFinding(
                    file=rel,
                    line=line_no,
                    kind="excessive_whitespace_padding",
                    line_length=len(line),
                    severity="high",
                    context=_whitespace_run_context(line, match),
                )
            )
            continue  # already flagged this line; don't also report it as an outlier

        if has_license_banner:
            continue  # softer signal only; a confirmed licensed vendor bundle is expected to have huge lines

        outlier_len = _outlier_length(line)
        if (
            len(lines) >= _MIN_LINES_FOR_OUTLIER
            and outlier_len >= _OUTLIER_ABSOLUTE_FLOOR
            and median_len > 0
            and outlier_len > median_len * _OUTLIER_RATIO
        ):
            findings.append(
                PaddingFinding(
                    file=rel,
                    line=line_no,
                    kind="line_length_outlier",
                    line_length=len(line),
                    severity="medium",
                    context=line[:80] + "...",
                )
            )

    return findings


def scan_path(
    target: str | os.PathLike,
    on_progress: OnProgress | None = None,
) -> list[PaddingFinding]:
    """`on_progress`, if given, is called as on_progress(done, total) as
    candidate files are scanned -- see polinrider_guard.progress -- so a
    caller (the web UI) can show a "N/total files" progress bar.
    """
    root = Path(target).resolve()
    entries = allowlist.load_allowlist(root)

    if root.is_file():
        findings = scan_file(root, root.parent)
    else:
        files = list(_iter_candidate_files(root))
        report = make_reporter(len(files), on_progress)
        report(0)
        findings = []
        for i, path in enumerate(files, start=1):
            findings.extend(scan_file(path, root))
            report(i)

    return [
        f for f in findings
        if not allowlist.is_file_line_allowlisted(entries, "hidden_payload_padding", f.file, f.line)
    ]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-padding",
        description="Detect a payload hidden via whitespace padding or an anomalously long line.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No hidden-payload padding found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file}:{f.line} ({f.kind}, {f.line_length} chars)")
            print(f"    {f.context}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
