"""Content-vs-extension scanner for the font-file (binary masquerade) vector.

Node.js executes files based on their byte content, not their name. PolinRider
has shipped JavaScript payloads named like ordinary font files (e.g.
`fa-solid-400.woff2`) specifically because extension-based scanners and human
reviewers both skip binary asset directories. This module verifies that a
file's declared type (its extension) matches its actual content, using magic
bytes first and a text/entropy heuristic as a fallback for wrapped/obfuscated
payloads.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import allowlist
from .progress import OnProgress, make_reporter
from .skip_lists import SKIP_DIR_NAMES

# extension -> (label, magic byte signatures). A file matches if it starts
# with ANY of the listed signatures for its own extension family.
MAGIC_SIGNATURES: dict[str, tuple[str, list[bytes]]] = {
    ".woff2": ("font/woff2", [b"wOF2"]),
    ".woff": ("font/woff", [b"wOFF"]),
    ".ttf": ("font/ttf", [b"\x00\x01\x00\x00", b"true", b"OTTO"]),
    ".otf": ("font/otf", [b"OTTO", b"\x00\x01\x00\x00"]),
    ".png": ("image/png", [b"\x89PNG\r\n\x1a\n"]),
    ".jpg": ("image/jpeg", [b"\xff\xd8\xff"]),
    ".jpeg": ("image/jpeg", [b"\xff\xd8\xff"]),
    ".gif": ("image/gif", [b"GIF87a", b"GIF89a"]),
    ".ico": ("image/x-icon", [b"\x00\x00\x01\x00"]),
    ".webp": ("image/webp", [b"RIFF"]),
    ".bmp": ("image/bmp", [b"BM"]),
    ".wasm": ("application/wasm", [b"\x00asm"]),
    ".pdf": ("application/pdf", [b"%PDF-"]),
    ".zip": ("application/zip", [b"PK\x03\x04", b"PK\x05\x06"]),
    ".gz": ("application/gzip", [b"\x1f\x8b"]),
}

# extension -> (label, byte offset, signatures) for formats whose magic
# isn't at the very start of the file. EOT's own spec puts a fixed "LP"
# marker at offset 34 -- offset 0 is actually EOTSize, a little-endian
# total-file-size field that varies per file, so checking it with
# startswith() (as MAGIC_SIGNATURES does) flags every legitimate .eot file.
OFFSET_MAGIC_SIGNATURES: dict[str, tuple[str, int, list[bytes]]] = {
    ".eot": ("font/eot", 34, [b"LP"]),
}

# Every extension we're willing to say "this should be a binary asset" about.
BINARY_LIKE_EXTENSIONS = set(MAGIC_SIGNATURES) | set(OFFSET_MAGIC_SIGNATURES)

# Heuristics for "this content is actually JS/text, not a binary asset".
# Public (no leading underscore) so polinrider_guard/recovery.py can reuse
# the exact same high-confidence signal to identify which historical blobs
# are safe to blank entirely during history surgery -- see its
# find_masquerade_blobs().
JS_KEYWORDS = re.compile(
    rb"\b(function|require|module\.exports|eval|const|let|var|=>|process\.env|Buffer\.from|import\s)\b"
)
_PRINTABLE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]")


def magic_bytes_match(ext: str, head: bytes) -> bool:
    """True if `head` (a file/blob's leading bytes) starts with (or, for
    formats like .eot whose marker isn't at offset 0, contains at the right
    offset) a magic-byte signature consistent with its claimed extension.
    Public so recovery.py can apply the identical check to blob content
    pulled from git history instead of a file on disk.
    """
    if ext in OFFSET_MAGIC_SIGNATURES:
        _label, offset, signatures = OFFSET_MAGIC_SIGNATURES[ext]
        return any(head[offset : offset + len(sig)] == sig for sig in signatures)
    _label, signatures = MAGIC_SIGNATURES[ext]
    return any(head.startswith(sig) for sig in signatures)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = len(_PRINTABLE.findall(data))
    return printable / len(data)


@dataclass
class MasqueradeFinding:
    file: str
    claimed_extension: str
    claimed_type: str
    actual_type: str
    reason: str
    severity: str

    def to_dict(self) -> dict:
        return {
            "type": "extension_masquerade",
            "file": self.file,
            "claimed_extension": self.claimed_extension,
            "claimed_type": self.claimed_type,
            "actual_type": self.actual_type,
            "reason": self.reason,
            "severity": self.severity,
        }


def _iter_candidate_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in BINARY_LIKE_EXTENSIONS:
                yield path


def check_file(path: Path, root: Path, deep: bool = True) -> MasqueradeFinding | None:
    ext = path.suffix.lower()
    try:
        head = path.read_bytes()[:512]
    except (OSError, PermissionError):
        return None

    rel = str(path.relative_to(root))
    label = (OFFSET_MAGIC_SIGNATURES[ext][0] if ext in OFFSET_MAGIC_SIGNATURES else MAGIC_SIGNATURES[ext][0])

    if magic_bytes_match(ext, head):
        return None  # magic bytes match the claimed type -- looks legitimate

    # Magic bytes did not match. Figure out what it actually looks like.
    if JS_KEYWORDS.search(head):
        return MasqueradeFinding(
            file=rel,
            claimed_extension=ext,
            claimed_type=label,
            actual_type="text/javascript",
            reason="magic bytes do not match declared type; content contains JavaScript syntax",
            severity="critical",
        )

    if deep:
        ratio = printable_ratio(head)
        entropy = shannon_entropy(head)
        # Legitimate compressed fonts/images are near-random (high entropy,
        # low printable-ASCII ratio). A long run of printable ASCII at low
        # entropy in a file claiming to be a compressed binary format is the
        # signature of a wrapped/obfuscated text payload.
        if ratio > 0.85 and entropy < 6.0:
            return MasqueradeFinding(
                file=rel,
                claimed_extension=ext,
                claimed_type=label,
                actual_type=f"text-like (printable_ratio={ratio:.2f}, entropy={entropy:.2f} bits/byte)",
                reason="magic bytes do not match declared type; content is mostly printable ASCII at low entropy",
                severity="high",
            )

    return MasqueradeFinding(
        file=rel,
        claimed_extension=ext,
        claimed_type=label,
        actual_type="unknown (magic bytes mismatch)",
        reason="magic bytes do not match declared type",
        severity="low",
    )


def scan_path(
    target: str | os.PathLike,
    deep: bool = True,
    on_progress: OnProgress | None = None,
) -> list[MasqueradeFinding]:
    """`on_progress`, if given, is called as on_progress(done, total) as
    candidate files are scanned -- see polinrider_guard.progress -- so a
    caller (the web UI) can show a "N/total files" progress bar.
    """
    root = Path(target).resolve()
    entries = allowlist.load_allowlist(root)

    if root.is_file():
        finding = check_file(root, root.parent, deep=deep) if root.suffix.lower() in BINARY_LIKE_EXTENSIONS else None
        if finding and allowlist.is_file_allowlisted(entries, "extension_masquerade", finding.file):
            finding = None
        return [finding] if finding else []

    files = list(_iter_candidate_files(root))
    report = make_reporter(len(files), on_progress)
    report(0)
    findings: list[MasqueradeFinding] = []
    for i, path in enumerate(files, start=1):
        finding = check_file(path, root, deep=deep)
        if finding and not allowlist.is_file_allowlisted(entries, "extension_masquerade", finding.file):
            findings.append(finding)
        report(i)
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-masquerade",
        description="Detect files whose content does not match their declared (binary) extension.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--no-deep", action="store_true", help="Skip entropy/printable-ratio fallback check")
    args = parser.parse_args(argv)

    findings = scan_path(args.path, deep=not args.no_deep)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No masquerading files found in {args.path}")
        for f in findings:
            print(f"SUSPICIOUS [{f.severity.upper()}]: {f.file}")
            print(f"  Extension claims: {f.claimed_extension} ({f.claimed_type})")
            print(f"  Actual content:   {f.actual_type}")
            print(f"  Reason:           {f.reason}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
