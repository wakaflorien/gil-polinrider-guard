"""Literal IOC scanner for confirmed PolinRider fingerprints.

Finds known-malicious patterns sitting in plain sight -- e.g. a
decoded/deobfuscated blob, a debug build, or a variant that hides its
payload behind whitespace padding (scan_padding.py) rather than invisible
codepoints. It reuses the same pattern list as scripts/surgical_clean.py so
detection and remediation stay in sync.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import allowlist
from .iocs import DEFAULT_IOC_PATTERNS
from .progress import OnProgress, make_reporter
from .skip_lists import SKIP_DIR_NAMES, SKIP_EXTENSIONS, SKIP_FILENAME_SUFFIXES


@dataclass
class IocFinding:
    file: str
    line: int
    description: str
    severity: str
    matched_text: str

    def to_dict(self) -> dict:
        return {
            "type": "ioc_literal_match",
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "severity": self.severity,
            "matched_text": self.matched_text,
        }


def _iter_candidate_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if name.lower().endswith(SKIP_FILENAME_SUFFIXES):
                continue
            yield path


def scan_file(path: Path, root: Path, patterns: list[tuple[re.Pattern, str, str]]) -> list[IocFinding]:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return []

    if b"\x00" in raw[:8192]:
        return []

    rel = str(path.relative_to(root))
    findings: list[IocFinding] = []
    for line_no, line in enumerate(raw.split(b"\n"), start=1):
        # A line can opt out of IOC matching with a trailing
        # `polinrider-guard:ignore` comment -- used by iocs.py itself, which
        # necessarily contains these patterns as literal data, the same way
        # an antivirus engine doesn't flag its own signature database.
        if b"polinrider-guard:ignore" in line:
            continue
        for pattern, description, severity in patterns:
            match = pattern.search(line)
            if match:
                findings.append(
                    IocFinding(
                        file=rel,
                        line=line_no,
                        description=description,
                        severity=severity,
                        matched_text=match.group(0).decode("utf-8", errors="replace"),
                    )
                )
    return findings


def scan_path(
    target: str | os.PathLike,
    on_progress: OnProgress | None = None,
) -> list[IocFinding]:
    """`on_progress`, if given, is called as on_progress(done, total) as
    candidate files are scanned -- see polinrider_guard.progress -- so a
    caller (the web UI) can show a "N/total files" progress bar.
    """
    root = Path(target).resolve()
    entries = allowlist.load_allowlist(root)
    patterns = [(re.compile(p), desc, sev) for p, desc, sev in DEFAULT_IOC_PATTERNS]

    if root.is_file():
        findings = scan_file(root, root.parent, patterns)
    else:
        files = list(_iter_candidate_files(root))
        report = make_reporter(len(files), on_progress)
        report(0)
        findings = []
        for i, path in enumerate(files, start=1):
            findings.extend(scan_file(path, root, patterns))
            report(i)

    return [
        f for f in findings
        if not allowlist.is_file_line_allowlisted(entries, "ioc_literal_match", f.file, f.line)
    ]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-ioc",
        description="Scan source files for known PolinRider literal IOCs (C2 domains, loader markers).",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No known IOC strings found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file}:{f.line} - {f.description}")
            print(f"    matched: {f.matched_text!r}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
