"""Scanner for ForceMemo-automation tooling: scripts that spoof the system
clock to forge a backdated git commit.

Detects the *tooling* itself rather than trying to infer backdating from
timestamps after the fact -- a pure author/committer date-gap check can't
reliably tell a forged commit from an ordinary long-delayed one (a developer
back from leave produces the exact same gap shape), and the real technique
this targets doesn't even leave a gap: confirmed against a real
PolinRider-family sample (a committed .bat file) that reads the previous
commit's date/author, sets the OS clock to match it, amends that commit in
place with hooks disabled, restores the real clock, and force-pushes.
Because the amend happens while the clock is spoofed, author and committer
dates come out identical -- a zero-gap forgery no timestamp comparison could
ever catch. There is no legitimate reason for a script to change the
operating system's clock in order to make a git commit.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist
from .progress import OnProgress, make_reporter
from .skip_lists import SKIP_DIR_NAMES

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".psm1", ".sh", ".bash"}

# (pattern, human description) -- any one of these setting the OS clock,
# combined with a git commit --amend anywhere in the same file, is the core
# signal. Legitimate date-testing in git uses GIT_AUTHOR_DATE/
# GIT_COMMITTER_DATE or `git commit --date=`, not the machine-wide clock.
CLOCK_SET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"(?im)^\s*date\s+%\w+%"), "Windows `date <value>` (sets the system date)"),
    (re.compile(rb"(?im)^\s*time\s+%\w+%"), "Windows `time <value>` (sets the system time)"),
    (re.compile(rb"(?i)\bSet-Date\b"), "PowerShell Set-Date"),
    (re.compile(rb"(?i)\bdate\s+-s\s"), "POSIX `date -s` (sets the system date)"),
    (re.compile(rb"(?i)\btimedatectl\s+set-time\b"), "systemd timedatectl set-time"),
]
AMEND_RE = re.compile(rb"git\s+commit\b[^\r\n]*--amend\b")
_NO_VERIFY_RE = re.compile(rb"--no-verify")
# -f\b alone misses combined short flags like `-uf` (set-upstream + force in
# one token, as the real sample uses) -- match any push-line flag cluster
# containing an f, plus the unambiguous long form.
_FORCE_PUSH_RE = re.compile(rb"git\s+push\b[^\r\n]*(?:--force\b|-[a-zA-Z]*f[a-zA-Z]*\b)")


@dataclass
class ClockTamperFinding:
    file: str
    indicators: list[str] = field(default_factory=list)
    severity: str = "critical"

    def to_dict(self) -> dict:
        return {
            "type": "clock_tamper_tooling",
            "file": self.file,
            "indicators": self.indicators,
            "severity": self.severity,
        }


def _iter_candidate_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SCRIPT_EXTENSIONS:
                yield path


def check_file(path: Path, root: Path) -> ClockTamperFinding | None:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return None

    if b"\x00" in raw[:8192]:
        return None

    clock_hits = [desc for pattern, desc in CLOCK_SET_PATTERNS if pattern.search(raw)]
    if not clock_hits or not AMEND_RE.search(raw):
        return None

    indicators = list(clock_hits)
    indicators.append("git commit --amend")
    if _NO_VERIFY_RE.search(raw):
        indicators.append("--no-verify (skips pre-commit/pre-push hooks)")
    if _FORCE_PUSH_RE.search(raw):
        indicators.append("force push")

    return ClockTamperFinding(file=str(path.relative_to(root)), indicators=indicators)


def scan_path(
    target: str | os.PathLike,
    on_progress: OnProgress | None = None,
) -> list[ClockTamperFinding]:
    """`on_progress`, if given, is called as on_progress(done, total) as
    candidate files are scanned -- see polinrider_guard.progress -- so a
    caller (the web UI) can show a "N/total files" progress bar.
    """
    root = Path(target).resolve()
    entries = allowlist.load_allowlist(root)

    if root.is_file():
        finding = check_file(root, root.parent) if root.suffix.lower() in SCRIPT_EXTENSIONS else None
        if finding and allowlist.is_file_allowlisted(entries, "clock_tamper_tooling", finding.file):
            finding = None
        return [finding] if finding else []

    files = list(_iter_candidate_files(root))
    report = make_reporter(len(files), on_progress)
    report(0)
    findings: list[ClockTamperFinding] = []
    for i, path in enumerate(files, start=1):
        finding = check_file(path, root)
        if finding and not allowlist.is_file_allowlisted(entries, "clock_tamper_tooling", finding.file):
            findings.append(finding)
        report(i)
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-clock-tamper",
        description=(
            "Detect scripts that spoof the system clock to forge a backdated "
            "git commit (ForceMemo automation tooling)."
        ),
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No clock-tampering git-automation scripts found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file}")
            for indicator in f.indicators:
                print(f"    - {indicator}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
