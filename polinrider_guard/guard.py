"""polinrider-guard: run every scanner against a path and produce one report.

This is the command meant to be run before opening an unfamiliar repository
in an IDE (the "pre-open checklist"), and the one whose --json output feeds
the batch cleaner in scripts/batch-clean.sh.
"""
from __future__ import annotations

import json as jsonlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Callable

from . import (
    scan_clock_tamper,
    scan_commit_camouflage,
    scan_ioc,
    scan_masquerade,
    scan_padding,
    scan_vscode,
)


# (step key, human label) for every scanner, in the order they run -- shared
# with polinrider_guard.webapp so the web UI's progress feed matches reality
# instead of a hardcoded guess at what the CLI is doing. The git-dependent
# scanner (commit_camouflage) is last, since it's the one --no-git / a
# missing .git directory skips.
SCANNER_STEPS: list[tuple[str, str]] = [
    ("extension_masquerade", "Extension masquerade (font-file vector)"),
    ("vscode_tasks", "Risky VS Code tasks (TasksJacker)"),
    ("hidden_payload_padding", "Hidden payload padding (whitespace/line-length anomaly)"),
    ("clock_tamper_tooling", "Clock-tamper git automation (ForceMemo tooling)"),
    ("ioc_literal_match", "Known IOC strings (C2 domains, loader markers)"),
    ("commit_camouflage", "Commit camouflage (mass-touch decoy commit)"),
]

# Scanners whose scan_path() accepts an on_progress(done, total) callback --
# the ones that walk a large, open-ended set of candidate files. vscode_tasks
# (a handful of tasks.json files via rglob) and commit_camouflage (one `git
# log` call, not a file walk) aren't file-count-shaped in the same way, so
# they're left out. Shared with polinrider_guard.webapp so both the
# single-scan and batch-scan progress feeds agree on which scanners can
# report a "N/total files" progress bar.
PROGRESS_CAPABLE_SCANNERS = {
    "extension_masquerade", "hidden_payload_padding", "clock_tamper_tooling", "ioc_literal_match",
}


def build_report(
    root: str | os.PathLike,
    scanners: dict[str, list[dict]],
    git_skipped_reason: str | None = None,
) -> dict:
    """Assemble the summary/severity-count envelope around raw scanner output.

    Split out of run_guard() so callers that need to report progress between
    scanners (the web UI) can run each scanner themselves and still produce
    an identical report shape at the end.
    """
    report: dict = {
        "target": str(Path(root).resolve()),
        "scanners": dict(scanners),
        "summary": {"total_findings": 0, "by_severity": {}},
    }
    if git_skipped_reason:
        report["git_skipped_reason"] = git_skipped_reason

    all_findings = [
        finding
        for findings in report["scanners"].values()
        for finding in findings
    ]
    report["summary"]["total_findings"] = len(all_findings)
    by_sev: dict[str, int] = {}
    for finding in all_findings:
        sev = finding.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    report["summary"]["by_severity"] = by_sev

    return report


def run_guard(
    target: str | os.PathLike,
    include_git: bool = True,
    scanners: list[str] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict:
    """Run the scanners against `target`.

    `scanners`, if given, restricts the run to that subset of SCANNER_STEPS
    keys (e.g. from a web UI's checkbox selection) instead of running all of
    them; unknown keys are ignored. Skipped scanners are reported as empty
    findings lists rather than omitted, so the report shape stays identical
    regardless of what was selected.

    `on_progress`, if given, is called as on_progress(scanner_key, done,
    total) from inside each progress-capable scanner's own worker thread as
    it walks its candidate files (see PROGRESS_CAPABLE_SCANNERS and
    polinrider_guard.progress) -- e.g. so a batch-scan caller can aggregate
    per-repo file-scan progress across scanners. Since scanners run
    concurrently, `on_progress` may be called from multiple threads at
    once; a caller with shared/mutable state to update in it is
    responsible for its own thread-safety there.
    """
    root = Path(target).resolve()
    all_keys = [key for key, _ in SCANNER_STEPS]
    selected = [key for key in all_keys if scanners is None or key in scanners]

    def _task(key: str, fn) -> Callable[[], object]:
        if key in PROGRESS_CAPABLE_SCANNERS and on_progress is not None:
            return lambda: fn(root, on_progress=partial(on_progress, key))
        return lambda: fn(root)

    # Each scanner does its own independent os.walk (some also shell out to
    # git) over the same read-only tree -- nothing shared/mutable between
    # them, so running them concurrently is safe and, for a large repo,
    # meaningfully faster than the equivalent sequential sum.
    scan_funcs = {
        "extension_masquerade": scan_masquerade.scan_path,
        "vscode_tasks": scan_vscode.scan_path,
        "hidden_payload_padding": scan_padding.scan_path,
        "clock_tamper_tooling": scan_clock_tamper.scan_path,
        "ioc_literal_match": scan_ioc.scan_path,
        "commit_camouflage": scan_commit_camouflage.scan_path,
    }
    all_tasks: dict[str, object] = {key: _task(key, fn) for key, fn in scan_funcs.items()}
    tasks = {key: fn for key, fn in all_tasks.items() if key in selected}
    if "commit_camouflage" in tasks and not include_git:
        del tasks["commit_camouflage"]

    findings: dict[str, list[dict]] = {key: [] for key in all_keys}
    git_skipped_reason = None

    if tasks:
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {key: executor.submit(fn) for key, fn in tasks.items()}
            for key, future in futures.items():
                if key == "commit_camouflage":
                    try:
                        findings[key] = [f.to_dict() for f in future.result()]
                    except scan_commit_camouflage.NotAGitRepoError:
                        findings[key] = []
                        git_skipped_reason = "not a git repository"
                else:
                    findings[key] = [f.to_dict() for f in future.result()]

    if "commit_camouflage" in selected and not include_git:
        git_skipped_reason = "--no-git"

    return build_report(root, findings, git_skipped_reason)


def _print_text_report(report: dict) -> None:
    target = report["target"]
    total = report["summary"]["total_findings"]

    if total == 0:
        print(f"No findings in {target}")
        return

    print(f"polinrider-guard report for {target}")
    print(f"Total findings: {total}  ({_format_severity_counts(report['summary']['by_severity'])})")
    print()

    labels = dict(SCANNER_STEPS)

    for key, findings in report["scanners"].items():
        if not findings:
            continue
        print(f"== {labels.get(key, key)} ({len(findings)}) ==")
        for f in findings:
            _print_finding_line(key, f)
        print()

    if report.get("git_skipped_reason"):
        print(f"(git checks skipped: {report['git_skipped_reason']})")


def _print_finding_line(scanner: str, f: dict) -> None:
    sev = f.get("severity", "?").upper()
    if scanner == "extension_masquerade":
        print(f"  [{sev}] {f['file']} claims {f['claimed_type']} but is {f['actual_type']}")
    elif scanner == "vscode_tasks":
        print(f"  [{sev}] {f['file']} task '{f['task_label']}': {'; '.join(f['reasons'])}")
    elif scanner == "ioc_literal_match":
        print(f"  [{sev}] {f['file']}:{f['line']} - {f['description']} ({f['matched_text']!r})")
    elif scanner == "hidden_payload_padding":
        print(f"  [{sev}] {f['file']}:{f['line']} ({f['kind']}, {f['line_length']} chars)")
        print(f"      {f['context']}")
    elif scanner == "clock_tamper_tooling":
        print(f"  [{sev}] {f['file']}: {'; '.join(f['indicators'])}")
    elif scanner == "commit_camouflage":
        print(
            f"  [{sev}] {f['commit'][:12]} - {f['subject']} "
            f"({f['files_changed']} files, {f['noop_like_files']} no-op-like, "
            f"new: {', '.join(f['suspicious_new_files'])})"
        )
    else:
        print(f"  [{sev}] {f}")


def _format_severity_counts(by_sev: dict) -> str:
    order = ["critical", "high", "medium", "low", "unknown"]
    parts = [f"{sev}={by_sev[sev]}" for sev in order if sev in by_sev]
    return ", ".join(parts)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="polinrider-guard",
        description="Run all PolinRider detection scanners against a path and produce a combined report.",
    )
    scanner_keys = [key for key, _ in SCANNER_STEPS]
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--no-git", action="store_true", help="Skip git history checks")
    parser.add_argument(
        "--scanners",
        metavar="KEY",
        choices=scanner_keys,
        nargs="+",
        help=f"Only run these scanners (default: all). Choices: {', '.join(scanner_keys)}",
    )
    args = parser.parse_args(argv)

    report = run_guard(args.path, include_git=not args.no_git, scanners=args.scanners)

    if args.json:
        print(jsonlib.dumps(report, indent=2))
    else:
        _print_text_report(report)

    return 1 if report["summary"]["total_findings"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
