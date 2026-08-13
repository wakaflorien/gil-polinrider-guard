"""Shared helper so scanners can report per-file scan progress without
flooding the caller with an event for every single file in a large repo.
"""
from __future__ import annotations

from typing import Callable

OnProgress = Callable[[int, int], None]


def make_reporter(total: int, on_progress: OnProgress | None) -> Callable[[int], None]:
    """Return a function taking just `done`, which calls `on_progress(done,
    total)` -- throttled to roughly 100 calls across the whole run (about
    every 1%, always including the first and last) rather than once per
    file, since a repo with tens of thousands of candidate files would
    otherwise flood the caller (an SSE stream, in the web UI's case) with
    an event per file. A no-op if `on_progress` wasn't given or there's
    nothing to scan.
    """
    if on_progress is None or total == 0:
        return lambda done: None
    step = max(1, total // 100)

    def report(done: int) -> None:
        if done == total or done % step == 0:
            on_progress(done, total)

    return report
