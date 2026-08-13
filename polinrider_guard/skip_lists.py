"""Shared file/directory skip-lists for the text-scanning modules
(scan_ioc.py, scan_padding.py, scan_clock_tamper.py). One list to keep in
sync instead of each scanner defining its own and drifting apart.
"""
from __future__ import annotations

# Directories never worth walking into: package manager output, VCS
# internals, build artifacts, caches. Extension is not a trust boundary for
# what's *inside* a file, but a whole directory tree of vendored/generated
# output is reasonable to skip wholesale.
SKIP_DIR_NAMES = {
    ".git", "node_modules", "vendor", "vendors", "dist", "build", ".venv", "venv",
    "__pycache__", ".tox", ".mypy_cache",
    # Framework/bundler build output -- same category as dist/build above,
    # just framework-specific names. A webpack-bundled page.js routinely has
    # a few genuinely huge lines (module code wrapped in eval(...)) next to
    # many short boilerplate ones, which is exactly the shape
    # scan_padding.py's line-length-outlier heuristic is designed to catch
    # in *hand-written* source -- it's meaningless noise against generated
    # bundles, the same reason dist/build are already skipped wholesale.
    ".next", ".nuxt", ".svelte-kit", ".output", ".turbo", ".parcel-cache",
}

# Extensions treated as binary assets and skipped by the text scanners --
# used only to avoid wasting time trying to decode obviously-non-text
# content, not to gate detection the way a naive scanner would.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    # Vector icons: a long single-line "d" path attribute is normal, not
    # payload-shaped, and this tool's threat model (supply-chain backdoors,
    # C2 domains, git-history tampering) doesn't overlap with SVG-embedded-
    # script XSS, a different attack class this project doesn't target.
    ".svg",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".mov", ".avi",
    ".pdf",
    # Source maps: always machine-generated, never hand-edited, and the
    # source they mirror is already scanned directly. Their JSON
    # sourcesContent field embeds the *entire* original file as one
    # JSON-escaped physical line (literal newlines aren't legal in a JSON
    # string, so each original line becomes a "...\n" escape run instead) --
    # that mechanically turns every leading-indentation run in the original
    # file into a "real content, gap, real content" shape once flattened,
    # which is structurally identical to actual whitespace-padding and
    # can't be told apart by regex. Guaranteed noise, not a detection gap.
    ".map",
}

# Bundled/minified third-party output, by filename convention (".min.js" is
# a double suffix, so this is a name-ending check, not SKIP_EXTENSIONS).
# Narrower and riskier than the rest of this skip-list: known vendor
# libraries routinely embed legitimate bidi-embedding/ZWJ characters (e.g.
# a bidi-wrapped RTL country name, or an HTML-entity table that defines
# zwj/zwnj/lrm/rlm as data) that a naive scanner can't distinguish from a
# real Trojan-Source-style attack by codepoint alone -- but PolinRider has
# specifically targeted minified/bundled JS, so this trades a real
# detection gap for the noise. Anything here should still get a human look
# on first import, just not a fresh flag on every scan. Ships disabled
# (empty) by default -- opt in by uncommenting the tuple below.
# SKIP_FILENAME_SUFFIXES = (".min.js", ".min.css", ".min.mjs")
SKIP_FILENAME_SUFFIXES = ()
