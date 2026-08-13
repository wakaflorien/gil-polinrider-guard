# gil-polinrider-guard

Detection and recovery tooling for **PolinRider**, a DPRK-linked
supply-chain campaign that has shipped invisible-Unicode payloads
(Glassworm), falsified git history to hide the injection commit
(ForceMemo), resolved a blockchain-backed C2 stage (BeaverTail), and — its
most recent confirmed variant — disguised the payload as a binary asset
like a font file so extension-based scanners never look at it (the
"font-file vector").

This repo gives you six independent scanners, an aggregator, a
history-surgery recovery tool (CLI, batch, and browser), YARA rules, git
hooks, and a CI workflow — all built around one idea: **file extension is a
trust model, not a security model.** None of the detectors here gate on
filename except where the mismatch between name and content *is* the thing
being detected.

Two detectors that used to live here were removed on purpose, not
overlooked. A codepoint-level invisible-Unicode scanner: the literal
Glassworm loader-marker string is still caught by the IOC scanner, but a
payload hidden behind genuinely invisible zero-width/bidi codepoints rather
than visible bytes is not. And a standalone author/committer date-gap
scanner: a large gap looks identical whether it's a forged commit or a
maintainer back from three weeks off, so a pure timestamp comparison
couldn't tell the two apart and mostly produced findings a human had to
explain away. ForceMemo backdating is still caught two other ways that
don't share that ambiguity — the *tooling* that produces a forged commit
(`scan_clock_tamper.py`) and the *shape* of a commit used to bury one
inside a mass reformat (`scan_commit_camouflage.py`).

## Contents

- [How to run](#how-to-run)
- [Install](#install)
- [Quick start: scan before you open a project](#quick-start-scan-before-you-open-a-project)
- [The six scanners](#the-six-scanners)
- [Suppressing a false positive (allowlist)](#suppressing-a-false-positive-allowlist)
- [Recovering an already-compromised repository](#recovering-an-already-compromised-repository)
- [Web UI](#web-ui)
- [Running in Docker](#running-in-docker)
- [Hardening a workstation](#hardening-a-workstation)
- [CI integration](#ci-integration)
- [YARA rules](#yara-rules)
- [Findings from a live sample](#findings-from-a-live-sample)
- [Project layout](#project-layout)
- [What this does not cover](#what-this-does-not-cover)

## How to run

**Web UI** — paste a git URL, watch it clone/scan step by step, read the
report in your browser:

```bash
pip install -e ".[web]"
polinrider-guard-web              # open http://127.0.0.1:8765
```

> **Windows note:** if `polinrider-guard-web` isn't found after install, pip put
> the console scripts in a `Scripts` folder that isn't on `PATH` (pip prints a
> warning naming the folder when this happens). Either add that folder to
> `PATH`, or run the module directly instead:
>
> ```bash
> python -m polinrider_guard.webapp
> ```

or with Docker Compose (no local Python needed):

```bash
docker compose up web             # open http://localhost:8765
```

**CLI** — scan a repo already on disk:

```bash
pip install -e .
polinrider-guard /path/to/cloned/repo
```

See [Install](#install) below for the individual-scanner commands, and
[Web UI](#web-ui) / [Running in Docker](#running-in-docker) for more options
(branches, `--json`, scanning without cloning to disk, Docker one-liners).

## Install

```bash
pip install -e .
# or, for running the test suite too:
pip install -e ".[dev]"
```

This installs six console commands: `polinrider-scan-masquerade`,
`polinrider-scan-vscode`, `polinrider-scan-ioc`,
`polinrider-scan-padding`, `polinrider-scan-clock-tamper`,
`polinrider-scan-commit-camouflage`, and the aggregator, `polinrider-guard`.

## Quick start: scan before you open a project

The highest-leverage thing you can do is scan a repository **before**
opening it in an IDE — this is what stops the auto-executing task from ever
running in the first place.

```bash
polinrider-guard /path/to/cloned/repo
```

```bash
polinrider-guard /path/to/cloned/repo --json   # structured output
polinrider-guard /path/to/cloned/repo --no-git # skip git history checks (e.g. not a repo yet)
```

Exit code is `0` if nothing was found, `1` if something was.

Try it against the fixtures shipped in this repo:

```bash
polinrider-guard examples/clean-project --no-git        # -> No findings, exit 0
polinrider-guard examples/vulnerable-samples --no-git    # -> 3 findings, exit 1
```

See [examples/vulnerable-samples/SAFETY.md](examples/vulnerable-samples/SAFETY.md)
for what that fixture contains and why it's safe.

## The six scanners

| Scanner | Detects | Command |
|---|---|---|
| Extension masquerade | Font-file vector: a file's magic bytes don't match its declared extension (e.g. JS content named `.woff2`) | `polinrider-scan-masquerade PATH` |
| Risky VS Code tasks | TasksJacker: `.vscode/tasks.json` configured to auto-run on folder open with output hidden | `polinrider-scan-vscode PATH` |
| Known IOC strings | Literal BeaverTail C2 domains, Glassworm loader marker, decode-and-eval / HiddenSpawn / EtherHiding patterns sitting in plain (non-hidden) source | `polinrider-scan-ioc PATH` |
| Hidden payload padding | A payload pushed off-screen behind 80+ spaces, or a line that's a massive outlier next to the rest of the file — structural, not byte-signature-based | `polinrider-scan-padding PATH` |
| Clock-tamper tooling | A script that spoofs the system clock and runs `git commit --amend` — the *tooling* behind a forged backdated commit, not just its aftermath | `polinrider-scan-clock-tamper PATH` |
| Commit camouflage | A mass-touch, mostly-no-op commit (e.g. a reformat sweep) that also slips in a new script/executable file — burying the one change that matters | `polinrider-scan-commit-camouflage PATH` |

Each one also works standalone with `--json` for scripting, and each is a
plain Python module under `polinrider_guard/` if you want to call it as a
library instead of a CLI.

## Suppressing a false positive (allowlist)

A finding you've reviewed and confirmed is legitimate — a vendored font that
happens to trip an entropy heuristic, a `.vscode/tasks.json` your team
actually relies on, a reformat commit that really is just a reformat — can
be suppressed without touching the flagged content itself. That matters most
for commit-camouflage findings: re-hashing a commit to "fix" a false
positive is often worse than the false positive, especially once it's
shared with collaborators.

Drop a `.polinrider-allowlist` file in the root of the path you scan (next
to `.git`, or next to the file for a single-file scan). One entry per line,
pipe-delimited, `#` for comments:

```text
# scanner | identifier | reason (optional, for your own records)
extension_masquerade   | assets/fonts/legacy-icons.woff2 | vendored upstream, verified with `file`
vscode_tasks           | .vscode/tasks.json              | team-owned auto-formatter, reviewed 2026-08-01
clock_tamper_tooling   | scripts/rebuild-release-tag.bat | internal release tooling, not a backdate
hidden_payload_padding | src/generated/bundle.js:412     | build output, long line is expected
ioc_literal_match      | test/fixtures/malware-sample.js:9 | intentional test fixture, see SAFETY.md
commit_camouflage      | a91cd3e                          | large reformat sweep, reviewed by two people
```

The identifier format depends on what the scanner reports a finding *as*:

| Scanner (`type` in JSON output) | Identifier format |
| --- | --- |
| `extension_masquerade`, `vscode_tasks`, `clock_tamper_tooling` | file path, relative to the scanned root |
| `hidden_payload_padding`, `ioc_literal_match` | `path:line` |
| `commit_camouflage` | commit SHA, or any unambiguous prefix of it (at least 7 characters) |

An allowlisted finding is dropped silently from the scan output — it never
appears in the report, the exit code, or the Web UI. It's a suppression, not
a fix: the underlying content is untouched, so `git blame`/`git log` still
show exactly what happened, and removing the allowlist entry brings the
finding straight back. Malformed lines are skipped rather than failing the
whole scan; a missing file means no entries, not an error.

## Recovering an already-compromised repository

If `polinrider-guard` finds a backdated/malicious commit that has legitimate
work on top of it, don't `git revert` (conflicts with everything after it)
and don't delete the file from history (destroys the legitimate work too).
Use the surgical cleaner, which strips only the offending lines from every
historical blob:

```bash
git clone --mirror <url> repo.git      # never rewrite your only copy
python scripts/surgical_clean.py repo.git                # dry run (default)
python scripts/surgical_clean.py repo.git --apply         # actually rewrite
# then, only after you've inspected the result yourself:
cd repo.git && git push --force --all && git push --force --tags
```

Requires `pip install git-filter-repo`. Full details, including why this
approach is used instead of `git filter-repo --invert-paths`, are in
[docs/ENTERPRISE_RECOVERY.md](docs/ENTERPRISE_RECOVERY.md).

### Cleaning many repositories at once

```bash
scripts/batch-clean.sh --repo-list repos.txt --workdir ./recovery
```

Clones each repo, runs `polinrider-guard` against a working copy (for the
audit trail), mirror-clones it, runs the surgical cleaner, and writes a
JSON-lines audit log to `./recovery/recovery-audit.jsonl`. **Never pushes on
its own** — add `--push --i-know-what-im-doing` only once you've reviewed
the result and coordinated with collaborators (their clones will need to be
re-cloned afterward).

### Recovering from the Web UI

After scanning a local path (see [Web UI](#web-ui) below), a **Recovery**
panel appears under the report. It runs the exact same logic as
`scripts/surgical_clean.py` — now shared as `polinrider_guard/recovery.py`
so the CLI and the browser can't drift apart, and covers all six scanners,
each handled the way its own technique demands:

- **IOC lines** (`scan_ioc.py`'s patterns) and **whitespace-padding-hidden
  lines** (`scan_padding.py`'s signal) — both per-line matches, stripped
  out of the blob while everything else stays byte-for-byte identical.
- **Whole clock-tamper scripts** (`scan_clock_tamper.py`'s signal) — a
  committed file like `config.bat` *is* the payload, so the entire blob is
  blanked rather than line-stripped.
- **Confirmed extension-masquerade blobs** (`scan_masquerade.py`'s
  highest-confidence tier only — magic bytes mismatch *and* JavaScript
  syntax in the content) — also blanked entirely. The softer entropy-based
  tier is intentionally left alone here: it isn't backed by an unambiguous
  content signal, so auto-blanking on it risks destroying a legitimate file
  on a false positive.
- **Historical risky `.vscode/tasks.json` blobs** (`scan_vscode.py`'s
  signal, applied to every past commit) — also blanked entirely, the same
  treatment as a clock-tamper script. Fixing only the *current* tree (see
  the removal action below) leaves the original fully recoverable from an
  older commit, a stale clone, or a fork — this covers that gap by finding
  every historical version of every `tasks.json` that ever contained a
  risky task and blanking that blob, regardless of whether it's still
  present in the current tree.
- **Camouflage commits** (`scan_commit_camouflage.py`'s signal) — reported
  for human review, not auto-rewritten. Which specific files in a
  mass-touch commit deserve removal is a judgment call this module doesn't
  make on its own; their content is usually also caught (and stripped) by
  one of the mechanisms above if it's actually malicious.
- **Risky VS Code tasks in the current tree** (`scan_vscode.py`'s signal)
  — reported, and optionally removed. This is a separate action from the
  historical-blob one above: it isn't git history at all, it's a live
  config file, so removal edits `.vscode/tasks.json` **directly in the
  directory you scanned**, deleting just the risky task object(s) from its
  `tasks` array and leaving any other, legitimate tasks in the file alone.
  It's the one Recovery action that doesn't go through the
  disposable-mirror-clone model, since there's no history to rewrite and
  the change is a normal, git-trackable working-tree edit (reversible with
  `git checkout -- .vscode/tasks.json` if the file is tracked). It
  re-serializes the file's JSON, so any comments in the original are lost
  and formatting is normalized — review the diff before committing if that
  matters to you.

The panel itself:

1. **Check what would be cleaned** — read-only, always safe, no confirmation
   needed. Shows the matching lines, the whole-file blobs that would be
   blanked, any camouflage commits found, and any risky VS Code tasks found.
2. **Rewrite history** — requires typing `REWRITE HISTORY` into a confirm
   field before the button enables. This always works on a disposable mirror
   clone the server makes on the spot; the directory you scanned is never
   modified directly, matching the CLI's own safety model.
3. **Also force-push to origin** (optional, its own checkbox) — requires a
   *second*, separate typed confirmation (`FORCE PUSH`) before it's possible,
   since this is the one action here that touches the real remote and can't
   be undone. If you don't check this, the rewrite is verified successful
   then discarded — nothing persists to push later, so use this box if you
   actually want to publish the fix rather than just confirm it would work.
   An optional access token field covers private repos over `http(s)`.
4. **Remove risky task(s)** — appears only when a risky VS Code task was
   found, and requires typing `REMOVE TASK` into its own confirm field.
   Unlike the other actions, this edits `.vscode/tasks.json` directly in
   the directory you scanned, right away — there's no disposable copy or
   force-push step, since it isn't touching git history.

All three confirmation phrases are enforced server-side, not just as
disabled buttons in the browser. Available after scanning either a local
path or a git URL — URL scans no longer delete their clone right after
scanning (see [Web UI](#web-ui) below) specifically so there's something
left to recover from.

## Web UI

For a point-and-click way to scan a repo — paste a git URL, get a colorized
report in the browser — without cloning it onto your machine first:

```bash
pip install -e ".[web]"
polinrider-guard-web              # http://127.0.0.1:8765
```

It supports two sources, picked with a toggle in the form:

- **Git URL** — `https://`, `git://`, `ssh://`, or `git@host:path`, plus an
  optional branch. Full-clones into a scratch directory (not a shallow
  `--depth 1` clone — Recovery below needs complete history to work
  correctly) and scans it. The clone is **kept on disk after scanning**
  rather than deleted, so Recovery and the file viewer have something to
  work with; it's replaced the next time you run a URL scan, not before
  (this is a single-user local tool, so "keep the one most recent clone
  around" is the whole cleanup policy — there's no TTL or multi-scan
  cache). For a private repo, paste a personal access token into the token
  field; it's sent once for that scan only (never stored, never logged, and
  stripped out of any error message before it reaches the browser), and is
  only accepted for `http(s)` URLs. A failed clone that looks auth-related
  gets a hint to add a token. `file://` URLs are rejected here — use the
  local path option below for anything already on disk.
- **Local path (already cloned)** — skips cloning entirely and scans a
  directory that's already on disk (or mounted into the container at
  `/scan`, see Docker below). Nothing is deleted afterward. Click **Browse…**
  to pick the folder from a directory listing rather than typing the path —
  browsers don't hand a real filesystem path to client-side folder pickers,
  so this lists directories from the machine actually running the scan
  (via `GET /api/browse`) instead.

Progress streams into the browser as the scan runs, with all scanners
running concurrently -- each one's row flips from pending to running to
done independently, in whatever order it actually finishes.

### Scanning every repo under a folder at once

Next to **Browse…** in local-path mode is **Scan all repos under this
path**, for when the path you'd enter is a parent folder full of separately
cloned repos (a workspace directory, the Docker `/scan` mount pointed at
something broader than one repo) rather than a single one. It walks that
folder server-side for every directory containing a `.git` (pruning the
same `node_modules`/`vendor`/build-output/cache directories the scanners
themselves skip, so it can't wander into something that could never hold a
separate project), and doesn't descend into a repo it's already found —
a vendored/checked-out repo nested inside another stays bundled with its
parent instead of becoming a second scan target. Each repo found is then
run through the exact same six-scanner pipeline as a single scan, with
bounded concurrency across repos (so a folder with dozens of repos doesn't
try to spin up dozens of repos' worth of scanner threads all at once) —
8 repos at a time by default, since each repo's own scan already runs its
six scanners concurrently internally. Raise it with
`polinrider-guard-web --batch-workers 16`, or `BATCH_WORKERS=16 docker
compose up web` under Compose, if you're scanning a large workspace and
have the cores/disk throughput to back a higher number.

The result is one dashboard: how many repos were scanned, how many had
findings, and a row per repo with its severity breakdown. Click **View
report** on any row to see that repo's full report — the same view a
single scan produces, "View file" buttons and all — and
[Recovery](#recovering-from-the-web-ui) works from there exactly as it
would after scanning that repo directly, since nothing about a repo's own
scan or recovery flow changes just because it was discovered this way.
Capped at 200 repos per run, noted on the dashboard if hit.

Every finding tied to a specific file has a **View file** button that opens
it in a modal, scrolled to and highlighting the matching line where one
applies (`GET /api/file`, resolved and checked to stay inside the scanned
directory — same trust boundary as scanning itself, not a new one).
[Recovery](#recovering-from-the-web-ui) is available after either kind of
scan, for the same reason: URL scans no longer delete their clone.

Binds to `127.0.0.1` only by default. All of this is meaningfully more
exposed than a plain read-only page — the URL mode clones whatever it's
given (and now keeps that clone on disk between scans), the local-path mode
and file viewer read whatever path they're given, and the folder browser
walks the directory tree of whatever machine is running the server — so
don't put this on a shared interface without your own auth in front of it.
Passing a non-loopback `--host` prints a warning to the console as a
reminder.

## Running in Docker

Scanning an unfamiliar repository from inside a container keeps it off your
host entirely.

```bash
docker build -t polinrider-guard .
docker run --rm -v /path/to/cloned/repo:/scan polinrider-guard .
docker run --rm -v /path/to/cloned/repo:/scan polinrider-guard . --json

# web UI instead, reachable at http://localhost:8765
docker run --rm -p 8765:8765 --entrypoint polinrider-guard-web polinrider-guard --host 0.0.0.0
```

Or with Compose, which mounts the current directory by default:

```bash
docker compose run --rm guard                              # scans this repo
SCAN_PATH=/path/to/cloned/repo docker compose run --rm guard
docker compose run --rm guard --json

docker compose up web                                       # web UI on :8765
SCAN_PATH=/path/to/cloned/repo docker compose up web        # then enter "/scan" as the local path in the UI
```

The image also ships `git` and `git-filter-repo`, so `scripts/surgical_clean.py`
can be run the same way against a mirror clone mounted into the container.

The mounted scan path is read-only by default (`:ro`), and Recovery's
git-history rewrite never needs it to be otherwise — that always works on a
disposable server-side mirror clone. The one exception is
**"Remove risky task(s)"** in the Recovery panel, which edits
`.vscode/tasks.json` directly in the scanned directory (see
[Recovering from the Web UI](#recovering-from-the-web-ui)) — against a
read-only mount, that action fails with a clear error instead of silently
doing nothing. Change `:ro` to `:rw` on the `web` service's volume in
`docker-compose.yml` if you want that action available and trust the
container with write access to whatever `SCAN_PATH` points at.

## Hardening a workstation

```bash
scripts/install-hooks.sh
```

Installs `pre-commit` (blocks a commit if the working tree has findings)
and `post-merge` (warns loudly after a merge/pull) as **global** git hooks
via `core.hooksPath`, so they run for every repo on the machine, not just
one. Bypass a single commit with `POLINRIDER_GUARD_SKIP=1 git commit ...`
or `git commit --no-verify`.

Also recommended: open unfamiliar repositories inside a
[Dev Container](https://containers.dev/) rather than your host environment,
disable VS Code's automatic-task execution
(`"task.allowAutomaticTasks": "off"` in user settings), and use
`npm install --ignore-scripts` on first install of an unfamiliar project.

## CI integration

`.github/workflows/polinrider-guard.yml` runs the test suite, self-scans
this project's own source (must be clean), and runs the negative-control
check (`examples/clean-project` must stay clean, `examples/vulnerable-samples`
must keep triggering findings — so a detection regression fails CI instead
of going unnoticed). Enforce it with branch protection so a compromised
contributor can't just edit the workflow file away; see
[docs/GITHUB_PROTECTION.md](docs/GITHUB_PROTECTION.md).

## YARA rules

`rules/polinrider.yar` covers most of the same ground as the Python
scanners (plus, currently, an invisible-Unicode rule the Python side no
longer has — see above), for environments that already run YARA (SIEM,
file-integrity monitoring, pre-commit via `yara` CLI). Deliberately **not**
filtered by file extension
for the payload rules — extension filtering is exactly what let the
font-file vector go undetected in the first place. The one rule that does
care about extension (`PolinRider_Binary_Extension_Masquerade`) uses it as
the thing being checked *against* the content, not as a gate on which files
get scanned.

```bash
yara -d filename=path/to/file rules/polinrider.yar path/to/file
```

## Findings from a live sample

Three of the six scanners (`scan_padding.py`, `scan_clock_tamper.py`,
`scan_commit_camouflage.py`) exist because of a real PolinRider-family
sample found via this tool, not a hypothetical. Summary, for anyone
auditing why these detectors look the way they do:

- **The payload** was appended to an otherwise-normal `eslint.config.mjs`
  as one 9,134-character line, preceded by hundreds of spaces so it never
  scrolled into view in a normal editor. It resolved its C2 server by
  reading a specific Ethereum transaction and reinterpreting the
  recipient-address field's raw bytes as two IPv4 addresses ("EtherHiding"
  — the address never appears as a string anywhere, on-chain or off, so
  there's no domain to blocklist). It then fetched two XOR-encrypted
  payloads from that resolved address and, for each one, both `eval()`'d it
  inline and unconditionally spawned it again as a fully detached, hidden,
  `stdio`-suppressed background `node` process that outlives the process
  that triggered ESLint entirely ("HiddenSpawn").
- **A companion `.bat` file** implemented ForceMemo as pure automation:
  read the previous commit's date/author from `git log`, set the *operating
  system clock* to match it, `git commit --amend --no-verify` while the
  clock was spoofed (forging identical author/committer dates — a zero-gap
  backdate that a pure date-gap check can't see), restored the real clock,
  then force-pushed with hooks still disabled.
- **The delivery commit** touched roughly 180 files with matching
  addition/deletion counts on nearly all of them (a no-op-shaped reformat
  sweep) while introducing the `.bat` file and the payload — burying the
  two changes that mattered in a diff nobody reviews file-by-file.

Windows Defender independently flagged the sample as `Trojan:NPM/PolinRider.SB`
and `Trojan:NPM/HiddenSpawn.IAF!MTB`, corroborating both the C2-resolution
and persistence mechanisms above.

## Project layout

```
polinrider_guard/       the six scanners + guard.py aggregator + shared IOC list
  skip_lists.py           shared directory/extension skip-lists
  allowlist.py            .polinrider-allowlist parsing, shared by every scanner
  recovery.py             history-surgery logic shared by the CLI and the web UI
  webapp.py              web UI (polinrider-guard-web): clone-a-URL, scan, render, recover
  web_static/            the web UI's single HTML/JS page
scripts/
  surgical_clean.py     CLI wrapper around polinrider_guard/recovery.py (dry-run by default)
  batch-clean.sh         multi-repo recovery orchestrator
  install-hooks.sh       installs global git hooks
hooks/                   pre-commit / post-merge hook scripts
rules/polinrider.yar     YARA rules
examples/
  clean-project/         negative control -- must always report 0 findings
  vulnerable-samples/     positive control -- reworded, inert fixtures (see SAFETY.md)
tests/                   pytest suite exercising every scanner + surgical clean
docs/
  ENTERPRISE_RECOVERY.md  full recovery walkthrough
  GITHUB_PROTECTION.md    branch protection settings for the CI workflow
```

## What this does not cover

This project is about detecting and recovering from the file/repo/IDE-level
IOCs of this specific campaign. It does not cover npm registry-level package
compromise (check your `node_modules` against published IOC lists
separately), notifying downstream forks of a public repository, or incident
reporting/legal obligations. Treat a positive finding as the start of an
investigation, not the end of one.
