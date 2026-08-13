import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "examples" / "clean-project"
VULNERABLE = ROOT / "examples" / "vulnerable-samples"

sys.path.insert(0, str(ROOT))

from polinrider_guard import (  # noqa: E402
    allowlist,
    guard,
    scan_clock_tamper,
    scan_commit_camouflage,
    scan_ioc,
    scan_masquerade,
    scan_padding,
    scan_vscode,
)


def _run_git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(repo):
    repo.mkdir()
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Test User")


def test_ioc_scanner_scans_minified_js_by_default(tmp_path):
    (tmp_path / "vendor.min.js").write_text(
        'const c2 = "trongrid.io";\n', encoding="utf-8"
    )
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1
    assert "trongrid.io" in findings[0].matched_text


def test_masquerade_scanner_clean():
    assert scan_masquerade.scan_path(CLEAN) == []


def test_masquerade_scanner_accepts_real_eot_header(tmp_path):
    # Real EOT headers put "LP" at offset 34 -- bytes 0-3 are EOTSize (the
    # file's own total length, a variable field, not a signature). This is
    # the actual header prefix from a Font Awesome fontawesome-webfont.eot.
    header = bytes.fromhex(
        "3d950000" "57940000" "02000200" "04000000" "00000000"
        "00000000" "00000100" "90010000" "0400" "4c50"
    )
    (tmp_path / "icons.eot").write_bytes(header + b"\x00" * 32)
    assert scan_masquerade.scan_path(tmp_path) == []


def test_masquerade_scanner_still_flags_js_disguised_as_eot(tmp_path):
    (tmp_path / "icons.eot").write_bytes(b"function evil(){require('fs')}" + b"\x00" * 16)
    findings = scan_masquerade.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].actual_type == "text/javascript"
    assert findings[0].severity == "critical"


def test_masquerade_scanner_finds_font_vector():
    findings = scan_masquerade.scan_path(VULNERABLE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.claimed_extension == ".png"
    assert finding.actual_type == "text/javascript"
    assert finding.severity == "critical"


def test_vscode_scanner_clean():
    assert scan_vscode.scan_path(CLEAN) == []


def test_vscode_scanner_finds_tasksjacker_pattern():
    findings = scan_vscode.scan_path(VULNERABLE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.task_label == "format-check"
    assert finding.severity == "critical"
    assert any("folderOpen" in r for r in finding.reasons)
    assert any("hide=true" in r for r in finding.reasons)


def test_ioc_scanner_clean():
    assert scan_ioc.scan_path(CLEAN) == []


def test_ioc_scanner_self_scan_is_clean():
    # iocs.py necessarily contains these patterns as literal data (it's the
    # pattern definitions module) -- it must not flag itself, the same way
    # an antivirus engine doesn't flag its own signature database.
    assert scan_ioc.scan_path(ROOT / "polinrider_guard") == []


def test_ioc_scanner_respects_ignore_marker(tmp_path):
    (tmp_path / "sample.js").write_text(
        'const c2 = "trongrid.io"; // polinrider-guard:ignore\n'
    )
    assert scan_ioc.scan_path(tmp_path) == []


def test_ioc_scanner_finds_c2_domain():
    findings = scan_ioc.scan_path(VULNERABLE)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "trongrid.io" in findings[0].matched_text
    assert findings[0].file.endswith("analytics.js")


def test_ioc_scanner_finds_implant_id_marker(tmp_path):
    (tmp_path / "loader.js").write_text('global.i="A8-3955";\n')
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "global.i" in findings[0].matched_text


def test_ioc_scanner_finds_require_to_global_stash(tmp_path):
    (tmp_path / "loader.js").write_text("global.r=require;\n")
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_ioc_scanner_finds_unicode_escaped_require(tmp_path):
    # http spells "http" -- real PolinRider loader sample
    # uses this to keep sensitive module names out of a plain grep. Matches
    # both the require()-specific pattern and the generic 4+-escape one.
    (tmp_path / "loader.js").write_text(
        'const http=require("\\u0068\\u0074\\u0074\\u0070");\n'
    )
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 2
    assert all(f.severity == "high" for f in findings)
    assert any("require(" in f.matched_text for f in findings)


def test_ioc_scanner_does_not_flag_ordinary_require(tmp_path):
    (tmp_path / "app.js").write_text('const http = require("http");\n')
    assert scan_ioc.scan_path(tmp_path) == []


def test_ioc_scanner_finds_hidden_spawn_persistence(tmp_path):
    (tmp_path / "loader.js").write_text(
        'spawn("node",["-e",r],{detached:!0,stdio:"ignore",windowsHide:!0}).unref();\n'
    )
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "HiddenSpawn" in findings[0].description


def test_ioc_scanner_does_not_flag_ordinary_spawn(tmp_path):
    (tmp_path / "app.js").write_text('spawn("node", ["build.js"], {stdio: "inherit"});\n')
    assert scan_ioc.scan_path(tmp_path) == []


def test_ioc_scanner_finds_etherhiding_pattern(tmp_path):
    (tmp_path / "loader.js").write_text(
        "const n2=Buffer.from(e.tx.to.replace(/^0x/i,''),'hex'),"
        "ip=b=>b[0]+'.'+b[1]+'.'+b[2]+'.'+b[3],"
        "[o,r]=[ip(n2.subarray(0,4)),ip(n2.subarray(4,8))];\n"
    )
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "EtherHiding" in findings[0].description


def test_ioc_scanner_finds_generic_unicode_escaped_string(tmp_path):
    # Not wrapped in require() -- the earlier require()-scoped pattern would
    # miss this, e.g. the real sample's C2 URL: I="https://eth.blockscout.com/api"
    (tmp_path / "loader.js").write_text(
        'const I="\\u0068\\u0074\\u0074\\u0070\\u0073";\n'
    )
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_padding_scanner_finds_whitespace_padded_payload(tmp_path):
    (tmp_path / "eslint.config.mjs").write_text(
        "export default [];" + " " * 200 + 'global.i="A8-3955";\n'
    )
    findings = scan_padding.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].kind == "excessive_whitespace_padding"
    assert findings[0].severity == "high"


def test_padding_scanner_ignores_leading_indentation(tmp_path):
    # Real false positive: a hand-aligned JS continuation line indented to
    # line up with the statement above it -- 80+ leading spaces but no real
    # content before the gap, unlike the actual attack shape (payload
    # appended after legitimate code on the same line).
    js = (
        "const details = fetchDetails(row.details)\n"
        + " " * 98
        + ".then(result => render(result));\n"
    )
    (tmp_path / "view.js").write_text(js)
    assert scan_padding.scan_path(tmp_path) == []


def test_padding_scanner_only_scans_js_family_files(tmp_path):
    # The whitespace-padding hiding technique this scanner targets is
    # JS-specific (see module docstring) -- non-JS files aren't walked at
    # all, regardless of content, so vendored/minified CSS/SVG/etc. assets
    # (the recurring real-world noise source) never reach either heuristic.
    payload_line = "export default [];" + " " * 200 + 'global.i="A8-3955";'
    (tmp_path / "style.css").write_text(payload_line)
    (tmp_path / "view.php").write_text(payload_line)
    assert scan_padding.scan_path(tmp_path) == []


def test_padding_scanner_finds_whitespace_padded_payload_on_last_line(tmp_path):
    # Same signal as test_padding_scanner_finds_whitespace_padded_payload,
    # but the padded line is the file's last line with no trailing newline
    # -- guards against a splitlines()-related edge case at EOF.
    payload_line = "export default [];" + " " * 200 + 'global.i="A8-3955";'
    (tmp_path / "eslint.config.mjs").write_text(
        "const a = 1;\nconst b = 2;\n" + payload_line
    )
    findings = scan_padding.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 3
    assert findings[0].kind == "excessive_whitespace_padding"


def test_padding_scanner_finds_line_length_outlier(tmp_path):
    normal_lines = "\n".join(f"const x{i} = {i};" for i in range(10))
    huge_line = "const payload = '" + ("A" * 3000) + "';"
    (tmp_path / "app.js").write_text(normal_lines + "\n" + huge_line + "\n")
    findings = scan_padding.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].kind == "line_length_outlier"
    assert findings[0].severity == "medium"


def test_padding_scanner_clean_on_normal_file(tmp_path):
    (tmp_path / "app.js").write_text("\n".join(f"const x{i} = {i};" for i in range(20)) + "\n")
    assert scan_padding.scan_path(tmp_path) == []


def test_padding_scanner_ignores_outlier_in_licensed_vendor_bundle(tmp_path):
    # Real false positive: a widely-distributed minified library (Socket.IO)
    # that opens with a terser/uglify/rollup-preserved "/*!" license banner
    # -- a much stronger signal of "distributed third-party code" than a
    # ".min.js" filename convention, which this project deliberately does
    # NOT trust alone (see SKIP_FILENAME_SUFFIXES in skip_lists.py).
    banner = (
        "/*!\n"
        " * Socket.IO v4.7.5\n"
        " * (c) 2014-2024 Guillermo Rauch\n"
        " * Released under the MIT License.\n"
        " */\n"
    )
    huge_line = '!function(e,t){"object"==typeof exports' + ("x" * 3000) + "}();"
    (tmp_path / "socket.io.min.js").write_text(banner + huge_line + "\n")
    assert scan_padding.scan_path(tmp_path) == []


def test_padding_scanner_still_finds_padding_in_licensed_vendor_bundle(tmp_path):
    # The license-banner exemption above only silences the softer
    # line_length_outlier signal -- the high-confidence whitespace-padding
    # check still runs even on a file with a license banner, since a real
    # supply-chain attack could tamper with a genuine vendor file (banner
    # intact) rather than adding a whole new one.
    banner = (
        "/*!\n"
        " * Socket.IO v4.7.5\n"
        " * (c) 2014-2024 Guillermo Rauch\n"
        " * Released under the MIT License.\n"
        " */\n"
    )
    tampered = banner + "const x = 1;" + " " * 200 + 'global.i="A8-3955";\n'
    (tmp_path / "socket.io.min.js").write_text(tampered)
    findings = scan_padding.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].kind == "excessive_whitespace_padding"


def test_padding_scanner_ignores_uniformly_minified_file(tmp_path):
    # Every line is long -- no single line is an outlier relative to the
    # file's own median, so a genuinely minified bundle doesn't trip this.
    lines = ["var a" + str(i) + " = function(){return " + ("x" * 400) + ";};" for i in range(10)]
    (tmp_path / "vendor.min.js").write_text("\n".join(lines) + "\n")
    assert scan_padding.scan_path(tmp_path) == []


def test_padding_scanner_skips_next_build_output(tmp_path):
    # Real-world false positive: a webpack-bundled Next.js page.js has a
    # few genuinely huge lines (module code wrapped in eval(...)) next to
    # many short boilerplate lines -- exactly the shape the line-length
    # outlier heuristic is designed to catch in hand-written source, but
    # meaningless noise in generated build output. .next is skipped
    # wholesale, the same as dist/build/node_modules.
    next_dir = tmp_path / ".next" / "server" / "app"
    next_dir.mkdir(parents=True)
    boilerplate = "\n".join(f"const x{i} = {i};" for i in range(10))
    huge_line = 'eval("' + ("A" * 5000) + '");'
    (next_dir / "page.js").write_text(boilerplate + "\n" + huge_line + "\n")

    assert scan_padding.scan_path(tmp_path) == []
    # Sanity check: the same content outside .next would have tripped it.
    (tmp_path / "page.js").write_text(boilerplate + "\n" + huge_line + "\n")
    assert len(scan_padding.scan_path(tmp_path)) == 1


def test_masquerade_scanner_skips_next_build_output(tmp_path):
    next_dir = tmp_path / ".next" / "static"
    next_dir.mkdir(parents=True)
    (next_dir / "icon.woff2").write_bytes(b"function evil(){require('fs')}")

    assert scan_masquerade.scan_path(tmp_path) == []


def test_clock_tamper_scanner_finds_real_pattern(tmp_path):
    (tmp_path / "config.bat").write_text(
        "for /f \"delims=\" %%A in ('cmd /c \"git log -1 --format=%%cd\"') do set LAST_COMMIT_DATE=%%A\n"
        "date %LAST_COMMIT_DATE%\n"
        "time %LAST_COMMIT_TIME%\n"
        "git commit --amend -m \"%LAST_COMMIT_TEXT%\" --no-verify\n"
        "git push -uf origin %CURRENT_BRANCH% --no-verify\n"
    )
    findings = scan_clock_tamper.scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert any("date" in i.lower() for i in findings[0].indicators)
    assert any("no-verify" in i for i in findings[0].indicators)
    assert any("force" in i.lower() for i in findings[0].indicators)


def test_clock_tamper_scanner_requires_both_clock_and_amend(tmp_path):
    (tmp_path / "just_amend.bat").write_text('git commit --amend -m "oops typo"\n')
    (tmp_path / "just_clock.bat").write_text("date %SOME_DATE%\n")
    assert scan_clock_tamper.scan_path(tmp_path) == []


def test_clock_tamper_scanner_ignores_non_script_extensions(tmp_path):
    (tmp_path / "notes.txt").write_text(
        "date %LAST_COMMIT_DATE%\ngit commit --amend -m x\n"
    )
    assert scan_clock_tamper.scan_path(tmp_path) == []


def test_commit_camouflage_scanner_finds_mass_touch_with_new_script(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)

    # Baseline commit: 45 files with real content.
    for i in range(45):
        (repo / f"file{i}.ts").write_text(f"export const value{i} = {i};\n" * 3)
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "initial commit")

    # "Camouflage" commit: touch all 45 files with a no-op-*shaped* rewrite
    # (every line replaced by an equivalent one, e.g. a line-ending/trailing-
    # whitespace sweep -- added==deleted per file, not a truly no-op byte-
    # identical rewrite, which git wouldn't even show as a change), and slip
    # in a new .bat file.
    for i in range(45):
        (repo / f"file{i}.ts").write_text(f"export const value{i} = {i}; \n" * 3)
    (repo / "config.bat").write_text("@echo off\nrem setup\n")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "return back")

    findings = scan_commit_camouflage.scan_path(repo)
    assert len(findings) == 1
    assert findings[0].subject == "return back"
    assert findings[0].files_changed >= 40
    assert "config.bat" in findings[0].suspicious_new_files
    assert findings[0].severity == "critical"


def test_commit_camouflage_scanner_clean_on_normal_history(tmp_path):
    repo = tmp_path / "repo2"
    _init_repo(repo)
    (repo / "a.txt").write_text("first\n")
    _run_git(repo, "add", "a.txt")
    _run_git(repo, "commit", "-q", "-m", "normal commit 1")
    (repo / "a.txt").write_text("first\nsecond\n")
    _run_git(repo, "add", "a.txt")
    _run_git(repo, "commit", "-q", "-m", "normal commit 2")
    assert scan_commit_camouflage.scan_path(repo) == []


def test_commit_camouflage_scanner_raises_on_non_repo(tmp_path):
    with pytest.raises(scan_commit_camouflage.NotAGitRepoError):
        scan_commit_camouflage.scan_path(tmp_path)


def test_guard_exit_code_clean(tmp_path):
    report = guard.run_guard(CLEAN, include_git=False)
    assert report["summary"]["total_findings"] == 0


def test_guard_exit_code_vulnerable():
    report = guard.run_guard(VULNERABLE, include_git=False)
    assert report["summary"]["total_findings"] > 0
    assert report["summary"]["by_severity"].get("critical", 0) >= 2


def test_cli_clean_project_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "polinrider_guard.guard", str(CLEAN), "--no-git"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "No findings" in result.stdout


def test_cli_vulnerable_samples_exits_one():
    result = subprocess.run(
        [sys.executable, "-m", "polinrider_guard.guard", str(VULNERABLE), "--no-git"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Total findings" in result.stdout


def _write_allowlist(root, *lines):
    (root / allowlist.ALLOWLIST_FILENAME).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_masquerade_scanner_respects_allowlist(tmp_path):
    (tmp_path / "icons.eot").write_bytes(b"function evil(){require('fs')}" + b"\x00" * 16)
    assert len(scan_masquerade.scan_path(tmp_path)) == 1

    _write_allowlist(tmp_path, "extension_masquerade|icons.eot|vendored, verified upstream")
    assert scan_masquerade.scan_path(tmp_path) == []


def test_vscode_scanner_respects_allowlist(tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    assert len(scan_vscode.scan_path(tmp_path)) == 1

    identifier = str(Path(".vscode") / "tasks.json")
    _write_allowlist(tmp_path, f"vscode_tasks|{identifier}|reviewed, intentional")
    assert scan_vscode.scan_path(tmp_path) == []


def test_clock_tamper_scanner_respects_allowlist(tmp_path):
    (tmp_path / "config.bat").write_text(
        "date %LAST_COMMIT_DATE%\n"
        "git commit --amend -m \"%LAST_COMMIT_TEXT%\" --no-verify\n"
    )
    assert len(scan_clock_tamper.scan_path(tmp_path)) == 1

    _write_allowlist(tmp_path, "clock_tamper_tooling|config.bat|internal tooling, reviewed")
    assert scan_clock_tamper.scan_path(tmp_path) == []


def test_padding_scanner_respects_allowlist(tmp_path):
    (tmp_path / "eslint.config.mjs").write_text(
        "export default [];" + " " * 200 + 'global.i="A8-3955";\n'
    )
    findings = scan_padding.scan_path(tmp_path)
    assert len(findings) == 1

    _write_allowlist(tmp_path, f"hidden_payload_padding|eslint.config.mjs:{findings[0].line}|reviewed")
    assert scan_padding.scan_path(tmp_path) == []


def test_ioc_scanner_respects_allowlist(tmp_path):
    (tmp_path / "loader.js").write_text('const c2 = "trongrid.io";\n')
    findings = scan_ioc.scan_path(tmp_path)
    assert len(findings) == 1

    _write_allowlist(tmp_path, f"ioc_literal_match|loader.js:{findings[0].line}|false positive, reviewed")
    assert scan_ioc.scan_path(tmp_path) == []


def test_commit_camouflage_scanner_respects_allowlist(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)

    for i in range(45):
        (repo / f"file{i}.ts").write_text(f"export const value{i} = {i};\n" * 3)
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "initial commit")

    for i in range(45):
        (repo / f"file{i}.ts").write_text(f"export const value{i} = {i}; \n" * 3)
    (repo / "config.bat").write_text("@echo off\nrem setup\n")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "return back")

    findings = scan_commit_camouflage.scan_path(repo)
    assert len(findings) == 1
    commit_hash = findings[0].commit

    _write_allowlist(repo, f"commit_camouflage|{commit_hash[:12]}|known-good reformat sweep, reviewed")
    assert scan_commit_camouflage.scan_path(repo) == []
