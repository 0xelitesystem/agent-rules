"""Regression tests for untrusted transcripts and rules files.

A transcript or a third-party rules file can come from someone else, so:
- a network (UNC) cwd from a transcript is never stat'ed or opened, and on
  Windows only a plain local drive path is;
- control and bidi characters never reach the terminal or Markdown raw;
- common credential shapes in an offending command are masked in every
  report (the masking is pattern based, so these cases, not every secret);
- the matcher regexes stay fast on very large commands.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from agent_rules import matchers as M
from agent_rules.checker import _name_words, _redact_secrets
from agent_rules.cli import check_transcript, main
from agent_rules.report import render_json, render_markdown, render_terminal
from agent_rules.rules import discover_rules_files, is_remote_path

ESC = "\x1b"
# Fullwidth reverse solidus. NFKC folds it to a plain backslash.
FW_BACKSLASH = chr(0xFF3C)
# More stand-ins NFKC folds to a separator or to "..". Python and Windows
# never fold them: to both they are part of a name.
FW_SLASH = chr(0xFF0F)
SMALL_BACKSLASH = chr(0xFE68)
TWO_DOT_LEADER = chr(0x2025)
VERTICAL_TWO_DOT = chr(0xFE30)

# The recheck's Unicode bypasses of the NFKC-first check. Each stand-in is
# one name to Python, so ".." folds over it and the OS is handed
# \??\UNC\attacker.invalid\share, the network redirector.
UNICODE_BYPASSES = [
    "\\a" + FW_BACKSLASH + "b\\..\\??\\UNC\\attacker.invalid\\share",
    "\\a" + FW_SLASH + "b\\..\\??\\UNC\\attacker.invalid\\share",
    "/a" + FW_SLASH + "b/../??/UNC/attacker.invalid/share",
    "\\a" + SMALL_BACKSLASH + "b\\..\\??\\UNC\\attacker.invalid\\share",
    "\\x\\..\\??\\" + TWO_DOT_LEADER + "\\..\\UNC\\attacker.invalid\\share",
    "\\x\\..\\??\\" + VERTICAL_TWO_DOT + "\\..\\UNC\\attacker.invalid\\share",
]


def _tool(tool_id, command, cwd="C:\\fake\\project", slug=""):
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T12:00:00.000Z",
        "sessionId": "security-session",
        "cwd": cwd,
        "slug": slug,
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": tool_id, "name": "Bash",
             "input": {"command": command}},
        ]},
    }


def _write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return str(path)


def _rules(tmp_path, text, name="CLAUDE.md"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# UNC cwd from a transcript
# ---------------------------------------------------------------------------

REMOTE_CWDS = [
    "\\\\attacker.invalid\\share",
    "//attacker.invalid/share",
    "\\\\?\\UNC\\attacker.invalid\\share",
    "\\\\.\\UNC\\attacker.invalid\\share",
    "\\\\attacker.invalid@80\\share",
    "/\\attacker.invalid\\share",
    # NT object namespace. Win32 hands \??\ to the kernel unchanged, and
    # \??\UNC is the network redirector, so these reach the host too.
    "\\??\\UNC\\attacker.invalid\\share",
    "/??/UNC/attacker.invalid/share",
    "\\GLOBAL??\\UNC\\attacker.invalid\\share",
    "\\Device\\Mup\\attacker.invalid\\share",
    # Win32 device paths.
    "\\\\.\\pipe\\attacker.invalid",
    "\\\\?\\GLOBALROOT\\Device\\Mup\\attacker.invalid\\share",
    "//?/UNC/attacker.invalid/share",
    # A UNC server as the first component only after normalisation.
    "  \\\\attacker.invalid\\share  ",
    FW_BACKSLASH * 2 + "attacker.invalid" + FW_BACKSLASH + "share",
    # NT namespace reached only after pathlib or realpath normalisation.
    "\\.\\??\\UNC\\attacker.invalid\\share",
    "/./??/UNC/attacker.invalid/share",
    "\\x\\..\\??\\UNC\\attacker.invalid\\share",
    "/x/../??/UNC/attacker.invalid/share",
    "\\..\\??\\UNC\\attacker.invalid\\share",
    # NT namespace reached only because Python does not NFKC fold.
    *UNICODE_BYPASSES,
]


def _looks_remote(value) -> bool:
    text = os.fspath(value) if isinstance(value, (str, os.PathLike)) else ""
    return "attacker.invalid" in text or text[:2] in ("\\\\", "//", "/\\", "\\/")


@pytest.fixture
def no_remote_io(monkeypatch, tmp_path):
    """Record, and refuse, any filesystem call on a remote-looking path.

    Nothing reaches the OS for such a path, so the test sends no packets
    even when the code under test is broken.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    touched: list[str] = []

    def guard(owner, name, refusal):
        real = getattr(owner, name)

        def wrapper(first, *args, **kwargs):
            if _looks_remote(first):
                touched.append(f"{name}({os.fspath(first)})")
                if isinstance(refusal, type):
                    raise refusal(f"blocked remote path in test: {first}")
                return refusal
            return real(first, *args, **kwargs)
        monkeypatch.setattr(owner, name, wrapper)

    for name in ("is_file", "exists", "is_dir"):
        guard(Path, name, False)
    for name in ("resolve", "stat", "open", "read_text", "read_bytes"):
        guard(Path, name, OSError)
    guard(os, "stat", OSError)
    guard(os, "lstat", OSError)
    guard(os.path, "isfile", False)
    guard(os.path, "exists", False)
    guard(os.path, "realpath", OSError)
    return touched


@pytest.mark.parametrize("cwd", REMOTE_CWDS)
def test_remote_cwd_is_never_touched_during_discovery(no_remote_io, cwd):
    discover_rules_files(cwd)
    assert no_remote_io == []


@pytest.mark.parametrize("cwd", REMOTE_CWDS)
def test_cli_reports_remote_cwd_as_not_checked(no_remote_io, tmp_path, capsys, cwd):
    transcript = _write_jsonl(tmp_path / "evil.jsonl", [_tool("t1", "ls", cwd=cwd)])
    rc = main(["check", transcript, "--no-color"])
    captured = capsys.readouterr()
    assert rc == 0
    assert no_remote_io == []
    assert "not checked" in captured.err


@pytest.mark.parametrize("path", [
    # NT namespace forms
    "\\??\\UNC\\host\\share",
    "/??/UNC/host/share",
    "\\??\\unc\\host\\share",
    "\\??\\C:\\Windows",
    "\\GLOBAL??\\UNC\\host\\share",
    "\\Device\\Mup\\host\\share",
    # \\?\ long and device forms
    "\\\\?\\UNC\\host\\share",
    "//?/UNC/host/share",
    "\\\\?\\C:\\Users\\dev",
    "\\\\?\\GLOBALROOT\\Device\\Mup\\host\\share",
    # \\.\ device forms
    "\\\\.\\UNC\\host\\share",
    "\\\\.\\pipe\\name",
    "\\\\.\\C:",
    # first component is a UNC server after normalisation
    "\\\\host\\share",
    "//host/share",
    "\\/host/share",
    "/\\host\\share",
    "\\\\host@SSL@443\\DavWWWRoot",
    " \\\\host\\share",
    "\t//host/share\n",
    FW_BACKSLASH * 2 + "host" + FW_BACKSLASH + "share",
    # dot segments that pathlib or realpath fold into the NT namespace
    "\\.\\??\\UNC\\host\\share",
    "/./??/UNC/host/share",
    "/.//??/UNC/host/share",
    "\\..\\??\\UNC\\host\\share",
    "\\x\\..\\??\\UNC\\host\\share",
])
def test_is_remote_path_flags_network_nt_and_device_paths(path):
    assert is_remote_path(path)


# Off Windows the earlier rule still applies, and all of these are local
# there. On Windows only the drive paths among them are: the allowlist below
# treats a rooted, relative or empty path as remote.
@pytest.mark.parametrize("path", [
    "",
    "C:\\Users\\dev\\project",
    "C:/Users/dev/project",
    "/home/dev/project",
    "/Users/dev/why?",
    "\\Users\\dev\\project",
    "relative\\dir",
    "relative/dir",
    "C:\\Users\\dev\\..\\project",
    "\\x\\..\\Users\\dev",
    "relative\\..\\??\\UNC\\host",
])
def test_is_remote_path_keeps_local_paths(path):
    assert not is_remote_path(path, windows=False)


@pytest.mark.parametrize("windows", [True, False, None],
                         ids=["windows rule", "other rule", "this os"])
@pytest.mark.parametrize("path", UNICODE_BYPASSES)
def test_unicode_bypasses_are_refused(path, windows):
    assert is_remote_path(path, windows=windows)


# Windows: a path is touched only when it is a plain local drive path.
LOCAL_DRIVE_PATHS = [
    "C:\\Users\\dev\\project",
    "C:/Users/dev/project",
    "c:\\users\\dev\\project",
    "D:\\",
    "Z:\\work\\repo",
    "C:\\Users\\dev\\project\\",
    "C:\\Users\\dev\\..\\project",
    "C:\\Users\\dev\\..\\..\\..\\..\\project",
    "C:\\\\Users\\dev\\project",
    "C:\\Program Files (x86)\\My App\\v1.2",
    "C:\\Users\\dev\\notes..old\\project",
    "C:\\Users\\Jos" + chr(0xE9) + "\\project",
    "C:\\Users\\" + "\u0424\u0451\u0434\u043e\u0440" + "\\project",
]

NOT_LOCAL_ON_WINDOWS = [
    # empty, relative, rooted without a drive, and drive-relative
    "",
    ".",
    "project",
    "relative\\dir",
    "relative/dir",
    "..\\project",
    "\\Users\\dev\\project",
    "/home/dev/project",
    "/Users/dev/why?",
    "\\x\\..\\Users\\dev",
    "relative\\..\\??\\UNC\\host",
    "C:",
    "C:dev\\project",
    " C:\\Users\\dev",
    "\\x\\..\\C:\\Users\\dev",
    "/C:/Users/dev",
    # UNC, \\?\, \??\, \\.\ and device forms, even with a drive inside
    "\\\\localhost\\C$\\Users\\dev",
    "\\\\?\\C:\\Users\\dev",
    "//?/C:/Users/dev",
    "\\??\\C:\\Users\\dev",
    "\\\\.\\C:\\Users\\dev",
    "\\\\.\\PhysicalDrive0",
    # a ? anywhere
    "C:\\Users\\dev\\?",
    "C:\\Users\\dev\\..\\..\\??\\UNC\\host\\share",
    # non-ASCII stand-ins for a separator, a dot or a colon
    "C:\\a" + FW_BACKSLASH + "b\\..\\..\\??\\UNC\\host\\share",
    "C:\\a" + FW_BACKSLASH + "b\\..\\project",
    "C:\\Users\\dev" + FW_SLASH + "project",
    "C:\\Users\\dev" + SMALL_BACKSLASH + "project",
    "C:\\Users\\" + TWO_DOT_LEADER + "\\project",
    "C:\\Users\\" + VERTICAL_TWO_DOT + "\\project",
    "C:\\Users\\" + chr(0xFF0E) * 2 + "\\project",
    "C:\\Users\\dev" + chr(0x2215) + "project",
    "C:\\Users\\dev" + chr(0x00A5) + "project",
    # a drive letter that is not an ASCII letter and colon
    chr(0xFF23) + ":\\Users\\dev",
    chr(0x0421) + ":\\Users\\dev",
    "C" + chr(0xFF1A) + "\\Users\\dev",
    "1:\\Users\\dev",
    "C|\\Users\\dev",
    # control characters, which no Windows file name holds
    "C:\\Users\\dev\x00\\project",
    "C:\\Users\\dev\r\n",
    "C:\\Users\\dev\t\\project",
    "C:\\Users\\dev\x1b[2J",
]


@pytest.mark.parametrize("path", LOCAL_DRIVE_PATHS)
def test_windows_allowlist_keeps_local_drive_paths(path):
    assert not is_remote_path(path, windows=True)


@pytest.mark.parametrize("path", NOT_LOCAL_ON_WINDOWS)
def test_windows_allowlist_refuses_everything_else(path):
    assert is_remote_path(path, windows=True)


@pytest.mark.skipif(os.name != "nt", reason="the default rule is the Windows one")
@pytest.mark.parametrize("path,remote",
                         [(p, False) for p in LOCAL_DRIVE_PATHS]
                         + [(p, True) for p in NOT_LOCAL_ON_WINDOWS])
def test_windows_default_rule_is_the_allowlist(path, remote):
    assert is_remote_path(path) is remote


# Forms only the Windows allowlist refuses. Off Windows they are ordinary
# relative names, so these run on Windows only.
WINDOWS_ONLY_REMOTE_CWDS = [
    "C:\\a" + FW_BACKSLASH + "b\\..\\..\\??\\UNC\\attacker.invalid\\share",
    "C:\\work\\attacker.invalid" + FW_BACKSLASH + "share",
    "attacker.invalid\\share",
    "\\attacker.invalid\\share",
    "C:attacker.invalid\\share",
]


@pytest.mark.skipif(os.name != "nt", reason="Windows path rules")
@pytest.mark.parametrize("cwd", WINDOWS_ONLY_REMOTE_CWDS)
def test_windows_cwd_outside_the_allowlist_is_never_touched(no_remote_io, tmp_path,
                                                           capsys, cwd):
    discover_rules_files(cwd)
    assert no_remote_io == []
    transcript = _write_jsonl(tmp_path / "evil.jsonl", [_tool("t1", "ls", cwd=cwd)])
    assert main(["check", transcript, "--no-color"]) == 0
    assert no_remote_io == []
    assert "not checked" in capsys.readouterr().err


# A malformed cwd made Path.resolve() raise ValueError, not OSError, on
# Python 3.10 and 3.11, and the whole check crashed. Now it is skipped.
MALFORMED_CWDS = [
    "C:\\Users\\dev\x00\\project",
    "/home/dev\x00/project",
    "C:\\" + "a" * 40000,
    "/" + "a" * 40000,
]


@pytest.mark.parametrize("cwd", MALFORMED_CWDS,
                         ids=["drive nul", "posix nul", "drive long", "posix long"])
def test_malformed_cwd_is_skipped_without_crashing(tmp_path, capsys, monkeypatch, cwd):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert discover_rules_files(cwd) == []
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", "ls", cwd=cwd)])
    assert main(["check", transcript, "--no-color"]) == 0
    capsys.readouterr()


@pytest.mark.parametrize("cwd", MALFORMED_CWDS,
                         ids=["drive nul", "posix nul", "drive long", "posix long"])
def test_discovery_survives_a_malformed_path_past_the_gate(tmp_path, monkeypatch, cwd):
    # Belt and braces: even if a malformed path got past is_remote_path,
    # discovery skips it instead of raising.
    import agent_rules.rules as rules_module
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(rules_module, "is_remote_path", lambda path: False)
    assert discover_rules_files(cwd) == []


# A cwd longer than Windows allows cannot be a real path on any system.
@pytest.mark.parametrize("windows", [True, False], ids=["windows rule", "other rule"])
def test_path_longer_than_windows_allows_is_refused(windows):
    longest = "C:\\" + "a" * 32764
    assert len(longest) == 32767
    assert not is_remote_path(longest, windows=windows)
    assert is_remote_path(longest + "a", windows=windows)
    assert is_remote_path("/" + "a" * 32767, windows=windows)


# ntpath.normpath is pure Python and quadratic on these in Python 3.10.
LONG_PATH_UNITS = ["C:\\\\\\", "\\.", "a\\..\\", "\\a" + FW_BACKSLASH + "b\\..",
                   "\\\\?\\", "////", "C:\\a\\.."]


@pytest.mark.parametrize("unit", LONG_PATH_UNITS)
@pytest.mark.parametrize("size", [32767, 1000000], ids=["at the limit", "1M chars"])
def test_is_remote_path_is_fast_on_long_paths(unit, size):
    text = (unit * (size // len(unit) + 1))[:size]
    start = time.perf_counter()
    is_remote_path(text, windows=True)
    is_remote_path(text, windows=False)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"{unit!r} x {size}: {elapsed:.2f}s"


def test_cli_says_nothing_about_a_missing_cwd(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", "ls", cwd="")])
    assert main(["check", transcript, "--no-color"]) == 0
    assert "not checked" not in capsys.readouterr().err


def test_local_cwd_still_discovers_its_rules_files(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("- Never use sudo.\n", encoding="utf-8")
    (project / "AGENTS.md").write_text("- Never use sudo.\n", encoding="utf-8")
    found = [p.name for p in discover_rules_files(str(project))]
    assert found == ["CLAUDE.md", "AGENTS.md"]


# ---------------------------------------------------------------------------
# Terminal and Markdown escape injection
# ---------------------------------------------------------------------------

UNSAFE = [ESC, "\x07", "\r", "\x9b", "\x7f", "\u202e", "\u2066", "\u200f", "\u061c"]


def _injection_result(tmp_path):
    forged = f"{ESC}[H{ESC}[2J COMPLIANCE SCORE 100/100 (A){ESC}[E"
    rules = _rules(tmp_path, (
        f"- Never use sudo.{ESC}]0;pwned{ESC}\\{ESC}[3A{ESC}[J forged\u202e\x9b\x7f\n"
        "- Never read `.env` or any secrets file.\n"
    ))
    transcript = _write_jsonl(tmp_path / "inject.jsonl", [
        _tool("t1", f"cat .env # {forged}\x07\r\u2066\u200f\u061c",
              cwd=f"C:\\proj{ESC}]0;title{ESC}\\\r\u202e",
              slug=f"slug{ESC}[8m"),
    ])
    return check_transcript(transcript, [rules])


def test_terminal_report_escapes_control_characters(tmp_path):
    result = _injection_result(tmp_path)
    assert result.high_violations()
    out = render_terminal(result, color=False)
    for ch in UNSAFE:
        assert ch not in out, repr(ch)
    # Shown, not hidden: the auditor can see something was there.
    assert "\\x1b[2J" in out
    assert "\\u202e" in out


def test_colored_terminal_report_only_has_its_own_escapes(tmp_path):
    result = _injection_result(tmp_path)
    out = render_terminal(result, color=True)
    assert f"{ESC}[2J" not in out
    assert f"{ESC}]0;" not in out
    assert f"{ESC}[8m" not in out


def test_markdown_report_escapes_control_characters(tmp_path):
    result = _injection_result(tmp_path)
    md = render_markdown(result)
    for ch in UNSAFE:
        assert ch not in md, repr(ch)
    assert "\\x1b" in md
    # Every table row stays on one line.
    rows = [line for line in md.splitlines() if line.startswith("| ")]
    assert len(rows) == 1 + len(result.findings)


def test_json_report_still_carries_the_raw_text(tmp_path):
    result = _injection_result(tmp_path)
    payload = json.loads(render_json(result))
    assert any(ESC in r["rule"] for r in payload["rules"])


# ---------------------------------------------------------------------------
# Credentials copied into reports
# ---------------------------------------------------------------------------

PINNED = "- Always use `C:\\Python314\\python.exe`; never run bare `python`.\n"
NO_PUSH_MAIN = "- Never push directly to main.\n"
NO_CURL = "- Never use curl\n"

OPENAI_KEY = "sk-proj-" + "Q7x" * 20
GITHUB_TOKEN = "ghp_" + "Z9k" * 12
AWS_ID = "AKIA" + "Q7XK" * 4
AWS_SECRET = "wJalr" + "Xk9Q/" * 7
BEARER = "eyJhbGciOi" + "Jq8" * 12
GITHUB_PAT = "github_pat_" + "B4n" * 14
DB_PASSWORD = "hunter2-" + "Pw9" * 6

SECRET_CASES = [
    (PINNED, f"OPENAI_API_KEY={OPENAI_KEY} python app.py", [OPENAI_KEY[8:]],
     "python app.py"),
    (PINNED, f"AWS_ACCESS_KEY_ID={AWS_ID} AWS_SECRET_ACCESS_KEY={AWS_SECRET} "
             "python deploy.py", [AWS_ID[4:], AWS_SECRET[:20]], "AWS_ACCESS_KEY_ID="),
    (NO_PUSH_MAIN, f"git push https://x-access-token:{GITHUB_TOKEN}@github.com/o/r.git main",
     [GITHUB_TOKEN[4:]], "git push https://x-access-token:***@github.com"),
    (NO_PUSH_MAIN, f"git push https://{GITHUB_PAT}@github.com/o/r.git main",
     [GITHUB_PAT[11:]], "git push https://github_pat_***@github.com"),
    (NO_CURL, f'curl -H "Authorization: Bearer {BEARER}" https://api.example.invalid/v1',
     [BEARER], "Authorization: Bearer ***"),
    (NO_CURL, f"curl https://api.example.invalid/v1?token={BEARER}&page=2",
     [BEARER], "token=***&page=2"),
    (PINNED, f"python manage.py createuser --password {DB_PASSWORD}",
     [DB_PASSWORD], "--password ***"),
]


@pytest.mark.parametrize("rules_text,command,secrets,remnant", SECRET_CASES)
def test_reports_mask_these_credentials(tmp_path, capsys, rules_text, command,
                                        secrets, remnant):
    rules = _rules(tmp_path, rules_text)
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", command)])
    md_path = tmp_path / "report.md"
    main(["check", transcript, "--rules", rules, "--no-color", "--md", str(md_path)])
    terminal = capsys.readouterr().out
    main(["check", transcript, "--rules", rules, "--json"])
    payload = capsys.readouterr().out
    markdown = md_path.read_text(encoding="utf-8")
    assert "VIOLATED" in terminal
    for secret in secrets:
        for name, text in (("terminal", terminal), ("json", payload),
                           ("markdown", markdown)):
            assert secret not in text, f"{name} report leaks {secret!r}"
    # The command is still recognisable.
    assert remnant in terminal


@pytest.mark.parametrize("command,leak", [
    # The 90-char evidence cut lands inside the token: only 8 of its
    # characters would be shown, too few to recognise after the cut.
    ("python app.py " + "x" * 62 + " " + GITHUB_TOKEN, "Z9k"),
    ("x" * 60 + f" OPENAI_API_KEY={OPENAI_KEY} python app.py", "Q7x"),
])
def test_secret_straddling_the_cut_is_still_masked(tmp_path, command, leak):
    rules = _rules(tmp_path, PINNED)
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", command)])
    result = check_transcript(transcript, [rules])
    finding = result.high_violations()[0]
    for text in (finding.evidence, finding.offending_command):
        assert leak not in text


@pytest.mark.parametrize("command", [
    "python build.py",
    "git push origin main",
    "export GITHUB_TOKEN=$GH_TOKEN && python app.py",
    'TOKEN="$(cat token.txt)" python app.py',
    'echo "== bootstrap auth ==" && python app.py',
    'python check.py --token-file tok.txt --key-id 7',
])
def test_ordinary_commands_are_reported_unchanged(tmp_path, command):
    rules = _rules(tmp_path, PINNED + NO_PUSH_MAIN)
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", command)])
    result = check_transcript(transcript, [rules])
    assert any(f.offending_command == command for f in result.high_violations())


# Ordinary values that look a little like credentials but are not. Each one
# is run through the real CLI as a VIOLATED finding (a generic "never run X"
# rule), so it takes the same evidence path as a real report.
ORDINARY_VALUES = [
    ("sort --key=2 data.txt", "sort"),
    ("echo monkey=banana", "echo"),
    ("git checkout feature/sk-login", "git checkout"),
    ('git commit -m "Rotate API key: see docs"', "git commit"),
    ('git commit -m "auth: fix login redirect"', "redirect"),
    ("docker run -v $PWD:/app node", "docker"),
    ("python train.py --max-token=4096", "train.py"),
    ("export CACHE_KEY=build-v2", "export"),
]


@pytest.mark.parametrize("command,subject", ORDINARY_VALUES,
                         ids=[c[1] for c in ORDINARY_VALUES])
def test_ordinary_values_are_not_masked(tmp_path, capsys, command, subject):
    rules = _rules(tmp_path, f"- Never run `{subject}`.\n")
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", command)])
    result = check_transcript(transcript, [rules])
    finding = result.findings[0]
    assert finding.verdict.name == "VIOLATED"
    assert finding.offending_command == command
    assert f"`{command}`" in finding.evidence
    main(["check", transcript, "--rules", rules, "--no-color"])
    assert command in capsys.readouterr().out
    main(["check", transcript, "--rules", rules, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert [r["offending_command"] for r in payload["rules"]] == [command]
    assert "***" not in json.dumps(payload)


V16 = "a1B2" * 4  # exactly 16 secret-shaped characters


@pytest.mark.parametrize("text", [
    *(c[0] for c in ORDINARY_VALUES),
    # Over-masking seen in review of the first redaction pass.
    "sort --sort-key=name",
    "export CACHE_KEY=build-v2",
    "python train.py --max-token=4096",
    'git commit -m "fix: auth=none default"',
    # A credential name's value is kept only when it is empty, none, null,
    # true, false, 0 or a plain number.
    "export API_TOKEN=",
    "curl https://api.example.invalid/v1?token=none&page=2",
    "app --auth=NULL --password=false --secret-rotation=True --token-ttl=0",
    "python train.py --max-token 4096 --temperature-token=0.7",
    # $NAME and ${NAME} are shell references, and so is a $ value.
    "docker run -v $PWD:/app node",
    "echo $TOKEN:$SECRET_KEY",
    "echo ${API_TOKEN:-unset}",
    "export GITHUB_TOKEN=$GH_TOKEN",
    'curl -H "Authorization: Bearer $TOKEN" https://api.example.invalid',
    # A name ending in file, path or dir points at where a credential lives.
    "gh auth login --token-file tok.txt --password-path ./pw --secret-dir /run",
    # After an unquoted "NAME: ", two or more plain words are prose, not a
    # value. (A single word is a value; see the masked cases.)
    'git commit -m "auth: fix login redirect"',
    'git commit -m "API key: rotate it"',
    'git commit -m "secret: rotate them weekly"',
    "echo token: Refresh on expiry",
    'echo "Bearer tokens expire hourly"',
    'echo "Basic auth is deprecated"',
    # A scheme word after a credential name, then a shell reference.
    'curl -H "X-Token: Bearer $TOKEN" https://api.example.invalid',
    # A plain value ends at its context's own delimiter.
    '-d "{\\"token\\": \\"none\\"}"',
    "DSN=db;PWD=0;UID=sa",
    # The value alone is not enough: the name must be a credential name.
    "echo monkey=" + V16,
    "python app.py --max-tokens=" + V16,
    "export AUTHOR=jane OAUTH_SCOPE=repo KEYS=a,b DB_PWD_HINT=x",
    # A bare "key" name needs 16 secret-shaped characters.
    "export CACHE_KEY=" + V16[:15],
    "export SORT_KEY_ID=" + V16[:15],
    "sort --key " + V16[:15] + " data.txt",
    # A token prefix needs at least 12 characters after it.
    "sk-" + V16[:11],
    "ghp_" + V16[:11],
    "AKIA" + V16[:11],
    "xoxz-" + V16,
    # "::" is a scope, not an assignment; lowercase "basic" is English.
    "pytest tests/test_auth.py::test_password_reset",
    "echo 'basic 3-step setup'",
    # A flag followed by another flag is not a value.
    "deploy --api-key --verbose-output-flag-name",
    # Nor is a shell operator: the token comes from a file here.
    "gh auth login --with-token < token.txt",
    "app --token | tee log.txt",
    # A quote followed by whitespace closes an outer string, so an empty
    # value after a scheme word is not read as an opening quote.
    'curl -H "Authorization: Bearer " u',
    'curl -H "X-Token: Bearer " -d "a b" u',
    # A $ inside double quotes is still a shell reference.
    '--password "$PW" x',
    # A quoted plain phrase after a bare Bearer is still prose.
    "echo Bearer 'tokens expire hourly'",
    # A URL port is not a userinfo password.
    "curl https://api.example.invalid:8443/v1?page=2",
    # "==" with whitespace or another = beside it is a comparison or a banner.
    'if [ "$PASSWORD" == "hunter2" ]; then',
    "[[ $TOKEN == abc ]] && password === other",
    "pip install requests==2.31 && test token_count==0 -a auth_ok==True",
])
def test_redaction_leaves_ordinary_values_alone(text):
    assert _redact_secrets(text) == text


@pytest.mark.parametrize("text,expected", [
    # NAME=value
    ("export API_TOKEN=" + V16, "export API_TOKEN=***"),
    ("export GITHUB_PAT_TOKEN=" + V16 + "+/=", "export GITHUB_PAT_TOKEN=***"),
    ("spring.datasource.password=" + V16, "spring.datasource.password=***"),
    ("key=" + V16, "key=***"),
    ("sort --key=" + V16, "sort --key=***"),
    ("ARGS=--token=" + V16 + " run", "ARGS=--token=*** run"),
    ("TOKEN=" + V16 + ".payload.signature x", "TOKEN=*** x"),
    # NAME: value
    ("curl -H 'x-api-key: " + V16 + "' u", "curl -H 'x-api-key: ***' u"),
    ('git commit -m "API key: ' + V16 + '"', 'git commit -m "API key: ***"'),
    ("aws_access_key: " + V16, "aws_access_key: ***"),
    # "name": "value", plain and shell-escaped
    ('{"password": "' + V16 + '"}', '{"password": "***"}'),
    ('{"client_secret":"' + V16 + '"}', '{"client_secret":"***"}'),
    ('-d "{\\"private_key\\": \\"' + V16 + '\\"}"',
     '-d "{\\"private_key\\": \\"***\\"}"'),
    # --name value
    ("deploy --access-key " + V16, "deploy --access-key ***"),
    # Token prefixes
    ("sk-" + V16, "sk-***"),
    ("ghp_" + V16, "ghp_***"),
    ("github_pat_" + V16, "github_pat_***"),
    ("AKIA" + V16.upper(), "AKIA***"),
    ("AIza" + V16, "AIza***"),
    ("xoxb-" + V16, "xoxb-***"),
    ("glpat-" + V16, "glpat-***"),
    # The final rule's required cases.
    ("export SECRET_KEY=django-insecure-abc", "export SECRET_KEY=***"),
    ("ENCRYPTION_KEY=0123456789abcdef0123", "ENCRYPTION_KEY=***"),
    ("--password hunter2", "--password ***"),
    ('"clientSecret": "s3cr3t"', '"clientSecret": "***"'),
    ("accessToken=abc123", "accessToken=***"),
    ("Authorization: Bearer x", "Authorization: Bearer ***"),
    ("PWD=pa55", "PWD=***"),
    ("DRIVER={ODBC Driver 18};SERVER=db;UID=sa;PWD=pa55;",
     "DRIVER={ODBC Driver 18};SERVER=db;UID=sa;PWD=***;"),
    # A credential name masks any other value, whatever its length. The
    # first two were left alone by the earlier 16-character narrowing rule.
    ("export API_TOKEN=" + V16[:15], "export API_TOKEN=***"),
    ("curl https://api.example.invalid/v1?token=abc123&page=2",
     "curl https://api.example.invalid/v1?token=***&page=2"),
    ("app --token=x --auth 7a --secret=-1a", "app --token=*** --auth *** --secret=***"),
    ("PASSPHRASE=p PASSWD=p CREDENTIALS=c AUTH=a apikey=k privateKey=k",
     "PASSPHRASE=*** PASSWD=*** CREDENTIALS=*** AUTH=*** apikey=*** privateKey=***"),
    # "key" together with a qualifier word makes a credential name.
    ("MASTER_KEY=m SESSION_KEY=s CLIENT_KEY=c SIGNING_KEY=g ACCESS_KEY=a",
     "MASTER_KEY=*** SESSION_KEY=*** CLIENT_KEY=*** SIGNING_KEY=*** ACCESS_KEY=***"),
    # camelCase names, and values in code.
    ("APIKey=k1 oauth2Token=t2 myAPIKey=k3", "APIKey=*** oauth2Token=*** myAPIKey=***"),
    ("node -e \"f({apiKey: 'k1', signingKey: 'k2'})\"",
     "node -e \"f({apiKey: '***', signingKey: '***'})\""),
    # A quoted value is masked to its closing quote.
    ('--password "correct horse battery"', '--password "***"'),
    ("TOKEN='a b c' run", "TOKEN='***' run"),
    # A NAME: value that is not a plain word is a value, not prose.
    ('git commit -m "token: v2"', 'git commit -m "token: ***"'),
    # A bare "key" name masks a value of 16 secret-shaped characters. These
    # two were left alone by the earlier narrowing rule.
    ("export CACHE_KEY=" + V16, "export CACHE_KEY=***"),
    ("export SORT_KEY_ID=" + V16, "export SORT_KEY_ID=***"),
    # Authorization header values are always masked, whatever the scheme.
    ("curl -H 'Authorization: Basic dXNlcjpw' u", "curl -H 'Authorization: Basic ***' u"),
    ("curl -H 'authorization: bearer x' u", "curl -H 'authorization: bearer ***' u"),
    ("curl -H 'Authorization: token t' u", "curl -H 'Authorization: token ***' u"),
    # A bare Bearer or Basic is masked when its value is not a plain word.
    ("echo Bearer abc123", "echo Bearer ***"),
    ("echo Basic dXNlcjpw", "echo Basic ***"),
    # With no space after the colon, a plain word is still a value.
    ("curl --header auth:abc u", "curl --header auth:*** u"),
    # Token prefixes at 12 characters (the earlier rule needed 16).
    ("sk-" + V16[:12], "sk-***"),
    ("sk_live_" + V16[:12], "sk_live_***"),
    ("rk_" + V16[:12], "rk_***"),
    ("ghp_" + V16[:12], "ghp_***"),
    ("gho_" + V16[:12], "gho_***"),
    ("github_pat_" + V16[:12], "github_pat_***"),
    ("glpat-" + V16[:12], "glpat-***"),
    ("xoxp-" + V16[:12], "xoxp-***"),
    ("AIza" + V16[:12], "AIza***"),
    ("AKIA" + V16[:12], "AKIA***"),
    ("ASIA" + V16[:12], "ASIA***"),
    # A value is masked up to the next whitespace or closing quote, whatever
    # characters it holds. The recheck found these leaking at @ and {.
    ("--password P@ssw0rd", "--password ***"),
    ("--password {x}y", "--password ***"),
    ("--password=p(a)s<s>[w]\\d x", "--password=*** x"),
    ("export API_TOKEN=a,b;c|d&e run", "export API_TOKEN=*** run"),
    ("curl -H 'X-Api-Key: k@y{1}' u", "curl -H 'X-Api-Key: ***' u"),
    ("curl -H 'Authorization: Bearer P@ss{x}' u",
     "curl -H 'Authorization: Bearer ***' u"),
    ("echo Bearer ab@cd(ef)", "echo Bearer ***"),
    # ...except where its context has a delimiter the value cannot hold raw.
    ("curl 'https://h.invalid/v1?token=a@b{c}&page=2'",
     "curl 'https://h.invalid/v1?token=***&page=2'"),
    ("sqlcmd DSN=db;PWD=p@s{s};UID=sa", "sqlcmd DSN=db;PWD=***;UID=sa"),
    ("sqlcmd UID=sa;PWD={p;ss} -Q x", "sqlcmd UID=sa;PWD=*** -Q x"),
    # After an unquoted "NAME: ", a single plain word is a value. The last
    # two were left alone by the earlier one-word prose reading.
    ("password: letmein", "password: ***"),
    ('echo "password: letmein"', 'echo "password: ***"'),
    ("echo 'secret: Summer'", "echo 'secret: ***'"),
    ('curl -H "X-Auth-Token: abcdef" u', 'curl -H "X-Auth-Token: ***" u'),
    ('curl -H "Authorization: letmein" u', 'curl -H "Authorization: ***" u'),
    ("echo password: letmein && ls", "echo password: *** && ls"),
    ('curl -H "X-Custom: Bearer letmein" u', 'curl -H "X-Custom: Bearer ***" u'),
    ('git commit -m "Document the Authorization: header"',
     'git commit -m "Document the Authorization: ***"'),
    ('git commit -m "token: Refresh on expiry. password: WIP"',
     'git commit -m "token: Refresh on expiry. password: ***"'),
    # A scheme word after any credential name masks the word after it.
    ("X-Token: Bearer abcdef", "X-Token: Bearer ***"),
    ('curl -H "X-Token: Bearer abcdef" u', 'curl -H "X-Token: Bearer ***" u'),
    ("X-Auth-Token: Token abcdef", "X-Auth-Token: Token ***"),
    ("X-Api-Key: Bot abcdef", "X-Api-Key: Bot ***"),
    ("x-token: bearer abcdef", "x-token: bearer ***"),
    ("X-Token: Bearer abcdef rotated weekly", "X-Token: Bearer *** rotated weekly"),
    ('{"x-token": "Bearer abc def"}', '{"x-token": "Bearer ***"}'),
    ("AUTH_HEADER=Bearer abcdef", "AUTH_HEADER=Bearer ***"),
    ("--token Bot abcdef", "--token Bot ***"),
    # A quoted word after a scheme word is masked to its closing quote.
    ('X-Token: Bearer "abc def"', 'X-Token: Bearer "***"'),
    ("X-Token: Bearer 'abc def' u", "X-Token: Bearer '***' u"),
    ("Authorization: Bearer 'abc def'", "Authorization: Bearer '***'"),
    ('curl -H "Authorization: Bearer \\"abc\\"" u',
     'curl -H "Authorization: Bearer \\"***\\"" u'),
    ("echo Bearer 'abc123'", "echo Bearer '***'"),
    ("--token Bot 'abc def'", "--token Bot '***'"),
    # A quote inside an unquoted word opens a quoted part of that word.
    ('--password=ab"cd ef" x', "--password=*** x"),
    ("PASSWORD=ab'c d'e x", "PASSWORD=*** x"),
    ('token=abc"def', "token=***"),
    # A quote followed by whitespace or closing punctuation closes an outer
    # string, and stays.
    ('sh -c "export TOKEN=abc"; ls', 'sh -c "export TOKEN=***"; ls'),
    ("node -e \"f('TOKEN=abc')\"", "node -e \"f('TOKEN=***')\""),
    ('curl -H "X-Api-Key: abc" -d "x y" u', 'curl -H "X-Api-Key: ***" -d "x y" u'),
    # A $ inside single quotes is literal, so the value is masked.
    ("--password '$uper' x", "--password '***' x"),
    ("X-Token: Bearer '$abc'", "X-Token: Bearer '***'"),
    # A URL userinfo password is masked up to the last @ before the host.
    ("https://u:p@ss@host.invalid/x", "https://u:***@host.invalid/x"),
    ("git clone https://oauth2:gl@pat@git.example.invalid/x.git",
     "git clone https://oauth2:***@git.example.invalid/x.git"),
    # A tight NAME==value: a value starting with = in the shell, or a secret
    # compared in code.
    ("PASSWORD==abc run", "PASSWORD==*** run"),
    ("app --password==abc run", "app --password==*** run"),
    ('if token=="hunter2":', 'if token=="***":'),
])
def test_redaction_masks_secret_shaped_values(text, expected):
    assert _redact_secrets(text) == expected


# The final rule's required masked cases, run through the real CLI as
# VIOLATED findings (a generic "never run X" rule). In these cases the value
# reaches no report, and the name stays readable.
REQUIRED_MASKED = [
    ("export SECRET_KEY=django-insecure-abc", "export", "django-insecure-abc",
     "export SECRET_KEY=***"),
    ("ENCRYPTION_KEY=0123456789abcdef0123 node app.js", "node",
     "0123456789abcdef0123", "ENCRYPTION_KEY=*** node app.js"),
    ("python manage.py createuser --password hunter2", "manage.py", "hunter2",
     "--password ***"),
    ("""curl -d '{"clientSecret": "s3cr3t"}' https://api.example.invalid""",
     "curl", "s3cr3t", '"clientSecret": "***"'),
    ("accessToken=abc123 node app.js", "node", "abc123", "accessToken=*** node"),
    ("curl -H 'Authorization: Bearer x' https://api.example.invalid", "curl",
     "Bearer x", "Authorization: Bearer ***"),
    ('sqlcmd "DSN=db;UID=sa;PWD=pa55"', "sqlcmd", "pa55", "PWD=***"),
]


@pytest.mark.parametrize("command,subject,secret,remnant", REQUIRED_MASKED,
                         ids=[c[2] for c in REQUIRED_MASKED])
def test_required_credentials_are_masked_in_every_report(tmp_path, capsys, command,
                                                         subject, secret, remnant):
    rules = _rules(tmp_path, f"- Never run `{subject}`.\n")
    transcript = _write_jsonl(tmp_path / "s.jsonl", [_tool("t1", command)])
    finding = check_transcript(transcript, [rules]).findings[0]
    assert finding.verdict.name == "VIOLATED"
    assert remnant in finding.offending_command
    md_path = tmp_path / "report.md"
    main(["check", transcript, "--rules", rules, "--no-color", "--md", str(md_path)])
    terminal = capsys.readouterr().out
    main(["check", transcript, "--rules", rules, "--json"])
    payload = capsys.readouterr().out
    markdown = md_path.read_text(encoding="utf-8")
    for name, text in (("terminal", terminal), ("json", payload),
                       ("markdown", markdown)):
        assert secret not in text, f"{name} report leaks {secret!r}"
    assert remnant in terminal


# The recheck's leaks, run through the real CLI the same way. Every one of
# these reached all three reports before this pass.
RECHECK_LEAKS = [
    ("python manage.py createuser --password P@ssw0rd", "manage.py", "ssw0rd",
     "--password ***"),
    ("python manage.py createuser --password {x}y", "manage.py", "{x}y",
     "--password ***"),
    ('echo "password: letmein"', "echo", "letmein", "password: ***"),
    ("echo 'secret: Summer'", "echo", "Summer", "secret: ***"),
    ('curl -H "X-Auth-Token: abcdef" https://api.example.invalid', "curl",
     "abcdef", "X-Auth-Token: ***"),
    ('curl -H "Authorization: letmein" https://api.example.invalid', "curl",
     "letmein", "Authorization: ***"),
    ('curl -H "X-Token: Bearer abcdef" https://api.example.invalid', "curl",
     "abcdef", "X-Token: Bearer ***"),
]


@pytest.mark.parametrize("command,subject,secret,remnant", RECHECK_LEAKS,
                         ids=[c[0][:40] for c in RECHECK_LEAKS])
def test_recheck_leaks_are_masked_in_every_report(tmp_path, capsys, command,
                                                  subject, secret, remnant):
    test_required_credentials_are_masked_in_every_report(
        tmp_path, capsys, command, subject, secret, remnant)


# Quoted values after a scheme word, quotes inside a word, a single-quoted $
# and a raw @ in a URL password. Each reached all three reports before.
QUOTED_LEAKS = [
    ("curl -H \"X-Token: Bearer 'Zq9 Wv7'\" https://api.example.invalid", "curl",
     "Wv7", "X-Token: Bearer '***'"),
    ("curl -H 'Authorization: Bearer \"Zq9Wv7\"' https://api.example.invalid",
     "curl", "Zq9Wv7", 'Authorization: Bearer "***"'),
    ('python manage.py createuser --password=ab"Zq9 Wv7"', "manage.py", "Wv7",
     "--password=***"),
    ("python manage.py createuser --password '$Zq9Wv7'", "manage.py", "Zq9Wv7",
     "--password '***'"),
    ("git clone https://oauth2:Zq9@Wv7@git.example.invalid/o/r.git", "clone",
     "Wv7", "oauth2:***@git.example.invalid"),
]


@pytest.mark.parametrize("command,subject,secret,remnant", QUOTED_LEAKS,
                         ids=[c[3] for c in QUOTED_LEAKS])
def test_quoted_and_userinfo_values_are_masked_in_every_report(
        tmp_path, capsys, command, subject, secret, remnant):
    test_required_credentials_are_masked_in_every_report(
        tmp_path, capsys, command, subject, secret, remnant)


@pytest.mark.parametrize("name,words", [
    ("accessToken", ["access", "token"]),
    ("clientSecret", ["client", "secret"]),
    ("APIKey", ["api", "key"]),
    ("myAPIKey", ["my", "api", "key"]),
    ("oauth2Token", ["oauth2", "token"]),
    ("OPENAI_API_KEY", ["openai", "api", "key"]),
    ("--max-token", ["max", "token"]),
    ("x-api-key", ["x", "api", "key"]),
    ("spring.datasource.password", ["spring", "datasource", "password"]),
    ("PWD", ["pwd"]),
])
def test_names_split_on_separators_and_camel_case(name, words):
    assert _name_words(name) == words


LARGE_REDACTION_INPUTS = [
    ("pair chain", "a=" * 50000),
    ("credential pair chain", "token=" * 20000),
    ("colon pair chain", "key: " * 20000),
    ("flag chain", "--token " * 20000),
    ("bearer chain", "Bearer " * 20000),
    ("authorization chain", "Authorization: Bearer " * 10000),
    ("unclosed quote chain", 'token="' * 20000),
    ("prose colon chain", "password: word " * 10000),
    ("reference chain", "$TOKEN=" * 20000),
    ("number chain", "--max-token=4096 " * 10000),
    ("long camelCase name", "aB" * 50000 + "Token=x"),
    ("long masked value", "token=" + "x" * 100000),
    ("long unmasked value", "key=" + "a:" * 50000),
    ("masked value of symbols", "token=" + "@{(<[\\" * 20000),
    ("scheme after name chain", "X-Token: Bearer " * 10000),
    ("scheme then reference chain", "X-Token: Bearer $T " * 10000),
    ("two-word prose chain", "auth: fix login " * 10000),
    ("prose then long whitespace", "password: word" + " " * 100000 + "word"),
    ("query chain", "?token=none&" * 20000),
    ("connection chain", ";PWD=0" * 20000),
    ("userinfo chain", "://token:a@" * 20000),
    ("quote inside word chain", 'token=a"b c"' * 20000),
    ("unclosed inner quote chain", 'token=a"' * 20000),
    ("closing quote chain", 'token=a" ' * 20000),
    ("quote after scheme chain", "X-Token: Bearer '" * 10000),
    ("escaped quote after scheme chain", 'Authorization: Bearer \\"' * 10000),
    ("userinfo many @", "https://u:" + "@" * 100000),
    ("userinfo no @", "https://u:" + "p" * 100000),
    ("userinfo @ chain", "://a:b@" * 20000),
    ("double equals chain", "token==" * 20000),
    ("plain double equals chain", "a==" * 50000),
]


@pytest.mark.parametrize("label,text", LARGE_REDACTION_INPUTS,
                         ids=[c[0] for c in LARGE_REDACTION_INPUTS])
def test_redaction_is_fast_on_large_text(label, text):
    # _short only hands it a bounded window, but the redactor itself must
    # stay linear too: every candidate checks 16 value characters, not all.
    start = time.perf_counter()
    _redact_secrets(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"{label}: {elapsed:.2f}s on {len(text)} chars"


# ---------------------------------------------------------------------------
# Regex speed on large commands
# ---------------------------------------------------------------------------

def _json_heredoc(copies):
    records = [{"type": "a", "m": [{"type": "text", "text": "hello world"}]}] * copies
    return "cat > f.json <<EOF\n" + json.dumps(records) + "\nEOF"


SLOW_INPUTS = [
    ("read-secrets json heredoc", M._READ_SECRET_CMD, _json_heredoc(1200)),
    ("read-secrets word run", M._READ_SECRET_CMD,
     "cat > out.txt <<'EOF'\n" + "a" * 20000 + "\nEOF"),
    ("read-secrets many readers", M._READ_SECRET_CMD, "type " * 4000),
    ("rm-rf Remove-Item", M._RM_RF, "Remove-Item -Recurse " * 1000),
    ("rm-rf flag letters", M._RM_RF, "rm -" + "r" * 16000),
    ("chrome many launchers", M._CHROME_LAUNCH, "open " * 8000),
    ("chrome long whitespace", M._CHROME_LAUNCH, "start" + " " * 20000 + "x"),
]


@pytest.mark.parametrize("label,pattern,command", SLOW_INPUTS,
                         ids=[s[0] for s in SLOW_INPUTS])
def test_matchers_are_fast_on_large_commands(label, pattern, command):
    start = time.perf_counter()
    assert pattern.search(command) is None
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"{label}: {elapsed:.2f}s on {len(command)} chars"


@pytest.mark.parametrize("pattern,command", [
    (M._READ_SECRET_CMD, "cat .env"),
    (M._READ_SECRET_CMD, "type config\\mysecret.txt"),
    (M._READ_SECRET_CMD, "head -n 5 ~/.ssh/id_rsa"),
    (M._READ_SECRET_CMD, "cat notes.txt type more /secrets/db"),
    (M._RM_RF, "rm -Rf build"),
    (M._RM_RF, "rm -xfr build"),
    (M._RM_RF, "Remove-Item dist -Force -Recurse"),
    (M._RM_RF, "echo x; Remove-Item dist -Recurse | Out-Null; -Force"),
    (M._CHROME_LAUNCH, "start chrome http://localhost"),
    (M._CHROME_LAUNCH, "open -a x start y chrome"),
])
def test_rewritten_matchers_still_detect(pattern, command):
    assert pattern.search(command)


@pytest.mark.parametrize("pattern,command", [
    (M._READ_SECRET_CMD, "cat README.md | grep secret"),
    (M._RM_RF, "rm -rf1 build"),
    (M._RM_RF, "rm -ff build"),
    (M._RM_RF, "Remove-Item dist -Recurse\n-Force"),
    (M._CHROME_LAUNCH, "start notepad\n  x chrome"),
])
def test_rewritten_matchers_still_ignore(pattern, command):
    assert not pattern.search(command)
