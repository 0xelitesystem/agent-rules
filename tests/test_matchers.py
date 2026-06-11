"""Each built-in matcher: precise topic binding and violation detection."""

from __future__ import annotations

from agent_rules.matchers import (
    BUILTIN_MATCHERS, find_commit_without_tests, match_rule, output_dir_matcher,
)
from agent_rules.models import Event, EventKind, Rule, RuleKind, Session
from agent_rules.rules import parse_rules_text


def _rule(text):
    return parse_rules_text("- " + text + "\n")[0]


def _cmd_event(command, index=0):
    return Event(kind=EventKind.TOOL_CALL, index=index, tool_name="Bash",
                 tool_input={"command": command})


def _read_event(path, index=0):
    return Event(kind=EventKind.TOOL_CALL, index=index, tool_name="Read",
                 tool_input={"file_path": path})


def _write_event(path, index=0):
    return Event(kind=EventKind.TOOL_CALL, index=index, tool_name="Write",
                 tool_input={"file_path": path, "content": "x"})


def test_chrome_matcher_binds_and_fires():
    m = match_rule(_rule("Never automate Chrome or Brave"))
    assert m.name == "no-chrome-brave"
    assert m.event_violates(_cmd_event("start brave http://x"))
    assert m.event_violates(_cmd_event("google-chrome --headless"))
    assert not m.event_violates(_cmd_event("git status"))


def test_pinned_python_matcher():
    m = match_rule(_rule("Always use C:\\Python314\\python.exe; never bare python"))
    assert m.name == "pinned-python"
    assert m.event_violates(_cmd_event("python build.py"))
    assert m.event_violates(_cmd_event("python3 -m pytest"))
    assert not m.event_violates(_cmd_event("C:\\Python314\\python.exe -m pytest"))


def test_no_verify_matcher():
    m = match_rule(_rule("Never commit with `--no-verify`"))
    assert m.name == "no-no-verify"
    assert m.event_violates(_cmd_event("git commit -m x --no-verify"))
    assert not m.event_violates(_cmd_event("git commit -m x"))


def test_force_push_matcher():
    m = match_rule(_rule("Don't force-push"))
    assert m.name == "no-force-push"
    assert m.event_violates(_cmd_event("git push --force origin feature"))
    assert m.event_violates(_cmd_event("git push -f origin feature"))
    assert not m.event_violates(_cmd_event("git push origin feature"))


def test_push_main_matcher():
    m = match_rule(_rule("Never push to main"))
    assert m.name == "no-push-main"
    assert m.event_violates(_cmd_event("git push origin main"))
    assert not m.event_violates(_cmd_event("git push origin feature"))


def test_read_secrets_matcher_cmd_and_read_tool():
    m = match_rule(_rule("Never read `.env` or secrets"))
    assert m.name == "no-read-secrets"
    assert m.event_violates(_cmd_event("cat .env"))
    assert m.event_violates(_read_event("C:\\proj\\.env"))
    assert not m.event_violates(_read_event("C:\\proj\\README.md"))


def test_install_deps_matcher():
    m = match_rule(_rule("Don't install dependencies without asking"))
    assert m.name == "no-install-deps"
    assert m.event_violates(_cmd_event("pip install redis"))
    assert m.event_violates(_cmd_event("npm install left-pad"))
    assert not m.event_violates(_cmd_event("pip show redis"))


def test_sudo_matcher():
    m = match_rule(_rule("Never use sudo"))
    assert m.name == "no-sudo"
    assert m.event_violates(_cmd_event("sudo apt update"))
    assert not m.event_violates(_cmd_event("apt list"))


def test_rm_rf_matcher():
    m = match_rule(_rule("Never run rm -rf or other destructive deletes"))
    assert m.name == "no-rm-rf"
    assert m.event_violates(_cmd_event("rm -rf /tmp/x"))
    assert not m.event_violates(_cmd_event("rm file.txt"))


def test_output_dir_matcher_detects_write_outside():
    rule = _rule("Output files go in `Output/`, never the repo root")
    m = output_dir_matcher(rule)
    assert m is not None
    assert m.event_violates(_write_event("C:\\proj\\junk.txt"))
    assert not m.event_violates(_write_event("C:\\proj\\Output\\result.txt"))


def test_every_builtin_matcher_has_a_predicate():
    for m in BUILTIN_MATCHERS:
        assert m.event_violates is not None
        assert m.describe


def test_find_commit_without_tests_ordering():
    session = Session(path="x", events=[
        _cmd_event("git commit -m a", index=0),  # no test before -> violation
    ])
    assert len(find_commit_without_tests(session)) == 1

    session2 = Session(path="x", events=[
        _cmd_event("pytest -q", index=0),
        _cmd_event("git commit -m a", index=1),  # tested -> ok
    ])
    assert find_commit_without_tests(session2) == []
