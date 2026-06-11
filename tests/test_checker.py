"""End-to-end checking: compliant, violating, mandate-ordering, n/a, fallback."""

from __future__ import annotations

from agent_rules.checker import check_rule, check_rules
from agent_rules.models import Confidence, RuleVerdict
from agent_rules.parser import parse_transcript
from agent_rules.rules import parse_rules_file, parse_rules_text


def _findings(transcript, rules_file):
    session = parse_transcript(transcript)
    rules = parse_rules_file(rules_file)
    return session, rules, check_rules(session, rules)


def _verdict_for(findings, needle):
    f = next(f for f in findings if needle.lower() in f.rule.text.lower())
    return f


def test_compliant_session_zero_high_violations(compliant_transcript, rules_file):
    _, _, findings = _findings(compliant_transcript, rules_file)
    high_viol = [f for f in findings if f.verdict is RuleVerdict.VIOLATED
                 and f.confidence is Confidence.HIGH]
    assert high_viol == [], [f.rule.text for f in high_viol]


def test_compliant_session_marks_python_compliant(compliant_transcript, rules_file):
    _, _, findings = _findings(compliant_transcript, rules_file)
    py = _verdict_for(findings, "python.exe")
    assert py.verdict is RuleVerdict.COMPLIANT
    assert py.confidence is Confidence.HIGH


def test_violating_session_catches_bare_python(violating_transcript, rules_file):
    _, _, findings = _findings(violating_transcript, rules_file)
    py = _verdict_for(findings, "python")
    assert py.verdict is RuleVerdict.VIOLATED
    assert py.confidence is Confidence.HIGH
    assert "python" in py.offending_command.lower()


def test_violating_session_catches_no_verify(violating_transcript, rules_file):
    _, _, findings = _findings(violating_transcript, rules_file)
    nv = _verdict_for(findings, "--no-verify")
    assert nv.verdict is RuleVerdict.VIOLATED
    assert "--no-verify" in nv.offending_command


def test_violating_session_catches_chrome(violating_transcript, rules_file):
    _, _, findings = _findings(violating_transcript, rules_file)
    chrome = _verdict_for(findings, "Chrome")
    assert chrome.verdict is RuleVerdict.VIOLATED


def test_violating_session_catches_repo_root_write(violating_transcript, rules_file):
    _, _, findings = _findings(violating_transcript, rules_file)
    out = _verdict_for(findings, "Output")
    assert out.verdict is RuleVerdict.VIOLATED
    assert "junk.txt" in out.offending_command


def test_commit_without_tests_is_violation(commit_without_tests_transcript, rules_file):
    _, _, findings = _findings(commit_without_tests_transcript, rules_file)
    mandate = _verdict_for(findings, "run tests before committing")
    assert mandate.verdict is RuleVerdict.VIOLATED
    assert mandate.confidence is Confidence.HIGH


def test_compliant_session_passes_test_before_commit(compliant_transcript, rules_file):
    _, _, findings = _findings(compliant_transcript, rules_file)
    mandate = _verdict_for(findings, "run tests before committing")
    assert mandate.verdict is RuleVerdict.COMPLIANT


def test_no_rules_apply_session(no_rules_apply_transcript, rules_file):
    session, rules, findings = _findings(no_rules_apply_transcript, rules_file)
    # No commit, no python, no chrome, no push -> nothing applicable.
    assert all(f.verdict is RuleVerdict.NOT_APPLICABLE for f in findings), \
        [(f.rule.text, f.verdict) for f in findings
         if f.verdict is not RuleVerdict.NOT_APPLICABLE]


def test_generic_fallback_is_low_confidence(tmp_path):
    # A rule with no precise matcher binding; subject 'frobnicate'.
    rules = parse_rules_text("- Never run frobnicate on production.\n")
    from agent_rules.models import Session, Event, EventKind
    session = Session(path="x", events=[
        Event(kind=EventKind.TOOL_CALL, index=0, tool_name="Bash",
              tool_input={"command": "frobnicate --prod"}),
    ])
    finding = check_rule(session, rules[0])
    assert finding.verdict is RuleVerdict.VIOLATED
    assert finding.confidence is Confidence.LOW


def test_generic_fallback_not_applicable_when_absent():
    rules = parse_rules_text("- Never run frobnicate on production.\n")
    from agent_rules.models import Session, Event, EventKind
    session = Session(path="x", events=[
        Event(kind=EventKind.TOOL_CALL, index=0, tool_name="Bash",
              tool_input={"command": "git status"}),
    ])
    finding = check_rule(session, rules[0])
    assert finding.verdict is RuleVerdict.NOT_APPLICABLE
    assert finding.confidence is Confidence.LOW
