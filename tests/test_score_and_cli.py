"""Score/grade, and CLI surface: json, md, --fail-on-violation exit codes."""

from __future__ import annotations

import json

from agent_rules.checker import check_rules
from agent_rules.cli import check_transcript, main
from agent_rules.models import (
    ComplianceResult, Confidence, Rule, RuleFinding, RuleKind, RuleVerdict,
    Session,
)
from agent_rules.parser import parse_transcript
from agent_rules.rules import parse_rules_file
from agent_rules.score import score_compliance


def _result(findings):
    r = ComplianceResult(session=Session(path="x"),
                         rules=[f.rule for f in findings], findings=findings)
    return score_compliance(r)


def _finding(verdict, conf=Confidence.HIGH):
    return RuleFinding(rule=Rule(kind=RuleKind.PROHIBITION, text="r"),
                       verdict=verdict, confidence=conf, evidence="e")


def test_score_all_compliant_is_100_grade_a():
    r = _result([_finding(RuleVerdict.COMPLIANT) for _ in range(4)])
    assert r.score == 100
    assert r.grade == "A"


def test_score_excludes_not_applicable():
    findings = [_finding(RuleVerdict.COMPLIANT),
                _finding(RuleVerdict.NOT_APPLICABLE),
                _finding(RuleVerdict.NOT_APPLICABLE)]
    r = _result(findings)
    # only 1 applicable, complied -> base 100, no violations
    assert r.score == 100


def test_high_violation_penalised_more_than_low():
    high = _result([_finding(RuleVerdict.COMPLIANT),
                    _finding(RuleVerdict.VIOLATED, Confidence.HIGH)])
    low = _result([_finding(RuleVerdict.COMPLIANT),
                   _finding(RuleVerdict.VIOLATED, Confidence.LOW)])
    assert high.score < low.score


def test_no_applicable_rules_has_no_score():
    r = _result([_finding(RuleVerdict.NOT_APPLICABLE)])
    assert r.score is None
    assert r.grade == ", "


def test_violations_pull_grade_to_f():
    findings = [_finding(RuleVerdict.VIOLATED, Confidence.HIGH) for _ in range(3)]
    r = _result(findings)
    assert r.grade == "F"
    assert r.score == 0


def test_check_transcript_library_entry(violating_transcript, rules_file):
    result = check_transcript(violating_transcript, [rules_file])
    assert result.high_violations()
    assert result.score is not None


def test_cli_json_output(capsys, violating_transcript, rules_file):
    rc = main(["check", violating_transcript, "--rules", rules_file, "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["grade"]
    assert payload["high_confidence_violations"] >= 1
    assert any(r["verdict"] == "violated" for r in payload["rules"])


def test_cli_fail_on_violation_exit_1(violating_transcript, rules_file):
    rc = main(["check", violating_transcript, "--rules", rules_file,
               "--fail-on-violation", "--json"])
    assert rc == 1


def test_cli_fail_on_violation_exit_0_when_clean(compliant_transcript, rules_file):
    rc = main(["check", compliant_transcript, "--rules", rules_file,
               "--fail-on-violation", "--json"])
    assert rc == 0


def test_cli_md_report_written(tmp_path, violating_transcript, rules_file):
    md = tmp_path / "report.md"
    rc = main(["check", violating_transcript, "--rules", rules_file,
               "--md", str(md), "--json"])
    assert rc == 0
    text = md.read_text(encoding="utf-8")
    assert "agent-rules compliance report" in text
    assert "VIOLATED" in text


def test_cli_terminal_no_color(capsys, violating_transcript, rules_file):
    rc = main(["check", violating_transcript, "--rules", rules_file, "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "\x1b[" not in out
    assert "COMPLIANCE SCORE" in out
