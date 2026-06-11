"""Rule extraction: prohibition vs mandate, subject, prose-skipping."""

from __future__ import annotations

from agent_rules.models import RuleKind
from agent_rules.rules import parse_rules_text


def _by_text(rules, needle):
    return next(r for r in rules if needle.lower() in r.text.lower())


def test_classifies_prohibition_and_mandate():
    text = (
        "- Never automate Chrome or Brave.\n"
        "- Always use C:\\Python314\\python.exe for Python.\n"
    )
    rules = parse_rules_text(text)
    assert len(rules) == 2
    chrome = _by_text(rules, "Chrome")
    pinned = _by_text(rules, "python.exe")
    assert chrome.kind is RuleKind.PROHIBITION
    assert pinned.kind is RuleKind.MANDATE


def test_dont_and_do_not_are_prohibitions():
    rules = parse_rules_text(
        "- Don't install dependencies without asking.\n"
        "- Do not push to main.\n"
    )
    assert all(r.kind is RuleKind.PROHIBITION for r in rules)


def test_no_prefix_prohibition():
    rules = parse_rules_text("- No force-push to shared branches.\n")
    assert len(rules) == 1
    assert rules[0].kind is RuleKind.PROHIBITION


def test_skips_prose_lines():
    text = (
        "# Heading\n"
        "This project is a CLI tool for auditing agents.\n"
        "It parses transcripts and reports findings.\n"
        "- Never read .env files.\n"
    )
    rules = parse_rules_text(text)
    # only the directive line survives
    assert len(rules) == 1
    assert ".env" in rules[0].text


def test_extracts_backticked_subject():
    rules = parse_rules_text("- Never commit with `--no-verify`.\n")
    assert rules[0].subject == "--no-verify"


def test_extracts_flag_subject_without_backticks():
    rules = parse_rules_text("- Don't pass --force to git push.\n")
    assert "--force" in rules[0].subject


def test_long_lines_are_not_rules():
    long = "- Always " + "x" * 400 + "\n"
    assert parse_rules_text(long) == []


def test_source_and_line_recorded():
    rules = parse_rules_text("intro\n- Never use sudo.\n", source="CLAUDE.md")
    assert rules[0].source == "CLAUDE.md"
    assert rules[0].line == 2
