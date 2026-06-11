"""Render a ComplianceResult: ANSI terminal report, Markdown, or JSON."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .models import (
    ComplianceResult, Confidence, RuleFinding, RuleKind, RuleVerdict,
)

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_CYAN = "\x1b[36m"

_VERDICT_STYLE = {
    RuleVerdict.COMPLIANT: (_GREEN, "✓", "COMPLIANT"),
    RuleVerdict.VIOLATED: (_RED, "✗", "VIOLATED"),
    RuleVerdict.NOT_APPLICABLE: (_DIM, "·", "N/A"),
}


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, *styles: str, enabled: bool = True) -> str:
    if not enabled or not styles:
        return text
    return "".join(styles) + text + _RESET


def _kind_tag(rule_kind: RuleKind) -> str:
    return "PROHIBIT" if rule_kind is RuleKind.PROHIBITION else "MANDATE "


def render_terminal(result: ComplianceResult, color: bool | None = None) -> str:
    color = _colors_enabled() if color is None else color
    session = result.session
    lines: list[str] = []
    out = lines.append

    title = session.slug or Path(session.path).stem[:12]
    out("")
    out(_paint("  agent-rules", _BOLD, _CYAN, enabled=color)
        + _paint(" — did the agent follow the rules?", _DIM, enabled=color))
    out(_paint(f"  session {title} · {len(session.events)} events"
               + (f" · {session.cwd}" if session.cwd else ""),
               _DIM, enabled=color))
    out("")

    if not result.rules:
        out("  no directive rules were found in the rules file(s) — nothing to check.")
        out("")
        return "\n".join(lines)

    if result.score is None:
        out(_paint(f"  {len(result.rules)} rule(s) parsed, but none applied to this "
                   "session — nothing to grade.", enabled=color))
        out("")
        # still show the rules so the user sees what was considered
        _render_findings(out, result, color)
        return "\n".join(lines)

    score_style = _GREEN if result.score >= 80 else (
        _YELLOW if result.score >= 60 else _RED)
    out(f"  {_paint('COMPLIANCE SCORE', _BOLD, enabled=color)}  "
        + _paint(f"{result.score}/100 ({result.grade})", _BOLD, score_style,
                 enabled=color))
    counts = result.counts()
    high = len(result.high_violations())
    out(_paint(
        f"  {counts['compliant']} compliant · {counts['violated']} violated · "
        f"{counts['not_applicable']} n/a"
        + (f" · {high} high-confidence violation(s)" if high else ""),
        _DIM, enabled=color))
    out("")

    _render_findings(out, result, color)
    return "\n".join(lines)


def _render_findings(out, result: ComplianceResult, color: bool) -> None:
    out(_paint("  RULES", _BOLD, enabled=color))
    # Order: violations first, then compliant, then n/a — most useful on top.
    order = {RuleVerdict.VIOLATED: 0, RuleVerdict.COMPLIANT: 1,
             RuleVerdict.NOT_APPLICABLE: 2}
    findings = sorted(result.findings, key=lambda f: order[f.verdict])
    for finding in findings:
        style, symbol, label = _VERDICT_STYLE[finding.verdict]
        conf = ""
        if finding.verdict is RuleVerdict.VIOLATED:
            conf = (" " + _paint("[HIGH]", _RED, enabled=color)
                    if finding.confidence is Confidence.HIGH
                    else " " + _paint("[low]", _DIM, enabled=color))
        tag = _paint(_kind_tag(finding.rule.kind), _DIM, enabled=color)
        out(f"  {_paint(symbol + ' ' + label.ljust(9), style, enabled=color)}"
            f" {tag} “{_short(finding.rule.text, 92)}”{conf}")
        out(_paint(f"    └─ {finding.evidence}", _DIM, enabled=color))
    out("")


def _short(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _finding_dict(finding: RuleFinding) -> dict:
    return {
        "rule": finding.rule.text,
        "kind": finding.rule.kind.value,
        "subject": finding.rule.subject,
        "source": finding.rule.source,
        "line": finding.rule.line,
        "matcher": finding.rule.matcher or None,
        "verdict": finding.verdict.value,
        "confidence": finding.confidence.value,
        "evidence": finding.evidence,
        "offending_command": finding.offending_command or None,
        "event_index": finding.event_index,
    }


def render_json(result: ComplianceResult) -> str:
    return json.dumps({
        "transcript": result.session.path,
        "session_id": result.session.session_id,
        "cwd": result.session.cwd,
        "score": result.score,
        "grade": result.grade,
        "counts": result.counts(),
        "high_confidence_violations": len(result.high_violations()),
        "rules": [_finding_dict(f) for f in result.findings],
    }, indent=2)


def render_markdown(result: ComplianceResult) -> str:
    lines = [
        "# agent-rules compliance report",
        "",
        f"- **Transcript:** `{Path(result.session.path).name}`",
        f"- **Project:** `{result.session.cwd or 'unknown'}`",
        f"- **Score:** {result.score if result.score is not None else 'n/a'}"
        f"/100 ({result.grade})",
        "",
        "## Rules",
        "",
        "| Verdict | Kind | Rule | Confidence | Evidence |",
        "|---|---|---|---|---|",
    ]
    order = {RuleVerdict.VIOLATED: 0, RuleVerdict.COMPLIANT: 1,
             RuleVerdict.NOT_APPLICABLE: 2}
    for finding in sorted(result.findings, key=lambda f: order[f.verdict]):
        _, symbol, label = _VERDICT_STYLE[finding.verdict]
        rule = finding.rule.text.replace("|", "\\|")
        evidence = finding.evidence.replace("|", "\\|")
        conf = (finding.confidence.value
                if finding.verdict is RuleVerdict.VIOLATED else "—")
        kind = "prohibition" if finding.rule.kind is RuleKind.PROHIBITION else "mandate"
        lines.append(f"| {symbol} {label} | {kind} | {rule} | {conf} | {evidence} |")
    lines.append("")
    return "\n".join(lines)
