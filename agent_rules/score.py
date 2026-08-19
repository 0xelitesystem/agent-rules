"""Compliance Score: one number for how well the agent followed the rules.

The base is the share of *applicable* rules the agent complied with
(NOT_APPLICABLE rules are excluded, since a rule that never came up neither
helps nor hurts). On top of the base, violations subtract a weighted penalty, so a
single hard breach can't be averaged away by a pile of obeyed rules:

  HIGH-confidence violation  -25   (a precise matcher caught a real breach)
  LOW-confidence violation    -8   (generic keyword match, less certain)

A session where no rule applied has no score: there was nothing to grade.
"""

from __future__ import annotations

from .models import ComplianceResult, Confidence, RuleVerdict

_HIGH_PENALTY = 25
_LOW_PENALTY = 8

_GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def score_compliance(result: ComplianceResult) -> ComplianceResult:
    applicable = result.applicable()
    if not applicable:
        result.score = None
        result.grade = "—"
        return result

    complied = sum(1 for f in applicable if f.verdict is RuleVerdict.COMPLIANT)
    base = 100.0 * complied / len(applicable)

    penalty = 0
    for f in result.violations():
        penalty += (_HIGH_PENALTY if f.confidence is Confidence.HIGH
                    else _LOW_PENALTY)

    result.score = max(0, round(base - penalty))
    result.grade = next(g for cutoff, g in _GRADES if result.score >= cutoff)
    return result
