"""Mine imperative rules from a rules file (CLAUDE.md / AGENTS.md / .cursorrules).

A rules file is mostly prose. We keep only the lines that are genuinely
*directive*: the ones that tell the agent to never do something or to
always do something. Each surviving line becomes a Rule, classified as a
PROHIBITION ("never / don't / do not / avoid / no X") or a MANDATE
("always / must / ensure / only X"), with a salient subject extracted so
a matcher can later decide whether a transcript event touched it.

This is a heuristic and we say so out loud: we read English imperative
markers, not intent. A line with no directive marker is skipped, and the
subject extraction is best-effort. The honest signal lives downstream, in
the high-precision matchers. This file's job is only to find candidate
rules and not drown the report in prose.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Rule, RuleKind

# Markers that make a line a prohibition. Word-boundaried so "another"
# doesn't trip "no" and "always" doesn't trip on a substring.
_PROHIBITION_MARKERS = re.compile(
    r"\b(?:never|don'?t|do not|avoid|must not|may not|cannot|can'?t|"
    r"shouldn'?t|should not|refrain from|under no circumstances|no longer)\b",
    re.IGNORECASE,
)

# A bare "no <noun>" prohibition ("no force-push", "no third-party deps").
_NO_PREFIX = re.compile(r"^\s*no\s+(?=[A-Za-z])", re.IGNORECASE)

# Markers that make a line a mandate.
_MANDATE_MARKERS = re.compile(
    r"\b(?:always|must|ensure|make sure|be sure to|only ever|only use|"
    r"only|required to|you have to|need to|needs to|should)\b",
    re.IGNORECASE,
)

# Leading list/heading noise stripped before classification.
_LEADING_NOISE = re.compile(r"^\s*(?:[-*+>]|\d+[.)]|#{1,6})\s*")
# Inline markdown emphasis / inline-code backticks removed for matching,
# but we keep the raw line for display.
_EMPHASIS = re.compile(r"[*_`]")

# Words that introduce the *object* of a directive; the subject is what
# follows. "never automate Chrome" -> subject side starts after "automate".
_VERB_LEAD = re.compile(
    r"\b(?:automate|launch|open|run|use|invoke|call|execute|commit|push|"
    r"force[- ]?push|install|read|cat|write|output|save|delete|remove|"
    r"touch|edit|access|read from|write to|put|place)\b",
    re.IGNORECASE,
)

# Stopwords we don't want to surface as a rule "subject".
_SUBJECT_STOP = {
    "the", "a", "an", "to", "of", "in", "on", "into", "with", "without",
    "any", "all", "your", "my", "our", "their", "its", "it", "them", "this",
    "that", "these", "those", "and", "or", "for", "from", "at", "by", "as",
    "be", "do", "not", "never", "always", "must", "only", "ensure", "avoid",
    "use", "using", "run", "running", "when", "if", "is", "are", "was",
}


def _looks_directive(text: str) -> tuple[bool, RuleKind]:
    """Is this line an imperative rule, and if so prohibition or mandate?

    Prohibitions win ties: "always avoid X" is a prohibition about X.
    """
    if _PROHIBITION_MARKERS.search(text) or _NO_PREFIX.search(text):
        return True, RuleKind.PROHIBITION
    if _MANDATE_MARKERS.search(text):
        return True, RuleKind.MANDATE
    return False, RuleKind.MANDATE


def _extract_subject(text: str, kind: RuleKind) -> str:
    """Best-effort salient subject: the tool / command / path / action.

    Strategy, in order:
    1. A quoted or backticked token ("`python`", "Output/", "--no-verify").
    2. The chunk right after an action verb ("automate <chrome>").
    3. The first few content words after the directive marker.
    All lowercased; punctuation trimmed; stopwords dropped.
    """
    raw = text
    # 1. backticked / quoted token, or a flag, or a path-looking token.
    quoted = re.search(r"[`\"']([^`\"']{2,60})[`\"']", raw)
    if quoted:
        return quoted.group(1).strip().lower()
    flag = re.search(r"(--[a-z][a-z0-9-]+)", raw, re.IGNORECASE)
    if flag:
        return flag.group(1).lower()

    work = _EMPHASIS.sub("", raw)
    # 2. text after an action verb.
    verb = _VERB_LEAD.search(work)
    tail = work[verb.end():] if verb else work
    # If we used a marker but no verb, cut everything up to the marker.
    if not verb:
        marker = _PROHIBITION_MARKERS.search(work) or _MANDATE_MARKERS.search(work)
        if marker:
            tail = work[marker.end():]
        no_prefix = _NO_PREFIX.match(work)
        if no_prefix:
            tail = work[no_prefix.end():]

    words = re.findall(r"[A-Za-z0-9_./:\\-]+", tail)
    salient = [w for w in words if w.lower() not in _SUBJECT_STOP]
    return " ".join(salient[:4]).strip().lower()


def parse_rules_text(text: str, source: str = "") -> list[Rule]:
    rules: list[Rule] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = _LEADING_NOISE.sub("", raw_line).strip()
        if not line or line.startswith("```"):
            continue
        if len(line) > 300:
            continue  # almost certainly prose / pasted content, not a rule
        # Strip emphasis only for the directive test; keep raw for display.
        probe = _EMPHASIS.sub("", line)
        is_rule, kind = _looks_directive(probe)
        if not is_rule:
            continue
        subject = _extract_subject(line, kind)
        rules.append(Rule(
            kind=kind,
            text=line,
            subject=subject,
            source=source,
            line=lineno,
        ))
    return rules


def parse_rules_file(path: str | Path) -> list[Rule]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_rules_text(text, source=str(path))


# Filenames we treat as rules files when auto-discovering, in priority order.
_RULES_FILENAMES = ("CLAUDE.md", "AGENTS.md", ".cursorrules")


def discover_rules_files(session_cwd: str = "") -> list[Path]:
    """Find rules files for a session: project cwd first, then ~/.claude.

    Order matters: the project's CLAUDE.md is the most specific, the
    user's global ~/.claude/CLAUDE.md is the fallback. We also pick up
    AGENTS.md and .cursorrules in the project root.
    """
    found: list[Path] = []
    seen: set[str] = set()

    def add(p: Path) -> None:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if p.is_file() and key not in seen:
            seen.add(key)
            found.append(p)

    if session_cwd:
        cwd = Path(session_cwd)
        for name in _RULES_FILENAMES:
            add(cwd / name)
    home = Path(__import__("os").path.expanduser("~"))
    add(home / ".claude" / "CLAUDE.md")
    return found
