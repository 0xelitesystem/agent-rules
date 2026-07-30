"""Data models for agent-rules.

The auditor reasons about three shapes. A Session is an ordered list of
Events (assistant text or tool calls), the same shape as agent-receipts, so
the two tools can share transcripts. A Rule is an imperative line mined
from a rules file (CLAUDE.md / AGENTS.md / .cursorrules). A RuleFinding is
the verdict on one rule: did the agent obey it, break it, or never trigger it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class EventKind(enum.Enum):
    TEXT = "text"
    TOOL_CALL = "tool_call"


@dataclass
class Event:
    """One thing that happened in the session, in transcript order."""

    kind: EventKind
    index: int  # position in the session event stream
    timestamp: str = ""
    is_sidechain: bool = False

    # TEXT events
    text: str = ""

    # TOOL_CALL events
    tool_name: str = ""
    tool_id: str = ""
    tool_input: dict = field(default_factory=dict)
    output: str = ""
    is_error: bool = False
    exit_code: int | None = None

    @property
    def command(self) -> str:
        """Shell command for Bash/PowerShell calls, else empty."""
        if self.tool_name in ("Bash", "PowerShell"):
            return str(self.tool_input.get("command", ""))
        return ""

    @property
    def file_path(self) -> str:
        """Target path for file-mutating and Read tools, else empty."""
        return str(self.tool_input.get("file_path", ""))

    def is_file_edit(self) -> bool:
        return self.tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")

    def is_file_write(self) -> bool:
        """A call that creates or overwrites a file (not just Edit-in-place)."""
        return self.tool_name in ("Write", "NotebookEdit")


@dataclass
class Session:
    """A parsed agent session transcript."""

    path: str
    session_id: str = ""
    cwd: str = ""
    git_branch: str = ""
    slug: str = ""
    version: str = ""
    events: list[Event] = field(default_factory=list)
    first_timestamp: str = ""
    last_timestamp: str = ""

    def tool_calls(self) -> list[Event]:
        return [e for e in self.events if e.kind is EventKind.TOOL_CALL]

    def text_events(self) -> list[Event]:
        return [e for e in self.events if e.kind is EventKind.TEXT]


class RuleKind(enum.Enum):
    PROHIBITION = "prohibition"  # never / don't / avoid / no X
    MANDATE = "mandate"  # always / must / ensure / only X


@dataclass
class Rule:
    """One imperative directive mined from a rules file."""

    kind: RuleKind
    text: str  # the raw rule line, trimmed
    subject: str = ""  # salient tool/command/path/action, lowercased
    source: str = ""  # which rules file it came from
    line: int = 0  # 1-based line number in that file
    matcher: str = ""  # name of the built-in matcher bound to it, if any


class RuleVerdict(enum.Enum):
    COMPLIANT = "compliant"  # rule was relevant and the agent obeyed it
    VIOLATED = "violated"  # the agent did the forbidden thing / skipped the mandate
    NOT_APPLICABLE = "not_applicable"  # the rule never came up this session


class Confidence(enum.Enum):
    HIGH = "high"  # a precise built-in matcher decided this
    LOW = "low"  # generic keyword-presence fallback


@dataclass
class RuleFinding:
    """The verdict on one rule, with a pointer to the offending event."""

    rule: Rule
    verdict: RuleVerdict
    confidence: Confidence = Confidence.HIGH
    evidence: str = ""  # human-readable: what we checked and what we saw
    offending_command: str = ""  # the command/path that broke the rule, if any
    event_index: int | None = None  # event index of the deciding evidence


@dataclass
class ComplianceResult:
    """Everything the compliance check produced for one session."""

    session: Session
    rules: list[Rule] = field(default_factory=list)
    findings: list[RuleFinding] = field(default_factory=list)
    score: int | None = None  # 0-100, None when no rule was applicable
    grade: str = ""

    def applicable(self) -> list[RuleFinding]:
        """Findings whose rule actually came up (compliant or violated)."""
        return [f for f in self.findings
                if f.verdict is not RuleVerdict.NOT_APPLICABLE]

    def violations(self) -> list[RuleFinding]:
        return [f for f in self.findings if f.verdict is RuleVerdict.VIOLATED]

    def high_violations(self) -> list[RuleFinding]:
        return [f for f in self.violations() if f.confidence is Confidence.HIGH]

    def counts(self) -> dict[str, int]:
        c = {v.value: 0 for v in RuleVerdict}
        for f in self.findings:
            c[f.verdict.value] += 1
        return c
