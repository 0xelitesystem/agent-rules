"""High-precision matchers: the reliable half of agent-rules.

Rule extraction (rules.py) is fuzzy English parsing. *This* file is where
the honesty lives. Each matcher is a small, hand-built detector for one
well-known governance topic: "never automate Chrome", "always use the
pinned python", "never commit with --no-verify", and so on. A matcher
knows two things:

  topic_match(rule)  -> is this rule *about* my topic?
  violation(event)   -> does this transcript event *break* my topic's rule?

When a rule binds to a matcher, its verdict is HIGH confidence: we are not
guessing, we recognised a specific forbidden/required pattern. Rules that
bind to no matcher fall back to a generic keyword check (checker.py),
marked LOW confidence and clearly labelled as such.

Mandate matchers (e.g. "always run tests before committing") express their
condition as an ordering check over the whole event stream rather than a
single offending event; the checker handles those specially.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import Event, EventKind, Rule, RuleKind, Session

# ---------------------------------------------------------------------------
# Small helpers shared by matchers
# ---------------------------------------------------------------------------


def _norm(command: str) -> str:
    return " ".join(command.split())


def _commands(session: Session) -> list[Event]:
    return [e for e in session.events
            if e.kind is EventKind.TOOL_CALL and e.command]


# A "launch a browser" command: chrome/brave/chromium binaries, `start`,
# `open`, Selenium/puppeteer/playwright pointed at chrome/brave, etc.
#
# The launcher branch is written so the regex engine stays linear on large
# commands: the whitespace run after the launcher is consumed whole
# ((?=\S) forbids splitting it), and the scan toward "chrome" stops at the
# next launcher word, because the search tries that launcher on its own.
# It matches exactly what `launcher\s+.*\b(?:chrome|brave)\b` matched.
_LAUNCHER = r"\b(?:start|open|xdg-open)\s"
_CHROME_LAUNCH = re.compile(
    r"\b(?:google[- ]?chrome|chrome\.exe|chromium|brave|brave\.exe|"
    r"brave-browser)\b"
    r"|--app=|chromedriver|"
    r"\b(?:start|open|xdg-open)\s+(?=\S)"
    r"(?:(?!" + _LAUNCHER + r")[^\n])*?\b(?:chrome|brave)\b",
    re.IGNORECASE,
)

# A bare `python` / `python3` invocation that is NOT the pinned interpreter.
# We require a word boundary and reject anything that is a path to python
# (contains a slash before it). "C:\Python314\python.exe" is fine.
_BARE_PYTHON = re.compile(r"(?<![\\/\w.])python(?:3)?(?:\.exe)?\b", re.IGNORECASE)
_PINNED_PYTHON = re.compile(r"[A-Za-z]:[\\/]python\d+[\\/]python", re.IGNORECASE)

_NO_VERIFY = re.compile(r"\bgit\s+commit\b.*--no-verify|\b--no-verify\b.*\bcommit\b",
                        re.IGNORECASE)
_FORCE_PUSH = re.compile(
    r"\bgit\s+push\b.*(?:--force\b|--force-with-lease\b|(?<!\w)-f(?!\w))",
    re.IGNORECASE,
)
_PUSH_MAIN = re.compile(
    r"\bgit\s+push\b\s+\S+\s+(?:HEAD:)?(?:main|master)\b"
    r"|\bgit\s+push\b\s+(?:origin\s+)?(?:main|master)\b",
    re.IGNORECASE,
)
# Reading a secrets file: cat/type/Get-Content/less on .env or *secret*,
# plus the Read tool pointed at such a file (handled separately).
#
# Linear on large commands: the scan after a reader word stops at the next
# reader word (the search tries that one on its own), and "secret" is matched
# bare, since the old [\w.]* padding around it could not change the verdict.
_READER = r"\b(?:cat|type|less|more|head|tail|bat|Get-Content|gc)\b"
_READ_SECRET_CMD = re.compile(
    _READER + r"(?:(?!" + _READER + r")[^|;&])*?"
    r"(?:\.env\b|\.env\.[\w.]+|/secrets?/|\\secrets?\\|secret|"
    r"id_rsa|\.pem\b|credentials)",
    re.IGNORECASE,
)
_SECRET_PATH = re.compile(
    r"(?:^|[\\/])\.env(?:\.[\w.]+)?$|secret|credentials|id_rsa|\.pem$",
    re.IGNORECASE,
)
_INSTALL_DEPS = re.compile(
    r"\b(?:pip|pip3|pipx)\s+install\b"
    r"|\bpython\b.*-m\s+pip\s+install\b"
    r"|\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|i)\b"
    r"|\b(?:apt|apt-get|brew|choco|cargo|gem|go)\s+(?:install|add|get)\b"
    r"|\buv\s+(?:pip\s+)?(?:install|add)\b",
    re.IGNORECASE,
)
_SUDO = re.compile(r"(?:^|[|;&]\s*|\bthen\s+)sudo\b", re.IGNORECASE)
# Recursive force delete. Written to stay linear on large commands, and to
# match exactly what the plainer form matched:
#   rm: one flag word that ends in r or f and contains both letters
#       (was -[a-zA-Z]*r[a-zA-Z]*f | -[a-zA-Z]*f[a-zA-Z]*r, then \b);
#   Remove-Item: -Recurse and -Force both later on the same line. Only the
#       first Remove-Item on each line is scanned from, since any later one
#       would find the same flags.
_RM_RF = re.compile(
    r"\brm\s+-(?=[a-zA-Z]*[rf]\b)(?=[a-zA-Z]*r)(?=[a-zA-Z]*f)"
    r"|(?:^|(?<=\n))(?:(?!Remove-Item\b)[^\n])*Remove-Item\b"
    r"(?=[^\n]*-Recurse\b)[^\n]*-Force\b",
    re.IGNORECASE,
)


@dataclass
class Matcher:
    """One named, high-precision detector for a governance topic."""

    name: str
    kind: RuleKind
    # Does a rule's text/subject indicate it is about this topic?
    topic: Callable[[Rule], bool]
    # For PROHIBITION matchers: does this single event break the rule?
    event_violates: Callable[[Event], bool] | None = None
    # Human label describing what a violation looks like.
    describe: str = ""

    def rule_is_about(self, rule: Rule) -> bool:
        return self.topic(rule)


def _has(*words: str) -> Callable[[Rule], bool]:
    """Topic test: rule text mentions any of these whole words/phrases."""
    pats = [re.compile(r"\b" + re.escape(w) + r"\b", re.IGNORECASE) for w in words]
    return lambda rule: any(p.search(rule.text) for p in pats)


def _read_targets_secret(event: Event) -> bool:
    if event.tool_name == "Read" and event.file_path:
        if _SECRET_PATH.search(Path(event.file_path).as_posix()):
            return True
    return bool(event.command and _READ_SECRET_CMD.search(event.command))


def _writes_outside_allowed(event: Event, allowed: str) -> bool:
    """Write/edit lands outside an allowed subdir (e.g. 'Output/').

    Heuristic: a file write whose path does not contain the allowed segment
    *and* sits at the project root level. We compare path segments.
    """
    if not (event.is_file_write() or event.tool_name == "Edit"):
        return False
    path = event.file_path
    if not path:
        return False
    posix = Path(path).as_posix().lower()
    seg = allowed.strip("/\\").lower()
    if not seg:
        return False
    return seg not in posix


# ---------------------------------------------------------------------------
# The built-in matcher library
# ---------------------------------------------------------------------------

BUILTIN_MATCHERS: list[Matcher] = [
    Matcher(
        name="no-chrome-brave",
        kind=RuleKind.PROHIBITION,
        topic=_has("chrome", "brave", "browser"),
        event_violates=lambda e: bool(e.command and _CHROME_LAUNCH.search(e.command)),
        describe="launched Chrome or Brave",
    ),
    Matcher(
        name="pinned-python",
        kind=RuleKind.PROHIBITION,
        # Topic: the rule is about which python to use. Could be phrased as a
        # mandate ("always use C:\\Python314\\python.exe") or a prohibition
        # ("never run bare python"); either way the violation is the same.
        topic=lambda r: bool(
            re.search(r"\bpython\b", r.text, re.IGNORECASE)
            and re.search(r"\bbare\b|python\d|interpreter|\.exe\b|C:\\?Python",
                          r.text, re.IGNORECASE)
        ),
        event_violates=lambda e: bool(
            e.command
            and _BARE_PYTHON.search(e.command)
            and not _PINNED_PYTHON.search(e.command)
        ),
        describe="ran bare `python` instead of the pinned interpreter",
    ),
    Matcher(
        name="no-no-verify",
        kind=RuleKind.PROHIBITION,
        topic=_has("--no-verify", "no-verify", "hooks", "bypass"),
        event_violates=lambda e: bool(e.command and _NO_VERIFY.search(e.command)),
        describe="committed with --no-verify (git hooks bypassed)",
    ),
    Matcher(
        name="no-force-push",
        kind=RuleKind.PROHIBITION,
        topic=_has("force-push", "force push", "--force", "force-with-lease"),
        event_violates=lambda e: bool(e.command and _FORCE_PUSH.search(e.command)),
        describe="force-pushed",
    ),
    Matcher(
        name="no-push-main",
        kind=RuleKind.PROHIBITION,
        topic=lambda r: bool(
            re.search(r"\bpush\b", r.text, re.IGNORECASE)
            and re.search(r"\bmain\b|\bmaster\b", r.text, re.IGNORECASE)
        ),
        event_violates=lambda e: bool(e.command and _PUSH_MAIN.search(e.command)
                                      and not _FORCE_PUSH.search(e.command)),
        describe="pushed directly to main/master",
    ),
    Matcher(
        name="no-read-secrets",
        kind=RuleKind.PROHIBITION,
        topic=_has(".env", "secret", "secrets", "credentials", "id_rsa", ".pem"),
        event_violates=_read_targets_secret,
        describe="read a secrets file (.env / credentials)",
    ),
    Matcher(
        name="no-install-deps",
        kind=RuleKind.PROHIBITION,
        topic=lambda r: bool(
            re.search(r"\binstall\b|\bdepend|\bpackage", r.text, re.IGNORECASE)
            and re.search(r"\bpip\b|\bnpm\b|\byarn\b|\bdep|\bpackage|\binstall\b",
                          r.text, re.IGNORECASE)
        ),
        event_violates=lambda e: bool(e.command and _INSTALL_DEPS.search(e.command)),
        describe="installed dependencies",
    ),
    Matcher(
        name="no-sudo",
        kind=RuleKind.PROHIBITION,
        topic=_has("sudo", "root", "elevated"),
        event_violates=lambda e: bool(e.command and _SUDO.search(e.command)),
        describe="ran a command with sudo",
    ),
    Matcher(
        name="no-rm-rf",
        kind=RuleKind.PROHIBITION,
        topic=lambda r: bool(re.search(r"\brm\b|recurse|recursive|delete", r.text,
                                       re.IGNORECASE)
                             and re.search(r"-rf|-fr|recurse|force|destructive",
                                           r.text, re.IGNORECASE)),
        event_violates=lambda e: bool(e.command and _RM_RF.search(e.command)),
        describe="ran a recursive force delete (rm -rf)",
    ),
]


# Matchers that need the *allowed directory* parsed out of the rule text,
# so they can't be a plain event predicate. They are built on demand.
_OUTPUT_DIR_RE = re.compile(
    r"(?:in|to|under|into|inside)\s+[`\"']?([\w.\-]+/[\w.\-/]*|[\w.\-]+/)",
    re.IGNORECASE,
)


def output_dir_matcher(rule: Rule) -> Matcher | None:
    """Build a 'write outside allowed dir' matcher if the rule names a dir.

    Recognises rules like "Output files go in Output/, never repo root" or
    "outputs go to dist/". We pull the allowed directory and produce a
    matcher whose violation is a Write/Edit landing elsewhere.
    """
    text = rule.text
    if not re.search(r"\boutput|\bwrite|\bsave|\bgenerated|\bfiles?\s+go\b",
                     text, re.IGNORECASE):
        return None
    if not re.search(r"\bnever\b|\bnot\b|\bonly\b|\bgo\s+in\b|\bgo\s+to\b|\bmust\b",
                     text, re.IGNORECASE):
        return None
    m = _OUTPUT_DIR_RE.search(text)
    allowed = ""
    if m:
        allowed = m.group(1).strip("/\\ ")
    else:
        # bare token like "Output/" without a preposition
        bare = re.search(r"[`\"']?([A-Za-z][\w.\-]*)/[`\"']?", text)
        if bare:
            allowed = bare.group(1)
    if not allowed:
        return None
    return Matcher(
        name="write-allowed-dir",
        kind=RuleKind.MANDATE,
        topic=lambda r: True,
        event_violates=lambda e: _writes_outside_allowed(e, allowed),
        describe=f"wrote a file outside the allowed directory ({allowed}/)",
    )


# ---------------------------------------------------------------------------
# Mandate ordering matcher: "always run tests before committing"
# ---------------------------------------------------------------------------

_TEST_RUN = re.compile(
    r"\bpytest\b|\bpython(?:3)?(?:\.exe)?\s+-m\s+(?:pytest|unittest)\b"
    r"|\bnpm\s+(?:run\s+)?test\b|\b(?:npx|yarn|pnpm|bun)\s+(?:run\s+)?test\b"
    r"|\bgo\s+test\b|\bcargo\s+test\b|\bjest\b|\bvitest\b|C:[\\/]Python\d+"
    r"[\\/]python(?:\.exe)?\s+-m\s+pytest",
    re.IGNORECASE,
)
_GIT_COMMIT = re.compile(r"\bgit\s+commit\b", re.IGNORECASE)


def is_test_before_commit_rule(rule: Rule) -> bool:
    if rule.kind is not RuleKind.MANDATE:
        return False
    t = rule.text.lower()
    has_test = "test" in t
    has_commit = "commit" in t
    has_before = "before" in t or "prior to" in t or "then commit" in t
    return has_test and has_commit and has_before


@dataclass
class OrderViolation:
    event_index: int
    command: str
    detail: str


def find_commit_without_tests(session: Session) -> list[OrderViolation]:
    """Each git commit with no successful test run since the previous commit.

    Models "always run tests before committing": a commit is a violation if
    no test command ran between it and the prior commit (or session start).
    """
    violations: list[OrderViolation] = []
    last_test_index = -1
    last_commit_index = -1
    for e in session.events:
        if e.kind is not EventKind.TOOL_CALL or not e.command:
            continue
        if _TEST_RUN.search(e.command):
            last_test_index = e.index
        elif _GIT_COMMIT.search(e.command) and "--amend" not in e.command:
            if last_test_index <= last_commit_index:
                violations.append(OrderViolation(
                    event_index=e.index,
                    command=_norm(e.command),
                    detail="no test run between this commit and the previous one",
                ))
            last_commit_index = e.index
    return violations


# ---------------------------------------------------------------------------
# Binding: pick the matcher for a rule
# ---------------------------------------------------------------------------


def match_rule(rule: Rule) -> Matcher | None:
    """Return the high-precision matcher bound to this rule, or None."""
    # Directory-write matcher is parameterised, try it first.
    dir_matcher = output_dir_matcher(rule)
    if dir_matcher is not None:
        return dir_matcher
    for matcher in BUILTIN_MATCHERS:
        if matcher.rule_is_about(rule):
            return matcher
    return None
