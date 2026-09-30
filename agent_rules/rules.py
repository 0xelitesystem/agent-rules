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

import ntpath
import os
import re
import unicodedata
from pathlib import Path, PureWindowsPath

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


# First path components that name the NT object namespace, not a folder.
_NT_NAMESPACE_ROOTS = ("device", "global??")

# A drive-absolute Windows path: a drive letter, a colon and a backslash.
_DRIVE_ABSOLUTE = re.compile(r"[A-Za-z]:\\")

# Non-ASCII stand-ins for a separator, a dot, a colon or a question mark:
# every character whose compatibility (NFKC) form holds one of \ / . : ?,
# plus the best-fit lookalikes a Windows code page can turn into \ or /
# (yen and won signs, fraction and division slashes, set minus, reverse
# solidus operator, big solidus and big reverse solidus). ASCII escapes only.
_LOOKALIKE_CHARS = re.compile(
    "["
    "\u00a5\u2024-\u2026\u2044\u2047-\u2049\u20a9\u2100\u2101\u2105\u2106"
    "\u2215\u2216\u2488-\u249b\u29f5\u29f8\u29f9\u2a74\u33c2\u33c7\u33d8"
    "\ufe13\ufe16\ufe19\ufe30\ufe52\ufe55\ufe56\ufe68\uff0e\uff0f\uff1a"
    "\uff1f\uff3c\U0001f100"
    "]"
)

# Control characters. No Windows file name holds one, and an embedded NUL
# makes Python raise ValueError instead of OSError when the path is used.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f]")

# The longest path Windows accepts; Python refuses a longer one with
# "path too long for Windows". A longer cwd cannot be a real path on any
# system, and ntpath.normpath is pure Python and quadratic on long runs of
# empty or "." components in 3.10, so it is refused before normalising.
_MAX_PATH_CHARS = 32767


def is_remote_path(path: str, *, windows: bool | None = None) -> bool:
    """True when a cwd read from a transcript must not be touched.

    On Windows, merely stat'ing a UNC or NT namespace path can open an SMB
    (or WebDAV) connection to the named host, so a cwd from a transcript is
    only stat'ed, resolved or opened when this returns False. The check is
    pure string work and never calls the filesystem itself. windows picks
    the rule; by default it follows os.name.

    Windows uses an allowlist. A path is local, and safe to touch, only when:

    - ntpath.normpath() of it starts with a drive letter, a colon and a
      backslash (C:\\Users\\dev, C:/Users/dev);
    - PureWindowsPath() of it reads exactly that drive letter and colon;
    - it holds no ? anywhere, no control character, and no non-ASCII
      stand-in for a separator, dot, colon or ? (a fullwidth backslash, a
      two-dot leader).

    Everything else is treated as remote: a UNC share (\\\\host\\share,
    //host/share), a \\\\?\\, \\??\\ or \\\\.\\ path, a device path, a path
    rooted without a drive (\\Users\\dev), a drive-relative one (C:dev) and
    a relative one. The text is judged exactly as given. It is not NFKC
    folded first, because neither Python nor Windows folds it: a fullwidth
    backslash is part of a name to both, so ".." can fold over it.

    Other systems keep the earlier rule (see _is_remote_elsewhere). On any
    system, a path longer than Windows allows (_MAX_PATH_CHARS) is refused.
    """
    if len(path) > _MAX_PATH_CHARS:
        return True
    if windows is None:
        windows = os.name == "nt"
    if windows:
        return not _is_local_drive_path(path)
    return _is_remote_elsewhere(path)


def _is_local_drive_path(text: str) -> bool:
    if "?" in text or _CONTROL_CHARS.search(text) or _LOOKALIKE_CHARS.search(text):
        return False
    normal = ntpath.normpath(text)
    if not _DRIVE_ABSOLUTE.match(normal):
        return False
    return PureWindowsPath(text).drive == normal[:2]


def _is_remote_elsewhere(path: str) -> bool:
    """The rule off Windows: remote when it has a UNC or NT namespace shape.

    Every / becomes \\ and surrounding whitespace is trimmed. The path is
    then remote when it starts with two separators (a UNC share, or a Win32
    device or long path such as \\\\?\\UNC\\host\\share or \\\\.\\pipe\\x),
    or when its first component is NT namespace syntax (\\??\\UNC\\...,
    /??/UNC/..., \\GLOBAL??\\... or \\Device\\...). A ? can never appear in
    a Win32 file name, so any first component holding one is refused.
    """
    forms: list[str] = []
    # The text is judged as given and NFKC folded (a fullwidth backslash
    # then counts as one), each as written and in the two forms pathlib and
    # os.path.realpath rewrite it to: they drop "." and fold "..", so
    # "\.\??\UNC\h\s" and "\x\..\??\UNC\h\s" both become "\??\UNC\h\s".
    for text in (path, unicodedata.normalize("NFKC", path)):
        text = text.strip().replace("/", "\\")
        forms += (text, str(PureWindowsPath(text)), ntpath.normpath(text))
    return any(_is_remote_form(form) for form in forms)


def _is_remote_form(text: str) -> bool:
    if text.startswith("\\\\"):
        return True
    if text.startswith("\\"):
        first = text[1:].split("\\", 1)[0]
        return "?" in first or first.lower() in _NT_NAMESPACE_ROOTS
    return False


def discover_rules_files(session_cwd: str = "") -> list[Path]:
    """Find rules files for a session: project cwd first, then ~/.claude.

    Order matters: the project's CLAUDE.md is the most specific, the
    user's global ~/.claude/CLAUDE.md is the fallback. We also pick up
    AGENTS.md and .cursorrules in the project root.

    The cwd comes from the transcript, so it is untrusted: a path that
    is_remote_path refuses (on Windows, anything but a plain local drive
    path) is skipped rather than resolved or opened.
    """
    found: list[Path] = []
    seen: set[str] = set()

    def add(p: Path) -> None:
        # A malformed path (an embedded NUL, one too long for the OS) raises
        # ValueError on some Pythons; it is skipped like a missing file.
        try:
            key = str(p.resolve())
        except (OSError, ValueError):
            key = str(p)
        try:
            is_file = p.is_file()
        except (OSError, ValueError):
            is_file = False
        if is_file and key not in seen:
            seen.add(key)
            found.append(p)

    if session_cwd and not is_remote_path(session_cwd):
        cwd = Path(session_cwd)
        for name in _RULES_FILENAMES:
            add(cwd / name)
    home = Path(__import__("os").path.expanduser("~"))
    add(home / ".claude" / "CLAUDE.md")
    return found
