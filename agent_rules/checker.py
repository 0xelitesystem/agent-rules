"""Check each mined rule against the session: did the agent obey it?

For every Rule we produce exactly one RuleFinding:

  VIOLATED       the agent did the forbidden thing, or skipped the mandated
                 thing, with the offending event, command, and a quote.
  COMPLIANT      the rule was *relevant* this session (the agent did the
                 governed kind of work) and broke it nowhere.
  NOT_APPLICABLE the rule never came up: the agent never touched its topic.

Confidence is HIGH when a built-in matcher (matchers.py) decided the
verdict, and LOW when we fell back to generic keyword presence. The score
only treats HIGH-confidence violations as hard failures.

A prohibition is COMPLIANT vs NOT_APPLICABLE based on whether the agent did
*adjacent* work the rule could have governed (e.g. a "never push to main"
rule is only "complied with" if the agent ran git at all; otherwise it
simply never came up). Mandates like "run tests before committing" are
ordering checks over the whole stream.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import matchers as M
from .models import (
    Confidence, Event, EventKind, Rule, RuleFinding, RuleKind,
    RuleVerdict, Session,
)


# Secret-shaped values in an offending command. Reports get shared (CI logs,
# PR comments), so these are masked before a command is stored in a finding.
# The masking is pattern based: it catches common credential shapes, and a
# secret in an unusual shape can still get through. Each mask keeps the
# name, scheme or prefix, so the command stays recognisable. The rule:
#
# 1. NAME is split into lowercase words on non-alphanumerics and on camelCase
#    boundaries (accessToken -> access, token; APIKey -> api, key).
# 2. NAME is a credential name when its words include one of
#    _CREDENTIAL_WORDS, or "key" together with one of _KEY_QUALIFIERS, or are
#    exactly "pwd". $NAME and ${NAME} are shell references, not assignments.
# 3. A credential name's value in NAME=value, NAME: value, "name": "value",
#    --name value or --name=value is masked whatever its length, unless it
#    is none, null, true, false, 0 or another plain number (--max-token=4096).
# 4. A name whose only match is a bare "key" (key, --key, CACHE_KEY) is
#    masked only when its value starts with 16 of [A-Za-z0-9_-+/=].
# 5. Authorization header values (Bearer, Basic, Token, Digest) are always
#    masked. A well-known token prefix (sk-, ghp_, AKIA, ...) is masked when
#    at least 12 [A-Za-z0-9_-] characters follow it.
# 6. A masked value runs to the next whitespace or the closing quote,
#    whatever characters it holds (--password P@ss{w}0rd is masked whole).
#    A quote inside an unquoted word opens a quoted part of that same shell
#    word, so --password=ab"cd ef" is masked whole too; a quote is read as
#    closing an outer string only when whitespace, the end of the text or
#    closing punctuation follows it. Three delimiters a value cannot hold
#    raw also end it: @ after a URL userinfo name (://token:VALUE@host), &
#    or # after a URL query name (?token=VALUE&page=2) and ; after a
#    connection-string name (;PWD=VALUE;), unless that value is braced.
# 7. After any credential name, a Bearer, Basic, Token, Bot or Digest scheme
#    word, in any case, is kept and the word after it is masked
#    (X-Token: Bearer ***). A quoted word there is masked to its closing
#    quote (X-Token: Bearer '***').
#
# Also kept from earlier passes: URL userinfo passwords, masked up to the
# last @ before the host (https://u:***@host, even for u:p@ss@host), PRIVATE
# KEY blocks, and sk_test_, hf_ and npm_ tokens.
#
# Three readings keep ordinary text readable:
# - A value that is itself a shell reference ($VAR, ${VAR}, $(cmd)) is left
#   alone: it names where the secret comes from, not the secret. A $ inside
#   single quotes is literal to the shell, so '$uper' is masked.
# - A name ending in file, path or dir (--token-file tok.txt) points at where
#   a credential is kept, so its value is a location, not the credential.
# - After an unquoted "NAME: ", the value is prose only when two or more
#   plain words follow before the end of the text or a closing quote
#   ("auth: fix login redirect"). A single word is a value, so
#   "password: letmein" and "Authorization: letmein" are masked. The same
#   test applies to the word after a Bearer or Basic that is not in an
#   Authorization header ("Bearer tokens expire hourly" stays).
#
# Every check below looks at a bounded number of characters, and a value is
# only measured in full when it is masked (the scan then jumps past it), so
# the redactor stays linear in the length of the text.
_CREDENTIAL_WORDS = frozenset({
    "token", "secret", "password", "passwd", "passphrase", "credential",
    "credentials", "auth", "authorization", "apikey", "privatekey",
})
_KEY_QUALIFIERS = frozenset({
    "api", "access", "private", "secret", "encryption", "signing", "client",
    "master", "session",
})
_LOCATION_WORDS = frozenset({"file", "path", "dir"})
_CREDENTIAL, _BARE_KEY = "credential", "bare key"

# camelCase boundaries: accessToken, APIKey, oauth2Token.
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z0-9])(?=[A-Z][a-z])")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")

# Characters that end an unquoted value (rule 6), by context: whitespace or
# a quote everywhere, plus the delimiter of a URL userinfo, a URL query or a
# connection string.
_PLAIN, _USERINFO, _QUERY, _CONNECTION = "plain", "userinfo", "query", "connection"
_VALUE_STOPS = {
    _PLAIN: r"\s\"'",
    _USERINFO: r"\s\"'@",
    _QUERY: r"\s\"'&#",
    _CONNECTION: r"\s\"';",
}
_VALUE_TOKEN = {context: re.compile(r"[^" + stops + r"]*")
                for context, stops in _VALUE_STOPS.items()}
_VALUE_STOP = {context: re.compile(r"[" + stops + r"]")
               for context, stops in _VALUE_STOPS.items()}
# A quoted value runs to its closing quote, or to the end of the text when
# the quote is never closed. An escaped opening quote closes on an escaped one.
_QUOTED_VALUE = {
    '"': re.compile(r'(?:[^"\\]|\\.)*', re.DOTALL),
    "'": re.compile(r"[^']*"),
    '\\"': re.compile(r'(?:[^\\]|\\(?!"))*'),
    "\\'": re.compile(r"(?:[^\\]|\\(?!'))*"),
}
# An opening quote, maybe shell-escaped, right before a value (after a scheme
# word). A quote followed by whitespace closes an outer string instead.
_OPEN_QUOTE = re.compile(r"\\?[\"'](?=\S)")
# What follows a quote that closes an outer string, rather than one that
# opens a quoted part of an unquoted word: whitespace, the end of the text or
# closing punctuation (-H "X-Api-Key: abc" -d x, f('TOKEN=abc'), "..."; ls).
_CLOSES_OUTER = re.compile(r"[\s;,)\]}>|&]|\Z")
# Values a credential name (or a bare Bearer/Basic) can hold that are not
# secrets, when the value ends right after them. A bare "key" name has its
# own test, _KEY_VALUE.
_NOT_SECRET = re.compile(r"(?:none|null|true|false|[+-]?\d+(?:\.\d+)?)",
                         re.IGNORECASE)
# One plain word (lowercase, Capitalised or ALL CAPS), maybe ending a sentence.
_PROSE_WORD = r"(?:[a-z]{1,15}|[A-Z][a-z]{0,14}|[A-Z]{1,15})[.!?:]?"
# Prose: two plain words, the second ending at whitespace, a quote or the end.
_PROSE = re.compile(_PROSE_WORD + r"\s+" + _PROSE_WORD + r"(?=[\s\"']|\Z)")
_SECRET_CHARS = r"A-Za-z0-9_\-+/="
_KEY_VALUE = re.compile(r"[" + _SECRET_CHARS + r"]{16}")
# Rule 7: an auth scheme word right after a credential name.
_SCHEME_WORD = re.compile(r"(?:bearer|basic|token|bot|digest)\s+", re.IGNORECASE)

# Candidate NAME + separator, found as zero-width lookaheads, so a value that
# is not masked is still scanned for a nested pair (ARGS=--token=...). A name
# starts a run of name characters and is not a $NAME or ${NAME} reference.
_NAME_CHARS = r"A-Za-z0-9_.\-"
_NAME_START = r"(?<![" + _NAME_CHARS + r"$])(?<!\$\{)"
_NAMED_VALUES = [
    # NAME=value, NAME: value, "name": "value" (quotes may be escaped), but
    # not "::", a scope (pytest tests/test_auth.py::test_x), and not an "=="
    # with whitespace or another = beside it, a comparison or a banner
    # (a == b, == auth ==). A tight NAME==value is a value that starts with
    # = in the shell, or a secret compared in code, so it is masked.
    re.compile(_NAME_START + r"(?=(?P<name>[" + _NAME_CHARS + r"]+)"
               r"(?P<sep>(?P<nq>\\?[\"'])?\s*"
               r"(?P<op>=(?!=)|(?<![\s=])==(?![\s=])|:(?!:))(?P<ws>\s*)"
               r"(?P<quote>\\?[\"'])?))"),
    # --name value, where the next word is not another flag or a shell
    # operator (--with-token < token.txt passes no value on the line).
    re.compile(_NAME_START + r"(?=(?P<name>--[" + _NAME_CHARS + r"]+)"
               r"(?P<sep>\s+(?![\s\-<>|&;])(?P<quote>\\?[\"'])?))"),
]
# Auth schemes. Inside an Authorization header the value is always masked,
# whatever the scheme's case. After a bare Bearer or Basic it is masked only
# when it is not a plain word; a lowercase "basic" there is just English.
_AUTH_HEADER = re.compile(r"\bAuthorization\\?[\"']?\s*[:=]\s*\\?[\"']?"
                          r"(?:Bearer|Basic|Token|Digest)\s+", re.IGNORECASE)
_BARE_SCHEME = re.compile(r"\b(?:[Bb]earer|BEARER|Basic|BASIC)\s+")
_REDACTIONS_BEFORE = [
    # https://user:TOKEN@host, masked up to the last @ before the host ends
    # (a raw @ in the password would otherwise leave its tail showing).
    (re.compile(r"(://[^/\s:@]+:)[^\s/?#\"']*@"), r"\1***@"),
]
_REDACTIONS_AFTER = [
    # Well-known token prefixes, each followed by at least 12 such characters.
    (re.compile(r"\b(sk_live_|sk_test_|sk-|rk_|gh[pousr]_|github_pat_|glpat-|"
                r"xox[abprs]-|AIza|A[KS]IA)[A-Za-z0-9_\-]{12,}"),
     r"\1***"),
    (re.compile(r"\b(hf_)[A-Za-z0-9]{30,}"), r"\1***"),
    (re.compile(r"\b(npm_)[A-Za-z0-9]{30,}"), r"\1***"),
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[^-]*"), r"\1 *** "),
]


def _name_words(name: str) -> list[str]:
    """NAME as lowercase words: split on non-alphanumerics and camelCase."""
    spaced = _CAMEL_BOUNDARY.sub(" ", name)
    return [w.lower() for w in _NON_ALNUM.split(spaced) if w]


def _secret_name_kind(name: str) -> str | None:
    """_CREDENTIAL, _BARE_KEY, or None when NAME is not a secret's name."""
    words = _name_words(name)
    if not words or words[-1] in _LOCATION_WORDS:
        return None
    found = set(words)
    if found & _CREDENTIAL_WORDS or words == ["pwd"]:
        return _CREDENTIAL
    if "key" in found:
        return _CREDENTIAL if found & _KEY_QUALIFIERS else _BARE_KEY
    return None


def _value_end(text: str, start: int, quote: str, context: str = _PLAIN) -> int:
    if quote:
        return _QUOTED_VALUE[quote].match(text, start).end()
    token = _VALUE_TOKEN[context]
    end = token.match(text, start).end()
    # Rule 6: a quote inside the word opens a quoted part of it
    # (--password=ab"cd ef"), unless what follows shows it closes an outer
    # string. Each pass moves forward, so this stays linear.
    while (start < end < len(text) and text[end] in "\"'"
           and not _CLOSES_OUTER.match(text, end + 1)):
        closing = _QUOTED_VALUE[text[end]].match(text, end + 1).end()
        end = token.match(text, min(closing + 1, len(text))).end()
    return end


def _is_reference(text: str, start: int, quote: str) -> bool:
    """Is the value a shell reference ($VAR, ${VAR}, $(cmd))? Inside single
    quotes a $ is literal, so there it is part of the value."""
    return quote != "'" and text.startswith("$", start)


def _open_quote(text: str, start: int, quote: str) -> tuple[str, int]:
    """Rule 7: after a scheme word, an unquoted value may open its own quote."""
    if not quote:
        opening = _OPEN_QUOTE.match(text, start)
        if opening:
            return opening.group(), opening.end()
    return quote, start


def _value_ends_at(text: str, pos: int, quote: str, context: str) -> bool:
    """Does a value end at text[pos]? Looks at one character only."""
    if pos == len(text):
        return True
    if quote:
        return text.startswith(quote, pos)
    return _VALUE_STOP[context].match(text, pos) is not None


def _is_secret_value(kind: str, text: str, start: int, prose: bool,
                     quote: str = "", context: str = _PLAIN) -> bool:
    """Should the value at text[start:] be masked? Looks at a few chars only."""
    if _is_reference(text, start, quote):
        return False
    if kind == _BARE_KEY:
        return _KEY_VALUE.match(text, start) is not None
    plain = _NOT_SECRET.match(text, start)
    if plain and _value_ends_at(text, plain.end(), quote, context):
        return False
    return not (prose and _PROSE.match(text, start))


def _value_context(text: str, name_start: int, op: str | None, start: int) -> str:
    """Rule 6: is an unquoted value in a URL userinfo, a URL query or a
    connection string, where its own delimiter also ends it?"""
    if op == ":" and text.endswith("://", 0, name_start):
        return _USERINFO
    if op == "=" and name_start:
        before = text[name_start - 1]
        if before in "?&":
            return _QUERY
        if before == ";" and not text.startswith("{", start):
            return _CONNECTION
    return _PLAIN


def _mask(text: str, spans) -> str:
    """Replace each (start, end) value span, in order, with ***."""
    out: list[str] = []
    pos = 0
    for start, end in spans:
        out.append(text[pos:start])
        out.append("***")
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _named_value_spans(pattern: re.Pattern, text: str):
    pos = 0
    for m in pattern.finditer(text):
        if m.start() < pos:
            continue
        kind = _secret_name_kind(m.group("name"))
        if kind is None:
            continue
        groups = m.groupdict()
        quote = groups["quote"] or ""
        op = groups.get("op")
        start = m.end("sep")
        scheme = _SCHEME_WORD.match(text, start)
        if scheme:
            # Rule 7: keep the scheme word, mask the word after it.
            context = _PLAIN
            quote, start = _open_quote(text, scheme.end(), quote)
            if _is_reference(text, start, quote):
                continue
        else:
            context = (_PLAIN if quote
                       else _value_context(text, m.start("name"), op, start))
            # An unquoted "NAME: word word" reads as prose (auth: fix login
            # redirect); a single word does not (password: letmein).
            prose = (op == ":" and bool(groups.get("ws"))
                     and not groups.get("nq") and not quote)
            if not _is_secret_value(kind, text, start, prose, quote, context):
                continue
        end = _value_end(text, start, quote, context)
        if end > start:
            yield start, end
            pos = end


def _scheme_value_spans(pattern: re.Pattern, text: str, always: bool):
    pos = 0
    for m in pattern.finditer(text):
        if m.end() < pos:
            continue
        quote, start = _open_quote(text, m.end(), "")
        if _is_reference(text, start, quote):
            continue
        if not always and not _is_secret_value(_CREDENTIAL, text, start, True, quote):
            continue
        end = _value_end(text, start, quote)
        if end > start:
            yield start, end
            pos = end


def _redact_secrets(text: str) -> str:
    """Mask common credential shapes before a command goes into a finding.

    Pattern based, so a secret in an unusual shape can still get through.
    """
    for pattern, replacement in _REDACTIONS_BEFORE:
        text = pattern.sub(replacement, text)
    text = _mask(text, _scheme_value_spans(_AUTH_HEADER, text, always=True))
    text = _mask(text, _scheme_value_spans(_BARE_SCHEME, text, always=False))
    for pattern in _NAMED_VALUES:
        text = _mask(text, _named_value_spans(pattern, text))
    for pattern, replacement in _REDACTIONS_AFTER:
        text = pattern.sub(replacement, text)
    return text


def _short(text: str, limit: int = 90) -> str:
    text = " ".join(text.split())
    # Redact a window a little past the cut, so a secret that straddles the
    # cut is still recognised and masked whole, not half shown.
    window = limit + 256
    cut = len(text) > window
    text = _redact_secrets(text[:window])
    if cut or len(text) > limit:
        return text[: limit - 1] + "…"
    return text


# Topic-activity probes: was the agent doing the kind of work this matcher
# governs at all? Used to tell COMPLIANT (relevant, obeyed) from
# NOT_APPLICABLE (topic never came up) for prohibition matchers.
_ACTIVITY = {
    "no-chrome-brave": re.compile(r"\bchrome|brave|browser|selenium|puppeteer|"
                                  r"playwright|webdriver|\bopen\b|\bstart\b",
                                  re.IGNORECASE),
    "pinned-python": re.compile(r"python", re.IGNORECASE),
    "no-no-verify": re.compile(r"\bgit\s+commit\b", re.IGNORECASE),
    "no-force-push": re.compile(r"\bgit\s+push\b", re.IGNORECASE),
    "no-push-main": re.compile(r"\bgit\s+push\b", re.IGNORECASE),
    "no-install-deps": re.compile(r"\bpip\b|\bnpm\b|\byarn\b|\bpnpm\b|\bbun\b|"
                                  r"\bapt\b|\bbrew\b|\bcargo\b|\bgo\b|\bgem\b",
                                  re.IGNORECASE),
    "no-sudo": re.compile(r"\bsudo\b|\binstall\b|\bsystemctl\b|\bservice\b|"
                          r"\bchmod\b|\bchown\b", re.IGNORECASE),
    "no-rm-rf": re.compile(r"\brm\b|Remove-Item|\bdel\b|\brmdir\b", re.IGNORECASE),
    "no-read-secrets": re.compile(r"\bcat\b|\btype\b|Get-Content|\.env|secret|"
                                  r"credentials|\.pem|id_rsa", re.IGNORECASE),
}


def _topic_active(session: Session, matcher_name: str) -> bool:
    # The parameterised write-allowed-dir matcher is "active" whenever the
    # agent wrote or created any file at all. That's the governed action.
    if matcher_name == "write-allowed-dir":
        return any(
            e.kind is EventKind.TOOL_CALL and (e.is_file_write() or e.tool_name == "Edit")
            for e in session.events
        )
    probe = _ACTIVITY.get(matcher_name)
    if probe is None:
        return True  # default: assume the topic could have come up
    for e in session.events:
        if e.kind is EventKind.TOOL_CALL:
            hay = e.command or e.file_path or e.tool_name
            if hay and probe.search(hay):
                return True
    return False


def _check_with_matcher(session: Session, rule: Rule,
                        matcher: "M.Matcher") -> RuleFinding:
    rule.matcher = matcher.name
    if matcher.event_violates is None:
        # Shouldn't happen for the event-style matchers we bind here.
        return RuleFinding(rule=rule, verdict=RuleVerdict.NOT_APPLICABLE,
                           confidence=Confidence.HIGH,
                           evidence="matcher has no event predicate")
    for e in session.events:
        if e.kind is not EventKind.TOOL_CALL:
            continue
        if matcher.event_violates(e):
            offending = e.command or e.file_path or e.tool_name
            return RuleFinding(
                rule=rule,
                verdict=RuleVerdict.VIOLATED,
                confidence=Confidence.HIGH,
                evidence=f"{matcher.describe}: `{_short(offending)}`",
                offending_command=_short(offending, 200),
                event_index=e.index,
            )
    if _topic_active(session, matcher.name):
        return RuleFinding(
            rule=rule, verdict=RuleVerdict.COMPLIANT, confidence=Confidence.HIGH,
            evidence=f"agent did related work but never {matcher.describe}",
        )
    return RuleFinding(
        rule=rule, verdict=RuleVerdict.NOT_APPLICABLE, confidence=Confidence.HIGH,
        evidence="the agent never did work this rule governs",
    )


def _check_test_before_commit(session: Session, rule: Rule) -> RuleFinding:
    rule.matcher = "tests-before-commit"
    commits = [e for e in session.events
               if e.kind is EventKind.TOOL_CALL and e.command
               and re.search(r"\bgit\s+commit\b", e.command)]
    if not commits:
        return RuleFinding(
            rule=rule, verdict=RuleVerdict.NOT_APPLICABLE, confidence=Confidence.HIGH,
            evidence="the agent made no commits, so the rule never came up",
        )
    violations = M.find_commit_without_tests(session)
    if violations:
        first = violations[0]
        return RuleFinding(
            rule=rule, verdict=RuleVerdict.VIOLATED, confidence=Confidence.HIGH,
            evidence=f"committed without running tests first: {first.detail} "
                     f"(`{_short(first.command)}`)",
            offending_command=_short(first.command, 200),
            event_index=first.event_index,
        )
    return RuleFinding(
        rule=rule, verdict=RuleVerdict.COMPLIANT, confidence=Confidence.HIGH,
        evidence="every commit had a test run before it",
    )


# Generic fallback: the rule's subject token appears in a command the agent
# ran. This is deliberately weak (LOW confidence) and only fires for
# prohibitions (a mandate can't be checked by mere keyword presence).
def _generic_subject_pattern(rule: Rule) -> re.Pattern | None:
    subject = rule.subject.strip()
    if not subject:
        return None
    # Distinctive tokens (flags, paths, words >=3 chars). We match if ANY of
    # them appears in a command, so "frobnicate production" should still flag
    # `frobnicate --prod`. Order longest-first so the report quote is sane.
    tokens = re.findall(r"--[\w-]+|[A-Za-z0-9_.\\/:-]{3,}", subject)
    tokens = sorted({t for t in tokens if not t.isdigit() and len(t) >= 3},
                    key=len, reverse=True)
    if not tokens:
        return None
    return re.compile("|".join(re.escape(t) for t in tokens), re.IGNORECASE)


def _check_generic(session: Session, rule: Rule) -> RuleFinding:
    pattern = _generic_subject_pattern(rule)
    if pattern is None:
        return RuleFinding(
            rule=rule, verdict=RuleVerdict.NOT_APPLICABLE, confidence=Confidence.LOW,
            evidence="no matchable subject extracted from the rule",
        )
    if rule.kind is RuleKind.PROHIBITION:
        for e in session.events:
            if e.kind is not EventKind.TOOL_CALL:
                continue
            hay = e.command or e.file_path
            if hay and pattern.search(hay):
                return RuleFinding(
                    rule=rule, verdict=RuleVerdict.VIOLATED, confidence=Confidence.LOW,
                    evidence=f"forbidden subject '{rule.subject}' appears in a "
                             f"command the agent ran (generic match, low confidence): "
                             f"`{_short(hay)}`",
                    offending_command=_short(hay, 200),
                    event_index=e.index,
                )
        return RuleFinding(
            rule=rule, verdict=RuleVerdict.NOT_APPLICABLE, confidence=Confidence.LOW,
            evidence=f"forbidden subject '{rule.subject}' never appears in any "
                     f"command (generic match, low confidence)",
        )
    # Mandates with no precise matcher cannot be checked generically.
    return RuleFinding(
        rule=rule, verdict=RuleVerdict.NOT_APPLICABLE, confidence=Confidence.LOW,
        evidence=f"mandate about '{rule.subject}' has no precise matcher; "
                 f"can't be verified by keyword presence (low confidence)",
    )


def check_rule(session: Session, rule: Rule) -> RuleFinding:
    if M.is_test_before_commit_rule(rule):
        return _check_test_before_commit(session, rule)
    matcher = M.match_rule(rule)
    if matcher is not None and matcher.event_violates is not None:
        return _check_with_matcher(session, rule, matcher)
    return _check_generic(session, rule)


def check_rules(session: Session, rules: list[Rule]) -> list[RuleFinding]:
    return [check_rule(session, rule) for rule in rules]
