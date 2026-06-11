"""agent-rules — did your coding agent actually follow its own rules?

Linters check that your CLAUDE.md is well-formed. This checks that your
agent *obeyed* it. It mines imperative rules from CLAUDE.md / AGENTS.md /
.cursorrules, then scans a session transcript for violations — the agent
doing the forbidden thing, or skipping the mandated thing.

Usage:
  agent-rules check <transcript.jsonl | session-id-prefix | latest> [options]
  agent-rules list [--project NAME] [--limit N]

Options:
  --rules FILE          rules file to check against (repeatable; default:
                        auto-discover CLAUDE.md/AGENTS.md/.cursorrules)
  --project NAME        only consider transcripts whose project folder matches
  --json                machine-readable JSON instead of the terminal report
  --md FILE             also write a Markdown report to FILE
  --fail-on-violation   exit 1 if any HIGH-confidence violation is found
  --no-color            disable ANSI colors
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .checker import check_rules
from .models import ComplianceResult
from .parser import discover_transcripts, parse_transcript, resolve_target
from .report import render_json, render_markdown, render_terminal
from .rules import discover_rules_files, parse_rules_file
from .score import score_compliance


def check_transcript(target: str, rules_files: list[str] | None = None,
                     project: str | None = None) -> ComplianceResult:
    """Library entry point: check a transcript against rules, return result.

    If rules_files is None/empty, auto-discover from the session cwd and
    ~/.claude/CLAUDE.md.
    """
    path = resolve_target(target, project)
    session = parse_transcript(path)

    files: list[Path] = []
    if rules_files:
        files = [Path(f) for f in rules_files]
    else:
        files = discover_rules_files(session.cwd)

    rules = []
    for f in files:
        if Path(f).is_file():
            rules.extend(parse_rules_file(f))

    result = ComplianceResult(session=session, rules=rules)
    result.findings = check_rules(session, rules)
    return score_compliance(result)


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        result = check_transcript(args.target, args.rules, args.project)
    except FileNotFoundError as exc:
        print(f"agent-rules: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(result))
    else:
        color = False if args.no_color else None
        print(render_terminal(result, color=color))

    if args.md:
        Path(args.md).write_text(render_markdown(result), encoding="utf-8")
        if not args.json:
            print(f"  markdown report written to {args.md}\n")

    if args.fail_on_violation and result.high_violations():
        return 1
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    transcripts = discover_transcripts(args.project)[: args.limit]
    if not transcripts:
        print("no transcripts found under ~/.claude/projects", file=sys.stderr)
        return 2
    for path in transcripts:
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
        size_kb = path.stat().st_size // 1024
        print(f"{path.stem[:8]}  {mtime:%Y-%m-%d %H:%M}  {size_kb:>6} KB  "
              f"{path.parent.name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-rules",
        description="Check whether your coding agent actually followed its "
                    "CLAUDE.md / AGENTS.md / .cursorrules.",
    )
    parser.add_argument("--version", action="version",
                        version=f"agent-rules {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="check one session against the rules")
    check.add_argument("target", help="transcript path, session-id prefix, or 'latest'")
    check.add_argument("--rules", action="append", metavar="FILE",
                       help="rules file (repeatable); default: auto-discover")
    check.add_argument("--project", help="filter session discovery by project name")
    check.add_argument("--json", action="store_true", help="JSON output")
    check.add_argument("--md", metavar="FILE", help="write Markdown report to FILE")
    check.add_argument("--fail-on-violation", action="store_true",
                       help="exit 1 if any HIGH-confidence violation is found")
    check.add_argument("--no-color", action="store_true", help="plain output")
    check.set_defaults(func=_cmd_check)

    lst = sub.add_parser("list", help="list recent session transcripts")
    lst.add_argument("--project", help="filter by project folder name")
    lst.add_argument("--limit", type=int, default=15)
    lst.set_defaults(func=_cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles often default to cp1252, which can't encode the
    # ✓ / ✗ / · / “ ” glyphs this report prints — writing them raises
    # UnicodeEncodeError and crashes the run. Reconfigure both streams to
    # UTF-8 with errors="replace" so output degrades gracefully instead.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
