"""Fixture transcripts and rules files in Claude Code's JSONL shape.

Shared with agent-receipts' transcript shape, so the helpers look familiar.
A "compliant" session does everything the demo rules require; a "violating"
session breaks several of them.
"""

from __future__ import annotations

import json

import pytest

CWD = "C:\\fake\\project"


def assistant_text(text: str) -> dict:
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T12:00:00.000Z",
        "sessionId": "fixture-session",
        "cwd": CWD,
        "gitBranch": "main",
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    }


def assistant_tool(tool_id: str, name: str, tool_input: dict) -> dict:
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T12:00:00.000Z",
        "sessionId": "fixture-session",
        "cwd": CWD,
        "gitBranch": "main",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input},
        ]},
    }


def tool_result(tool_id: str, content: str, is_error: bool = False) -> dict:
    return {
        "type": "user",
        "timestamp": "2026-06-10T12:00:01.000Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tool_id,
             "content": content, "is_error": is_error},
        ]},
        "toolUseResult": (f"Error: Exit code 1\n{content}" if is_error
                          else {"stdout": content, "stderr": "", "interrupted": False}),
    }


def write_jsonl(path, records: list[dict]) -> str:
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return str(path)


# A realistic rules file used by most tests.
RULES_TEXT = """\
# Project rules

## Environment
- Always use `C:\\Python314\\python.exe`; never run bare `python`.
- Never automate Chrome or Brave.

## Git
- Never commit with `--no-verify`.
- Never push to main, and don't force-push.
- Always run tests before committing.

## Files & deps
- Output files go in `Output/`, never the repo root.
- Don't install dependencies without asking.
- Never read `.env` or secrets.
"""


@pytest.fixture
def rules_file(tmp_path):
    path = tmp_path / "CLAUDE.md"
    path.write_text(RULES_TEXT, encoding="utf-8")
    return str(path)


@pytest.fixture
def compliant_transcript(tmp_path):
    """Uses the pinned python, runs tests before committing, writes to Output/,
    no --no-verify, no chrome, no main push."""
    records = [
        assistant_text("Implementing the feature per the rules."),
        assistant_tool("t1", "Bash", {
            "command": "C:\\Python314\\python.exe -m pytest -q"}),
        tool_result("t1", "12 passed in 0.4s"),
        assistant_tool("t2", "Write", {
            "file_path": "C:\\fake\\project\\Output\\result.txt",
            "content": "done"}),
        tool_result("t2", "ok"),
        assistant_tool("t3", "Bash", {"command": "git commit -am 'feature'"}),
        tool_result("t3", "[feature 123abc] feature"),
        assistant_text("Feature complete, tests pass."),
    ]
    return write_jsonl(tmp_path / "compliant.jsonl", records)


@pytest.fixture
def violating_transcript(tmp_path):
    """Bare python, git commit --no-verify, launches chrome, writes repo root."""
    records = [
        assistant_text("Shipping fast."),
        assistant_tool("t1", "Bash", {"command": "python build.py"}),
        tool_result("t1", "built"),
        assistant_tool("t2", "Bash", {"command": "start chrome http://localhost"}),
        tool_result("t2", ""),
        assistant_tool("t3", "Write", {
            "file_path": "C:\\fake\\project\\junk.txt", "content": "x"}),
        tool_result("t3", "ok"),
        assistant_tool("t4", "Bash", {
            "command": "git commit -am 'wip' --no-verify"}),
        tool_result("t4", "[main 999aaa] wip"),
        assistant_text("Done."),
    ]
    return write_jsonl(tmp_path / "violating.jsonl", records)


@pytest.fixture
def commit_without_tests_transcript(tmp_path):
    """Edits code and commits, but never runs tests, violating the mandate."""
    records = [
        assistant_tool("t1", "Edit", {
            "file_path": "C:\\fake\\project\\src\\app.py",
            "old_string": "a", "new_string": "b"}),
        tool_result("t1", "ok"),
        assistant_tool("t2", "Bash", {
            "command": "C:\\Python314\\python.exe build.py"}),
        tool_result("t2", "built"),
        assistant_tool("t3", "Bash", {"command": "git commit -am 'change'"}),
        tool_result("t3", "[feature abc] change"),
        assistant_text("Committed."),
    ]
    return write_jsonl(tmp_path / "commit_no_tests.jsonl", records)


@pytest.fixture
def no_rules_apply_transcript(tmp_path):
    """The agent only reads files and writes prose, touching no governed topic."""
    records = [
        assistant_text("Let me look around."),
        assistant_tool("t1", "Read", {
            "file_path": "C:\\fake\\project\\README.md"}),
        tool_result("t1", "# readme"),
        assistant_text("Understood the layout."),
    ]
    return write_jsonl(tmp_path / "no_apply.jsonl", records)
