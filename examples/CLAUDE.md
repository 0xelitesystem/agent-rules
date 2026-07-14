# Project rules

These rules are binding for any agent working in this repo.

## Environment
- Always use `C:\Python314\python.exe` for Python; never run bare `python`.
- Never automate Chrome or Brave, it closes the user's real browser window.

## Git
- Never commit with `--no-verify`; the pre-commit hooks must run.
- Never push directly to main, and don't force-push.
- Always run tests before committing.

## Files & deps
- Output files go in `Output/`, never the repo root.
- Don't install dependencies without asking first.
- Never read `.env` or any secrets file.

## Style
- Write clear commit messages.
