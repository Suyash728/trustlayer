# DEPRECATED — see CLAUDE.md

This file is no longer the source of truth. Its content moved to **`CLAUDE.md`**, corrected
against what actually shipped.

Do not read this file for stack, commands, scope, or architecture rules. Several of its
instructions were wrong or referred to files that never existed:

- It pinned the Codex CLI (`codex exec --json`) and `app/services/codex_runner.py` as the
  agent runtime. The agent layer is built on `claude-agent-sdk`; no `codex_runner.py` exists.
- Its install and run commands (`pip install -r requirements.txt`, `uvicorn app.main:app`,
  `pnpm dev`) referenced files that were never created.
- Its mutmut section contained two contradictory rules for deriving line numbers. Only the
  "locate the removed line's text in the real source" rule is correct; walking the `@@` hunk
  is wrong because `mutmut show` diffs the function in isolation.
- Its frozen scope list (public URL, SSE stream, single run view) was superseded by direct
  instruction; a CLI was built instead.

The full history is in git. `CLAUDE.md` records which decisions changed and why.
