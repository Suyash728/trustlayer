# TrustLayer — Agent Operating Guide

This file is the single source of truth for stack, commands, scope, and working style.
It supersedes `AGENTS.md`, which is deprecated and kept only as a pointer.

## What this is

A tool that proves whether AI-written tests actually catch bugs. It audits a repository
mechanically, then uses an agent to raise its mutation score — discarding any generated
test that does not hold up.

The thesis: line coverage is a vanity metric; mutation score is the oracle. The demo repo
`demo-repos/pricing-py` sits at **100% line coverage and a 61.7% mutation score**, which is
the whole argument in one number.

## The rule everything else serves

**No LLM produces any verdict.** Checks are mechanical or they don't ship. Every finding
carries evidence a human can re-derive by hand — a resolved version, a real exported name,
a registry 404, a source line.

The agent *writes tests*. Whether a test survives is decided by running it, never by asking
a model. A generated test that fails against unmodified source is evidence the agent
misunderstood the code, so it is **discarded, never repaired** — repairing it would launder
the misunderstanding into the suite and everything downstream would inherit it.

## Working style

- Plan before building anything over ~30 lines. Show the plan, wait.
- Never write against a remembered API. Check the installed version's actual surface first
  and tell me what you found.
- Every subprocess call gets an explicit timeout.
- No LLM call in any verdict path.
- A check with a false positive is worse than no check.
- After implementing, self-review your own diff before reporting done: unhandled errors,
  missing timeouts, and any API you assumed exists without checking.
- If blocked after one retry, stop and report the blocker with two options. Do not guess.

## Stack (as built)

- **CLI**: Typer + Rich, Python 3.12, installed from the root `pyproject.toml`.
- **Agent runtime**: `claude-agent-sdk` 0.2.128, model `claude-opus-5`.
  This replaced the Codex CLI that `AGENTS.md` pinned — see "Decisions that changed".
- **Mutation testing**: mutmut 3.6.0 + pytest.
- **TypeScript checks**: ts-morph 27.0.2 via Node 24 (`trustlayer/checks/node/`).
- **Persistence**: SQLite at `~/.trustlayer/runs.db`, stdlib `sqlite3`, no ORM.
- **Local UI**: FastAPI + Jinja2 on `localhost:7777`, Tailwind and HTMX from CDN.
  One process, no build step, no `node_modules`. Read-only: it cannot trigger a run.
- **Not built**: Next.js frontend, SSE streaming, Railway/Vercel deploy, any remote
  surface. `apps/web/` is an empty directory. `apps/api/` holds only the mutmut re-export
  and its test.

## Commands (verified)

```sh
uv sync                                        # install; there is no requirements.txt
npm install --prefix trustlayer/checks/node    # optional: enables the TypeScript checks
uv run ruff check .                            # lint — must be clean
uv run pytest -q                               # 126 tests, single config at the repo root
uv run trustlayer audit <path> --all
uv run trustlayer baseline <repo> --module src/x.py
uv run trustlayer harden <repo> --target 90
uv run trustlayer history <repo> -n 10
uv run trustlayer diff <repo>
uv run trustlayer ui                           # localhost:7777, opens a browser
```

> `ruff format` has **never** been run on this repo — it would reformat 18 of 31 files.
> `ruff check .` is the enforced gate. Do not run `ruff format` as part of a task; if you
> want it, make it its own commit.

## Architecture rules

- **All mutmut parsing lives in `trustlayer/mutation.py`.** It returns
  `MutationRun(score, killed, survived, total, survivors)`.
  `apps/api/app/services/mutation.py` re-exports it, so the API app depends on the
  `trustlayer` package and never the reverse. Nothing else parses tool output.
  Tests must patch `trustlayer.mutation.subprocess.run` — the re-export means patching the
  `app.services.mutation` namespace intercepts nothing.
- **All agent invocations go through `trustlayer/agent/runtime.py`.** Never call
  `claude_agent_sdk.query()` from anywhere else.
- **Agent tool restriction is enforced by a `PreToolUse` hook, not `allowed_tools`.**
  The SDK forwards `allowed_tools` to the `claude` CLI and enforces nothing itself, and
  `can_use_tool` is silently skipped whenever an allowlist entry allows a whole tool
  (`CanUseToolShadowedWarning`). The hook is consulted for every call. If you touch the
  gate, the denial matrix in `tests/test_agent.py` is the contract.
- **All SQLite access lives in `trustlayer/store.py`.** `check` is a SQL reserved word,
  so the column is quoted as `"check"` in every statement — unquoting it anywhere is a
  syntax error at table creation, which `tests/test_store.py` pins.
- **`audit` records a run by default** (`--no-save` opts out). A failure to record is a
  warning on stderr, never a change to the exit code a hook branches on.
- **A run stores git context honestly.** `git_sha` plus `git_root`, `git_dirty`, and
  `path_is_repo_root` in `summary_json`, because auditing a subdirectory records the
  *parent* repo's SHA and a dirty tree is not comparable to a commit.
- **`diff` matches findings on `(check, file, claim, verdict)` — never the line number.**
  A finding that moved because someone added an import is the same finding.
- **The UI is read-only.** It renders the database and cannot trigger a run or write to a
  repository. Severity is a reserved *status* palette; counts are ink and a small coloured
  mark carries identity, so a colour never means anything on its own.
- **The agent never writes to a real repository.** It works in a temp copy
  (`trustlayer/agent/workspace.py`); runs end by printing a diff and applying nothing.
- Every subprocess call has an explicit timeout. No exceptions.
- Severity owns the exit code: `0` clean, `1` medium, `2` high, `3` operational error.
  Operational failures must never exit `2`, or a pre-commit hook cannot tell a bad path
  from a real finding.
- Use the simplest approach that works. No abstraction layers or premature interfaces.

## Definition of done

1. `ruff check .` is clean.
2. `pytest -q` passes.
3. The feature runs end-to-end against `demo-repos/pricing-py` with no login.
4. You ran the verification command yourself and pasted the real output.

## Scope

Built and shipped:

| Layer | What |
|---|---|
| L1 | `trustlayer audit` — language/runner/pinned-version detection → `RepoProfile` |
| L2 | Four mechanical checks: api-resolution, stale-models, fail-open, composed |
| L3 | Report layer — grouped findings, severity exit codes, `--json`, suite state |
| L4 | Agent layer — `run_agent`, `baseline` generation, `harden` mutation loop |
| L5 | Persistence (`~/.trustlayer/runs.db`), `history`, `diff`, and a local read-only `ui` |

`AGENTS.md` froze scope to a web app (public URL, SSE stream, single run view). **That list
was superseded by direct instruction** across L1–L5; none of it was built and the CLI was
built instead. It is recorded here as history, not as a plan.

Still do **not** build without asking: auth, user accounts, a PR bot, GitHub App
integration, arbitrary repo-URL input, or multi-agent orchestration.

## Do-not-touch

- Never commit `.env`, API keys, or `auth.json`.
- Never edit files under `demo-repos/` unless a task explicitly says to.
- Never push to main directly; work on a branch.
- Never auto-apply agent-generated tests to a real repo. Print the diff; let a human decide.

## Decisions that changed since the original guide

- **Agent runtime is `claude-agent-sdk`, not the Codex CLI.** `AGENTS.md` pinned
  `codex exec --json` and `app/services/codex_runner.py`; L4a was built on the Claude Agent
  SDK by instruction. No `codex_runner.py` exists. The `gpt-5.3-codex` placeholder was never
  resolved and is now moot.
- **`mutation.py` moved** to `trustlayer/mutation.py` and finally returns the
  `{score, killed, survived, survivors}` shape the old guide always specified but the code
  never implemented.
- **Install/run commands changed**: `requirements.txt`, `app.main:app`, and `pnpm` commands
  in the old guide referred to files that never existed.

## mutmut 3.6.0 output format (VERIFIED — do not rediscover)

- `mutmut results --all true` → one line per mutant:
  `<module>.x_<funcname>__mutmut_<N>: <status>`, status `killed|survived|timeout|…`.
  The text before `: ` is the exact ID for `mutmut show`.
- `mutmut show <id>` → `# <id>: <status>` header, then a unified diff with `--- <path>` /
  `+++ <path>` (no `a/` `b/` prefix) and a standard `@@ -a,b +c,d @@` hunk.
- **`mutmut show` diffs the FUNCTION in isolation.** Its `@@` offsets are relative to the
  function body, **not** the file. Never derive file line numbers from the hunk — locate the
  removed line's text in the real source instead.
  (The original guide contained both this rule and an earlier, contradictory one saying to
  walk the hunk. Walking the hunk is wrong; only this rule survives.)
- `mutmut result-ids` does **not** exist in 3.6.0. Never call it.
- mutmut and pytest live in the target repo's `.venv`. A workspace copy excludes `.venv`, so
  resolve those executables from the **original** repo. Use `Path.absolute()`, never
  `.resolve()` — resolving a `.venv/bin/python` symlink drops the venv's site-packages and
  the tool disappears.
