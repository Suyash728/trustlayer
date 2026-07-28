# TrustLayer — Agent Operating Guide

## What this is
A web app that proves whether AI-written tests actually catch bugs. It runs mutation
testing on a repo, feeds surviving mutants to a Codex agent, and has the agent write
targeted tests that kill them — showing the mutation score climb live.
The thesis: line coverage is a vanity metric; mutation score is the oracle.

## Stack (PINNED — never substitute)
- Backend: FastAPI, Python 3.12, uvicorn. Deployed on Railway via Dockerfile.
- Frontend: Next.js 14 App Router, Tailwind. Deployed on Vercel.
- Streaming: SSE via FastAPI StreamingResponse (media_type="text/event-stream").
- Agent runtime: Codex CLI, invoked as `codex exec --json` via subprocess.
- Mutation testing: mutmut 3.x + pytest.
- Codex model for server-side runs: gpt-5.3-codex   <-- REPLACE with verified ID

## Commands (exact)
- Install API:  `cd apps/api && pip install -r requirements.txt`
- Run API:      `cd apps/api && uvicorn app.main:app --reload --port 8000`
- Lint:         `ruff check . --fix && ruff format .`
- Test API:     `cd apps/api && pytest -q`
- Run web:      `cd apps/web && pnpm dev`
- Build web:    `cd apps/web && pnpm build`

## Architecture rules
- All Codex invocations go through `app/services/codex_runner.py`. Never shell out
  to `codex` from a route handler.
- All mutation-tool invocations go through `app/services/mutation.py`. It returns the
  normalized shape `{score: float, killed: int, survived: int,
  survivors: [{id, file, line, diff}]}`. Nothing else parses tool output.
- Every subprocess call has an explicit timeout. No exceptions.
- API responses use `{ success, data, error }`.
- Use the simplest approach that works. Do not add abstraction layers, plugin
  systems, or premature interfaces. This ships in 7 days.

## Definition of done (all must hold before you say a task is complete)
1. `ruff check .` is clean.
2. `pytest -q` passes.
3. The feature runs end-to-end against `demo-repos/pricing-py` with no login.
4. You ran the verification command yourself and pasted the real output.

## Scope guardrails (FROZEN)
MUST: public no-login URL; baseline coverage-vs-mutation panel; Codex agent loop that
raises the mutation score; live SSE stream of that loop; repo with visible agentic history.
Do NOT build: auth, user accounts, a PR bot, GitHub App integration, arbitrary repo
URL input, multi-agent orchestration, or any dashboard beyond the single run view.
If you think something outside this list is needed, stop and ask.

## Do-not-touch
- Never commit `.env`, API keys, or `auth.json`.
- Never edit files under `demo-repos/` unless a task explicitly says to.
- Never push to main directly; work on a branch.

## Working style
- Plan before you build. For any task over ~30 lines, write the plan first, wait for
  approval, then execute.
- After implementing, self-review your own diff before reporting done: look for
  unhandled errors, missing timeouts, and any API you assumed exists without checking.
- If blocked after one retry, stop and report the blocker with two options. Do not guess.