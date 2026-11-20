# killscore — Agent Operating Guide

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
- **Agent runtime**: `claude-agent-sdk` 0.2.128, model `claude-opus-5` by default, with an
  opt-in Ollama backend (default `gpt-oss:20b`, any `tools`-capable model via
  `KILLSCORE_OLLAMA_MODEL`) for local runs. This replaced the Codex CLI
  that `AGENTS.md` pinned — see "Decisions that changed".
- **MCP server**: `mcp` 1.29/1.30 (FastMCP), stdio only (`killscore mcp`). Pinned `<2`: mcp 2.x
  renamed FastMCP to MCPServer, and an unpinned wheel install crashed on it (found 2026-11-20).
- **Mutation testing**: mutmut 3.6.0 + pytest.
- **TypeScript checks**: ts-morph 27.0.2 via Node 24 (`killscore/checks/node/`).
- **Persistence**: SQLite at `~/.killscore/runs.db`, stdlib `sqlite3`, no ORM.
- **Local web UI**: FastAPI + Jinja2 on `localhost:7777`, Tailwind and HTMX from CDN.
  One process, no build step, no `node_modules`. Read-only: it cannot trigger a run.
- **Terminal UI**: Textual 8.2.8 (`killscore tui`). No browser, no CDN, works offline.
  Unlike the web UI it *may* trigger runs — see the scoping note in Architecture rules.
- **Not built**: Next.js frontend, SSE streaming, Railway/Vercel deploy, any remote
  surface. `apps/web/` is an empty directory. `apps/api/` holds only the mutmut re-export
  and its test.

## Commands (verified)

```sh
uv sync                                        # install; there is no requirements.txt
npm install --prefix killscore/checks/node    # optional: TS checks (or `killscore setup-node`)
uv run ruff check .                            # lint — must be clean
uv run pytest -q                               # ~625 tests, offline, single root config
uv run killscore audit <path> --all
uv run killscore audit <path> --format sarif --fail-on high --baseline known.json
uv run killscore mcp                          # stdio MCP server for coding agents
uv run python scripts/update_top_pypi.py       # corpus refresh (also weekly in CI)
uv run python scripts/update_top_npm.py        # ~10 min: npm rate-limits scoped lookups
uv run python scripts/check_model_sources.py   # tripwire for the deprecation registry
uv build                                       # wheel; data/ is force-included
uv run killscore deps <repo>                  # dependency risk scores; --no-network works offline
uv run killscore baseline <repo> --module src/x.py
uv run killscore harden <repo> --target 90 --max-total-cost 5
uv run killscore deps <repo> --explain --backend ollama   # local model writes the prose
uv run killscore history <repo> -n 10
uv run killscore diff <repo>
uv run killscore ui                           # localhost:7777, opens a browser
uv run killscore tui                          # terminal UI; a=audit, h=harden, q=quit
```

> `ruff format` has **never** been run on this repo — it would reformat 18 of 31 files.
> `ruff check .` is the enforced gate. Do not run `ruff format` as part of a task; if you
> want it, make it its own commit.

## Architecture rules

- **All mutmut parsing lives in `killscore/mutation.py`.** It returns
  `MutationRun(score, killed, survived, total, survivors)`.
  `apps/api/app/services/mutation.py` re-exports it, so the API app depends on the
  `killscore` package and never the reverse. Nothing else parses tool output.
  Tests must patch `killscore.mutation.subprocess.run` — the re-export means patching the
  `app.services.mutation` namespace intercepts nothing.
- **All agent invocations go through `killscore/agent/runtime.py`.** Never call
  `claude_agent_sdk.query()` from anywhere else.
- **Agent tool restriction is enforced by a `PreToolUse` hook, not `allowed_tools`.**
  The SDK forwards `allowed_tools` to the `claude` CLI and enforces nothing itself, and
  `can_use_tool` is silently skipped whenever an allowlist entry allows a whole tool
  (`CanUseToolShadowedWarning`). The hook is consulted for every call. If you touch the
  gate, the denial matrix in `tests/test_agent.py` is the contract.
- **The risk score is mechanical; the LLM only writes prose.** `killscore/risk.py` is pure
  and does no I/O, `killscore/registry.py` fetches, `killscore/checks/slopsquat.py` adapts.
  `killscore/explain.py` runs *after* scoring with `allowed_tools=()` and returns a string;
  there is no code path from that string back into a score, a severity, or an exit code. If
  you add a factor, add it to `risk.py` with a `Factor` detail line, or the score stops being
  re-derivable by hand.
- **Two slopsquat invariants are load-bearing, and `tests/test_slopsquat.py` pins both.**
  Typo-adjacency alone must stay under the MEDIUM threshold (25 < 40), and an unmeasurable
  factor must score 0 and say why. Breaking either turns the check into a false-positive
  generator, which is worse than not shipping it.
- **A corpus hit is never fetched.** `score_package` short-circuits on membership in
  `data/top_pypi_packages.json`, so requesting one wastes a round trip on an answer that
  cannot change the result — and it is why a manifest of ordinary packages scores offline.
- **An injected `fetcher=` disables the registry cache.** Caching a fake answer would poison
  every later run with data no registry ever returned. `fetch_many` enforces this.
- **The new checks are guard-first, and the guards are the point.** `import-effects` is
  silent on *any* nesting, because the AST cannot see a feature flag; `pinned-version`
  compares with PEP 440 via `packaging`, because `==1.0` legitimately matches a release
  published as `1.0.0`; `call-signature` reports only module-level plain functions called
  with no star-unpacking. Loosening any of these turns a check into a false-positive
  generator. `tests/test_import_effects.py` and `tests/test_call_signature.py` lead with
  silence tests for exactly this reason.
- **Field-test guards (added 2026-11-20 after auditing 9 sibling repos; 8 of 9 HIGHs were
  false).** `env-default-degrades-url` is silent when the empty value is tested before use —
  the getter is itself a condition, has a non-empty `or` fallback, or its bound name appears in
  a later `if`/`while`/ternary/`assert` in the same scope (`_is_guarded` in `fail_open.py`,
  `isGuarded` in `fail_open.mjs`; keep them in step). `api-resolution` maps known import aliases
  (`IMPORT_DISTRIBUTIONS`: `cv2`→opencv-python, …) and looks up the distribution, never the
  import name; a 404 only means "possible-slopsquat" when every named distribution 404s. The TS
  resolver treats a relative import naming an existing *file* (`./globals.css`) as resolved.
  `tests/test_env_default_guards.py`, `tests/test_ts_asset_imports.py` and the alias tests in
  `tests/test_api_resolution_guards.py` pin both silence and firing.
- **Empty handlers with a comment still fire `swallowed-exception` — by decision.** Models
  write `except ValueError: pass  # ignore malformed input` when cutting corners, so a comment
  is not evidence of intent. Deliberate cases use `# killscore: ignore[fail-open]`.
- **`Dependency.source` is where the version came from; `declared_in` is the manifest that
  names it.** `slopsquat` (a claim about the name) reports at `declared_in`; `pinned-version`
  (a claim about the locked version) keeps `source`. `find_declaration_line` prefers a match
  outside a `#` comment, because manifests explain their dependencies in comments.
- **`call-signature` deliberately ignores bound methods and mixed-argument arity.** Both are
  v1 limitations, not oversights. `obj.method(...)` cannot be resolved to a signature without
  knowing what `obj` is, and computing whether a positional count satisfies required
  parameters *while keywords also fill slots* is where an off-by-one becomes a false
  accusation. Do not "improve" either without adding the silence tests first.
- **The tool gate is one policy with two call sites.** `ToolGate.evaluate` is pure and
  backend-independent; the Claude backend reaches it through its `PreToolUse` hook and the
  Ollama loop calls it directly in `_handle_call`. `evaluate` records nothing, so the loop
  must append to `gate.denied` itself — forget that and a local run denies correctly while
  reporting zero denials. `tests/test_localtools.py` runs one denial matrix against both
  backends; never write a second copy.
- **Local tools use Claude's tool names and argument keys on purpose.**
  `Read(file_path)`, `Bash(command)`, and so on. `ToolGate` keys its policy on those exact
  names and on `PATH_ARGUMENT_KEYS`, so matching them is what removes the translation layer
  that would otherwise drift.
- **`harden --budget` caps one turn-set, not the run.** `--max-total-cost` is the ceiling on
  the whole loop and is checked after every agent call. Up to 5 iterations x 3 survivors = 15
  turn-sets, so the two numbers differ by an order of magnitude.
- **Every long operation in the TUI runs in a Textual thread worker, and this is not
  optional.** Textual runs an asyncio loop; `run_agent` calls `anyio.run()`, which starts a
  second one, and nesting them raises. `run_mutation` blocks on `subprocess.run`, and the
  registry and Ollama clients block on `urllib`. Calling any of them from the UI thread is a
  crash or a multi-minute freeze. Results come back through `app.call_from_thread`.
- **Suppression is applied once, in `runner.iter_checks`**, from `killscore/config.py`
  (`[tool.killscore] exclude` + inline `killscore: ignore[check]`). Every surface reports
  the count (`CheckResult.suppressed`); a clean run that hid findings must say so. `deps`
  applies `exclude` to declarations *before* fetching. `--baseline` is applied in the CLI
  after saving, so `runs.db` keeps every finding.
- **The exit code is owned by `report.exit_code_for`.** `--fail-on` moves the threshold, a
  HIGH always exits 2, and `cli.main_entry` (the console script) maps Click usage errors and
  uncaught exceptions to 3. Typer vendors Click as the private `typer._click`, whose layout
  changed between 0.27 and 0.29 and broke a fresh wheel install — never import from it;
  `tests/test_packaging.py` greps for it.
- **Unknown is a note, not a finding.** "PyPI unreachable", "no node_modules", "repository
  unreadable" (gha-refs) and "not installed in a borrowed venv" are `CheckResult.notes` or
  skips. A LOW finding at an invented location is still a false claim.
- **`slopsquat` scores PyPI and npm through one path.** `risk.Corpus.ecosystem` decides name
  canonicalisation (PEP 503 vs exact) and wording; `registry.fetch_many(ecosystem=...)` picks
  the fetcher and the cache key. `check_slopsquat_all` returns one result per ecosystem
  (`slopsquat:pypi`, `slopsquat:npm`); `check_slopsquat` is the PyPI-only legacy shape.
- **Check dispatch lives in `killscore/checks/runner.py`, not in `cli.py`.** `iter_checks`
  yields each result as it lands (the TUI shows progress); `run_checks` returns the finished
  list (the CLI). One table — two copies would drift the moment a check is added and the
  surfaces would disagree about what `--all` means.
- **`harden`'s `on_event` is one-directional.** A listener receives what already happened and
  returns nothing, so it cannot influence a score, a discard, a stop reason or an exit code.
  `tests/test_tui.py` runs the loop with and without a listener and asserts identical
  outcomes. Same contract as `explain.py`.
- **Presentation helpers shared by both UIs live in `killscore/presentation.py`.** Two
  answers to "did this repository get worse" that disagree is worse than either alone; a test
  asserts the web UI's `_trend`/`_rank` are literally the shared functions.
- **All SQLite access lives in `killscore/store.py`.** `check` is a SQL reserved word,
  so the column is quoted as `"check"` in every statement — unquoting it anywhere is a
  syntax error at table creation, which `tests/test_store.py` pins.
- **`audit` records a run by default** (`--no-save` opts out). A failure to record is a
  warning on stderr, never a change to the exit code a hook branches on.
- **A run stores git context honestly.** `git_sha` plus `git_root`, `git_dirty`, and
  `path_is_repo_root` in `summary_json`, because auditing a subdirectory records the
  *parent* repo's SHA and a dirty tree is not comparable to a commit.
- **`diff` matches findings on `(check, file, claim, verdict)` — never the line number.**
  A finding that moved because someone added an import is the same finding.
- **The web UI is read-only, and that rule is scoped to `killscore/ui/`** (scoped
  2026-09-09). It renders the database and cannot trigger a run or write to a
  repository. `killscore/tui/` **may** start an audit or a harden run — an interactive
  UI that cannot trigger anything is a viewer. Two invariants did **not** move and are
  asserted in `tests/test_tui.py`: the agent still works in a temp copy and the TUI shows
  its diff without any apply path, and no model produces a verdict on either surface.
- **Severity is a reserved *status* palette on both surfaces**; counts are ink and a small
  coloured mark carries identity, so a colour never means anything on its own. In the
  terminal this matters more, because the palette belongs to the user — `severity_cell`
  always emits the word as well as the mark, and a test asserts it.
- **The MCP server owns fd 1 at the OS level.** `mcp_server.serve` dups the real stdout for
  the transport and `dup2`s stderr onto fd 1, so prints, libraries and child processes cannot
  corrupt JSON-RPC. FastMCP only emits `structuredContent` for a parameterised return type -
  keep tool returns `dict[str, Any]`, not `dict`. No agent tools over MCP.
- **The pytest gate allow-lists arguments, not just the command.** `ToolGate` tokenises with
  shlex and denies `--pastebin`, `--junitxml`, `--basetemp`, `-p <plugin>`, `-c`, `-W` and
  any path outside the workspace. Extend `PYTEST_FLAGS` / `PYTEST_VALUE_OPTIONS` only with
  options that cannot write, load code, or reach the network, and add the denial to the
  shared matrix in `tests/test_localtools.py`.
- **Coverage in agent runs is measured, never read.** `verify.measure_coverage` runs the suite
  under the original venv's `coverage run` with the data file in its own temp dir. The copied
  `.coverage` is the user's stale one; reading it reported the same number before and after.
  Unknown renders `n/a (reason)`, never `0%`.
- **The agent never writes to a real repository.** It works in a temp copy
  (`killscore/agent/workspace.py`); runs end by printing a diff and applying nothing.
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
| L1 | `killscore audit` — language/runner/pinned-version detection → `RepoProfile` |
| L2 | Four mechanical checks: api-resolution, stale-models, fail-open, composed |
| L3 | Report layer — grouped findings, severity exit codes, `--json`, suite state |
| L4 | Agent layer — `run_agent`, `baseline` generation, `harden` mutation loop |
| L5 | Persistence (`~/.killscore/runs.db`), `history`, `diff`, and a local read-only `ui` |
| L6 | Slopsquat guard — `slopsquat` check + `deps` command, deterministic risk score, PyPI only |
| L7 | Check breadth (`import-effects`, `pinned-version`, `call-signature`) + Ollama backend |
| L8 | Terminal UI — run browser, live audits, live `harden` dashboard |
| L9 | v0.2: `test-tautology`, `lock-drift`, `gha-refs`, npm in `deps`, exclude/ignore/baseline, `--fail-on`, SARIF, pre-commit, GitHub Action, MCP server, wheel/uvx packaging, measured coverage, Ollama capability probe |

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

- **Renamed TrustLayer → killscore (2026-11-20), still released as v0.2.0.** `trustlayer` on
  PyPI belongs to an unrelated project (see `docs/v3-build-log.md`), and `detent` was rejected
  because PyPI's `detent` is a near-identical AI-agent verification tool. Clean break, no shims:
  nothing was ever published under the old name. Config is `[tool.killscore]` /
  `.killscore.toml`, inline ignores are `# killscore: ignore[...]`, env vars are `KILLSCORE_*`,
  data lives in `~/.killscore/`, MCP tools are `killscore_*`.
- **The agent runtime is no longer Claude-only (reversed 2026-08-28).** CLAUDE.md previously
  recorded `claude-agent-sdk` as the single backend. `killscore/agent/ollama.py` now runs the
  same work on a local model, opt-in via `--backend ollama` or `KILLSCORE_BACKEND`, because
  this machine already has the models and a local run costs nothing. **The security boundary
  did not move**: `ToolGate` is still the source of truth, still enforced before every tool
  execution, and the denial matrix now runs against both backends. Claude remains the default.
- **Agent runtime is `claude-agent-sdk`, not the Codex CLI.** `AGENTS.md` pinned
  `codex exec --json` and `app/services/codex_runner.py`; L4a was built on the Claude Agent
  SDK by instruction. No `codex_runner.py` exists. The `gpt-5.3-codex` placeholder was never
  resolved and is now moot.
- **`mutation.py` moved** to `killscore/mutation.py` and finally returns the
  `{score, killed, survived, survivors}` shape the old guide always specified but the code
  never implemented.
- **Install/run commands changed**: `requirements.txt`, `app.main:app`, and `pnpm` commands
  in the old guide referred to files that never existed.

## Registry APIs (VERIFIED 2026-08-16 — do not rediscover)

- **`pypi.org/pypi/<name>/json` → `info.downloads` is DEAD.** It returns
  `{last_day: -1, last_week: -1, last_month: -1}` for every project on the index. Never read
  it. Download counts come from `pypistats.org/api/packages/<name>/recent`, which is a third
  party — so a failure there is `downloads: unavailable`, worth zero points, never a signal.
- The same response carries `ownership.roles` (a list of `{role, user}`) — that is the
  maintainer-count signal, and it is official. It is absent on mirrors, which means
  "unavailable", not "zero maintainers".
- Project age is the **earliest upload across all files of all versions**, not the first key
  of `releases`: a version can exist with an empty file list and would date the project wrong.
- npm (re-probed 2026-11-20, implemented in `registry.fetch_npm`): scoped names go in the
  URL as `@scope%2Fname`. 404 body is `{"error":"Not found"}`. **An unpublished package is
  HTTP 200** with only `{_id, name, time}` and `time.unpublished = {time, versions}`. A package
  npm seized after removing malware has `dist-tags.latest` like `0.0.1-security` or
  `1.0.0-security` *and* description "security holding package" - require both. A version's
  `deprecated: ""` means un-deprecated. Downloads: `api.npmjs.org/downloads/point/last-month/
  <name>` -> `{downloads, start, end, package}`; the comma-separated bulk form takes up to 128
  **unscoped** names only. ~600 scoped lookups in a burst (even 2 at a time, 0.3 s apart) get
  HTTP 429; one a second does not.
- npm has no first-party popularity ranking. The corpus names come from the
  `npm-high-impact` package (MIT), `lib/top-download.js` (`export const topDownload = [...]`,
  15 916 names >= 1M downloads/week, read from its registry tarball).
- Distance is **Damerau-Levenshtein (OSA), not Levenshtein.** Plain Levenshtein scores a
  transposition as 2, so `reqeusts` would read as far from `requests` as an unrelated
  two-character difference. Transposition is the most common typo and a primary squat vector.

## Ollama API (VERIFIED 2026-08-28 — do not rediscover)

`POST http://localhost:11434/api/chat`, body `{model, messages, stream: false, tools?}`.
Probed against the models actually installed here; the shapes differ by family and the
difference is load-bearing.

**Two families, two different tool-call shapes.**

- **gpt-oss** (`gpt-oss:20b`, `gpt-oss-agent-32k`, `gpt-oss-agent-64k`) returns a structured
  `message.tool_calls`: a list of `{id, function: {index, name, arguments}}`. **`arguments`
  is a decoded object, not a JSON string** — OpenAI's API returns a string there, so a client
  written to that shape breaks. `message.content` is empty on a tool turn.
- **qwen2.5-coder** (`qwen2.5-coder:14b-instruct-q4_K_M`, `qwen2.5-coder-agent-32k`) returns
  **`tool_calls: None`** and emits the call as raw JSON text in `message.content`:
  `{"name": "read_file", "arguments": {"path": "config.yaml"}}`. Both the stock and the
  agent-tuned build behave this way, so it is the family, not the Modelfile.

**Superseded 2026-11-20 (Ollama 0.40.16):** the gate is no longer a `gpt-oss` name prefix.
`POST /api/show {model}` returns `capabilities` (e.g. `["completion","tools","thinking"]`,
or `["embedding"]`), `model_info["<arch>.context_length"]` (ignore the
`.rope.scaling.original_context_length` key), and the Modelfile as text in `parameters`
(`num_ctx  16384`); an unknown model is HTTP 404. `ollama.tool_loop_refusal` uses it.
`capabilities` reflects the *template*, not behaviour: qwen3.5-9b returns structured
`tool_calls` in the gpt-oss shape, while glm-4-9b advertises `tools` and still writes
`Read\n{"file_path": ...}` as prose and then hallucinates the file. Hence `recover_text_call`
(only an unambiguous single call) and `looks_like_text_call` (anything else ends the run).
`options.num_ctx` is sent explicitly on every chat. The installed models changed since the
probe below: `gpt-oss-agent-64k` and qwen2.5-coder are no longer on this machine;
`gpt-oss-20b-16k`, `qwen3.5-9b-uncensored`, `qwen3.8-27b`, `glm-4-9b` and
`deepseek-r1-0528:8b` are. **The default is now the stock `gpt-oss:20b`** (portable, and the
`-agent-*` builds only existed to raise `num_ctx`, which is now sent per request). It is not
installed here, so a missing model's 404 is turned into a list of installed `tools` models
(`_missing_model_hint`); nothing is auto-selected. Live tests run against
`KILLSCORE_OLLAMA_MODEL=qwen3.5-9b-uncensored:latest` on this machine (both pass: a plain
answer and a real Read through `ToolGate`).

To be precise about the risk: a text-emitted call is a **reliability** problem, not a gate
bypass. `ToolGate` still evaluates whatever gets parsed, so a mangled call is denied rather
than executed. The problem is that a lost call is indistinguishable from a model choosing not
to call anything, so a loop built on it silently does nothing.

**This was found twice, independently.** The probe above reproduced it, and a controlled A/B
test recorded in `~/AI/OPENCODE.md` reached the same conclusion from the other direction: it
traces the cause to qwen2.5-coder's own `<tool_call>` tag-wrapping at Q4 quantization, shows
it is unaffected by context length, and concludes that the gpt-oss agent build is "the only
model on this machine verified reliable" for a real tool loop.

**Local setup lives in `~/AI`.** Start the server with `systemctl --user start ollama`, not a
bare `ollama serve` - the unit sets `OLLAMA_MODELS=/home/suyash/AI/models/ollama`,
`OLLAMA_MAX_LOADED_MODELS=1` (switching models evicts the resident one) and
`OLLAMA_KEEP_ALIVE=5m`. `~/AI/OLLAMA-ACCESS.md` and `~/AI/OPENCODE.md` are the reference.
Ollama and ComfyUI cannot both hold a model in VRAM on this machine.

- **`message.thinking`** is present on gpt-oss turns (hundreds of characters) and is
  reasoning, **not** answer text. Never concatenate it into output; read `message.content`.
- **A model without tool support fails fast and definitively**: HTTP 400 with body
  `{"error": "... does not support tools"}`, in about 0.1s. `gemma3:12b` is the case here.
- **Tools offered but not used** is not an error: `tool_calls` is absent and `content`
  carries prose. Treat it as a normal text turn.
- **Feeding a result back**: append the assistant message verbatim, then
  `{"role": "tool", "content": "<result>", "tool_name": "<name>"}`. Verified round-trip.
- **Token and timing fields**: `eval_count` (output tokens), `prompt_eval_count` (input
  tokens), `total_duration` (nanoseconds), `done_reason`. These are what a local run reports
  instead of a dollar cost, which is always zero.
- **Context length**: the server defaults to `num_ctx=4096` regardless of the model's
  training length, and at 4096 the tool loop demonstrably fails. The `-agent-32k` /
  `-agent-64k` variants set `num_ctx` to 32768 / 65536 in their own Modelfile, which is the
  entire reason they existed. *Superseded:* killscore now sends `options.num_ctx` itself, so a
  stock tag is fine for agent work. The measured cost of 8x the context is about +360 MB of
  VRAM.
- Observed latency, warm: ~1s for short prose, 6-20s for a tool turn. First call per model
  pays a load cost on top.

## Textual 8.2.8 (VERIFIED 2026-09-09 — do not rediscover)

- **Never name an attribute `_running` on a `Screen`, `Widget` or `App`.** `_running` is a
  `MessagePump` internal that Textual sets when the node's message pump starts. A re-entry
  guard reading it is therefore always true, so the action it guards never runs — silently,
  with no error anywhere. This cost a full debugging session: every piece worked in
  isolation and only stepping through the action line by line found it. The TUI uses
  `_audit_running` / `_harden_running`.
- `Static` exposes **`.content`**, not `.renderable`. Reading `.renderable` raises.
- Screen capture is **`App.export_screenshot()`** (SVG). There is no `export_text()`.
- Tests: `App.run_test()` is an **async context manager** yielding a `Pilot`
  (`press`, `click`, `pause(delay)`). Async tests use `@pytest.mark.anyio` with a local
  `anyio_backend` fixture returning `"asyncio"`, matching `tests/test_agent.py`.
- Wait for thread workers with **`await app.workers.wait_for_complete()`**. Polling
  `pilot.pause()` in a loop races the worker and produces flaky, confusing failures.
- `BINDINGS` must be annotated `ClassVar[list[Binding]]` or ruff's RUF012 rejects it.

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
- **`mutants/` is not scratch space, and it goes stale.** It holds a *copy* of the project
  including a copy of `tests/`, plus `mutmut-stats.json` mapping each mutated function to the
  tests that cover it. mutmut runs the tests from that copy and consults that map, and
  refreshes **neither** when the real `tests/` changes. A test added after the first run is
  never copied in, never enters the map, and never runs against a single mutant, so the score
  comes back identical however good the test is.

  This silently broke `harden`: every iteration reported the same score, every run reported
  +0.0%, and the plateau detector stopped the loop on a number that could not move. Measured
  on `pricing-py`, a generated test worth +1.9% read as +0.0%.

  `run_mutation(fresh=True)` is therefore the default and clears `mutants/` and
  `.mutmut-cache` first. mutmut 3.6.0 has no flag for this — `mutmut run --help` offers only
  `--max-children`. A stale score is worse than a slow one; `tests/test_mutation_cache.py`
  pins it.
- `mutmut result-ids` does **not** exist in 3.6.0. Never call it.
- mutmut and pytest live in the target repo's `.venv`. A workspace copy excludes `.venv`, so
  resolve those executables from the **original** repo. Use `Path.absolute()`, never
  `.resolve()` — resolving a `.venv/bin/python` symlink drops the venv's site-packages and
  the tool disappears.
