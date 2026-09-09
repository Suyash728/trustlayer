# Plan — an interactive terminal UI (`trustlayer tui`)

Status: **proposal, not built.** One decision below needs sign-off before Phase 2 starts.

## Context

TrustLayer already has a UI: `trustlayer ui` serves a read-only browser over
`~/.trustlayer/runs.db` on localhost:7777. So "add a TUI" needs a better reason than "a TUI
would be nice", and there are two.

**The web UI is CDN-dependent.** Tailwind and HTMX load from a CDN, which is what "no build
step, no `node_modules`" costs — the README says plainly that offline "the page still renders
and every link works, it is just unstyled". A terminal UI has no such dependency. For a tool
whose whole pitch is that it works offline and deterministically, having the only visual
surface degrade without a network is an odd shape.

**`harden` is silent for its entire run.** Verified: there is no callback, generator, or
progress hook anywhere in `trustlayer/agent/`. A `harden` run takes minutes — the local-model
run measured 5m47s — and prints nothing at all until it prints everything. During that time
the mutation loop is baselining, targeting survivors, writing tests, discarding failures and
re-measuring, and none of it is visible. That is the actual gap, and it is the one a TUI is
uniquely good at.

Browsing past runs is the *third* reason, and the weakest, because the web UI already does it.
It is still worth building first — it is the cheapest way to prove the shell.

## Verified before planning

| Fact | Why it matters |
|---|---|
| `textual` 8.2.8 is current, and is what mutmut already pulls into the demo venv | One new dependency, no version conflict with the existing toolchain |
| `rich` is already a declared dependency | Textual is built on Rich, so existing renderables drop straight into widgets |
| `run_agent` calls `anyio.run()` at [runtime.py:266](../trustlayer/agent/runtime.py#L266) | **It starts its own event loop and cannot be called from inside Textual's.** This dictates the concurrency design below |
| `store.py` already exposes `latest_run_per_repo`, `list_runs`, `get_run`, `run_findings`, `previous_run`, `diff_runs` | The entire browser needs **no new queries** |
| `_rank` and `_trend` already exist in `trustlayer/ui/app.py` | Both UIs want them; extract rather than copy |

## The decision that needs sign-off

CLAUDE.md states: *"The UI is read-only. It renders the database and cannot trigger a run or
write to a repository."*

An interactive UI that cannot trigger anything is a viewer, not an interactive UI. The
proposal is to **scope that rule to `trustlayer/ui/` — the web surface — and let the TUI
trigger runs.** It is a real change to a recorded rule, so it is called out rather than
quietly worked around.

Two invariants do **not** move, and the TUI inherits both unchanged:

- **The agent never writes to a real repository.** It works in a temp copy and the run ends
  by printing a diff that a human applies. The TUI shows that diff; it does not apply it.
- **No LLM produces any verdict.** The TUI renders scores computed by `risk.py` and
  `mutation.py` and never asks a model anything.

If the answer is no, Phase 1 still stands on its own as an offline replacement for the web
viewer, and Phases 2–3 are dropped.

## Design

### Concurrency — the one hard constraint

Textual runs an asyncio event loop. `run_agent` calls `anyio.run()`, which starts a *second*
one, and nesting event loops raises. `run_mutation` shells out with a blocking
`subprocess.run`, and the Ollama client uses blocking `urllib`.

So: **every long operation runs in a Textual thread worker** (`@work(thread=True)`), and
posts results back to the UI as messages. Nothing calls `run_agent`, `run_mutation`, or
`fetch_many` on the UI thread. This is not a style preference — the first is a crash and the
other two freeze the interface.

### Progress events

`harden` and `baseline` gain an **optional** `on_event` callback. It is optional so every
existing caller is unaffected, and it is strictly one-directional: the callback receives
events and returns nothing, so it cannot influence a score, a discard decision, or an exit
code. Same shape as `explain.py`, where prose is produced after the verdict and has no path
back into it.

Events worth emitting, all of which the loop already computes and throws away:

```
mutation-baseline   score, killed, survived, total
iteration-start     number, survivors targeted
agent-turn          survivor id, cost or tokens, denials
tests-pruned        written, discarded, which files
iteration-end       score before, score after
stopped             reason (target / plateau / cost ceiling / iteration limit)
```

### Screens

1. **Projects** — one row per repository, newest run, severity counts, trend arrow. Mirrors
   the web UI's index, reusing `latest_run_per_repo` and `_trend`.
2. **Run detail** — findings grouped by check, worst first; a detail pane showing the
   evidence lines for the selected finding. Reuses `run_findings`.
3. **Run** — pick a repo and a check set, watch findings arrive as each check finishes.
4. **Harden** — the live mutation loop: current score, iteration table, survivors being
   targeted, tests written and discarded, cumulative cost or tokens, and the stop reason when
   it lands.

### Presentation rules, inherited

Severity keeps the reserved status palette, and **colour is never the only carrier** — every
severity shows a text label or symbol as well, exactly as the web UI does. Counts stay ink.
This matters more in a terminal, where the palette is the user's, not ours.

## Phases

Each phase ends green (`ruff check .` clean, `pytest -q` passing) and is committed
separately.

### Phase 1 — shell and read-only browser

`trustlayer tui` opens the projects screen; enter drills into a run; the detail pane shows
evidence. No writes, no network, no new store queries. Works with no connection, which is the
point.

Extract `_rank` and `_trend` out of `trustlayer/ui/app.py` into a shared module and have the
web UI import them from there, so the two surfaces cannot drift apart on what a trend means.

### Phase 2 — running audits from inside *(needs the decision above)*

Pick a repository, pick checks, run. Each check reports as it completes rather than at the
end. Uses the existing `_run_checks` in `cli.py`, called from a thread worker.

`--no-save` semantics need a deliberate answer: a TUI-triggered audit should record like any
other run, or `history` and `diff` develop holes. Recommend recording, with a visible toggle.

### Phase 3 — the harden dashboard

The reason to build this at all. Add the `on_event` callback to `harden`, run the loop in a
thread worker, render iterations live. Show the diff at the end, read-only, with a copy-path
affordance — never an apply button.

The cost ceiling and denial list are already tracked and already reported at the end; here
they become visible while there is still time to act on them.

### Phase 4 — polish

Filtering by severity or check, jump-to-file, a compare view matching the web UI's, and a
help panel. Only after 1–3 have been used in anger.

## Files

**New**

- `trustlayer/tui/__init__.py` — `create_app()`, mirroring `trustlayer/ui/`'s shape
- `trustlayer/tui/app.py` — the Textual `App`, screens, key bindings
- `trustlayer/tui/widgets.py` — findings table, evidence pane, iteration table
- `trustlayer/tui/workers.py` — thread workers wrapping audit / deps / harden
- `tests/test_tui.py` — headless tests driving the app through Textual's `Pilot`

**Modified**

- `trustlayer/cli.py` — a `tui` command beside `ui`
- `trustlayer/agent/harden.py`, `baseline.py` — the optional `on_event` callback
- `trustlayer/ui/app.py` — import `_rank`/`_trend` from the shared module instead of defining them
- `pyproject.toml` — `textual>=8.2`
- `README.md`, `CLAUDE.md` — the new command, and the scoping of the read-only rule

**Reused unchanged:** every `store.py` query, `report.py`'s `Report`/`CheckResult`/`Finding`/
`Severity`, `risk.py`'s `RiskScore` and `Factor`, and the existing `_run_checks` wiring.

## Verification

Textual ships `App.run_test()`, which drives an app headlessly through a `Pilot` — no
terminal, no snapshots, works in CI. **Confirm that API against the installed 8.2.8 before
writing tests**; this plan has not run it.

```sh
uv sync
uv run ruff check .
uv run pytest -q                          # must stay green, 332+ passing

uv run trustlayer tui                     # Phase 1: browser opens, arrows navigate, q quits
uv run trustlayer tui --no-network        # renders identically; the web UI would be unstyled

# Phase 3, the one that justifies the work:
systemctl --user start ollama
uv run trustlayer tui                     # drive harden on demo-repos/pricing-py
                                          # expect: 61.7% baseline, iterations appearing live,
                                          # score climbing, diff shown and not applied
```

Properties to pin:

- **Nothing long-running blocks the UI thread.** A test that starts a harden worker and
  asserts the app still responds to a keypress.
- **The callback cannot change a verdict.** Run `harden` with and without `on_event` and
  assert identical scores, discards and stop reasons — the same shape as the existing
  "explanation cannot change a score" test.
- **No apply path exists.** Assert the diff is rendered read-only and no code path writes to
  the audited repository.
- **Severity is never colour-only.** Assert every severity cell carries a text label.

## Out of scope

Replacing the CLI (`audit` keeps owning exit codes; a TUI has no useful exit status and
should always exit 0 — CI keeps using `audit`), remote or hosted surfaces, auth, editing
files from the TUI, applying generated tests, and replacing `trustlayer ui`, which stays as
the read-only web viewer.
