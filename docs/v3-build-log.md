# v3 build log — check breadth and a local model backend

What shipped on `v3-checks-and-local-backend`, why each decision went the way it did, and
what running the code found that reading it would not have.

Prompted by an external review of the repo. Its strategic read was right — "we never ask an
LLM whether the test is good; we run the mutant" is the differentiator — but its tactical
priority (distribution first) was deferred in favour of widening that differentiator.

## Triage of the review

| Claim | Verdict |
|---|---|
| Checks are narrow (api-resolution, stale-models, fail-open, composed) | Stale. `slopsquat` and `deps` had landed after the review was written. |
| No LICENSE, no `.github/`, no PyPI release, thin `pyproject.toml` metadata | True. Deferred by decision. |
| "Publish to PyPI as `trustlayer`" | **Impossible.** The name belongs to an unrelated "AI Safety & Risk Intelligence middleware", v0.1.3, four releases Feb 2026. `trust-layer` and `trustlayer-cli` are free. A positioning collision as much as a packaging one. |
| Add a dead-code check | Already covered — `composed` wraps `vulture` and dedupes it against native findings. |
| Agent cost control is missing | True, and worse than described. See Phase 7. |

## Phases

### 1 — `import-effects`

Network, subprocess, and destructive I/O that runs at module scope. Pure AST, no
environment, so it runs by default.

The check is its silence. **Any nesting means no finding** — a call inside `if`, `try`,
`with`, a loop, a function or a class is skipped, because the AST cannot see that a
`subprocess` call sits behind a feature flag or under `if TYPE_CHECKING`. **Reads are not
effects**: `open(path)`, `Path.read_text()`, `json.load(open(...))` never report.

Deliberately *not* flagged: `requests.Session()`, `httpx.Client()` and bare `socket.socket()`
construct without performing I/O, so flagging them would make the evidence line untrue.

Severity gradation: deleting data on import is HIGH, being slow or spawning a process is
MEDIUM. 39 tests, most asserting silence.

### 2 — `pinned-version`

`fastapi==0.999.0` names a real, popular, correctly spelled package and still cannot be
installed. Neither `slopsquat` nor `api-resolution` sees it: one asks whether the project
exists, the other whether the import resolves, and both answers are yes.

**Comparison is PEP 440, not string equality.** `urllib3==2.0` legitimately resolves to the
release published as `2.0.0`; string matching would report that correct pin as missing.
Verified against live PyPI, where it instead correctly reports the real yank reason for
2.0.0. `packaging` was already importable but undeclared, and is now a declared dependency —
PEP 440 comparison (epochs, pre/post/dev, local versions) is too subtle to hand-roll.

Only a *fully* yanked release counts as yanked; yanking is per-file under PEP 592 and a
partially yanked release still has something installable. `yanked_reason` is frequently null
on a genuine yank, so an absent reason reports as "no reason recorded" rather than being
dropped.

`PackageFacts` gained `versions` and `yanked_versions`, both defaulting to empty so a row
missing them cannot crash a run, and `CACHE_FORMAT_VERSION` went to 2 so v1 rows miss and
refetch rather than deserialize half-empty.

### 3 — `call-signature`

Ships inside the opt-in `api-resolution` check, which already resolves against the audited
repo's own interpreter. It answers "can this be called the way the code calls it" — the next
thing a model gets wrong once it has the name right.

The probe now returns **structured parameters** (name, kind, has-default) rather than a
rendered string, so the check never parses prose to reach a verdict.

The guards are the check. It stays silent when:

| Situation | Why |
|---|---|
| Not a plain Python function | C builtins have no reliable signature; classes drag in `__new__` and metaclasses |
| `@overload`-ed | The runtime signature is only one of several valid shapes |
| `inspect.signature()` raises | Nothing to compare against |
| `*args` / `**kwargs` in the signature | Arity unbounded, any keyword potentially valid |
| `*a` / `**kw` at the call site | The real count is not statically knowable |
| Receiver is not a plain name | `factory().go()` says nothing about `go` |
| Not module-level | Bound-vs-unbound `self` makes the count ambiguous |

Arity is judged only on a call with no keywords. A mixed call like `get(url, timeout=5)` is
still checked for an unknown *keyword* — the name is in the signature or it is not — but
deciding whether the positional count satisfies required parameters while keywords also fill
slots is where an off-by-one becomes a false accusation. A v1 limitation, recorded in
CLAUDE.md so it is not later "improved" into a false-positive generator.

**Validated against real code, not just fixtures**: scanning all of TrustLayer's own source
(rich, typer, fastapi, anyio, packaging, claude_agent_sdk) produces zero signature findings
outside the deliberate fixture.

### 4 — Probing the Ollama API

Documentation only, no client code, because CLAUDE.md forbids writing against a remembered
API. The probe found the thing that rule exists for.

**Two families, two different shapes.** gpt-oss returns a structured `message.tool_calls`
whose `arguments` is a **decoded object** — OpenAI's API returns a JSON *string* there, so a
client written to that shape breaks. qwen2.5-coder returns **`tool_calls: None`** and emits
the call as raw JSON text in `message.content`. A client assuming `message.tool_calls` would
have seen zero tool calls from qwen forever, with no error.

Also recorded: `message.thinking` is reasoning and not answer text; a model without tool
support fails fast with HTTP 400 and a JSON error body; tools offered but unused is a normal
text turn; the tool-result round-trip format; and the token/duration fields that stand in for
a dollar cost locally.

### 5 — The Ollama backend, no-tool path

`deps --explain --backend ollama`. Claude stays the default; the local path is opt-in per
invocation or via `TRUSTLAYER_BACKEND`, and an **unrecognised backend name falls back to
Claude rather than failing**, so a typo in an environment variable cannot silently route work
to a different model.

Only `message.content` is ever read — letting `thinking` through would put the model's
scratchpad into a user-facing explanation.

A local run costs nothing, which makes `cost_usd` useless for comparison, so `AgentResult`
also carries backend, model, and token counts. A real run attributes itself: *"written by
gpt-oss-agent-64k:latest via ollama, 646->1637 tokens, 17.6s — it changed no score."*

Failure stays cosmetic, verified by killing the server mid-run: a clear warning on stderr,
and the exit code still 2.

### 6 — The tool loop and the gate

Read / Write / Edit / Glob / Grep / Bash implemented locally, with `ToolGate.evaluate`
consulted before every execution.

**The tool names and argument keys deliberately match Claude's** — `Read(file_path)`,
`Bash(command)` — because `ToolGate` keys its policy on exactly those. Matching them means
one policy governs both backends with no translation layer to drift, which is why there is a
single denial matrix run against both call sites rather than two copies.

Verified live: `gpt-oss-agent-64k` read a source file, created a test directory, wrote a
parametrized pytest file and ran pytest — 9 turns, 16.3s. Verified adversarially too: asked
to run `git status`, write outside the workspace and curl a URL, the run recorded the denial,
created nothing outside the temp copy, and the model correctly inferred the sandbox from the
refusal.

**Bug caught here:** `ToolGate.evaluate` is the pure policy function and records nothing —
the Claude path appends to `gate.denied` in its callback and its hook. The loop calls
`evaluate` directly, so without an explicit append a local run would deny correctly and
report zero denials.

Tool use is refused outright on non-gpt-oss models. That is a **reliability** decision, not a
security one — the gate still evaluates whatever gets parsed, so a mangled call is denied
rather than executed — but a lost call is indistinguishable from a model choosing not to
call anything, so a loop built on it silently does nothing. The same conclusion was reached
independently by a controlled A/B test in `~/AI/OPENCODE.md`, which traces the cause to
qwen2.5-coder's `<tool_call>` tag-wrapping at Q4 quantization.

### 7 — Cost control and backend wiring

**`--budget` never capped a run.** It caps one agent turn-set, and `harden` makes up to 3 per
iteration for up to 5 iterations — so `--budget 2` could spend up to $30 while the flag said
two dollars. `total_cost` was accumulated and then never compared to anything.

`--max-total-cost` is now checked after every agent call and reported through
`stopped_because` the way a plateau is. A test pins the difference: the run that would have
made 15 agent calls makes 2. Work already done is still pruned and measured before the loop
exits, so a partial iteration reports honestly.

### 8 — Documentation

README gained the new checks and the local-backend section. CLAUDE.md explicitly **reversed
its own recorded single-backend decision** rather than sitting in contradiction with the
code, while noting what did not change: `ToolGate` is still the source of truth, still
enforced before every tool execution, and the denial matrix now covers both backends.

## The bug that only running it could find

The plan listed `harden --backend ollama` as a verification command. It had never been run.
Running it produced:

```
iteration 1   61.7% -> 61.7%  (+0.0%)  targeted 3  written 3  discarded 0
```

Easy to read as "the local model is not good enough". It was not that.

`mutants/` is not scratch space. It holds a *copy* of the project including a copy of
`tests/`, plus `mutmut-stats.json` mapping each mutated function to the tests that cover it.
mutmut runs the tests from that copy and consults that map, and refreshes **neither** when
the real `tests/` changes. A test added after the first run is never copied in, never enters
the map, and never runs against a single mutant.

Isolated rather than assumed — same repo, same test, same mutmut:

| | score | survived |
|---|---|---|
| baseline | 61.7% | 41 |
| + a test that provably kills the `>= 499.0` → `> 499.0` mutant | **61.7%** | 41 |
| the same test, cache cleared | **63.6%** | 39 |

So every `harden` run ever made reported +0.0%, and the plateau detector then stopped the
loop on a number that was structurally incapable of moving. The flagship feature was
measuring a stale cache.

`run_mutation(fresh=True)` is now the default. mutmut 3.6.0 has no flag for this — `mutmut
run --help` offers only `--max-children`.

The same local-model run, after the fix:

```
baseline score  61.7%
  iteration 1   61.7% -> 65.4%  (+3.7%)  targeted 3  written 2  discarded 0
  iteration 2   65.4% -> 69.2%  (+3.8%)  targeted 3  written 3  discarded 0
final score     69.2%  (+7.5%)
cost            $0 (local, 201528->20383 tokens)
```

**61.7% → 69.2%, zero tests discarded, 5m47s, $0.** The model had been doing good work the
whole time; the ruler was broken.

This bug was invisible to the entire test suite, because every mutation test patches
`subprocess.run`. It could only surface by running the real loop end to end — an argument for
doing that on every feature with a real-world path, not only the ones that cost money.

## Deferred, by decision

LICENSE, PyPI, GitHub Action, SARIF, pre-commit example, `ruff format`, `--strict` mode,
language pluggability, the model-registry contribution workflow, and npm support for
`slopsquat` (`PackageFacts` is registry-neutral, so it slots in behind the same shape).

The PyPI name collision should be settled before any distribution work starts, because it may
change the project's name.
