# killscore

**Mechanical checks for AI-written code and mutation-verified tests.** Hallucinated APIs,
slopsquatted dependencies, and assertions that can't fail. No LLM produces a verdict.

The name is the thesis. Line coverage is a vanity metric; the mutation *kill score* is the
oracle. A small pricing module with **100% line coverage scored 61.7%** under mutation
testing: more than a third of its bugs could be introduced without a single test noticing.
`killscore harden` took it to 80.4% on a local model, and every test it kept was proven by
running it.

**No LLM produces any verdict.** Checks are mechanical or they do not ship. Every finding
carries evidence you can re-derive by hand: a resolved package version, a real exported
name, a registry 404, a source line. Where a model is used at all, it writes tests or prose,
and neither can change a score, a severity or an exit code.

- [Quick start](#quick-start)
- [Install](#install)
- [CI, pre-commit and coding agents](#ci-pre-commit-and-coding-agents)
- [Checks](#checks)
- [Dependency risk: `deps`](#dependency-risk-deps)
- [Raising the mutation score: `harden`](#raising-the-mutation-score-harden)
- [Reports, exit codes and configuration](#reports-exit-codes-and-configuration)
- [History and the two UIs](#history-and-the-two-uis)
- [Maintaining the data](#maintaining-the-data)
- [Development](#development)

## Quick start

```sh
uvx killscore audit .            # five offline checks, no setup
uvx killscore audit . --all      # plus the checks that resolve imports or contact registries
uvx killscore deps .             # risk-score every PyPI and npm dependency
```

Every finding names the line, what is wrong, and the concrete way it fails:

```text
fail-open:python
  HIGH   app.py:11  getenv('API_BASE_URL', <empty default>)
         env-default-degrades-url
           11: API_BASE_URL = os.getenv("API_BASE_URL", "")
           An unset variable yields an empty base URL, so requests resolve against a
           relative path and silently hit the wrong host instead of raising.
  HIGH   app.py:20  check_access() falls through to True
         gate-fails-open
           20: return True
           When no branch matches, the function returns permissive, so an unrecognised
           caller is granted access instead of being denied.

5 high  |  5 medium  |  0 low
```

The exit code follows severity (`2` here), so the same command works as a pre-commit hook or
a CI gate.

## Install

```sh
uvx killscore audit .        # from a wheel, no checkout needed
uv sync                      # or from a checkout: Python package and CLI
killscore setup-node         # optional: enables the TypeScript checks
```

The wheel carries its data: the model deprecation registry and both package corpora. The
TypeScript checks need ts-morph, which a wheel cannot ship, so `setup-node` installs it into
`~/.killscore/node` (or `$KILLSCORE_NODE_DIR`). In a checkout,
`npm install --prefix killscore/checks/node` works too. Without either, those checks skip
and say why. They never guess.

From a checkout, run the CLI as `uv run killscore ...`, or activate the venv
(`.venv/bin/activate`, `.venv/bin/activate.fish`) and drop the prefix. The examples below
omit it.

## CI, pre-commit and coding agents

**GitHub Action.** `action.yml` runs a check, uploads SARIF to code scanning, and exits with
the CLI's own code. Inputs reach the shell through `env`, never interpolation.

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v7
  - uses: Suyash728/killscore@v0.2.0
    with: { args: --all, fail-on: high }
```

**pre-commit.** `.pre-commit-hooks.yaml` defines `killscore-audit` and `killscore-deps`:

```yaml
- repo: https://github.com/Suyash728/killscore
  rev: v0.2.0
  hooks:
    - id: killscore-audit
      args: [--fail-on, high]
```

**SARIF.** `--format sarif` writes SARIF 2.1.0, validated against the published schema: one
rule per `(check, verdict)`, severity as `error`/`warning`/`note`, repo-relative locations,
fingerprints from the line-free identity (see [`diff`](#history-and-the-two-uis)), and
skipped checks as tool notifications, so "no results" and "could not run" stay
distinguishable.

**MCP.** `killscore mcp` serves `killscore_audit`, `killscore_deps` and `killscore_models`
over stdio, so a coding agent can check its own work before it says it is done:

```sh
claude mcp add killscore -- uvx killscore mcp
```

Results are the same JSON documents plus `exit_code` and `exit_meaning`; a bad request is
`exit_code: 3` with an `error`, never a clean-looking result. stdout carries JSON-RPC and
nothing else: the real fd 1 is handed to the transport and fd 1 itself is pointed at stderr,
so a stray `print`, a library or a child process cannot corrupt the stream. There is no
agent tool: killscore does not let one agent start another.

## Checks

```sh
killscore audit <path>                        # the default checks
killscore audit <path> --all                  # every check, including opt-in
killscore audit <path> --only api-resolution  # exactly one
```

The default checks read files and nothing else. The opt-in ones import code from the
audited repository's environment, shell out to linters, or contact package registries and
github.com, and none of that should be a surprise side effect of typing `audit`.

| Check | Finds | Runs |
|---|---|---|
| [`stale-models`](#stale-models) | Retired or retiring model IDs in source and env files | default |
| [`fail-open`](#fail-open) | Code that degrades silently instead of failing loudly | default |
| [`import-effects`](#import-effects) | Network, subprocess or destructive I/O at import time | default |
| [`test-tautology`](#test-tautology) | Test assertions that cannot fail | default |
| [`lock-drift`](#lock-drift) | A lockfile generated from a different manifest | default |
| [`api-resolution`](#api-resolution) | Imports, attributes and call signatures that do not exist in the installed environment | opt-in |
| [`slopsquat`](#dependency-risk-deps) | Dependencies that are fake, seized, barely established, or one typo from a popular package | opt-in |
| [`pinned-version`](#pinned-version) | Pins the index does not have, or that were yanked | opt-in |
| [`gha-refs`](#gha-refs) | GitHub Actions refs that were never published, and inputs an action does not take | opt-in |
| [`composed`](#composed) | Findings from ruff, semgrep, vulture, eslint and knip | opt-in |

Every check is built guard-first. A check that cannot turn something into a certain finding
records a note or skips with a reason; it never reports a guess. A false positive costs
more than silence, because it trains people to ignore the output.

### `stale-models`

Finds deprecated model IDs in source and env files. Evidence: the recorded retirement date,
the successor, and the vendor page it came from. A model retiring within
`--warn-expiring-within` (default `90d`) is flagged before it breaks.

Every entry in the registry carries a `source_url` on the vendor's own deprecation page. An
entry not yet confirmed there is reported as MEDIUM (`retired-model-unverified`), never HIGH:
a note is not vendor evidence, so it cannot fail a build on its own.

### `fail-open`

Code that degrades silently instead of failing loudly, in Python and TypeScript. Each
finding carries the source line plus the concrete failure mode.

| Verdict | Severity | Example |
|---|---|---|
| `env-default-degrades-url` | HIGH | `API_URL = os.getenv("API_URL", "")` |
| `gate-fails-open` | HIGH | `def check_access(...)` that ends in `return True` |
| `swallowed-exception` | MEDIUM | `except Exception: pass`, `catch {}` |
| `cors-wildcard-with-credentials` | MEDIUM | `allow_origins=["*"]` with `allow_credentials=True` |

Each detector needs two independent signals. An empty env default is only reported when the
variable or its target names a URL, host or endpoint (a credential such as `WEBHOOK_SECRET`
does not count), and **only when nothing tests it before use**: a getter that is itself a
condition, has a non-empty `or` fallback, or whose variable is checked later
(`if not endpoint: raise`, `return url is None or ...`, `url != ""`) is silent. An implicit
`None` default (`os.environ.get("URL")`) is reported only when it is formatted into a URL
string: `None` is Python's "not set", which a library replaces with its default or rejects,
while `f"https://{None}/v1"` is a request to the wrong host.

A gate is a function whose name asks a yes/no question about access (`is_`, `has_`, `can_`,
`check_`, `allow`, `authorize`, ...). `resolve_auth_mode()` falling through to `True` picks a
mode; it does not grant anything, so it is not judged.

An empty handler with an explanatory comment **still fires**. `except ValueError: pass  #
ignore malformed input` is exactly what a model writes when it cuts a corner, so a comment is
not evidence of intent. Mark deliberate cases with
`# killscore: ignore[fail-open] -- <reason>`.

### `import-effects`

Importing a module executes its top-level code. When that code opens a connection, shells
out or deletes a file, every importer inherits the effect, including the test collector,
before a single test is selected. Models write this constantly, because "set up the client"
has no notion that module scope is not a function body.

The check is its silence. **Nesting of any kind means nothing is reported**: a call inside
`if`, `try`, `with`, a loop, a function or a class is skipped, because the AST cannot see that
a `subprocess` call sits behind a feature flag or under `if TYPE_CHECKING`. **Reads are not
effects** either: `open(path)`, `Path.read_text()` and `json.load(open(...))` never report.
Deleting data on import is HIGH; being slow or spawning a process is MEDIUM.

**A script has no importer to affect.** A file outside any package (no `__init__.py` beside
it) that no file in the repository imports, such as `examples/`, `scripts/` or
`docs/conf.py`, is not judged, and the report says how many were skipped. pytest imports
`conftest.py`, `test_*.py` and `*_test.py` on its own, so those are always judged.

### `test-tautology`

Assertions in collected test files (`test_*.py`, `*_test.py`) that cannot fail. Each shape
is decided from the AST, and pytest itself confirms every one of them *passes*:

| Verdict | Example | Why it never fails |
|---|---|---|
| `mock-auto-attribute` | `assert m.called_once_with(x)` | Mock invents the attribute and returns a truthy Mock. Python 3.12 deny-lists six of these names (the test then errors instead); `awaited_*` is guarded on no version |
| `uncalled-assertion` | `m.assert_called_once_with` | no `()`: as a statement it does nothing, inside `assert` it is a truthy bound method |
| `unused-raises` | `pytest.raises(ValueError)` | the context manager is discarded; the legacy call form with a function is left alone |
| `constant-assertion` | `assert True`, `assert (x == 1, "msg")` | a truthy constant, or a non-empty tuple |
| `always-true-comparison` | `assert len(x) >= 0` | a length is never negative |
| `self-comparison` | `assert x == x` | **MEDIUM**, because `x == x` is False for NaN; `x != x` is never reported |

### `lock-drift`

`uv.lock`, `package-lock.json` (v2+) and `pnpm-lock.yaml` (v6+) record the manifest specs they
were generated from. killscore compares those with the manifest as it is now (the same
comparison `uv sync --locked`, `npm ci` and `pnpm install --frozen-lockfile` make before
refusing to install) and checks each `uv.lock` version against its PEP 440 specifier.

A pnpm v6 lockfile for a single project records its specs at the top level rather than under
`importers`, and both shapes are read. When uv locks one package at several versions (forked
resolutions for conflicting groups), a spec is satisfied if any locked version satisfies it.

npm semver ranges are never evaluated: comparing what the lockfile recorded is exact, and
re-implementing range arithmetic is where a false accusation would come from. Requirements
with environment markers, dynamic dependencies, `poetry.lock`, npm lockfile v1 and yarn are
not judged.

### `api-resolution`

Imports and attributes that do not exist in the installed environment, and calls that do
not match the real signature. Evidence: the resolved distribution and version, the real
exported names ranked by similarity, the actual signature, or a definitive PyPI 404.

It resolves against **the audited repository's own interpreter** (`.venv/`, `venv/` or the
poetry env), never killscore's. With no environment to resolve against, it skips and says
what to install. A nested project without a virtualenv of its own is resolved against the
root one, but "not installed" from that borrowed environment is withheld, because that venv
was never meant to hold those dependencies.

An import is reported as a possible slopsquat (HIGH) only when PyPI returns a definitive 404.
A network failure is a note: "we could not reach PyPI" and "this package does not exist" are
not the same claim. An import name is also not always a distribution name: `cv2` is
published as `opencv-python`, `PIL` as `Pillow`, `fitz` as `PyMuPDF`. A hand-curated table
(`IMPORT_DISTRIBUTIONS`) maps these traps to their distributions, which are looked up instead,
so `import cv2` without OpenCV installed reads as *not installed* (MEDIUM), not as a fake
package. A mapped import is still HIGH if every distribution it names returns 404.

Shapes that look missing but are not are left alone: a submodule imported from its package
(`from xml.etree import ElementTree` is not in `dir(xml.etree)` until imported), a module
alias the file rebinds elsewhere (`json = resp.json()`), and a first-party package in a
nested directory or `src/` layout.

For TypeScript, the import specifiers are resolved against the repository's own
`node_modules`. A relative import of an existing non-code file (`import "./globals.css"`)
counts as resolved: TypeScript only resolves modules it can type, and a bundler owns that
import.

**Call signatures.** Once a name resolves, the next thing a model gets wrong is how to call
it. The guards are the check: it stays silent when the callable is not a plain Python function
(C builtins have no reliable signature; classes drag in `__new__` and metaclasses), when the
function is `@overload`-ed, when the signature has `*args` or `**kwargs`, when the call site
uses `*a` or `**kw`, and when the receiver is not a plain name (`factory().go()` says nothing
about `go`). Arity is judged only on calls without keywords; a mixed call like
`get(url, timeout=5)` is still checked for an unknown keyword. Scanning all of killscore's
own source produces zero signature findings outside the deliberate fixture.

### `pinned-version`

`fastapi==0.999.0` names a real, popular, correctly spelled package and still cannot be
installed. Neither `slopsquat` nor `api-resolution` sees it: one asks whether the project
exists, the other whether the import resolves, and both answers are yes.

Comparison is **PEP 440, not string equality**: `urllib3==2.0` legitimately resolves to the
release published as `2.0.0`. A pin that is not a valid version at all is left alone. Only a
*fully* yanked release counts as yanked, because yanking is per-file under PEP 592. A missing
version is HIGH; a yanked one is MEDIUM, because it still installs when pinned exactly.

### `gha-refs`

`astral-sh/setup-uv@v10` looks right and fails at runtime: past v7, setup-uv publishes only
exact `v10.x.y` tags. `gha-refs` lists a public repository's branches and tags with
`git ls-remote` and reports a ref that is not among them (HIGH), naming the tags that do
exist with that prefix. It reads the action's `action.yml` at that ref to report `with:` keys
it does not declare (MEDIUM, since GitHub only warns), and checks `uses: ./path` actions on
disk. A repository `ls-remote` cannot read is a note, never a finding: a private action and a
nonexistent one look identical without credentials.

### `composed`

Runs ruff, semgrep, vulture, eslint and knip when they are installed and reports their
findings, deduplicated against killscore's own. Security rules are MEDIUM (ruff's
flake8-bandit `S` + digits, semgrep `ERROR`, eslint errors); everything else, including
ruff's `SIM` style rules, is LOW. A missing linter is a skip with a reason,
never an audit failure. semgrep runs only with a local config (`.semgrep.yml`), because
`--config=auto` needs the network and sends metrics.

## Dependency risk: `deps`

LLMs invent package names. Attackers register those names and wait. The dangerous artifact
is rarely an import in a repo with a working virtualenv; it is a `requirements.txt`
generated thirty seconds ago and installed by nobody yet.

```sh
killscore deps <path>              # ranked score table, riskiest first (PyPI and npm)
killscore deps <path> --json       # every factor and its point value
killscore deps <path> --format sarif
killscore deps <path> --no-network # corpus and cache only; never contacts a registry
killscore deps <path> --explain    # adds prose from a model; opt-in, changes no score
killscore audit <path> --only slopsquat
```

This reads **manifests, not imports**, so it needs no virtualenv at all. That is what lets a
bare `requirements.txt` be scored, and it avoids manufacturing 404s from import names that
differ from their distributions (`api-resolution` owns that path). A finding points at the
manifest line that declares the package, never at the lockfile that echoes it or a comment
that mentions it, so SARIF annotations and inline ignores land where the fix goes.

### The score

Additive, capped at 100, higher is riskier. Every point is attached to a stated fact.

| Factor | Condition | Points |
|---|---|---|
| **nonexistent** | registry returns a definitive 404 | **100** |
| **unpublished** (npm) | the record exists with only `time.unpublished` | **100** |
| **security holding** (npm) | npm replaced the package after removing malware (`0.0.N-security`, "security holding package") | **100** |
| age | first release under 30 / 90 / 365 days ago | 30 / 20 / 10 |
| releases | exactly one release / three or fewer | 15 / 8 |
| maintainers | one account or none | 10 |
| downloads | under 1 000 / 10 000 in the last month | 20 / 10 |
| typo-adjacency | 1 / 2 edits from a top-2000 package, unless the package itself has 1M+ downloads a month | 25 / 12 |
| yanked | latest release is yanked | 10 |
| deprecated (npm) | latest version carries a deprecation message | 10 |
| vulnerabilities | the index carries advisories | 5 |

`>= 70` is HIGH, `>= 40` MEDIUM, `>= 20` LOW, and below that there is no finding at all.
Distance is Damerau-Levenshtein, not plain Levenshtein: transposing two characters is the
most common typo, and plain Levenshtein scores `reqeusts` as **two** edits from `requests`.

**Three rules keep the false-positive rate at zero where it matters:**

1. **A package in the vendored corpus scores 0 and is never fetched.** This removes the
   largest false-positive class before any factor runs, and means a manifest of ordinary
   dependencies is scored entirely offline.
2. **Typo-adjacency alone cannot reach MEDIUM.** It is worth 25 and MEDIUM starts at 40. Real
   packages sit near popular names all the time; that only matters stacked on youth or
   near-zero downloads. Measured against the live registry, `beautifulsoup` scores exactly 35:
   LOW, reading `unfamiliar-dependency`, which is accurate rather than accusatory.
3. **An unavailable factor scores 0 and says so.** If pypistats is rate-limited the evidence
   reads `downloads: unavailable (pypistats unreachable: HTTP 429)` and contributes nothing.
   A registry that cannot be reached at all yields `unscorable`, never a risk claim.

### Where the data comes from

Registry age, release history and maintainer count come from **official** endpoints:
`pypi.org/pypi/<name>/json`, whose `ownership.roles` block is the maintainer signal.
**PyPI publishes no download counts** (`info.downloads` is `-1` for every project), so
download volume comes from pypistats.org, a third party: when it fails, the factor is
unavailable and scores nothing.

On npm all three are first-party: `registry.npmjs.org/<name>` (scoped names as
`@scope%2Fname`) and `api.npmjs.org/downloads/point/last-month/<name>`. npm names are compared
exactly, since npm does not fold case or `-_.` the way PyPI does. A `package.json` alias
(`"x": "npm:lodash@^4"`) is scored as the package it installs; `file:`, `link:`, `workspace:`
and git specs are listed in a note and never scored, because a local path "not existing on
npm" is not evidence of anything.

Responses are cached in `~/.killscore/runs.db` for 24 hours, per registry. `--no-network`
reads that cache without a TTL and contacts nothing, so a warm cache reproduces an online run
byte for byte: the score is deterministic, and the network only ever adds evidence.

`--explain` is opt-in. Every score, severity and verdict is computed before a model is
contacted, and there is no code path from the returned text back into any of them. The model
runs with no tools: it cannot read the repository, reach a registry or check the arithmetic.
If it fails, you lose the prose and nothing else.

## Raising the mutation score: `harden`

```sh
killscore baseline <repo> --module src/thing.py   # generate tests for untested code
killscore harden <repo> --target 90               # raise the mutation score
killscore harden <repo> --max-total-cost 5        # ceiling on the whole run, in dollars
```

Both run the agent in a **temp copy** of the repository. Your repo is never written to, not
even a `git stash` entry, and each run ends by printing a diff for review. Applying it is a
human decision; nothing is applied automatically.

**Generated tests that fail are discarded, never repaired.** A generated test that fails
against unmodified source is evidence the agent misunderstood the code; repairing it would
launder that misunderstanding into the suite. The discard count leads the report, because it
is the honest signal.

`harden` stops on **plateau** as well as on the target: two consecutive iterations with no
improvement end the loop. **`--budget` caps one agent turn-set, not the run.** `harden` makes
up to three per iteration for up to five iterations, so `--budget 2` can spend far more than
two dollars; `--max-total-cost` is the ceiling on the whole run, checked after every call.

Coverage before and after is **measured**, not read: the suite runs under the original
venv's `coverage run`, with the data file in its own temp directory. A repository without
coverage installed reports `n/a (coverage is not installed in ...)`, never `0%`, which would
be a different claim.

### What the agent may do

Read files, write test files, and run pytest. Nothing else: no network, no git.

Enforcement is a **PreToolUse hook**, not `allowed_tools`. The SDK forwards `allowed_tools`
to the `claude` CLI and enforces nothing itself, and `can_use_tool` is silently skipped
whenever an allowlist entry allows a whole tool (`CanUseToolShadowedWarning`). The hook is
consulted for every call. Bash is a positive match on the test runner plus a metacharacter
check, so `pytest && git push` is denied by construction. Every denial is recorded and
reported.

pytest's own arguments are allow-listed too, because the runner can reach outside the
workspace: `--pastebin` uploads output, `--junitxml`, `--basetemp` and `--debug` write
wherever they point, and `-p` loads a plugin. Every positional argument must resolve inside
the workspace. The residual risk, stated plainly: a test file the agent writes is code, and
running it runs that code.

### On a local model

The agent defaults to Claude and runs on Ollama on request:

```sh
killscore harden <path> --backend ollama --max-total-cost 5
killscore deps <path> --explain --backend ollama
export KILLSCORE_BACKEND=ollama        # or set it once
```

The default model is `gpt-oss:20b`; any model whose `ollama show` lists `tools` works.
`KILLSCORE_OLLAMA_MODEL` and `KILLSCORE_OLLAMA_HOST` override the model and endpoint. If the
model is not installed, the error lists installed models that report tool support; nothing is
picked for you. An unrecognised backend name falls back to Claude rather than routing work to
a different model.

**Tool support is asked of the server, not guessed from a name.** `POST /api/show` reports a
model's capabilities and trained context length, and a model without `tools` is refused
before a call is spent. That claim is about the template, not the behaviour: on Ollama
0.40.16, glm-4-9b advertises `tools` and still writes `Read\n{"file_path": ...}` as prose,
then invents the file. So a call written as text is recovered only when the **entire** reply
is exactly one call naming a tool the run offered; anything that merely looks like a call
ends the run with an explicit error. A lost call must never pass for a finished task.

`num_ctx` is sent on every request: `KILLSCORE_OLLAMA_NUM_CTX`, else the Modelfile value,
else 32768, never above the trained length. The server default of 4096 demonstrably breaks
the tool loop, so a loop that would run at 4096 or less is refused.

Both backends go through the same `ToolGate` policy: the Claude backend through its
`PreToolUse` hook, the local loop before executing anything. The local tools use Claude's
tool names and argument keys, so there is no translation layer to drift, and one denial
matrix runs against both. A local run reports tokens and wall-clock time instead of a dollar
cost.

## Reports, exit codes and configuration

```sh
killscore audit <path> --format json          # or --json; stdout is pure JSON
killscore audit <path> --format sarif         # SARIF 2.1.0
killscore audit <path> --fail-on high         # which severities fail (default: medium)
killscore audit <path> --baseline known.json  # fail only on findings not already known
killscore audit <path> --no-color             # NO_COLOR is also honoured
```

### Exit codes

Severity owns the exit code, so `audit` drops straight into a pre-commit hook:

| Code | Meaning |
|---|---|
| `0` | Clean, or low-severity findings only |
| `1` | At least one medium-severity finding |
| `2` | At least one high-severity finding |
| `3` | Operational error: bad path, bad flag, bad config, a crash |

Operational failures deliberately exit `3`, never `2`: a mistyped path must not look like a
high-severity finding to a hook. Click exits `2` on a bad option and Python exits `1` on an
uncaught exception, so the entry point maps both to `3`. `--fail-on` moves the threshold,
never the meaning: `--fail-on high` lets medium findings exit `0`, `--fail-on low` makes low
ones exit `1`, and a high finding exits `2` whatever the threshold.

### The report

Findings are grouped by check, worst group first and worst finding first within each group.
Colour marks severity and nothing else, always beside the word; output is ASCII only, so it
survives CI logs and pipes. The report ends with the test-suite state and a count by
severity.

Test counts come from the AST: nothing is imported, no collector runs, and parametrized cases
are counted once. Coverage is read from an artifact the repository already produced
(`coverage.xml`, `coverage.json`, `coverage/coverage-summary.json`, `lcov.info`, or
`.coverage` through the repo's own `coverage report`). **The test suite is never run to
obtain it.** With no artifact, coverage is reported as unavailable, not guessed. Below 50%
coverage, the report suggests `killscore harden`.

What a check could not decide is listed under **notes**, such as imports it could not
classify because PyPI was unreachable. Findings hidden by configuration are counted under
**suppressed**, every time: a clean report that hid findings says so.

### Exclude, ignore, baseline

```toml
# pyproject.toml (or the top level of .killscore.toml)
[tool.killscore]
exclude = ["tests/fixtures", "vendor/**", "*.generated.py"]
```

```python
MODEL = "gemini-2.0-flash"  # killscore: ignore[stale-models] -- pinned until the migration
```

`exclude` patterns match repo-relative paths; a directory pattern covers everything below it,
and excluded manifests are never sent to a registry. An inline `killscore: ignore[check]` (or
`// killscore: ignore[check]`) on the finding's own line hides it; `ignore[api-resolution]`
covers `api-resolution:python`. An unknown setting is an error (exit `3`), so
`excludes = [...]` cannot silently exclude nothing.

A baseline is the audit's own JSON: `killscore audit . --format json > known.json`, then
`killscore audit . --baseline known.json` fails only on findings not in it. Matching ignores
line numbers, so a known finding that moved is still known. The run database still records
every finding.

## History and the two UIs

Every `audit` records a run in `~/.killscore/runs.db` (`--no-save` opts out), keyed to the
git SHA, so a run is comparable to a commit.

```sh
killscore history <path> -n 10   # recent runs with severity counts
killscore diff <path>            # what appeared or disappeared since the previous run
killscore tui                    # terminal UI: a = audit, h = harden, enter = open, q = quit
killscore ui                     # localhost:7777, a read-only browser over the database
```

A run also records the git root, whether the tree was **dirty**, and whether the audited path
was the repo root: auditing a subdirectory records the *parent* repository's SHA, and a run
against uncommitted work must never look like a run against a commit.

`diff` matches findings on `(check, file, claim, verdict)` and ignores the line number. A
finding that shifted because someone added an import above it is the same finding; including
the line would turn one unrelated edit into a screenful of false churn.

**The terminal UI** needs no browser and no network. It can do three things the web UI
cannot: run an audit and show findings as each check lands; show `harden` working, with each
iteration's before-and-after score, tests written and discarded, and denied tool calls (from
the CLI, the loop prints nothing until it prints everything); and show the resulting diff.
There is no apply button, and a test asserts there is no apply path at all. Its exit status
is always `0`; `audit` owns exit codes.

**The web UI** is read-only: it renders the database and cannot trigger a run. Tailwind and
HTMX load from a CDN, which is what "no build step, no node_modules" costs, so offline it
still works but is unstyled.

## Maintaining the data

Two files are hand-vendored snapshots, not live feeds. Both go stale, and both print their
own provenance so a reader can always tell how old the judgement is. A scheduled workflow
(`.github/workflows/update-corpora.yml`) runs every Monday: it refreshes both package corpora
and opens a pull request with any change (nothing is merged automatically), and it runs the
model-registry tripwire described below.

### The model deprecation registry

`data/model_deprecations.toml`. Vendors retire models on their own schedule and nothing here
updates itself, so review it on every release and at least every quarter. Entries carry
`verified = false` until confirmed against an official vendor page with a recorded
`source_url`; `killscore models --list` prints those as **UNVERIFIED**, and an unverified
row is a lead, not an authority.

On 2026-11-20 every row was checked against the vendor's own page, and the seeded values
were **wrong more often than right**: Groq retired both Llama models on 2026-08-16, not
06-17; `gemini-2.5-flash` retires on 2026-12-01 (successor `gemini-3.5-flash-lite`), not
10-16; and a `gemini-2.0-flash*` wildcard covered variants with different dates and
successors, so it was replaced by explicit IDs. All thirteen rows are now verified.

`scripts/check_model_sources.py` re-fetches every `source_url` and fails when a verified ID no
longer appears on its page. It deliberately does not parse dates out of vendor prose; it is a
tripwire that tells a human which row to re-verify. To review:

1. Run `killscore models --list` and look at the Source column.
2. For each UNVERIFIED row, find the vendor's deprecation notice.
3. Fill in `source_url`, set `verified = true`, and correct the date if it differs.
4. Add newly announced retirements; remove models that were un-deprecated.

### The package corpora

`data/top_pypi_packages.json` and `data/top_npm_packages.json` are the typo-adjacency targets
and the offline popularity baseline. A stale corpus means a genuinely popular new package can
score as unfamiliar until the snapshot catches up.

`scripts/update_top_pypi.py` regenerates the PyPI corpus from
[hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json),
preserving the provenance keys (`source`, `upstream_last_update`, `vendored_on`);
`vendored_on` only moves when the package list does. `scripts/update_top_npm.py` takes names
from the `npm-high-impact` package and counts from api.npmjs.org, and refuses to write a
corpus with any count missing: api.npmjs.org rate-limits bursts of scoped lookups, and a
corpus silently missing hundreds of popular names is worse than a stale one.

## Development

```sh
uv sync
npm install --prefix killscore/checks/node   # the TypeScript checks and their tests
uv run ruff check .
uv run pytest -q
```

The suite is offline. pytest is configured once, at the repository root: do not add
`[tool.pytest.ini_options]` to `apps/api/pyproject.toml` if one is ever created there, because
pytest uses exactly one config file (the nearest going up), so a second table would silently
take over for runs inside that directory.

The deliberately broken sample repositories that the checks are tested against live in
`tests/fixtures/` and are excluded from killscore's own self-audit.
