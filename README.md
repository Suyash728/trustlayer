# TrustLayer

Proves whether AI-written tests actually catch bugs, and whether AI-written code is telling
the truth about the APIs it calls.

The governing rule for every check in this repo: **no LLM produces any verdict.** Checks are
mechanical or they do not ship. Every finding carries evidence you can re-derive by hand —
a resolved package version, a real exported name, a registry 404, a source line.

## Install

```sh
uv sync                                        # Python package and CLI
npm install --prefix trustlayer/checks/node    # optional: enables the TypeScript checks
```

The TypeScript checks skip with an explicit reason if the second step is missing. They never
guess.

Run the CLI as `uv run trustlayer ...`, or activate the venv (`.venv/bin/activate`,
`.venv/bin/activate.fish`) and drop the prefix. The examples below omit it.

### The demo repository

`demo-repos/pricing-py` needs **its own** environment. Without one, `audit` skips
`api-resolution` — there is no interpreter to resolve imports against — and reports coverage
as unavailable, and `harden` has no mutmut to run.

Run these **from the repository root** — every path below is relative to it, so running
them from inside `demo-repos/pricing-py` builds a `demo-repos/pricing-py/demo-repos/...`
that does not exist:

```sh
uv venv demo-repos/pricing-py/.venv
uv pip install --python demo-repos/pricing-py/.venv/bin/python -e demo-repos/pricing-py
cd demo-repos/pricing-py && .venv/bin/python -m pytest -q --cov   # writes .coverage
```

**`--python` is not optional here.** `uv pip install` prefers `$VIRTUAL_ENV` over the
`.venv` in the current directory, and TrustLayer's own venv is usually activated by this
point. So `cd demo-repos/pricing-py && uv pip install -e .` installs mutmut, pytest-cov and
an editable `pricing-py` into the **root** venv and leaves the demo venv empty; the symptom
is `No module named pytest` from an interpreter you just installed pytest into. Naming the
interpreter explicitly is immune to whatever is activated. If it already happened, `uv sync`
at the root prunes the strays.

The `--cov` run has to happen with the demo repo as the working directory: coverage writes
`.coverage` to the current directory, and `audit` reads that artifact from inside the
repository it is auditing. It never runs a suite to obtain coverage.

## Usage

```sh
trustlayer audit <path>                        # detection + stale-models + fail-open
trustlayer audit <path> --all                  # everything, including the opt-in checks
trustlayer audit <path> --only api-resolution  # exactly one check
trustlayer audit <path> --warn-expiring-within 90d
trustlayer audit <path> --json                 # machine output, stdout is pure JSON
trustlayer audit <path> --no-color             # NO_COLOR is also honoured
trustlayer deps <path>                         # score dependencies for slopsquatting
trustlayer models --list
```

`api-resolution`, `composed` and `slopsquat` are opt-in rather than default. The first
imports code from the audited repository's environment in order to introspect it; the second
shells out to linters; the third contacts package registries. None should be a surprise side
effect of typing `audit`.

### Exit codes

Severity owns the exit code, so `audit` drops straight into a pre-commit hook:

| Code | Meaning |
|---|---|
| `0` | Clean, or low-severity findings only |
| `1` | At least one medium-severity finding |
| `2` | At least one high-severity finding |
| `3` | Operational error — bad path, bad flag, unreadable repo |

Operational failures deliberately exit `3` rather than `2`. If a mistyped path exited `2`,
a hook could not tell it apart from a genuine high-severity finding.

### Report format

Findings are grouped by check, worst group first, worst finding first within each group.
Colour is used for severity and nothing else — no emoji, no boxes, ASCII only, so the
output survives CI logs and pipes. The report ends with the test-suite state and a count
by severity.

Test counts come from the AST: nothing is imported, no collector runs, and parametrized
cases are counted once. Coverage is read from an artifact the repo already produced
(`coverage.xml`, `coverage.json`, `coverage/coverage-summary.json`, `lcov.info`, or
`.coverage` via the repo's own `coverage report`). **The test suite is never run to obtain
it.** If no artifact exists, coverage is reported as unavailable rather than guessed.

Below 50% coverage the report suggests `trustlayer harden`, which now exists — see
"The agent layer" below.

## What each check does

| Check | Finds | Evidence it carries |
|---|---|---|
| `api-resolution` | Imports and attributes that do not exist in the installed environment | Resolved distribution + version, the real exported names ranked by similarity, or a definitive PyPI 404 |
| `stale-models` | Deprecated model IDs in source and env files | Recorded retirement date, successor, and whether the entry was ever verified |
| `fail-open` | Code that degrades silently instead of failing loudly | The source line plus the concrete failure mode |
| `slopsquat` | Declared dependencies that do not exist, are barely established, or sit one typo from a popular package | Registry age, release count, maintainer count, download volume, and edit distance — each with its own point value |
| `composed` | Findings from ruff, semgrep, vulture, eslint, knip | The tool's own message, deduplicated against native findings |

A missing linter is always a skip with a reason, never an audit failure.

### Detection guarantees

`api-resolution` resolves against **the audited repository's own interpreter** (`.venv/`,
`venv/`, or the poetry env), never TrustLayer's. If there is no environment to resolve
against, the check skips and tells you what to install rather than guessing.

A package is only reported as a possible slopsquat when PyPI returns a definitive 404. A
network failure downgrades to `unresolvable`, because "we could not reach PyPI" and "this
package does not exist" are not the same claim.

## The slopsquat guard

LLMs invent package names. Attackers register those names and wait. The dangerous artifact
is rarely an import in a repo with a working virtualenv — it is a `requirements.txt` that was
generated thirty seconds ago and installed by nobody yet.

```sh
trustlayer deps <path>              # ranked score table, riskiest first
trustlayer deps <path> --json       # every factor and its point value
trustlayer deps <path> --no-network # corpus and cache only; never contacts a registry
trustlayer deps <path> --explain    # adds prose from a model; opt-in, changes no score
trustlayer audit <path> --only slopsquat
```

This check reads **manifests, not imports**, and therefore needs no virtualenv at all. That
is deliberate twice over: it is what lets a bare `requirements.txt` be scored, and it avoids
a false positive that would otherwise be unavoidable — import names and distribution names
differ (`yaml` ships as PyYAML, `cv2` as opencv-python), so scoring a bare import name would
manufacture 404s for real packages. `api-resolution` already owns the import path and does it
properly, behind an interpreter probe.

### The score

Additive, capped at 100, higher is riskier. Every point is attached to a stated fact.

| Factor | Condition | Points |
|---|---|---|
| **nonexistent** | registry returns a definitive 404 | **100** |
| age | first release under 30 / 90 / 365 days ago | 30 / 20 / 10 |
| releases | exactly one release / three or fewer | 15 / 8 |
| maintainers | one account or none | 10 |
| downloads | under 1 000 / 10 000 in the last month | 20 / 10 |
| typo-adjacency | 1 / 2 edits from a top-2000 package | 25 / 12 |
| yanked | latest release is yanked | 10 |
| vulnerabilities | the index carries advisories | 5 |

`>= 70` is HIGH, `>= 40` MEDIUM, `>= 20` LOW, below that no finding at all. Distance is
Damerau-Levenshtein, not plain Levenshtein: transposing two characters is the most common way
a name is mistyped, and plain Levenshtein scores `reqeusts` as **two** edits from `requests`,
which is the same as a package that differs by two unrelated letters.

**Three rules keep the false-positive rate at zero where it matters:**

1. **A package in the vendored top-2000 corpus scores 0 and is never fetched.** This removes
   the largest false-positive class before any factor runs, and means a manifest of ordinary
   dependencies is scored entirely offline.
2. **Typo-adjacency alone cannot reach MEDIUM.** It is worth 25 and MEDIUM starts at 40. Real
   packages sit near popular names all the time; that fact only matters stacked on youth or
   near-zero downloads. Measured against the live registry, `beautifulsoup` scores exactly 35
   — LOW, reading `unfamiliar-dependency`, which is accurate rather than accusatory.
3. **An unavailable factor scores 0 and says so.** If pypistats is rate-limited the evidence
   reads `downloads: unavailable (pypistats unreachable: HTTP 429)` and contributes nothing.
   A registry that cannot be reached at all yields `unscorable`, never a risk claim.

### Where the data comes from

Registry age, release history, and maintainer count come from **official** endpoints —
`pypi.org/pypi/<name>/json`, whose `ownership.roles` block is the maintainer signal.

**PyPI publishes no download counts.** `info.downloads` returns `{-1, -1, -1}` for every
project and must never be read. Download volume comes from pypistats.org, which is a third
party, so it is optional enrichment: when it fails, the factor is unavailable and scores
nothing.

Responses are cached in `~/.trustlayer/runs.db` for 24 hours. `--no-network` reads that cache
without a TTL and contacts nothing, so a warm cache reproduces an online run byte for byte —
which is the honest demonstration that the score is deterministic and the network only ever
adds evidence.

### The explanation is prose, never a verdict

`--explain` is opt-in and off by default. Every score, severity, and verdict is computed
before a model is contacted, and there is no code path from the returned text back into any
of them. The agent runs with `allowed_tools=()`, so the tool gate denies every call: it
cannot read the repository, reach a registry, or check the arithmetic. If it fails, you lose
the prose and nothing else — the exit code is unchanged.

## The agent layer

```sh
trustlayer baseline <repo> --module src/thing.py   # generate tests for untested code
trustlayer harden <repo> --target 90               # raise the mutation score
```

Both run the agent in a **temp copy** of the repository. Your repo is never written to —
not even a `git stash` entry — and each run ends by printing a diff for review. Applying
it is a human decision; nothing is applied automatically.

**Generated tests that fail are discarded, never repaired.** A generated test that fails
against unmodified source is evidence the agent misunderstood the code; repairing it would
launder that misunderstanding into the suite and everything downstream would inherit it.
The discard count leads the report — it is the honest signal.

`harden` stops on **plateau**, not just on the target: two consecutive iterations with no
score improvement ends the loop, because grinding twenty iterations for 2% wastes tokens.

### Tool restriction

The agent may read files, write test files, and run pytest. Nothing else. It cannot reach
the network or touch git.

Enforcement is a **PreToolUse hook**, not `allowed_tools`. The SDK forwards `allowed_tools`
to the `claude` CLI and enforces nothing itself, and `can_use_tool` is silently skipped
whenever an allowlist entry allows a whole tool (`CanUseToolShadowedWarning`) — verified
against a live agent. The hook is consulted for every call. Bash is a positive match on the
test runner plus a metacharacter check, so `pytest && git push` is denied by construction.
Every denial is recorded and reported.

**Known limitation:** coverage is reported as 0% for workspace runs. The temp copy excludes
`.venv`, so the coverage reader cannot find an interpreter to summarize `.coverage`.
Mutation score is unaffected — `harden` resolves mutmut from the original repo.

## History and the local UI

Every `audit` records a run in `~/.trustlayer/runs.db` (`--no-save` opts out), keyed to the
git SHA so a run is comparable to a commit.

```sh
trustlayer history <path> -n 10   # recent runs with severity counts
trustlayer diff <path>            # what appeared or disappeared since the previous run
trustlayer ui                     # localhost:7777, read-only browser over the database
```

A run also records the git root, whether the tree was **dirty**, and whether the audited
path was the repo root — because auditing a subdirectory records the *parent* repo's SHA,
and a run against uncommitted work must never look like a run against a commit.

`diff` matches findings on `(check, file, claim, verdict)` and deliberately ignores the
line number. A finding that shifted because someone added an import above it is the same
finding; including the line would turn one unrelated edit into a screenful of false churn.

**`trustlayer ui` needs a network connection to look right.** Tailwind and HTMX load from
CDN, which is what "no build step, no node_modules" costs. The page still renders and every
link works offline; it is just unstyled.

## Maintaining the model deprecation registry

**`data/model_deprecations.toml` goes stale. It needs periodic manual review.**

It is a hand-maintained snapshot, not a live feed. Vendors retire models on their own
schedule and nothing in this repo updates itself. Review it on every release, and at minimum
every quarter.

Entries carry `verified = false` until someone confirms them against an official vendor
deprecation page and records the `source_url`. `trustlayer models --list` prints these as
**UNVERIFIED**. An unverified row is a lead, not an authority.

> As of the initial seeding, **all seven entries are UNVERIFIED** — they were seeded from a
> maintainer's note. Two known gaps: the `gemini-2.0-flash*` family has no recorded
> successor, and the three embedding models have no recorded retirement date. Both were left
> empty rather than guessed, because inventing them is the exact failure this check exists
> to catch.

To review:

1. `trustlayer models --list` and look at the Source column.
2. For each UNVERIFIED row, find the vendor's deprecation notice.
3. Fill in `source_url`, set `verified = true`, and correct the date if it differs.
4. Add newly announced retirements; remove entries for models that were un-deprecated.

## Maintaining the top-packages corpus

**`data/top_pypi_packages.json` goes stale. It needs periodic regeneration.**

Same policy as the model registry above, and for the same reason: it is a hand-vendored
snapshot, not a live feed. It is the typo-adjacency target list and the offline popularity
baseline, so a stale corpus means a genuinely popular new package can be scored as unfamiliar
until the snapshot catches up.

The file records its own provenance — `source`, `upstream_last_update`, and `vendored_on` —
and `trustlayer deps` prints all three, so a reader can always tell how old the judgement is.

To regenerate, take the top 2 000 rows of
[hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json)
and preserve the provenance keys. Review on every release, and at minimum every quarter.

## Development

```sh
ruff check .
pytest -q
```

`pytest` is configured once at the repo root. Do **not** add `[tool.pytest.ini_options]` to
`apps/api/pyproject.toml` if one is ever created there: pytest uses exactly one config file,
the nearest one going up, so a second table would silently take over for invocations inside
that directory and diverge from root-level runs.
