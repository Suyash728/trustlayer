# TrustLayer

**Line coverage tells you your tests *ran*. It doesn't tell you they'd *catch a bug*.**

TrustLayer checks AI-written code and AI-written tests for the things that look fine but
aren't: imports that don't exist, packages that were never published, tests that pass no
matter what the code does.

The demo repo in this project has **100% line coverage and a 61.7% mutation score**. That
means: every line runs during the tests, but nearly 40% of deliberately broken versions of
the code still pass. That gap is the entire point of this tool.

## The one rule

**No AI decides anything here.** Every finding is produced by a mechanical check, and every
finding comes with evidence you can verify by hand — a real version number, a real function
name, a 404 from PyPI, a line of source.

An AI *does* write tests (see [Fixing tests](#fixing-tests-the-agent)), but whether a test is
kept is decided by running it, not by asking a model.

## Install

```sh
uv sync                                        # installs the CLI
npm install --prefix trustlayer/checks/node    # optional, enables TypeScript checks
```

Run it as `uv run trustlayer ...`. (Or activate the venv and just type `trustlayer` — the
examples below leave the prefix off.)

<details>
<summary><b>Setting up the demo repo</b> (needed for the mutation-testing examples)</summary>

`demo-repos/pricing-py` needs its own virtualenv. Run these **from the repo root**:

```sh
uv venv demo-repos/pricing-py/.venv
uv pip install --python demo-repos/pricing-py/.venv/bin/python -e demo-repos/pricing-py
cd demo-repos/pricing-py && .venv/bin/python -m pytest -q --cov
```

Two things that will bite you if you skip them:

- **`--python` is required.** Without it, `uv pip install` installs into whatever venv is
  currently active — usually TrustLayer's — and the demo venv stays empty. The symptom is
  `No module named pytest` from an interpreter you just installed pytest into. If that
  happens, run `uv sync` at the root to clean up.
- **The `--cov` run must happen inside the demo repo.** Coverage writes `.coverage` to the
  current directory, and TrustLayer reads that file rather than running your tests itself.

</details>

## Quick start

```sh
trustlayer audit <path>                 # run the default checks
trustlayer audit <path> --all           # run everything, including opt-in checks
trustlayer audit <path> --json          # machine-readable output
trustlayer deps <path>                  # score dependencies for fake/typo-squatted packages
trustlayer harden <path> --target 90    # have an AI write tests that raise the mutation score
trustlayer history <path>               # past runs
trustlayer ui                           # browse past runs at localhost:7777
```

Some checks are **opt-in** (`--all` or `--only <name>`) because they do more than read files:
`api-resolution` and `call-signature` import code from the repo you're auditing, `composed`
shells out to other linters, and `slopsquat` and `pinned-version` contact PyPI.

### Exit codes

The worst finding decides the exit code, so `audit` drops straight into a pre-commit hook.

| Code | Meaning |
|---|---|
| `0` | Clean, or low-severity only |
| `1` | At least one medium-severity finding |
| `2` | At least one high-severity finding |
| `3` | Something went wrong — bad path, bad flag, unreadable repo |

A mistyped path exits `3`, not `2`, so a hook can tell "the tool broke" apart from "the code
has a real problem."

## The checks

| Check | What it catches | Default? |
|---|---|---|
| `api-resolution` | Imports, attributes, and function calls that don't exist in the installed packages | opt-in |
| `call-signature` | Calls that don't match the real function signature | opt-in |
| `stale-models` | Deprecated AI model IDs in your code and `.env` files | on |
| `fail-open` | Code that silently degrades instead of failing loudly | on |
| `import-effects` | Network calls, subprocesses, or file deletion that run just from importing a module | on |
| `pinned-version` | Version pins PyPI doesn't have, or that were yanked | opt-in |
| `slopsquat` | Dependencies that don't exist, are brand new, or sit one typo from a popular package | opt-in |
| `composed` | Findings from ruff, semgrep, vulture, eslint, knip | opt-in |

A missing tool is always reported as a **skip with a reason**, never a failure. If a check
can't answer honestly, it says so instead of guessing.

Two examples of what that means in practice:

- `api-resolution` resolves against **the audited repo's own Python**, not TrustLayer's. No
  virtualenv found? It skips and tells you what to install.
- A package is only called a possible squat when PyPI returns a definitive 404. If the network
  fails, the result is `unresolvable` — "we couldn't reach PyPI" and "this doesn't exist" are
  different claims.

<details>
<summary><b>Why three of these checks are so conservative</b></summary>

**`import-effects`** stays silent on *any* nesting. A `subprocess` call inside an `if`, `try`,
`with`, loop, function, or class is ignored — the parser can't tell whether it sits behind a
feature flag. Reads (`open()`, `read_text()`) are never reported either. Deleting data on
import is HIGH; being slow or spawning a process is MEDIUM.

**`pinned-version`** compares versions using PEP 440 rules, not string matching. `urllib3==2.0`
correctly resolves to the release published as `2.0.0`, and string matching would flag that
valid pin as broken. Only a *fully* yanked release counts as yanked.

**`call-signature`** stays silent when it can't be certain: C builtins, `@overload`-ed
functions, signatures with `*args`/`**kwargs`, call sites using `*a`/`**kw`, and anything
called on a non-name receiver (`factory().go()` tells you nothing about `go`). It also only
judges argument *count* on calls with no keywords — working out whether the positional count
is satisfied while keywords also fill slots is where an off-by-one becomes a false accusation.

The pattern is deliberate: **a check with a false positive is worse than no check.** Scanning
all of TrustLayer's own source produces zero signature findings outside the test fixture.

</details>

## Scoring dependencies (`deps`)

LLMs invent package names. Attackers register those names and wait. The dangerous artifact is
usually a `requirements.txt` that was generated a minute ago and installed by nobody yet.

```sh
trustlayer deps <path>              # ranked table, riskiest first
trustlayer deps <path> --json       # every factor and its points
trustlayer deps <path> --no-network # cache and offline corpus only
trustlayer deps <path> --explain    # adds a plain-English write-up; changes no score
```

This reads your **manifest files, not your imports**, so it needs no virtualenv — and it
avoids a false positive it otherwise couldn't dodge, since import names and package names
differ (`yaml` ships as PyYAML, `cv2` as opencv-python).

The score is additive, capped at 100, higher is riskier. Every point is tied to a stated fact:

| Factor | Condition | Points |
|---|---|---|
| **nonexistent** | PyPI returns a definitive 404 | **100** |
| age | first release under 30 / 90 / 365 days ago | 30 / 20 / 10 |
| releases | exactly one / three or fewer | 15 / 8 |
| maintainers | one account or none | 10 |
| downloads | under 1,000 / 10,000 last month | 20 / 10 |
| typo-adjacency | 1 / 2 edits from a top-2000 package | 25 / 12 |
| yanked | latest release is yanked | 10 |
| vulnerabilities | PyPI carries advisories | 5 |

`≥70` is HIGH, `≥40` MEDIUM, `≥20` LOW, below that nothing is reported.

<details>
<summary><b>Three rules that keep false positives near zero</b></summary>

1. **A package in the bundled top-2000 list scores 0 and is never looked up.** This kills the
   biggest false-positive class before anything runs, and it's why a manifest of ordinary
   dependencies scores fully offline.
2. **Being typo-adjacent alone can't reach MEDIUM.** It's worth 25 and MEDIUM starts at 40.
   Real packages sit near popular names constantly; that only matters stacked on top of
   youth or near-zero downloads. `beautifulsoup` scores 35 — LOW, "unfamiliar dependency",
   which is accurate rather than accusatory.
3. **A factor we couldn't measure scores 0 and says why.** If the download API is rate-limited
   you get `downloads: unavailable (HTTP 429)` worth nothing, not a guess.

Distance is Damerau-Levenshtein, not plain Levenshtein: transposing two letters is the most
common typo, and plain Levenshtein would score `reqeusts` as two edits from `requests` — the
same as a package differing by two unrelated letters.

**Where the data comes from:** age, releases, and maintainers come from PyPI's official API.
Download counts come from pypistats.org, a third party — so when it fails, that factor is
simply unavailable. PyPI itself publishes no usable download counts.

Responses are cached for 24 hours in `~/.trustlayer/runs.db`. `--no-network` reads that cache
and contacts nothing, so a warm cache reproduces an online run exactly — which is the honest
proof that the score is deterministic and the network only adds evidence.

**`--explain` never changes a verdict.** Every score and severity is computed before a model
is contacted, and there's no path from its text back into any of them. It runs with zero tools
allowed — it can't read your repo, reach a registry, or check the arithmetic. If it fails, you
lose the prose and nothing else.

</details>

## Fixing tests (the agent)

```sh
trustlayer baseline <repo> --module src/thing.py   # write tests for untested code
trustlayer harden <repo> --target 90               # raise the mutation score
trustlayer harden <repo> --max-total-cost 5        # spending ceiling for the whole run
```

**Your repository is never written to.** Both commands work in a temp copy and end by printing
a diff. Applying it is your decision.

**Tests that fail are thrown away, never fixed up.** If a generated test fails against
unmodified source, the agent misunderstood the code — patching the test would bake that
misunderstanding into your suite. The discard count is printed first, because it's the honest
signal.

`harden` also stops on a **plateau**: two iterations with no improvement ends the loop, rather
than grinding through twenty for another 2%.

> ⚠️ **`--budget` caps one agent turn-set, not the whole run.** `harden` makes up to 3 per
> iteration for up to 5 iterations, so `--budget 2` can spend far more than $2. Use
> `--max-total-cost` for a real ceiling — it's checked after every agent call.

### What the agent is allowed to do

Read files, write test files, and run pytest. That's it — no network, no git.

This is enforced by a **hook that runs before every tool call**, not by an allowlist. (The SDK
just forwards allowlists to the CLI and enforces nothing itself.) Bash commands must
positively match the test runner and contain no shell metacharacters, so `pytest && git push`
is denied by construction. Every denial is recorded and reported.

> **Known limitation:** coverage reads as 0% during agent runs. The temp copy excludes `.venv`,
> so there's no interpreter available to summarize the coverage file. Mutation score is
> unaffected.

### Running on a local model

The agent uses Claude by default, and Ollama on request:

```sh
systemctl --user start ollama
trustlayer harden <path> --backend ollama --max-total-cost 5
export TRUSTLAYER_BACKEND=ollama       # or set it once
```

`TRUSTLAYER_OLLAMA_MODEL` and `TRUSTLAYER_OLLAMA_HOST` override the model and endpoint. An
unrecognised backend name falls back to Claude rather than failing, so a typo can't silently
route your work somewhere unexpected.

Two constraints, both enforced rather than merely documented:

- **Tools only work with gpt-oss models.** Other families (qwen2.5-coder) emit tool calls as
  raw text instead of structured data, and a lost call looks identical to a model choosing not
  to call anything — so the loop would silently do nothing. Asking for tools with an
  unsupported model fails immediately with a clear message.
- **Use a context-raised build** (`gpt-oss-agent-32k` or `-64k`). Ollama caps context at 4096
  regardless of what the model was trained for, and the tool loop demonstrably fails there.

The same permission gate covers both backends — one policy, two call sites, one shared test
suite. A local run reports tokens and wall-clock time instead of a dollar cost.

## History and the web UI

Every `audit` records a run in `~/.trustlayer/runs.db` (`--no-save` opts out), keyed to the git
commit.

```sh
trustlayer history <path> -n 10   # recent runs with severity counts
trustlayer diff <path>            # what appeared or disappeared since last run
trustlayer ui                     # localhost:7777, read-only
```

A run also records whether the working tree was **dirty** and whether you audited the repo root
— auditing a subdirectory records the *parent* repo's commit, and a run against uncommitted
work must never look like a run against a commit.

`diff` matches findings on check, file, claim, and verdict — deliberately **not** the line
number. A finding that shifted because someone added an import above it is the same finding.

> `trustlayer ui` needs a network connection to look right: Tailwind and HTMX load from a CDN,
> which is the price of "no build step, no node_modules." Offline, it still works — just
> unstyled.

## Maintenance

Two data files are hand-vendored snapshots, not live feeds. **Both go stale.** Review them on
every release, and at minimum every quarter.

**`data/model_deprecations.toml`** — which AI models are retired. Entries stay
`verified = false` until someone confirms them against an official vendor page and records the
`source_url`; `trustlayer models --list` prints those as **UNVERIFIED**. An unverified row is
a lead, not an authority.

> All seven current entries are UNVERIFIED — seeded from a maintainer's note. Two known gaps:
> the `gemini-2.0-flash*` family has no recorded successor, and the three embedding models
> have no retirement date. Both were left empty rather than guessed, because inventing them is
> exactly the failure this check exists to catch.

**`data/top_pypi_packages.json`** — the typo-adjacency target list and offline popularity
baseline. A stale corpus means a genuinely popular new package reads as unfamiliar. Regenerate
from the top 2,000 rows of
[hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json),
preserving the `source`, `upstream_last_update`, and `vendored_on` keys — `trustlayer deps`
prints all three so a reader can always tell how old the judgement is.

## Development

```sh
ruff check .    # must be clean
pytest -q
```

`pytest` is configured once, at the repo root. Don't add a second `[tool.pytest.ini_options]`
anywhere else — pytest uses exactly one config file (the nearest one going up), so a second
table would silently take over for runs inside that directory.

See [CLAUDE.md](CLAUDE.md) for architecture rules and the reasoning behind the design
decisions.
