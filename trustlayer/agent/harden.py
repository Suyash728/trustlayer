"""L4c - the mutation loop.

Baseline the mutation score, take up to 3 survivors from different functions, ask the
agent for one minimal killing test each, discard anything that fails on unmodified
source, re-measure, repeat.

Plateau detection is the real stop condition, not the target. A loop that grinds twenty
iterations to move 2% is burning tokens for nothing, so two consecutive iterations
without improvement ends it and the report says "plateaued", not "succeeded".

The agent works in a temp copy of the repository. The user's repo is never written to -
not even a stash entry - and the run ends by printing a diff for review, applying nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from trustlayer.agent.baseline import tooling_interpreter
from trustlayer.agent.runtime import DEFAULT_ALLOWED_TOOLS, resolve_backend, run_agent
from trustlayer.agent.verify import count_tests, prune_to_passing
from trustlayer.agent.workspace import Workspace, diff_workspace, workspace
from trustlayer.mutation import MutationRun, Survivor, run_mutation


MAX_SURVIVORS_PER_ITERATION = 3
DEFAULT_MAX_ITERATIONS = 5
DEFAULT_TARGET_SCORE = 90.0
PLATEAU_LIMIT = 2  # consecutive iterations without improvement before stopping

# A ceiling on the whole run, not on one turn-set. `max_budget_usd` caps each run_agent
# call individually, and this loop makes up to MAX_SURVIVORS_PER_ITERATION of them per
# iteration - so without a cumulative stop a `--budget 2` run could spend many times that.
DEFAULT_MAX_TOTAL_COST_USD = 10.0

SYSTEM_PROMPT = (
    "You write pytest tests that kill mutants. You may read files, write test files, and "
    "run pytest. You cannot use the network or git; those tools are blocked. Never modify "
    "source files - only test files."
)


@dataclass(frozen=True)
class Iteration:
    number: int
    score_before: float
    score_after: float
    survivors_targeted: list[str] = field(default_factory=list)
    tests_written: int = 0
    tests_discarded: int = 0
    cost_usd: float = 0.0

    @property
    def improvement(self) -> float:
        return round(self.score_after - self.score_before, 1)


@dataclass(frozen=True)
class HardenResult:
    baseline_score: float
    final_score: float
    iterations: list[Iteration] = field(default_factory=list)
    stopped_because: str = ""
    diff: str = ""
    workspace_path: str = ""
    total_cost_usd: float = 0.0
    total_discarded: int = 0
    # A local backend costs nothing, so tokens are what it reports instead.
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    backend: str = "claude"
    error: str | None = None

    @property
    def improvement(self) -> float:
        return round(self.final_score - self.baseline_score, 1)


def pick_survivors(survivors: list[Survivor], limit: int = MAX_SURVIVORS_PER_ITERATION) -> list[Survivor]:
    """At most one survivor per function.

    Two mutants in the same function usually need the same test, so spending three agent
    turns on them buys one kill. Spreading across functions buys three.
    """
    chosen: list[Survivor] = []
    seen: set[str] = set()
    for survivor in survivors:
        key = survivor.function or survivor.id
        if key in seen:
            continue
        seen.add(key)
        chosen.append(survivor)
        if len(chosen) >= limit:
            break
    return chosen


def build_prompt(root: Path, survivor: Survivor, existing_tests: str) -> str:
    source_path = root / survivor.file
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError:
        source = "<source unavailable>"

    location = f"{survivor.file}:{survivor.line}" if survivor.line else survivor.file
    return f"""A mutation survived. Write one test that kills it.

Source file `{survivor.file}`:
```python
{source}
```

The surviving mutation, at {location}:
```diff
{survivor.diff}
```

Existing tests (do not duplicate these):
```python
{existing_tests}
```

Write ONE minimal test that:
- FAILS if the mutated line were applied (the `+` line in the diff above)
- PASSES against the source exactly as written above (the `-` line)

That distinction is the whole point: a test that passes under both versions kills nothing.
Pick inputs where the two versions actually produce different results.

Append the test to the existing test file for this module. Do not modify the source.
Run pytest afterwards to confirm it passes. Then stop."""


def harden(
    repository: Path | str,
    *,
    target_score: float = DEFAULT_TARGET_SCORE,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    timeout: float = 600,
    max_budget_usd: float = 2.0,
    max_total_cost_usd: float = DEFAULT_MAX_TOTAL_COST_USD,
    keep_workspace: bool = False,
    backend: str | None = None,
) -> HardenResult:
    """Raise a repository's mutation score, in a throwaway copy."""
    origin = Path(repository).resolve()

    with workspace(origin, keep=keep_workspace) as space:
        try:
            return _loop(
                space, target_score, max_iterations, timeout, max_budget_usd,
                max_total_cost_usd, backend,
            )
        except TimeoutError as error:
            return HardenResult(
                baseline_score=0.0,
                final_score=0.0,
                workspace_path=str(space.path),
                error=str(error),
            )


def _loop(
    space: Workspace,
    target_score: float,
    max_iterations: int,
    timeout: float,
    max_budget_usd: float,
    max_total_cost_usd: float,
    backend: str | None,
) -> HardenResult:
    root = space.path
    # The workspace excludes .venv, so mutmut and pytest must come from the original.
    mutmut = _mutmut_executable(space.source)
    interpreter = tooling_interpreter(space.source)
    baseline = run_mutation(root, executable=mutmut)

    iterations: list[Iteration] = []
    score = baseline.score
    current: MutationRun = baseline
    flat_streak = 0
    stopped = "reached the iteration limit"
    total_cost = 0.0
    total_input_tokens = total_output_tokens = 0
    total_discarded = 0
    budget_exhausted = False

    if score >= target_score:
        stopped = f"already at or above the {target_score}% target"

    for number in range(1, max_iterations + 1):
        if score >= target_score:
            stopped = f"reached the {target_score}% target"
            break

        targets = pick_survivors(current.survivors)
        if not targets:
            stopped = "no survivors left to target"
            break

        written = discarded = 0
        for survivor in targets:
            test_path = _test_file_for(root, survivor)
            before_count = count_tests(test_path) if test_path.is_file() else 0

            result = run_agent(
                build_prompt(root, survivor, _read(test_path)),
                cwd=root,
                allowed_tools=DEFAULT_ALLOWED_TOOLS,
                timeout=timeout,
                max_budget_usd=max_budget_usd,
                system_prompt=SYSTEM_PROMPT,
                backend=backend,
            )
            total_cost += result.cost_usd or 0.0
            total_input_tokens += result.input_tokens
            total_output_tokens += result.output_tokens
            if total_cost >= max_total_cost_usd:
                stopped = f"hit the ${max_total_cost_usd} total cost ceiling"
                budget_exhausted = True
                break
            if test_path.is_file():
                written += max(count_tests(test_path) - before_count, 0)

        # Anything that fails on unmodified source is a misunderstanding, not a kill.
        _, dropped = prune_to_passing(root, _test_files(root), interpreter=interpreter)
        discarded = len(dropped)
        total_discarded += discarded

        current = run_mutation(root, executable=mutmut)
        previous_score, score = score, current.score
        iterations.append(
            Iteration(
                number=number,
                score_before=previous_score,
                score_after=score,
                survivors_targeted=[s.id for s in targets],
                tests_written=written,
                tests_discarded=discarded,
                cost_usd=total_cost,
            )
        )

        if budget_exhausted:
            break

        if score <= previous_score:
            flat_streak += 1
            if flat_streak >= PLATEAU_LIMIT:
                stopped = f"plateaued: {PLATEAU_LIMIT} iterations with no improvement"
                break
        else:
            flat_streak = 0

    return HardenResult(
        baseline_score=baseline.score,
        final_score=score,
        iterations=iterations,
        stopped_because=stopped,
        diff=diff_workspace(space),
        workspace_path=str(space.path),
        total_cost_usd=round(total_cost, 4),
        total_input_tokens=total_input_tokens,
        total_output_tokens=total_output_tokens,
        backend=resolve_backend(backend),
        total_discarded=total_discarded,
    )


def _mutmut_executable(tools_root: Path) -> str:
    for candidate in (tools_root / ".venv" / "bin" / "mutmut", tools_root / "venv" / "bin" / "mutmut"):
        if candidate.is_file():
            return str(candidate.absolute())
    return "mutmut"


def _test_file_for(root: Path, survivor: Survivor) -> Path:
    stem = Path(survivor.file).stem
    candidate = root / "tests" / f"test_{stem}.py"
    if candidate.is_file():
        return candidate
    existing = sorted((root / "tests").glob("test_*.py")) if (root / "tests").is_dir() else []
    return existing[0] if existing else candidate


def _test_files(root: Path) -> list[Path]:
    tests = root / "tests"
    return sorted(tests.glob("test_*.py")) if tests.is_dir() else []


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return "<no existing tests>"
