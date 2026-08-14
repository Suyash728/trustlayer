"""L4b - test generation for untested code.

Reads a module, enumerates its public functions and branches, has the agent write a
pytest suite covering each branch, then runs it. Any test that fails against unmodified
source is discarded, not fixed.

The discard count is the honest signal and leads the report: a run that wrote 20 tests and
kept 6 tells you the agent misread the module, and that is worth knowing far more than
the fact that 6 tests exist.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from trustlayer.agent.runtime import DEFAULT_ALLOWED_TOOLS, AgentResult, run_agent
from trustlayer.agent.verify import count_tests, prune_to_passing, run_suite
from trustlayer.suite import inspect_suite


SYSTEM_PROMPT = (
    "You write pytest tests. You may read files, write test files, and run pytest. "
    "You cannot use the network or git; those tools are blocked and attempts are logged. "
    "Never modify source files - only test files."
)


@dataclass(frozen=True)
class FunctionProfile:
    name: str
    line: int
    branches: int


@dataclass(frozen=True)
class BaselineResult:
    module: str
    test_file: str
    functions: list[FunctionProfile] = field(default_factory=list)
    branches: int = 0
    tests_written: int = 0
    tests_kept: int = 0
    tests_discarded: int = 0
    discards: list[tuple[str, str]] = field(default_factory=list)
    coverage_before: float | None = None
    coverage_after: float | None = None
    agent: AgentResult | None = None
    error: str | None = None

    @property
    def discard_rate(self) -> float:
        return round(self.tests_discarded / self.tests_written * 100, 1) if self.tests_written else 0.0


def profile_module(path: Path) -> tuple[list[FunctionProfile], int]:
    """Public functions and their branch counts, by AST. Nothing is imported."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return [], 0

    profiles: list[FunctionProfile] = []
    for node in tree.body:
        # public surface only
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name.startswith("_"):
            continue
        profiles.append(FunctionProfile(node.name, node.lineno, _count_branches(node)))

    return profiles, sum(profile.branches for profile in profiles)


def _count_branches(node: ast.AST) -> int:
    """One per decision point, plus the implicit fall-through of the function itself."""
    branches = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp, ast.While, ast.For, ast.AsyncFor)):
            branches += 1
        elif isinstance(child, ast.BoolOp):
            branches += len(child.values) - 1
        elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
            branches += 1
        elif isinstance(child, ast.comprehension):
            branches += len(child.ifs)
    return branches


def build_prompt(module: Path, relative: str, profiles: list[FunctionProfile], test_file: str) -> str:
    source = module.read_text(encoding="utf-8")
    listing = "\n".join(
        f"  - {p.name}() at line {p.line}: {p.branches} branch(es)" for p in profiles
    )
    return f"""Write a pytest suite for `{relative}`.

Source:
```python
{source}
```

Public functions and their branch counts:
{listing}

Requirements:
- Write the suite to `{test_file}`.
- Cover every branch listed above. Aim for one focused test per branch.
- Test the real functions. Do not mock or patch anything in `{relative}`.
- Assert on actual computed values, not on the implementation restated.
- Every test must pass against the source exactly as written above. Do not modify the
  source. If you believe the source has a bug, still write the test to match the code's
  real behaviour and note the suspected bug in a comment.
- Run `pytest {test_file} -q` when done and make sure it is green.

Write the file, run the tests, and stop."""


def tooling_interpreter(tools_root: Path) -> list[str] | None:
    """The original repo's interpreter. The workspace copy has no .venv, so without
    this pytest is never found and the suite silently never runs."""
    for candidate in (tools_root / ".venv" / "bin" / "python", tools_root / "venv" / "bin" / "python"):
        if candidate.is_file():
            return [str(candidate.absolute())]
    return None


def generate_baseline(
    root: Path,
    module: Path,
    *,
    tools_root: Path | None = None,
    timeout: float = 600,
    max_budget_usd: float = 2.0,
) -> BaselineResult:
    """Generate a suite for `module` inside `root`, then keep only what passes."""
    root = Path(root)
    module = Path(module)
    relative = module.relative_to(root).as_posix() if module.is_absolute() else module.as_posix()
    absolute = root / relative

    if not absolute.is_file():
        return BaselineResult(module=relative, test_file="", error=f"{relative} does not exist")

    profiles, branches = profile_module(absolute)
    if not profiles:
        return BaselineResult(
            module=relative, test_file="", error=f"no public functions found in {relative}"
        )

    test_file = f"tests/test_{absolute.stem}_generated.py"
    (root / "tests").mkdir(exist_ok=True)

    before = inspect_suite(root).coverage_percent

    agent = run_agent(
        build_prompt(absolute, relative, profiles, test_file),
        cwd=root,
        allowed_tools=DEFAULT_ALLOWED_TOOLS,
        timeout=timeout,
        max_budget_usd=max_budget_usd,
        system_prompt=SYSTEM_PROMPT,
    )

    target = root / test_file
    if not target.is_file():
        return BaselineResult(
            module=relative,
            test_file=test_file,
            functions=profiles,
            branches=branches,
            coverage_before=before,
            agent=agent,
            error=agent.error or "the agent did not write a test file",
        )

    written = count_tests(target)
    interpreter = tooling_interpreter(Path(tools_root)) if tools_root else None
    suite, discarded = prune_to_passing(root, [target], interpreter=interpreter)
    kept = count_tests(target) if target.is_file() else 0

    if suite.error:
        # Reporting "0 discarded" when the suite never ran would be a fail-open: it would
        # claim every generated test was verified when none were.
        return BaselineResult(
            module=relative, test_file=test_file, functions=profiles, branches=branches,
            tests_written=written, coverage_before=before, agent=agent,
            error=f"could not verify generated tests: {suite.error}",
        )

    return BaselineResult(
        module=relative,
        test_file=test_file,
        functions=profiles,
        branches=branches,
        tests_written=written,
        tests_kept=kept,
        tests_discarded=written - kept,
        discards=discarded,
        coverage_before=before,
        coverage_after=inspect_suite(root).coverage_percent,
        agent=agent,
    )


def suite_is_green(root: Path) -> bool:
    return run_suite(Path(root)).ok
