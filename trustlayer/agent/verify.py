"""Run a generated suite against unmodified source and discard whatever fails.

This is the mechanical half of the agent layer. The agent proposes tests; this module
decides which survive, by running them. A generated test that fails against unmodified
source is evidence the agent misunderstood the code, so it is removed - never repaired.
Repairing it would launder a misunderstanding into the suite, and everything downstream
(coverage, mutation score) would inherit the lie.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
import re
import tempfile

from trustlayer.checks.base import run_tool


SUITE_TIMEOUT_SECONDS = 300

# `pytest -q --tb=no -rf` reports one line per failure:
#   FAILED tests/test_x.py::test_name - AssertionError: ...
#   ERROR  tests/test_x.py::test_name
FAILURE_RE = re.compile(r"^(?:FAILED|ERROR)\s+(?P<file>[^\s:]+)::(?P<test>[\w\[\]\-.]+)")
COLLECTION_ERROR_RE = re.compile(r"^ERROR\s+(?P<file>[^\s:]+)\s*$")


COVERAGE_REPORT_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class CoverageMeasure:
    """Line coverage measured by running the suite, or the reason it could not be."""

    percent: float | None = None
    reason: str | None = None  # set exactly when percent is None

    def render(self) -> str:
        if self.percent is None:
            return f"n/a ({self.reason})"
        return f"{self.percent:.1f}%"


def measure_coverage(
    root: Path, interpreter: list[str] | None, timeout: float = SUITE_TIMEOUT_SECONDS
) -> CoverageMeasure:
    """Run the suite under coverage.py and read the total. Never reads a stale artifact.

    The workspace copy carries whatever `.coverage` the user last produced, and reading it
    reports the user's old number before *and* after the agent ran - so this always measures
    fresh. The data file lives in its own temp directory: never in the user's repository,
    and never inside the workspace, where it would show up in the diff.

    `--fail-under=0` overrides a project's own `fail_under`, which would otherwise turn a
    low number into a non-zero exit and an unparseable report.
    """
    if interpreter is None:
        return CoverageMeasure(reason="no virtualenv in the original repository")

    with tempfile.TemporaryDirectory(prefix="trustlayer-coverage-") as scratch:
        data_file = Path(scratch) / ".coverage"
        run = run_tool(
            [
                *interpreter, "-m", "coverage", "run", f"--data-file={data_file}",
                "-m", "pytest", "-q", "--tb=no", "-p", "no:cacheprovider",
            ],
            cwd=root,
            timeout=timeout,
        )
        if run.error:
            return CoverageMeasure(reason=run.error)
        if "No module named coverage" in run.stderr:
            return CoverageMeasure(reason=f"coverage is not installed in {interpreter[0]}")
        if not data_file.is_file():
            return CoverageMeasure(reason="the suite produced no coverage data")

        report = run_tool(
            [
                *interpreter, "-m", "coverage", "report", "--format=total", "--fail-under=0",
                f"--data-file={data_file}",
            ],
            cwd=root,
            timeout=COVERAGE_REPORT_TIMEOUT_SECONDS,
        )
    lines = report.stdout.strip().splitlines()
    try:
        return CoverageMeasure(percent=float(lines[-1]))
    except (IndexError, ValueError):
        detail = (report.stderr.strip().splitlines() or [report.error or "no output"])[-1]
        return CoverageMeasure(reason=f"coverage report failed: {detail}")


@dataclass(frozen=True)
class SuiteRun:
    ok: bool
    failures: list[tuple[str, str]] = field(default_factory=list)  # (file, test)
    collection_errors: list[str] = field(default_factory=list)
    output: str = ""
    error: str | None = None


def run_suite(
    root: Path, timeout: float = SUITE_TIMEOUT_SECONDS, interpreter: list[str] | None = None
) -> SuiteRun:
    """Run the repository's pytest suite. A non-zero exit is data, not an exception.

    `interpreter` matters for workspace runs: the temp copy excludes .venv, so the
    caller must pass the ORIGINAL repo's interpreter or pytest will not be found and the
    suite would silently never run."""
    interpreter = interpreter or _interpreter(root)
    run = run_tool(
        [*interpreter, "-m", "pytest", "-q", "--tb=no", "-rf", "-p", "no:cacheprovider"],
        cwd=root,
        timeout=timeout,
    )
    if run.error:
        return SuiteRun(ok=False, error=run.error)

    combined = run.stdout + "\n" + run.stderr
    failures: list[tuple[str, str]] = []
    collection_errors: list[str] = []

    for line in combined.splitlines():
        stripped = line.strip()
        match = FAILURE_RE.match(stripped)
        if match:
            failures.append((match.group("file"), match.group("test")))
            continue
        collection = COLLECTION_ERROR_RE.match(stripped)
        if collection:
            collection_errors.append(collection.group("file"))

    return SuiteRun(
        ok=run.returncode == 0,
        failures=failures,
        collection_errors=collection_errors,
        output=combined,
    )


def _interpreter(root: Path) -> list[str]:
    """Prefer the repo's own interpreter. absolute(), never resolve(): resolving the
    .venv/bin/python symlink drops the venv's site-packages and pytest disappears."""
    for candidate in (root / ".venv" / "bin" / "python", root / "venv" / "bin" / "python"):
        if candidate.is_file():
            return [str(candidate.absolute())]
    return ["python3"]


def discard_failing_tests(path: Path, failing: set[str]) -> list[str]:
    """Remove the named test functions from a file. Returns what was actually removed.

    Names may carry a parametrize suffix (`test_x[case]`); the base name is what matches
    the AST node, so the whole parametrized function goes.
    """
    bases = {name.split("[", 1)[0] for name in failing}
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []

    removed: list[str] = []
    kept_body = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in bases:
            removed.append(node.name)
            continue
        if isinstance(node, ast.ClassDef):
            inner = [
                child
                for child in node.body
                if not (
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name in bases
                )
            ]
            removed.extend(
                child.name
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name in bases
            )
            if not inner:
                inner = [ast.Pass()]
            node.body = inner
        kept_body.append(node)

    if not removed:
        return []

    tree.body = kept_body
    try:
        path.write_text(ast.unparse(ast.fix_missing_locations(tree)) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        return []
    return removed


def count_tests(path: Path) -> int:
    """Count test functions in a file via AST. Nothing is imported or executed."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return 0

    total = 0
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            total += 1
        elif isinstance(node, ast.ClassDef):
            total += sum(
                1
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name.startswith("test")
            )
    return total


def prune_to_passing(
    root: Path,
    test_files: list[Path],
    timeout: float = SUITE_TIMEOUT_SECONDS,
    interpreter: list[str] | None = None,
):
    """Run the suite and discard failing tests until it is green or nothing is left.

    Returns (SuiteRun, discarded) where `discarded` is (file, test) pairs. Bounded by the
    number of test files so a pathological suite cannot loop forever.
    """
    discarded: list[tuple[str, str]] = []
    run = run_suite(root, timeout, interpreter)

    for _ in range(len(test_files) + 2):
        if run.ok or run.error:
            break

        # A file that fails to import cannot be pruned test-by-test; drop the whole file.
        for broken in run.collection_errors:
            target = root / broken
            if target.is_file() and target in test_files:
                discarded.append((broken, "<entire file: collection error>"))
                target.unlink()

        by_file: dict[str, set[str]] = {}
        for file, test in run.failures:
            by_file.setdefault(file, set()).add(test)

        removed_any = False
        for file, names in by_file.items():
            target = root / file
            if not target.is_file() or target not in test_files:
                continue  # never touch tests the agent did not write
            for name in discard_failing_tests(target, names):
                discarded.append((file, name))
                removed_any = True

        if not removed_any and not run.collection_errors:
            break
        run = run_suite(root, timeout, interpreter)

    return run, discarded
