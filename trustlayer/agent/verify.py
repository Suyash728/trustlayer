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

from trustlayer.checks.base import run_tool


SUITE_TIMEOUT_SECONDS = 300

# `pytest -q --tb=no -rf` reports one line per failure:
#   FAILED tests/test_x.py::test_name - AssertionError: ...
#   ERROR  tests/test_x.py::test_name
FAILURE_RE = re.compile(r"^(?:FAILED|ERROR)\s+(?P<file>[^\s:]+)::(?P<test>[\w\[\]\-.]+)")
COLLECTION_ERROR_RE = re.compile(r"^ERROR\s+(?P<file>[^\s:]+)\s*$")


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
