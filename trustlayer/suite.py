"""Cheap read of a repository's test-suite state.

Nothing here executes the test suite, imports the repo, or runs a collector. Test counts
come from the AST; coverage comes from artifacts the repo already produced. If no artifact
exists, coverage is reported as unavailable rather than guessed at.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from xml.etree import ElementTree

from trustlayer.checks.base import iter_files, run_tool


COVERAGE_TIMEOUT_SECONDS = 30
LOW_COVERAGE_THRESHOLD = 50.0

PYTHON_TEST_NAME_RE = re.compile(r"^test_.*\.py$|^.*_test\.py$")
JS_TEST_NAME_RE = re.compile(r".*\.(test|spec)\.(ts|tsx|js|jsx|mts|cts|mjs|cjs)$")
JS_TEST_CALL_RE = re.compile(r"(?<![\w.$])(?:it|test)\s*(?:\.\w+\s*)?\(")

COVERAGE_INTERPRETERS = (
    Path(".venv") / "bin" / "python",
    Path("venv") / "bin" / "python",
    Path(".venv") / "Scripts" / "python.exe",
)


@dataclass(frozen=True)
class SuiteState:
    test_files: int = 0
    tests: int = 0
    coverage_percent: float | None = None
    coverage_source: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def harden_suggested(self) -> bool:
        return self.coverage_percent is not None and self.coverage_percent < LOW_COVERAGE_THRESHOLD


def inspect_suite(root: Path) -> SuiteState:
    """Count test files and tests, then read coverage from an existing artifact."""
    python_files = list(iter_files(root, lambda p: bool(PYTHON_TEST_NAME_RE.match(p.name))))
    js_files = list(iter_files(root, lambda p: bool(JS_TEST_NAME_RE.match(p.name))))

    notes: list[str] = []
    tests = sum(_count_python_tests(path) for path in python_files)
    if js_files:
        tests += sum(_count_js_tests(path) for path in js_files)
        notes.append("TypeScript test count is a text scan, not a parse")
    if python_files:
        notes.append("parametrized cases counted once")

    percent, source, coverage_note = _read_coverage(root)
    if coverage_note:
        notes.append(coverage_note)

    return SuiteState(
        test_files=len(python_files) + len(js_files),
        tests=tests,
        coverage_percent=percent,
        coverage_source=source,
        notes=notes,
    )


def _count_python_tests(path: Path) -> int:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return 0

    count = 0
    for node in tree.body:
        if _is_test_function(node):
            count += 1
        elif isinstance(node, ast.ClassDef):
            count += sum(1 for child in node.body if _is_test_function(child))
    return count


def _is_test_function(node: ast.AST) -> bool:
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")


def _count_js_tests(path: Path) -> int:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return 0
    return len(JS_TEST_CALL_RE.findall(source))


def _read_coverage(root: Path) -> tuple[float | None, str | None, str | None]:
    """Read coverage from an artifact. Never runs the test suite."""
    for reader in (_from_cobertura, _from_coverage_json, _from_istanbul, _from_lcov, _from_dotcoverage):
        percent, source = reader(root)
        if percent is not None:
            return round(percent, 1), source, None

    unavailable = (
        "no coverage artifact found (looked for coverage.xml, coverage.json, "
        "coverage/coverage-summary.json, lcov.info, .coverage)"
    )
    return None, None, unavailable


def _from_cobertura(root: Path) -> tuple[float | None, str | None]:
    path = root / "coverage.xml"
    if not path.is_file():
        return None, None
    try:
        rate = ElementTree.parse(path).getroot().get("line-rate")
        return (float(rate) * 100, "coverage.xml") if rate is not None else (None, None)
    except (ElementTree.ParseError, OSError, TypeError, ValueError):
        return None, None


def _from_coverage_json(root: Path) -> tuple[float | None, str | None]:
    path = root / "coverage.json"
    if not path.is_file():
        return None, None
    try:
        totals = json.loads(path.read_text(encoding="utf-8")).get("totals") or {}
        percent = totals.get("percent_covered")
        return (float(percent), "coverage.json") if percent is not None else (None, None)
    except (OSError, ValueError, AttributeError):
        return None, None


def _from_istanbul(root: Path) -> tuple[float | None, str | None]:
    path = root / "coverage" / "coverage-summary.json"
    if not path.is_file():
        return None, None
    try:
        lines = (json.loads(path.read_text(encoding="utf-8")).get("total") or {}).get("lines") or {}
        percent = lines.get("pct")
        return (float(percent), "coverage/coverage-summary.json") if percent is not None else (None, None)
    except (OSError, ValueError, AttributeError):
        return None, None


def _from_lcov(root: Path) -> tuple[float | None, str | None]:
    path = root / "lcov.info"
    if not path.is_file():
        return None, None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, None

    found = sum(int(line[3:]) for line in text.splitlines() if line.startswith("LF:") and line[3:].isdigit())
    hit = sum(int(line[3:]) for line in text.splitlines() if line.startswith("LH:") and line[3:].isdigit())
    return (hit / found * 100, "lcov.info") if found else (None, None)


def _from_dotcoverage(root: Path) -> tuple[float | None, str | None]:
    """Ask the repo's own coverage to summarize an existing data file. No tests are run."""
    data_file = root / ".coverage"
    if not data_file.is_file():
        return None, None

    interpreter = next((root / c for c in COVERAGE_INTERPRETERS if (root / c).is_file()), None)
    if interpreter is None:
        return None, None

    # cwd is the repo, so both paths must be absolute or they resolve against it twice.
    # absolute(), never resolve(): .venv/bin/python is a symlink, and following it to the
    # real interpreter drops the venv's site-packages, so `-m coverage` stops existing.
    run = run_tool(
        [
            str(interpreter.absolute()),
            "-m",
            "coverage",
            "report",
            "--format=total",
            f"--data-file={data_file.absolute()}",
        ],
        cwd=root,
        timeout=COVERAGE_TIMEOUT_SECONDS,
    )
    total = run.stdout.strip().splitlines()[-1] if run.stdout.strip() else ""
    try:
        return float(total), ".coverage"
    except ValueError:
        return None, None
