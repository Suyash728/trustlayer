"""2.1: coverage during baseline/harden is measured fresh, from the original venv.

It used to read 0%: the workspace copy has no venv to summarize `.coverage` with, the copied
`.coverage` was the user's stale one anyway, and the CLI printed "unknown" as `0%`.
"""

from __future__ import annotations

from pathlib import Path
import sys
import textwrap

import pytest

from killscore.agent.verify import CoverageMeasure, measure_coverage
from killscore.cli import _coverage_change


# The suite's own interpreter has coverage and pytest (the dev group), which is exactly what
# `tooling_interpreter` hands `measure_coverage` from an original repo's .venv.
INTERPRETER = [sys.executable]


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


@pytest.fixture
def workspace_copy(tmp_path):
    """What `workspace()` hands the agent: a project with no venv of its own."""
    root = tmp_path / "project"
    _write(root, "pyproject.toml", """
        [tool.pytest.ini_options]
        testpaths = ["tests"]
        pythonpath = ["src"]

        [tool.coverage.run]
        source = ["src"]
    """)
    _write(root, "src/calc.py", """
        def add(a, b):
            return a + b


        def discount(price, percent):
            if percent >= 100:
                return 0
            return price - price * percent / 100
    """)
    _write(root, "tests/test_calc.py", """
        from calc import add, discount


        def test_add():
            assert add(2, 3) == 5


        def test_discount():
            assert discount(200, 50) == 100
            assert discount(10, 100) == 0
    """)
    return root


def test_coverage_is_measured_with_the_original_interpreter(workspace_copy):
    measured = measure_coverage(workspace_copy, INTERPRETER)

    assert measured.reason is None
    assert measured.percent == 100.0


def test_a_stale_coverage_file_in_the_copy_is_never_read(workspace_copy):
    (workspace_copy / ".coverage").write_bytes(b"not a coverage database")

    assert measure_coverage(workspace_copy, INTERPRETER).percent == 100.0


def test_measuring_writes_nothing_into_the_workspace(workspace_copy):
    before = sorted(p.relative_to(workspace_copy) for p in workspace_copy.rglob("*"))
    measure_coverage(workspace_copy, INTERPRETER)
    after = sorted(p.relative_to(workspace_copy) for p in workspace_copy.rglob("*"))

    new = [p for p in after if p not in before and "__pycache__" not in p.parts]
    assert new == []


def test_coverage_moves_when_tests_are_removed(workspace_copy):
    """After != before is the property the old artifact read could never show."""
    _write(workspace_copy, "tests/test_calc.py", """
        from calc import add


        def test_add():
            assert add(2, 3) == 5
    """)

    measured = measure_coverage(workspace_copy, INTERPRETER)
    assert measured.percent is not None and measured.percent < 100.0


def test_no_interpreter_is_a_reason_not_a_zero(tmp_path):
    measured = measure_coverage(tmp_path, None)

    assert measured.percent is None
    assert "no virtualenv" in measured.reason


def test_an_interpreter_without_coverage_says_so(tmp_path, monkeypatch):
    from killscore.agent import verify
    from killscore.checks.base import ToolRun

    monkeypatch.setattr(
        verify,
        "run_tool",
        lambda *a, **k: ToolRun(False, "", "/x/python: No module named coverage", 1),
    )
    measured = measure_coverage(tmp_path, ["/x/python"])

    assert measured.percent is None
    assert "not installed" in measured.reason


def test_unknown_coverage_never_renders_as_zero():
    unknown = CoverageMeasure(reason="no virtualenv in the original repository")

    assert "0%" not in _coverage_change(unknown, unknown)
    assert _coverage_change(CoverageMeasure(61.7), None) == "61.7% -> n/a"
