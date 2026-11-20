"""2.1: coverage during baseline/harden is measured fresh, from the original venv.

It used to read 0%: the workspace copy has no venv to summarize `.coverage` with, the copied
`.coverage` was the user's stale one anyway, and the CLI printed "unknown" as `0%`.
"""

from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from trustlayer.agent.baseline import tooling_interpreter
from trustlayer.agent.verify import CoverageMeasure, measure_coverage
from trustlayer.agent.workspace import EXCLUDED
from trustlayer.cli import _coverage_change


DEMO = Path(__file__).resolve().parents[1] / "demo-repos" / "pricing-py"
DEMO_PYTHON = tooling_interpreter(DEMO)

needs_demo_venv = pytest.mark.skipif(
    DEMO_PYTHON is None, reason="demo-repos/pricing-py has no .venv"
)


@pytest.fixture
def workspace_copy(tmp_path):
    """What `workspace()` hands the agent: a copy with no venv and the user's stale data."""
    copy = tmp_path / "pricing-py"
    shutil.copytree(DEMO, copy, ignore=EXCLUDED)
    return copy


@needs_demo_venv
def test_coverage_is_measured_with_the_original_interpreter(workspace_copy):
    measured = measure_coverage(workspace_copy, DEMO_PYTHON)

    assert measured.reason is None
    assert measured.percent == 100.0  # the demo repo's whole point: 100% lines, ~62% mutants


@needs_demo_venv
def test_a_stale_coverage_file_in_the_copy_is_never_read(workspace_copy):
    (workspace_copy / ".coverage").write_bytes(b"not a coverage database")

    assert measure_coverage(workspace_copy, DEMO_PYTHON).percent == 100.0


@needs_demo_venv
def test_measuring_writes_nothing_into_the_workspace(workspace_copy):
    before = sorted(p.relative_to(workspace_copy) for p in workspace_copy.rglob("*"))
    measure_coverage(workspace_copy, DEMO_PYTHON)
    after = sorted(p.relative_to(workspace_copy) for p in workspace_copy.rglob("*"))

    new = [p for p in after if p not in before and "__pycache__" not in p.parts]
    assert new == []


@needs_demo_venv
def test_coverage_moves_when_tests_are_removed(workspace_copy):
    """After != before is the property the old artifact read could never show."""
    for test in (workspace_copy / "tests").glob("test_*.py"):
        test.write_text("def test_nothing():\n    assert True\n")

    measured = measure_coverage(workspace_copy, DEMO_PYTHON)
    assert measured.percent is not None and measured.percent < 100.0


def test_no_interpreter_is_a_reason_not_a_zero(tmp_path):
    measured = measure_coverage(tmp_path, None)

    assert measured.percent is None
    assert "no virtualenv" in measured.reason


def test_an_interpreter_without_coverage_says_so(tmp_path, monkeypatch):
    from trustlayer.agent import verify
    from trustlayer.checks.base import ToolRun

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
