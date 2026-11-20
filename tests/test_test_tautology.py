"""test-tautology: assertions that cannot fail. Silence first, as with every check."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from killscore.checks.base import Severity
from killscore.checks.test_tautology import check_test_tautology


FIXTURES = Path(__file__).parent / "fixtures"


def test_real_assertions_and_near_misses_are_silent():
    result = check_test_tautology(FIXTURES / "tautology-clean")

    assert result.skipped is False
    assert result.findings == []


def test_every_tautology_shape_is_reported_once():
    result = check_test_tautology(FIXTURES / "tautology-dirty")
    by_line = {f.line: (f.verdict, f.severity) for f in result.findings}

    assert by_line == {
        15: ("mock-auto-attribute", Severity.HIGH),
        20: ("uncalled-assertion", Severity.HIGH),
        25: ("uncalled-assertion", Severity.HIGH),
        29: ("unused-raises", Severity.HIGH),
        34: ("constant-assertion", Severity.HIGH),
        38: ("constant-assertion", Severity.HIGH),
        43: ("self-comparison", Severity.MEDIUM),
        48: ("always-true-comparison", Severity.HIGH),
    }


def test_the_mock_finding_names_the_real_method_and_the_version_split(tmp_path):
    result = check_test_tautology(FIXTURES / "tautology-dirty")
    awaited = next(f for f in result.findings if f.verdict == "mock-auto-attribute")
    assert "notifier.assert_awaited_once_with" in " ".join(awaited.evidence)
    assert "no Python version guards this name" in " ".join(awaited.evidence)

    (tmp_path / "test_x.py").write_text(
        "from unittest import mock\n\ndef test_a():\n    m = mock.Mock()\n"
        "    assert m.called_once_with(1)\n"
    )
    called = check_test_tautology(tmp_path).findings[0]
    assert called.verdict == "mock-auto-attribute"
    assert "3.12+ raises AttributeError" in " ".join(called.evidence)


def test_the_dirty_suite_really_passes_which_is_the_problem():
    """Ground truth: pytest itself reports these tautologies as passing tests."""
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-W", "ignore",
         str(FIXTURES / "tautology-dirty")],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert run.returncode == 0, run.stdout
    assert "8 passed" in run.stdout


def test_unittest_style_tautologies(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import unittest\n"
        "class T(unittest.TestCase):\n"
        "    def test_a(self):\n"
        "        x = 1\n"
        "        self.assertEqual(x, x)\n"
        "        self.assertTrue(True)\n"
        "        self.assertEqual(x, 1)\n"
    )
    result = check_test_tautology(tmp_path)

    assert {(f.line, f.verdict) for f in result.findings} == {
        (5, "self-comparison"), (6, "constant-assertion"),
    }


def test_only_collected_test_files_are_read(tmp_path):
    (tmp_path / "conftest.py").write_text("assert True\n")
    (tmp_path / "helpers.py").write_text("assert True\n")
    result = check_test_tautology(tmp_path)

    assert result.skipped is True


def test_a_bare_raises_name_is_not_assumed_to_be_pytest(tmp_path):
    (tmp_path / "test_x.py").write_text("from mylib import raises\n\ndef test_a():\n    raises(ValueError)\n")

    assert check_test_tautology(tmp_path).findings == []
