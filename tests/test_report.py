"""Report layer tests: exit-code contract, grouping order, JSON, colour, suite state."""

import io
import json
from pathlib import Path
import re

import pytest
from rich.console import Console
from typer.testing import CliRunner

from trustlayer.checks.base import CheckResult, Finding, Severity
from trustlayer.checks.fail_open import check_python_fail_open
from trustlayer.cli import app
from trustlayer.detect import profile_repository
from trustlayer.report import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_HIGH,
    EXIT_MEDIUM,
    Report,
    render_text,
    to_dict,
)
from trustlayer.suite import SuiteState, inspect_suite


FIXTURES = Path(__file__).parent / "fixtures"
DEMO_REPO = FIXTURES.parents[1] / "demo-repos" / "pricing-py"
runner = CliRunner()


def finding(severity, check="c", file="a.py", line=1, verdict="v"):
    return Finding(severity=severity, check=check, file=file, line=line, claim="x", verdict=verdict)


def build_report(root, results, suite=None):
    return Report(
        root=Path(root).resolve(),
        profile=profile_repository(root),
        results=results,
        suite=suite or SuiteState(),
    )


def render(report, **console_kwargs):
    buffer = io.StringIO()
    render_text(report, Console(file=buffer, force_terminal=True, width=100, **console_kwargs))
    return buffer.getvalue()


# ------------------------------------------------------------------ exit-code contract


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("failopen-dirty", EXIT_HIGH),
        ("report-medium", EXIT_MEDIUM),
        ("failopen-clean", EXIT_CLEAN),
    ],
)
def test_exit_code_is_driven_by_the_worst_severity(fixture, expected):
    result = runner.invoke(app, ["audit", str(FIXTURES / fixture), "--only", "fail-open"])

    assert result.exit_code == expected


def test_an_operational_error_never_looks_like_a_finding():
    """A bad path must not exit 2, or a hook cannot tell it from a high-severity finding."""
    result = runner.invoke(app, ["audit", str(FIXTURES / "does-not-exist")])

    assert result.exit_code == EXIT_ERROR


def test_an_unknown_check_is_an_operational_error():
    result = runner.invoke(app, ["audit", str(FIXTURES / "failopen-clean"), "--only", "nonsense"])

    assert result.exit_code == EXIT_ERROR


def test_only_and_all_cannot_be_combined():
    result = runner.invoke(app, ["audit", str(FIXTURES / "failopen-clean"), "--only", "fail-open", "--all"])

    assert result.exit_code == EXIT_ERROR


def test_exit_code_property_matches_the_counts():
    root = FIXTURES / "failopen-clean"
    assert build_report(root, [CheckResult("c", [finding(Severity.LOW)])]).exit_code == EXIT_CLEAN
    assert build_report(root, [CheckResult("c", [finding(Severity.MEDIUM)])]).exit_code == EXIT_MEDIUM
    assert build_report(root, [CheckResult("c", [finding(Severity.HIGH)])]).exit_code == EXIT_HIGH


# ------------------------------------------------------------------------- grouping


def test_groups_are_ordered_worst_first_and_sorted_within():
    report = build_report(
        FIXTURES / "failopen-clean",
        [
            CheckResult("zeta-low", [finding(Severity.LOW, check="zeta-low")]),
            CheckResult(
                "alpha-high",
                [
                    finding(Severity.MEDIUM, check="alpha-high", file="b.py", line=2),
                    finding(Severity.HIGH, check="alpha-high", file="a.py", line=9),
                ],
            ),
            CheckResult("beta-medium", [finding(Severity.MEDIUM, check="beta-medium")]),
        ],
    )

    assert [name for name, _ in report.groups] == ["alpha-high", "beta-medium", "zeta-low"]
    # Worst finding first inside the group, regardless of file order.
    assert [f.severity for f in report.groups[0][1]] == [Severity.HIGH, Severity.MEDIUM]


def test_a_check_with_no_findings_gets_no_group():
    report = build_report(FIXTURES / "failopen-clean", [CheckResult("empty", [])])

    assert report.groups == []


# ---------------------------------------------------------------------------- render


def test_only_the_severity_label_is_coloured():
    root = FIXTURES / "failopen-dirty"
    output = render(build_report(root, [check_python_fail_open(root)]))

    coloured = [line for line in output.splitlines() if "\x1b[" in line]
    assert coloured, "expected at least one coloured line"

    # Every coloured span must be a severity token: the label on a finding line, or a
    # count on the summary line. File paths, claims and evidence must never be styled.
    spans = re.findall(r"\x1b\[\d+m(.*?)\x1b\[0m", output)
    assert spans
    for span in spans:
        assert re.fullmatch(r"(?:\d+ )?(?:high|medium|low)\s*", span, re.IGNORECASE), span


def test_no_boxes_or_emoji_in_the_report():
    root = FIXTURES / "failopen-dirty"
    output = render(build_report(root, [check_python_fail_open(root)]))

    assert not set(output) & set("╭╮╰╯│─┏┓┗┛┃━┡┩╇┳┻╋")
    assert output.isascii(), "report must stay ASCII for CI logs and hooks"


def test_evidence_is_indented_under_its_finding():
    root = FIXTURES / "failopen-dirty"
    output = render(build_report(root, [check_python_fail_open(root)]))
    lines = output.splitlines()

    verdict_index = next(i for i, line in enumerate(lines) if line.strip() == "env-default-degrades-url")
    evidence = lines[verdict_index + 1]
    indent = len(evidence) - len(evidence.lstrip())
    verdict_indent = len(lines[verdict_index]) - len(lines[verdict_index].lstrip())
    assert indent > verdict_indent


def test_no_color_and_NO_COLOR_produce_identical_ansi_free_output(monkeypatch):
    root = FIXTURES / "failopen-dirty"
    report = build_report(root, [check_python_fail_open(root)])

    flagged = render(report, no_color=True)
    monkeypatch.setenv("NO_COLOR", "1")
    from_env = render(report)

    assert "\x1b[" not in flagged
    assert "\x1b[" not in from_env
    assert flagged == from_env


# ------------------------------------------------------------------------------ JSON


def test_json_output_is_parseable_and_carries_the_schema():
    result = runner.invoke(
        app, ["audit", str(FIXTURES / "failopen-dirty"), "--only", "fail-open", "--json"]
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == EXIT_HIGH
    assert payload["version"] == 1
    assert payload["exit_code"] == EXIT_HIGH
    assert payload["summary"]["high"] == 5  # 3 from app.py, 2 from app.ts
    assert payload["summary"]["total"] == len(payload["findings"])
    assert {"severity", "check", "file", "line", "claim", "verdict", "evidence"} <= set(
        payload["findings"][0]
    )
    assert {"test_files", "tests", "coverage_percent", "harden_suggested"} <= set(payload["suite"])


def test_json_stdout_contains_nothing_but_json():
    result = runner.invoke(
        app, ["audit", str(FIXTURES / "failopen-dirty"), "--only", "fail-open", "--json"]
    )

    assert result.stdout.lstrip().startswith("{")
    assert result.stdout.rstrip().endswith("}")


def test_to_dict_reports_skipped_checks():
    report = build_report(
        FIXTURES / "failopen-clean",
        [CheckResult("composed:vulture", skipped=True, skip_reason="vulture is not installed")],
    )
    payload = to_dict(report)

    assert payload["checks"][0]["skipped"] is True
    assert payload["checks"][0]["skip_reason"] == "vulture is not installed"


# ------------------------------------------------------------------------ suite state


def test_tests_are_counted_from_the_ast_without_executing_anything():
    suite = inspect_suite(FIXTURES / "report-lowcov")

    assert suite.test_files == 1
    assert suite.tests == 1


def test_coverage_is_read_from_an_existing_cobertura_report():
    suite = inspect_suite(FIXTURES / "report-lowcov")

    assert suite.coverage_percent == 33.3
    assert suite.coverage_source == "coverage.xml"
    assert suite.harden_suggested is True


def test_coverage_is_read_from_an_existing_dotcoverage_without_running_tests():
    suite = inspect_suite(DEMO_REPO)

    assert suite.coverage_percent == 100.0
    assert suite.coverage_source == ".coverage"
    assert suite.harden_suggested is False


def test_missing_coverage_is_reported_as_unavailable_not_guessed():
    suite = inspect_suite(FIXTURES / "failopen-clean")

    assert suite.coverage_percent is None
    assert any("no coverage artifact" in note for note in suite.notes)


def test_the_harden_suggestion_appears_only_below_the_threshold():
    low = build_report(
        FIXTURES / "report-lowcov", [], SuiteState(1, 1, 33.3, "coverage.xml", [])
    )
    high = build_report(FIXTURES / "report-lowcov", [], SuiteState(1, 1, 90.0, "coverage.xml", []))

    assert "trustlayer harden" in render(low, no_color=True)
    assert "trustlayer harden" not in render(high, no_color=True)
