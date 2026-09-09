"""Terminal UI tests, driven headlessly through Textual's Pilot.

Verified against textual 8.2.8: `App.run_test()` is an async context manager yielding a
`Pilot` with `press`, `click` and `pause`. No terminal, no snapshots, so this runs in CI
alongside everything else.

The database is always injected. `tests/conftest.py` already redirects the default path, but
these tests build their own runs and assert on them, so they pass `db_path` explicitly.
"""

from pathlib import Path
from typing import ClassVar

import pytest

from trustlayer.checks.base import CheckResult, Finding, Severity
from trustlayer.detect import profile_repository
from trustlayer.presentation import rank, severity_counts, trend
from trustlayer.report import Report
from trustlayer.store import save_run
from trustlayer.suite import SuiteState
from trustlayer.tui import create_app
from trustlayer.tui.app import ProjectsScreen, RunScreen, severity_cell


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def finding(severity=Severity.HIGH, claim="thing()", verdict="gate-fails-open", line=12):
    return Finding(
        severity=severity,
        check="fail-open:python",
        file="app.py",
        line=line,
        claim=claim,
        verdict=verdict,
        evidence=["the source line", "why it matters"],
    )


def seeded(tmp_path: Path, findings=None) -> Path:
    """A database with one recorded run against a real fixture repository."""
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-dirty"
    report = Report(
        root=root.resolve(),
        profile=profile_repository(root),
        results=[CheckResult("fail-open:python", findings if findings is not None else [finding()])],
        suite=SuiteState(),
    )
    save_run(report, 0.4, db_path=db)
    return db


# ------------------------------------------------------------------ shared helpers


def test_both_surfaces_share_one_definition_of_a_trend():
    """Two answers to "did this get worse" that disagree is worse than either alone."""
    from trustlayer.ui import app as web

    assert web._trend is trend
    assert web._rank is rank


def test_severity_is_never_carried_by_colour_alone():
    """In a terminal the palette belongs to the user, so the word has to be there too."""
    for severity in ("high", "medium", "low"):
        cell = severity_cell(severity)
        assert severity.upper() in cell


def test_an_unknown_severity_still_renders_a_label():
    assert "MYSTERY" in severity_cell("mystery")


def test_severity_counts_reads_worst_first():
    class _Run:
        counts: ClassVar[dict[str, int]] = {"high": 2, "medium": 0, "low": 1}

    assert severity_counts(_Run()) == "2 high  0 medium  1 low"


# ---------------------------------------------------------------------- the app


@pytest.mark.anyio
async def test_the_projects_screen_lists_recorded_runs(tmp_path):
    app = create_app(db_path=seeded(tmp_path))

    async with app.run_test() as pilot:
        table = pilot.app.screen.query_one("#projects")
        assert table.row_count == 1
        assert "failopen-dirty" in str(table.get_row_at(0)[0])


@pytest.mark.anyio
async def test_an_empty_database_says_so_rather_than_showing_a_bare_table(tmp_path):
    app = create_app(db_path=tmp_path / "empty.db")

    async with app.run_test() as pilot:
        note = pilot.app.screen.query_one("#projects-empty")
        assert "No runs recorded" in str(note.content)


@pytest.mark.anyio
async def test_opening_a_run_shows_its_findings_and_evidence(tmp_path):
    app = create_app(db_path=seeded(tmp_path))

    async with app.run_test() as pilot:
        await pilot.press("enter")
        await pilot.pause()

        assert isinstance(pilot.app.screen, RunScreen)
        table = pilot.app.screen.query_one("#findings")
        assert table.row_count == 1
        evidence = str(pilot.app.screen.query_one("#evidence").content)
        assert "the source line" in evidence
        assert "gate-fails-open" in evidence


@pytest.mark.anyio
async def test_escape_returns_to_the_project_list(tmp_path):
    app = create_app(db_path=seeded(tmp_path))

    async with app.run_test() as pilot:
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(pilot.app.screen, RunScreen)

        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(pilot.app.screen, ProjectsScreen)


@pytest.mark.anyio
async def test_findings_are_ordered_worst_first(tmp_path):
    db = seeded(
        tmp_path,
        findings=[
            finding(severity=Severity.LOW, claim="low()", line=1),
            finding(severity=Severity.HIGH, claim="high()", line=2),
            finding(severity=Severity.MEDIUM, claim="medium()", line=3),
        ],
    )
    app = create_app(db_path=db)

    async with app.run_test() as pilot:
        await pilot.press("enter")
        await pilot.pause()

        table = pilot.app.screen.query_one("#findings")
        severities = [str(table.get_row_at(i)[0]) for i in range(table.row_count)]
        assert "HIGH" in severities[0]
        assert "MEDIUM" in severities[1]
        assert "LOW" in severities[2]


@pytest.mark.anyio
async def test_a_run_with_no_findings_says_so(tmp_path):
    app = create_app(db_path=seeded(tmp_path, findings=[]))

    async with app.run_test() as pilot:
        await pilot.press("enter")
        await pilot.pause()

        assert "No findings" in str(pilot.app.screen.query_one("#evidence").content)


@pytest.mark.anyio
async def test_a_missing_run_is_reported_rather_than_crashing(tmp_path):
    app = create_app(db_path=tmp_path / "empty.db")

    async with app.run_test() as pilot:
        pilot.app.push_screen(RunScreen(999, db_path=tmp_path / "empty.db"))
        await pilot.pause()

        assert "not found" in str(pilot.app.screen.query_one("#run-summary").content)


@pytest.mark.anyio
async def test_quitting_exits_cleanly(tmp_path):
    app = create_app(db_path=seeded(tmp_path))

    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()

    assert app.is_running is False


# ------------------------------------------------------------------------- CLI


def test_the_tui_command_is_registered():
    from trustlayer.cli import app as cli

    names = {command.name or command.callback.__name__ for command in cli.registered_commands}
    assert "tui" in names
