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
from textual.widgets import Switch

from trustlayer.checks.base import CheckResult, Finding, Severity
from trustlayer.checks.runner import ALL_CHECKS, DEFAULT_CHECKS
from trustlayer.detect import profile_repository
from trustlayer.presentation import rank, severity_counts, trend
from trustlayer.report import Report
from trustlayer.store import list_runs, save_run
from trustlayer.suite import SuiteState
from trustlayer.tui import create_app
from trustlayer.tui.app import AuditScreen, ProjectsScreen, RunScreen, severity_cell
from trustlayer.tui.workers import run_audit


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


# ------------------------------------------------------------------ running audits


DIRTY = FIXTURES / "import-effects-dirty"


async def run_audit_screen(pilot, screen: AuditScreen):
    """Start a run and wait for the thread worker, rather than sleeping and hoping."""
    screen.action_start()
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()


@pytest.mark.anyio
async def test_an_audit_runs_from_the_ui_and_renders_its_findings(tmp_path):
    db = tmp_path / "runs.db"
    app = create_app(db_path=db)

    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(DIRTY), db_path=db)
        app.push_screen(screen)
        await pilot.pause()
        await run_audit_screen(pilot, screen)

        table = screen.query_one("#audit-findings")
        assert table.row_count == 6
        status = str(screen.query_one("#audit-status").content)
        assert "2 high" in status and "4 medium" in status


@pytest.mark.anyio
async def test_the_guard_does_not_block_the_first_run(tmp_path):
    """Regression: the flag was once named `_running`, which is a MessagePump internal
    Textual sets when the screen's pump starts - so the guard was always true and no audit
    ever launched, silently."""
    db = tmp_path / "runs.db"
    app = create_app(db_path=db)

    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(DIRTY), db_path=db)
        app.push_screen(screen)
        await pilot.pause()

        assert screen._audit_running is False
        await run_audit_screen(pilot, screen)
        assert screen.query_one("#audit-findings").row_count > 0


@pytest.mark.anyio
async def test_a_recorded_run_lands_in_the_database(tmp_path):
    db = tmp_path / "runs.db"
    app = create_app(db_path=db)

    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(DIRTY), db_path=db)
        app.push_screen(screen)
        await pilot.pause()
        await run_audit_screen(pilot, screen)

        assert "recorded as #" in str(screen.query_one("#audit-status").content)
        assert len(list_runs(db_path=db)) == 1


@pytest.mark.anyio
async def test_recording_can_be_switched_off(tmp_path):
    db = tmp_path / "runs.db"
    app = create_app(db_path=db)

    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(DIRTY), db_path=db)
        app.push_screen(screen)
        await pilot.pause()
        screen.query_one("#audit-save", Switch).value = False
        await run_audit_screen(pilot, screen)

        assert "recorded as #" not in str(screen.query_one("#audit-status").content)
        assert list_runs(db_path=db) == []


@pytest.mark.anyio
async def test_a_bad_path_is_reported_rather_than_crashing(tmp_path):
    app = create_app(db_path=tmp_path / "runs.db")

    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(tmp_path / "nope"), db_path=tmp_path / "runs.db")
        app.push_screen(screen)
        await pilot.pause()
        screen.action_start()
        await pilot.pause()

        assert "not a directory" in str(screen.query_one("#audit-status").content)
        assert screen._audit_running is False


@pytest.mark.anyio
async def test_the_interface_stays_responsive_while_a_run_is_in_flight(tmp_path):
    """The whole reason the work is threaded. A frozen UI is the failure this prevents."""
    import threading

    from trustlayer.tui import app as tui_app
    from trustlayer.tui.workers import AuditOutcome

    release = threading.Event()

    def slow_audit(*args, **kwargs):
        release.wait(timeout=10)  # hold the worker thread open
        return AuditOutcome()

    app = create_app(db_path=tmp_path / "runs.db")
    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(DIRTY), db_path=tmp_path / "runs.db")
        app.push_screen(screen)
        await pilot.pause()

        original = tui_app.run_audit
        tui_app.run_audit = slow_audit
        try:
            screen.action_start()
            await pilot.pause()
            assert screen._audit_running is True  # still working

            # The UI thread is free: a keypress is still processed while the worker blocks.
            await pilot.press("tab")
            await pilot.pause()
            assert app.is_running is True
        finally:
            release.set()
            await app.workers.wait_for_complete()
            tui_app.run_audit = original


@pytest.mark.anyio
async def test_all_checks_selects_the_opt_in_ones_too(tmp_path):
    captured = {}
    from trustlayer.tui import app as tui_app
    from trustlayer.tui.workers import AuditOutcome

    def capture(root, selected, **kwargs):
        captured["selected"] = selected
        return AuditOutcome()

    app = create_app(db_path=tmp_path / "runs.db")
    async with app.run_test() as pilot:
        screen = AuditScreen(path=str(DIRTY), db_path=tmp_path / "runs.db")
        app.push_screen(screen)
        await pilot.pause()
        screen.query_one("#audit-all", Switch).value = True

        original = tui_app.run_audit
        tui_app.run_audit = capture
        try:
            await run_audit_screen(pilot, screen)
        finally:
            tui_app.run_audit = original

    assert set(captured["selected"]) == set(ALL_CHECKS)


def test_progress_callbacks_cannot_change_a_verdict(tmp_path):
    """`on_result` and `on_status` receive what already happened and return nothing."""
    quiet = run_audit(DIRTY, list(DEFAULT_CHECKS), save=False, db_path=tmp_path / "a.db")
    noisy = run_audit(
        DIRTY,
        list(DEFAULT_CHECKS),
        save=False,
        db_path=tmp_path / "b.db",
        on_result=lambda result: None,
        on_status=lambda message: None,
    )

    assert quiet.report.exit_code == noisy.report.exit_code
    assert [f.claim for f in quiet.report.findings] == [f.claim for f in noisy.report.findings]
