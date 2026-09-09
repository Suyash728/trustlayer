"""The terminal UI.

Why this exists alongside `trustlayer ui`, which already browses the same database:

- The web UI loads Tailwind and HTMX from a CDN, so it is unstyled without a network. For a
  tool whose argument is that it works offline and deterministically, having the only visual
  surface degrade offline is the wrong shape. This one has no such dependency.
- `harden` is silent for minutes at a time. The mutation loop baselines, targets survivors,
  writes tests, discards failures and re-measures, and none of it is visible until the run
  ends. That is the gap a terminal UI is actually good at.

**Concurrency, and the reason for it.** Textual runs an asyncio event loop. `run_agent`
calls `anyio.run()`, which starts a *second* one, and nesting event loops raises;
`run_mutation` blocks on `subprocess.run`; the registry and Ollama clients block on
`urllib`. So every long operation runs in a thread worker (`@work(thread=True)`) and posts
its result back as a message. Nothing calls into those from the UI thread - the first is a
crash and the rest freeze the interface.

**Colour never carries meaning alone.** Severity gets a text label as well as a style, the
same rule the web UI follows. In a terminal the palette belongs to the user, not to us.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from trustlayer.presentation import rank, severity_counts, trend
from trustlayer.store import (
    get_run,
    latest_run_per_repo,
    previous_run,
    run_findings,
)


SEVERITY_STYLES = {"high": "red", "medium": "yellow", "low": "cyan"}


def severity_cell(severity: str) -> str:
    """A label plus a mark. The word is the meaning; the colour only reinforces it."""
    style = SEVERITY_STYLES.get(severity, "")
    mark = f"[{style}]■[/{style}]" if style else "■"
    return f"{mark} {severity.upper()}"


class ProjectsScreen(Screen):
    """One row per repository: its newest run, severity counts, and the trend."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "open_run", "Open run"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(self, db_path=None) -> None:
        super().__init__()
        self.db_path = db_path
        self._runs: dict[str, int] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="projects", cursor_type="row", zebra_stripes=True)
        yield Static("", id="projects-empty")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#projects", DataTable)
        table.add_columns("repository", "last run", "commit", "findings", "trend")
        self.action_refresh()

    def action_refresh(self) -> None:
        table = self.query_one("#projects", DataTable)
        table.clear()
        self._runs.clear()

        rows = latest_run_per_repo(self.db_path)
        for run in rows:
            movement = trend(run, previous_run(run, self.db_path))
            key = str(run.id)
            self._runs[key] = run.id
            table.add_row(
                run.repo_name,
                run.started_at[:19],
                run.short_sha + ("+dirty" if run.dirty else ""),
                severity_counts(run),
                f"{movement['symbol']} {movement['label']}".strip(),
                key=key,
            )

        note = self.query_one("#projects-empty", Static)
        note.update(
            "" if rows else "No runs recorded yet. Run `trustlayer audit <path>` first."
        )

    def action_open_run(self) -> None:
        table = self.query_one("#projects", DataTable)
        if not table.row_count:
            return
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        run_id = self._runs.get(str(key))
        if run_id is not None:
            self.app.push_screen(RunScreen(run_id, db_path=self.db_path))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        run_id = self._runs.get(str(event.row_key.value))
        if run_id is not None:
            self.app.push_screen(RunScreen(run_id, db_path=self.db_path))


class RunScreen(Screen):
    """Findings for one run, worst first, with the evidence for the selected row."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape,backspace", "app.pop_screen", "Back"),
    ]

    def __init__(self, run_id: int, db_path=None) -> None:
        super().__init__()
        self.run_id = run_id
        self.db_path = db_path
        self._findings: dict[str, object] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("", id="run-summary")
            with Horizontal():
                yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
                yield Static("", id="evidence", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        run = get_run(self.run_id, self.db_path)
        summary = self.query_one("#run-summary", Static)
        if run is None:
            summary.update(f"run {self.run_id} not found")
            return

        dirty = " +dirty" if run.dirty else ""
        summary.update(
            f"{run.repo_path}\n"
            f"#{run.id}  {run.started_at[:19]}  {run.short_sha}{dirty}  "
            f"{run.duration_s:.1f}s  |  {severity_counts(run)}"
        )

        table = self.query_one("#findings", DataTable)
        table.add_columns("severity", "location", "claim", "check")
        findings = sorted(
            run_findings(self.run_id, self.db_path),
            key=lambda f: (rank(f.severity), f.check, f.file, f.line),
        )
        for finding in findings:
            key = str(finding.id)
            self._findings[key] = finding
            table.add_row(
                severity_cell(finding.severity),
                f"{finding.file}:{finding.line}",
                finding.claim,
                finding.check,
                key=key,
            )

        self.query_one("#evidence", Static).update(
            "Select a finding to see the evidence." if findings else "No findings in this run."
        )
        if findings:
            self._show_evidence(str(findings[0].id))

    def _show_evidence(self, key: str) -> None:
        finding = self._findings.get(key)
        pane = self.query_one("#evidence", Static)
        if finding is None:
            pane.update("")
            return
        lines = [
            f"{finding.severity.upper()}  {finding.verdict}",
            f"{finding.file}:{finding.line}",
            "",
            *finding.evidence,
        ]
        pane.update("\n".join(lines) or "no evidence recorded")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value is not None:
            self._show_evidence(str(event.row_key.value))


class TrustLayerApp(App):
    """Read-only browser over the run database."""

    TITLE = "TrustLayer"
    CSS = """
    #projects, #findings { height: 1fr; }
    #findings { width: 3fr; }
    #evidence { width: 2fr; padding: 1 2; border-left: solid $panel; }
    #run-summary { padding: 0 1; height: auto; }
    #projects-empty { padding: 1 2; height: auto; }
    """
    BINDINGS: ClassVar[list[Binding]] = [Binding("q", "quit", "Quit")]

    def __init__(self, db_path: Path | str | None = None) -> None:
        super().__init__()
        self.db_path = db_path

    def on_mount(self) -> None:
        self.push_screen(ProjectsScreen(db_path=self.db_path))


def create_app(db_path: Path | str | None = None) -> TrustLayerApp:
    return TrustLayerApp(db_path=db_path)
