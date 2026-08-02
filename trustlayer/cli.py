"""TrustLayer command line interface."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Annotated

from rich.console import Console
from rich.text import Text
import typer

from trustlayer.checks.api_resolution import check_api_resolution
from trustlayer.checks.base import CheckResult, Finding
from trustlayer.checks.composed import check_composed
from trustlayer.checks.fail_open import check_fail_open
from trustlayer.checks.stale_models import check_stale_models, load_registry
from trustlayer.detect import profile_repository
from trustlayer.report import EXIT_ERROR, Report, render_json, render_registry, render_text
from trustlayer.store import diff_runs, list_runs, save_run
from trustlayer.suite import inspect_suite


# The callback keeps Typer in subcommand mode, so the CLI is `trustlayer audit <path>`
# rather than collapsing to `trustlayer <path>` when only one command is registered.
app = typer.Typer(add_completion=False, help="Prove whether AI-written tests catch bugs.")

DEFAULT_CHECKS = ("stale-models", "fail-open")
OPT_IN_CHECKS = ("api-resolution", "composed")
ALL_CHECKS = DEFAULT_CHECKS + OPT_IN_CHECKS

DURATION_RE = re.compile(r"^(?P<count>\d+)\s*(?P<unit>[dwmy]?)$", re.IGNORECASE)
UNIT_DAYS = {"": 1, "d": 1, "w": 7, "m": 30, "y": 365}


@app.callback()
def main() -> None:
    """TrustLayer."""


def _fail(message: str) -> typer.Exit:
    """Operational errors exit 3, so they can never be read as a severity verdict."""
    Console(stderr=True).print(f"error: {message}")
    return typer.Exit(code=EXIT_ERROR)


@app.command()
def audit(
    # No `exists=True`: Typer would exit 2 on a bad path, which is the "high severity" code.
    path: Annotated[Path, typer.Argument(help="Repository to audit.")],
    only: Annotated[
        str | None,
        typer.Option("--only", help=f"Run exactly one check. One of: {', '.join(ALL_CHECKS)}."),
    ] = None,
    run_all: Annotated[bool, typer.Option("--all", help="Run every check, including the opt-in ones.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output on stdout.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour. NO_COLOR is also honoured.")] = False,
    warn_expiring_within: Annotated[
        str | None,
        typer.Option("--warn-expiring-within", metavar="90d", help="Also flag models retiring within this window."),
    ] = None,
    no_save: Annotated[bool, typer.Option("--no-save", help="Do not record this run in ~/.trustlayer/runs.db.")] = False,
) -> None:
    """Audit a repository and report findings by severity.

    Exit codes: 0 clean, 1 medium findings, 2 high findings, 3 operational error. The first
    three are what a pre-commit hook branches on.

    `api-resolution` and `composed` are opt-in: the first imports code from the audited
    repository's environment, the second shells out to linters.
    """
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")

    try:
        selected = _selected_checks(only, run_all)
        warn_days = _parse_duration(warn_expiring_within)
    except ValueError as error:
        raise _fail(str(error)) from error

    started = time.monotonic()
    try:
        profile = profile_repository(path)
        results = _run_checks(path, selected, warn_days)
        suite = inspect_suite(path)
    except OSError as error:
        raise _fail(f"could not audit {path}: {error}") from error
    duration = time.monotonic() - started

    report = Report(root=path.resolve(), profile=profile, results=results, suite=suite)

    if not no_save:
        try:
            save_run(report, duration)
        except (OSError, sqlite3.Error) as error:
            # Persistence is a convenience; failing to record must not change the verdict
            # a hook branches on, so this is a warning on stderr, not an exit code.
            Console(stderr=True).print(f"warning: could not record run: {error}")

    if as_json:
        # stdout carries JSON and nothing else, so it stays pipeable.
        print(render_json(report))
    else:
        render_text(report, Console(no_color=no_color))

    raise typer.Exit(code=report.exit_code)


def _run_checks(root: Path, selected: list[str], warn_days: int | None) -> list[CheckResult]:
    results: list[CheckResult] = []

    if "stale-models" in selected:
        results.append(check_stale_models(root, warn_within_days=warn_days))
    if "fail-open" in selected:
        results.extend(check_fail_open(root))
    if "api-resolution" in selected:
        results.extend(check_api_resolution(root))
    if "composed" in selected:
        native: list[Finding] = [f for result in results for f in result.findings]
        results.extend(check_composed(root, native))

    return results


def _selected_checks(only: str | None, run_all: bool) -> list[str]:
    if only and run_all:
        raise ValueError("--only and --all cannot be combined")
    if run_all:
        return list(ALL_CHECKS)
    if only is None:
        return list(DEFAULT_CHECKS)
    if only not in ALL_CHECKS:
        raise ValueError(f"unknown check {only!r}. Choose from: {', '.join(ALL_CHECKS)}")
    return [only]


def _parse_duration(value: str | None) -> int | None:
    """Accepts 90, 90d, 12w, 6m, 1y."""
    if value is None:
        return None
    match = DURATION_RE.match(value.strip())
    if not match:
        raise ValueError(f"could not read duration {value!r}; use a form like 90d, 12w, 6m")
    return int(match.group("count")) * UNIT_DAYS[match.group("unit").lower()]


@app.command()
def models(
    list_: Annotated[
        bool, typer.Option("--list", help="Print the deprecation registry with dates and sources.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour. NO_COLOR is also honoured.")] = False,
) -> None:
    """Inspect the model deprecation registry."""
    if not list_:
        raise _fail("nothing to do; use `trustlayer models --list`")

    try:
        registry = load_registry()
    except OSError as error:
        raise _fail(f"could not read the registry: {error}") from error

    render_registry(registry, Console(no_color=no_color), today=datetime.now(tz=UTC).date())



@app.command()
def baseline(
    path: Annotated[Path, typer.Argument(help="Repository containing the module.")],
    module: Annotated[str, typer.Option("--module", help="Module to generate tests for.")],
    budget: Annotated[float, typer.Option("--budget", help="Max USD for the run.")] = 2.0,
    timeout: Annotated[float, typer.Option("--timeout", help="Seconds per agent turn-set.")] = 600,
) -> None:
    """Generate a pytest suite for an untested module, discarding whatever fails."""
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")

    from trustlayer.agent.baseline import generate_baseline
    from trustlayer.agent.workspace import diff_workspace, workspace

    console = Console()
    with workspace(path) as space:
        result = generate_baseline(
            space.path, space.path / module, tools_root=path,
            timeout=timeout, max_budget_usd=budget
        )
        diff = diff_workspace(space)

    if result.error:
        console.print(f"[red]baseline failed:[/red] {result.error}")
        raise typer.Exit(code=EXIT_ERROR)

    console.print(f"module        {result.module}")
    console.print(f"functions     {len(result.functions)}  |  branches {result.branches}")
    console.print(f"tests written {result.tests_written}")
    console.print(f"tests kept    {result.tests_kept}")
    console.print(
        f"[bold yellow]tests DISCARDED {result.tests_discarded}"
        f"  ({result.discard_rate}% of written)[/bold yellow]"
    )
    for file, name in result.discards:
        console.print(f"  - {file}::{name}")
    console.print(
        f"coverage      {result.coverage_before or 0:.0f}% -> {result.coverage_after or 0:.0f}%"
    )
    if result.agent and result.agent.denied:
        console.print(f"denied tools  {len(result.agent.denied)}")
        for denial in result.agent.denied:
            console.print(f"  - {denial}")
    console.print("\n--- diff for review (nothing applied) ---")
    console.print(diff or "(no changes)")


@app.command()
def harden(
    path: Annotated[Path, typer.Argument(help="Repository to harden.")],
    target: Annotated[float, typer.Option("--target", help="Mutation score to reach.")] = 90.0,
    max_iterations: Annotated[int, typer.Option("--max-iterations")] = 5,
    budget: Annotated[float, typer.Option("--budget", help="Max USD per agent turn-set.")] = 2.0,
    keep_workspace: Annotated[bool, typer.Option("--keep-workspace")] = False,
) -> None:
    """Raise a repository's mutation score. Runs in a temp copy; applies nothing."""
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")

    from trustlayer.agent.harden import harden as run_harden

    console = Console()
    result = run_harden(
        path,
        target_score=target,
        max_iterations=max_iterations,
        max_budget_usd=budget,
        keep_workspace=keep_workspace,
    )

    if result.error:
        console.print(f"[red]harden failed:[/red] {result.error}")
        raise typer.Exit(code=EXIT_ERROR)

    console.print(f"baseline score  {result.baseline_score}%")
    for step in result.iterations:
        arrow = f"{step.score_before}% -> {step.score_after}%"
        console.print(
            f"  iteration {step.number}  {arrow:>18}  ({step.improvement:+}%)"
            f"  targeted {len(step.survivors_targeted)}"
            f"  written {step.tests_written}  discarded {step.tests_discarded}"
        )
    console.print(f"final score     {result.final_score}%  ({result.improvement:+}%)")
    console.print(f"[bold]stopped[/bold]         {result.stopped_because}")
    console.print(f"tests discarded {result.total_discarded}")
    console.print(f"cost            ${result.total_cost_usd}")
    console.print("\n--- diff for review (nothing applied) ---")
    console.print(result.diff or "(no changes)")
if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())


SEVERITY_STYLE = {"high": "red", "medium": "yellow", "low": "cyan"}


def _counts_cell(counts: dict) -> Text:
    cell = Text()
    for index, name in enumerate(("high", "medium", "low")):
        if index:
            cell.append("  ")
        value = counts.get(name, 0)
        cell.append(f"{value} {name}", style=SEVERITY_STYLE[name] if value else "")
    return cell


@app.command()
def history(
    path: Annotated[Path, typer.Argument(help="Repository to show history for.")],
    limit: Annotated[int, typer.Option("-n", "--limit", help="How many runs to show.")] = 10,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Show the last N recorded runs for a repository."""
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")

    console = Console(no_color=no_color)
    try:
        runs = list_runs(path, limit=limit)
    except sqlite3.Error as error:
        raise _fail(f"could not read the run database: {error}") from error

    if not runs:
        # An empty history is a fact, not a failure - exit 0 so a script can branch on it.
        console.print(Text(f"no runs recorded for {path.resolve()}"))
        return

    console.print(Text(f"{path.resolve()}  |  {len(runs)} run(s)"))
    console.print()
    for run in runs:
        line = Text(f"  #{run.id:<4} {run.started_at[:19]}  {run.short_sha}")
        if run.dirty:
            line.append("+dirty", style="yellow")
        line.append(f"  {run.duration_s:5.1f}s  ")
        line.append_text(_counts_cell(run.counts))
        console.print(line)


@app.command()
def diff(
    path: Annotated[Path, typer.Argument(help="Repository to diff.")],
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Show findings that appeared or disappeared since the previous run."""
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")

    console = Console(no_color=no_color)
    try:
        runs = list_runs(path, limit=2)
    except sqlite3.Error as error:
        raise _fail(f"could not read the run database: {error}") from error

    if len(runs) < 2:
        console.print(Text(f"need two runs to diff; {len(runs)} recorded for {path.resolve()}"))
        return

    latest, prior = runs[0], runs[1]
    appeared, disappeared = diff_runs(prior.id, latest.id)

    console.print(Text(f"#{prior.id} {prior.short_sha}  ->  #{latest.id} {latest.short_sha}"))
    console.print()

    if not appeared and not disappeared:
        console.print(Text("no change"))
        return

    for label, findings, style in (("appeared", appeared, "red"), ("disappeared", disappeared, "green")):
        if not findings:
            continue
        header = Text(f"{label} ({len(findings)})", style=style)
        console.print(header)
        for finding in findings:
            row = Text("  ")
            row.append(f"{finding.severity.upper():<7}", style=SEVERITY_STYLE.get(finding.severity, ""))
            row.append(f"{finding.file}:{finding.line}  {finding.claim}")
            console.print(row)
            console.print(Text(f"         {finding.check}  {finding.verdict}"))
        console.print()


@app.command()
def ui(
    port: Annotated[int, typer.Option("--port", help="Port to serve on.")] = 7777,
    host: Annotated[str, typer.Option("--host", help="Interface to bind.")] = "127.0.0.1",
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Do not open a browser.")] = False,
) -> None:
    """Serve the local run browser. Read-only: it cannot trigger a run."""
    import threading
    import webbrowser

    import uvicorn

    from trustlayer.ui import create_app

    url = f"http://{host}:{port}"
    Console().print(f"trustlayer ui  {url}   (ctrl-c to stop)")

    if not no_browser:
        # Open after a short delay so the server is listening when the tab loads.
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    uvicorn.run(create_app(), host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
