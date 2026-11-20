"""TrustLayer command line interface."""

from __future__ import annotations

from dataclasses import replace
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

from trustlayer.checks.runner import ALL_CHECKS, run_checks, select
from trustlayer.checks.slopsquat import scan, scan_findings
from trustlayer.checks.stale_models import load_registry
from trustlayer.config import apply_baseline, load_baseline, load_config
from trustlayer.detect import profile_repository
from trustlayer.report import (
    DEFAULT_FAIL_ON,
    EXIT_ERROR,
    FAIL_ON_LEVELS,
    Report,
    deps_exit_code,
    render_deps,
    render_deps_json,
    render_json,
    render_registry,
    render_text,
)
from trustlayer.sarif import render_sarif, to_sarif
from trustlayer.store import diff_runs, list_runs, save_run
from trustlayer.suite import inspect_suite


# The callback keeps Typer in subcommand mode, so the CLI is `trustlayer audit <path>`
# rather than collapsing to `trustlayer <path>` when only one command is registered.
app = typer.Typer(add_completion=False, help="Prove whether AI-written tests catch bugs.")

OUTPUT_FORMATS = ("text", "json", "sarif")
DURATION_RE = re.compile(r"^(?P<count>\d+)\s*(?P<unit>[dwmy]?)$", re.IGNORECASE)
UNIT_DAYS = {"": 1, "d": 1, "w": 7, "m": 30, "y": 365}


def _print_version(value: bool) -> None:
    if value:
        from trustlayer import __version__

        print(f"trustlayer {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Print the version."),
    ] = False,
) -> None:
    """TrustLayer."""


def main_entry() -> int:
    """The console-script entry point.

    Typer exits 1 on an uncaught exception, and 1 means "medium findings" to a hook. A crash
    is an operational failure, so it is mapped to 3 here with a one-line reason on stderr.
    """
    try:
        # Without standalone mode, a `typer.Exit(code)` comes back as the return value.
        returned = app(standalone_mode=False)
    except typer.Exit as exit_:
        return exit_.exit_code
    except typer.Abort:
        Console(stderr=True).print("aborted")
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR
    except Exception as error:  # noqa: BLE001 - the whole point is to catch everything
        if callable(getattr(error, "show", None)) and isinstance(getattr(error, "exit_code", None), int):
            # A Click usage error (bad option, missing argument). Typer vendors Click as a
            # private module whose layout changed between 0.27 and 0.29, so it is matched by
            # Click's documented interface rather than imported. Click exits 2 for these,
            # and 2 means "high findings" here, so it is remapped.
            error.show()
            return EXIT_ERROR
        Console(stderr=True).print(
            f"error: trustlayer crashed: {type(error).__name__}: {error}", markup=False
        )
        return EXIT_ERROR
    return returned if isinstance(returned, int) else 0


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
    output_format: Annotated[
        str | None,
        typer.Option("--format", metavar="text|json|sarif", help="Output format. --json is --format json."),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", metavar="high|medium|low", help="Lowest severity that fails (exit 1/2)."),
    ] = DEFAULT_FAIL_ON,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="Hide findings already in this `--format json` output."),
    ] = None,
) -> None:
    """Audit a repository and report findings by severity.

    Exit codes: 0 clean, 1 medium findings, 2 high findings, 3 operational error. The first
    three are what a pre-commit hook branches on.

    `api-resolution`, `composed`, `slopsquat` and `pinned-version` are opt-in:
    `api-resolution` imports code from the audited repository's environment, `composed`
    shells out to linters, and `slopsquat` and `pinned-version` contact package registries.

    `[tool.trustlayer] exclude = [...]` in pyproject.toml (or `.trustlayer.toml`) and an
    inline `# trustlayer: ignore[check]` hide findings; the count hidden is always printed.
    """
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")

    try:
        selected = select(only, run_all)
        warn_days = _parse_duration(warn_expiring_within)
        fmt = _output_format(output_format, as_json)
        _check_fail_on(fail_on)
        config = load_config(path)
        known = load_baseline(baseline) if baseline is not None else None
    except ValueError as error:  # ConfigError is a ValueError
        raise _fail(str(error)) from error

    started = time.monotonic()
    try:
        profile = profile_repository(path)
        results = run_checks(path, selected, warn_days, profile, config)
        suite = inspect_suite(path)
    except OSError as error:
        raise _fail(f"could not audit {path}: {error}") from error
    duration = time.monotonic() - started

    report = Report(
        root=path.resolve(), profile=profile, results=results, suite=suite, fail_on=fail_on
    )

    if not no_save:
        try:
            save_run(report, duration)
        except (OSError, sqlite3.Error) as error:
            # Persistence is a convenience; failing to record must not change the verdict
            # a hook branches on, so this is a warning on stderr, not an exit code.
            Console(stderr=True).print(f"warning: could not record run: {error}")

    if known is not None:
        # The database keeps the full run; only what is shown and the exit code are filtered,
        # so `history` and `diff` still see every finding.
        filtered, hidden = apply_baseline(report.results, known)
        report = replace(report, results=filtered, baselined=hidden, baseline_source=str(baseline))

    # stdout carries the machine format and nothing else, so it stays pipeable.
    if fmt == "json":
        print(render_json(report))
    elif fmt == "sarif":
        notes = [f"{report.baselined} known finding(s) hidden by baseline {baseline}"] if report.baselined else []
        print(
            render_sarif(
                to_sarif(report.findings, results=report.results, exit_code=report.exit_code, notes=notes)
            )
        )
    else:
        render_text(report, Console(no_color=no_color))

    raise typer.Exit(code=report.exit_code)


def _output_format(output_format: str | None, as_json: bool) -> str:
    chosen = (output_format or ("json" if as_json else "text")).lower()
    if chosen not in OUTPUT_FORMATS:
        raise ValueError(f"--format must be one of {', '.join(OUTPUT_FORMATS)}, got {chosen!r}")
    if as_json and chosen != "json":
        raise ValueError(f"--json conflicts with --format {chosen}")
    return chosen


def _check_fail_on(fail_on: str) -> None:
    if fail_on not in FAIL_ON_LEVELS:
        raise ValueError(f"--fail-on must be one of {', '.join(FAIL_ON_LEVELS)}, got {fail_on!r}")


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
def deps(
    path: Annotated[Path, typer.Argument(help="Repository whose dependencies to score.")],
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output on stdout.")] = False,
    no_network: Annotated[
        bool,
        typer.Option("--no-network", help="Never contact a registry; use the corpus and the cache only."),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add an LLM-written explanation. Changes no score."),
    ] = False,
    backend: Annotated[
        str | None,
        typer.Option("--backend", help="Model backend for --explain: claude (default) or ollama."),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour. NO_COLOR is also honoured.")] = False,
    output_format: Annotated[
        str | None,
        typer.Option("--format", metavar="text|json|sarif", help="Output format. --json is --format json."),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", metavar="high|medium|low", help="Lowest severity that fails (exit 1/2)."),
    ] = DEFAULT_FAIL_ON,
) -> None:
    """Score declared dependencies against real registry state.

    Needs no virtualenv: it reads manifests, so a `requirements.txt` nobody has installed
    yet can still be scored. Exit codes match `audit` - 0 clean, 1 medium, 2 high, 3 error.

    Every score is mechanical. `--explain` asks a model to describe the scores in prose
    after they are computed; it cannot alter a score, a severity, or a verdict. Use
    `--backend ollama` to have a local model write it instead of Claude.
    """
    if not path.is_dir():
        raise _fail(f"{path} is not a directory")
    try:
        fmt = _output_format(output_format, as_json)
        _check_fail_on(fail_on)
        config = load_config(path)
    except ValueError as error:
        raise _fail(str(error)) from error

    try:
        result = scan(path, offline=no_network, config=config)
    except OSError as error:
        raise _fail(f"could not scan {path}: {error}") from error

    if result.skip_reason:
        raise _fail(result.skip_reason)

    explanation = None
    if explain:
        from trustlayer.explain import explain_scan

        explanation, failure = explain_scan(result, path, backend=backend)
        if failure:
            # Losing the prose must never change the verdict a hook branches on.
            Console(stderr=True).print(f"warning: could not generate an explanation: {failure}")

    code = deps_exit_code(result, fail_on)
    if fmt == "json":
        print(render_deps_json(result, path.resolve(), explanation))
    elif fmt == "sarif":
        print(render_sarif(to_sarif(scan_findings(result), exit_code=code, notes=result.notes)))
    else:
        render_deps(result, path.resolve(), Console(no_color=no_color), explanation)

    raise typer.Exit(code=code)


@app.command()
def baseline(
    path: Annotated[Path, typer.Argument(help="Repository containing the module.")],
    module: Annotated[str, typer.Option("--module", help="Module to generate tests for.")],
    budget: Annotated[float, typer.Option("--budget", help="Max USD for the run.")] = 2.0,
    timeout: Annotated[float, typer.Option("--timeout", help="Seconds per agent turn-set.")] = 600,
    backend: Annotated[
        str | None,
        typer.Option("--backend", help="Model backend: claude (default) or ollama."),
    ] = None,
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
            timeout=timeout, max_budget_usd=budget, backend=backend,
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
    console.print(Text(f"coverage      {_coverage_change(result.coverage_before, result.coverage_after)}"))
    if result.agent:
        console.print(f"cost          {_spend(result.agent)}")
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
    max_total_cost: Annotated[
        float,
        typer.Option(
            "--max-total-cost",
            help="Hard ceiling on the whole run. --budget only caps one turn-set, and a run makes many.",
        ),
    ] = 10.0,
    backend: Annotated[
        str | None,
        typer.Option("--backend", help="Model backend: claude (default) or ollama."),
    ] = None,
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
        max_total_cost_usd=max_total_cost,
        backend=backend,
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
    console.print(Text(f"line coverage   {_coverage_change(result.coverage_before, result.coverage_after)}"))
    console.print(f"[bold]stopped[/bold]         {result.stopped_because}")
    console.print(f"tests discarded {result.total_discarded}")
    console.print(f"cost            {_harden_spend(result)}")
    console.print("\n--- diff for review (nothing applied) ---")
    console.print(result.diff or "(no changes)")
def _coverage_change(before, after) -> str:
    """Never prints a missing measurement as 0%: "unknown" and "zero" are different claims."""
    left = before.render() if before is not None else "n/a"
    right = after.render() if after is not None else "n/a"
    return f"{left} -> {right}"


def _spend(agent) -> str:
    """A local run costs nothing, so reporting "$0.0" would read as a broken meter."""
    if getattr(agent, "backend", "claude") == "ollama":
        return f"$0 (local {agent.model}, {agent.input_tokens}->{agent.output_tokens} tokens)"
    return f"${agent.cost_usd or 0:.4f}"


def _harden_spend(result) -> str:
    if result.backend == "ollama":
        return f"$0 (local, {result.total_input_tokens}->{result.total_output_tokens} tokens)"
    return f"${result.total_cost_usd}"


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
def mcp() -> None:
    """Serve the checks to coding agents over a local stdio MCP server.

    Tools: trustlayer_audit, trustlayer_deps, trustlayer_models. stdout carries JSON-RPC
    and nothing else; logs go to stderr. Register it with, for example:

        claude mcp add trustlayer -- uvx trustlayer mcp
    """
    from trustlayer.mcp_server import serve

    serve()


@app.command(name="setup-node")
def setup_node(
    directory: Annotated[
        Path | None,
        typer.Option("--dir", help="Where to install (default: $TRUSTLAYER_NODE_DIR or ~/.trustlayer/node)."),
    ] = None,
) -> None:
    """Install the ts-morph helper that the TypeScript checks need. Requires node and npm.

    An installed wheel cannot carry node_modules, and Node resolves ESM imports next to the
    script, so the helper scripts and their dependencies are set up together in one
    directory outside site-packages.
    """
    from trustlayer.checks import node_helper

    target, outcome = node_helper.setup(directory)
    if not outcome.ok:
        detail = outcome.error or (outcome.stderr.strip().splitlines() or ["npm failed"])[-1]
        raise _fail(f"could not install the helper in {target}: {detail}")
    Console().print(Text(f"ts-morph helper installed in {target}"))


@app.command()
def tui() -> None:
    """Browse recorded runs in the terminal.

    Unlike `ui`, this needs no browser and no network: the web UI loads Tailwind and HTMX
    from a CDN and is unstyled offline. Interactive, so its exit status carries no verdict -
    always 0. Use `audit` in a hook or CI, where severity owns the exit code.
    """
    from trustlayer.tui import create_app

    create_app().run()


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
    from trustlayer.ui.app import LOOPBACK_HOSTS

    url = f"http://{host}:{port}"
    Console().print(f"trustlayer ui  {url}   (ctrl-c to stop)")

    # The Host check only works when every legitimate name is known. On a loopback bind it
    # is; on any other interface the user chose exposure, so say so instead of guessing.
    loopback = host in LOOPBACK_HOSTS
    if not loopback:
        Console(stderr=True).print(
            f"warning: serving run data on {host}, not loopback; anyone who can reach it can read it"
        )

    if not no_browser:
        # Open after a short delay so the server is listening when the tab loads.
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    app_ = create_app(allowed_hosts=LOOPBACK_HOSTS if loopback else None)
    uvicorn.run(app_, host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main_entry())
