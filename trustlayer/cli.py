"""TrustLayer command line interface."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re
from typing import Annotated

from rich.console import Console
import typer

from trustlayer.checks.api_resolution import check_api_resolution
from trustlayer.checks.base import CheckResult, Finding
from trustlayer.checks.composed import check_composed
from trustlayer.checks.fail_open import check_fail_open
from trustlayer.checks.stale_models import check_stale_models, load_registry
from trustlayer.detect import profile_repository
from trustlayer.render import render_check_results, render_profile, render_registry


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


@app.command()
def audit(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, dir_okay=True, readable=True, help="Repository to audit."),
    ],
    check: Annotated[
        list[str] | None,
        typer.Option("--check", help=f"Run a specific check. Repeatable. One of: {', '.join(ALL_CHECKS)}."),
    ] = None,
    run_all: Annotated[bool, typer.Option("--all", help="Run every check, including the opt-in ones.")] = False,
    warn_expiring_within: Annotated[
        str | None,
        typer.Option("--warn-expiring-within", metavar="90d", help="Also flag models retiring within this window."),
    ] = None,
) -> None:
    """Detect languages, runners and pinned versions, then run the mechanical checks.

    `api-resolution` and `composed` are opt-in: the first imports code from the audited
    repository's environment, the second shells out to linters. Neither should be a
    surprise side effect of `audit`.
    """
    console = Console()
    selected = _selected_checks(check, run_all)
    warn_days = _parse_duration(warn_expiring_within)

    profile = profile_repository(path)
    render_profile(profile, console)

    results = _run_checks(Path(path), selected, warn_days)
    if results:
        render_check_results(results, console)

    if not profile.projects:
        raise typer.Exit(code=1)


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


def _selected_checks(requested: list[str] | None, run_all: bool) -> list[str]:
    if run_all:
        return list(ALL_CHECKS)
    if not requested:
        return list(DEFAULT_CHECKS)

    unknown = [name for name in requested if name not in ALL_CHECKS]
    if unknown:
        raise typer.BadParameter(f"unknown check(s): {', '.join(unknown)}. Choose from: {', '.join(ALL_CHECKS)}")
    return requested


def _parse_duration(value: str | None) -> int | None:
    """Accepts 90, 90d, 12w, 6m, 1y."""
    if value is None:
        return None
    match = DURATION_RE.match(value.strip())
    if not match:
        raise typer.BadParameter(f"could not read duration {value!r}; use a form like 90d, 12w, 6m")
    return int(match.group("count")) * UNIT_DAYS[match.group("unit").lower()]


@app.command()
def models(
    list_: Annotated[
        bool, typer.Option("--list", help="Print the deprecation registry with dates and sources.")
    ] = False,
) -> None:
    """Inspect the model deprecation registry."""
    console = Console()
    if not list_:
        console.print("Nothing to do. Use [bold]trustlayer models --list[/bold].")
        raise typer.Exit(code=2)

    try:
        registry = load_registry()
    except OSError as error:
        console.print(f"[red]could not read the registry:[/red] {error}")
        raise typer.Exit(code=2) from error

    render_registry(registry, console, today=datetime.now(tz=UTC).date())
