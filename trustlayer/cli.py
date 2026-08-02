"""TrustLayer command line interface."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re
import sys
from typing import Annotated

from rich.console import Console
import typer

from trustlayer.checks.api_resolution import check_api_resolution
from trustlayer.checks.base import CheckResult, Finding
from trustlayer.checks.composed import check_composed
from trustlayer.checks.fail_open import check_fail_open
from trustlayer.checks.stale_models import check_stale_models, load_registry
from trustlayer.detect import profile_repository
from trustlayer.report import EXIT_ERROR, Report, render_json, render_registry, render_text
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

    try:
        profile = profile_repository(path)
        results = _run_checks(path, selected, warn_days)
        suite = inspect_suite(path)
    except OSError as error:
        raise _fail(f"could not audit {path}: {error}") from error

    report = Report(root=path.resolve(), profile=profile, results=results, suite=suite)

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


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
