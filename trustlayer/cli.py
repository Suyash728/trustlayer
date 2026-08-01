"""TrustLayer command line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from rich.console import Console
import typer

from trustlayer.detect import profile_repository
from trustlayer.render import render_profile


# The callback keeps Typer in subcommand mode, so the CLI is `trustlayer audit <path>`
# rather than collapsing to `trustlayer <path>` when only one command is registered.
app = typer.Typer(add_completion=False, help="Prove whether AI-written tests catch bugs.")


@app.callback()
def main() -> None:
    """TrustLayer."""


@app.command()
def audit(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Repository to audit.",
        ),
    ],
) -> None:
    """Detect languages, test runners, and pinned dependency versions in a repository."""
    console = Console()
    profile = profile_repository(path)
    render_profile(profile, console)

    if not profile.projects:
        raise typer.Exit(code=1)
