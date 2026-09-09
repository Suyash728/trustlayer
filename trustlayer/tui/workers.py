"""Long operations, run off the UI thread.

**This module exists because of one hard constraint.** Textual runs an asyncio event loop.
`run_agent` calls `anyio.run()`, which starts a *second* one, and nesting event loops raises
immediately. `run_mutation` blocks on `subprocess.run`. The registry and Ollama clients block
on `urllib`. None of them may be called from the UI thread: the first is a crash, the rest
freeze the interface for however long the work takes - minutes, for a mutation loop.

So each of these runs inside a Textual thread worker and reports back through
`app.call_from_thread`, which is the documented-safe way to touch the UI from another thread.

Nothing here decides anything. It calls the same functions the CLI calls, in the same order,
and forwards what they return.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import time

from trustlayer.agent.harden import HardenEvent, HardenResult, harden
from trustlayer.checks.base import CheckResult
from trustlayer.checks.runner import iter_checks
from trustlayer.detect import profile_repository
from trustlayer.report import Report
from trustlayer.store import save_run
from trustlayer.suite import inspect_suite


@dataclass(frozen=True)
class AuditOutcome:
    """What an audit run produced. `error` set means nothing else is meaningful."""

    report: Report | None = None
    run_id: int | None = None
    duration_s: float = 0.0
    error: str | None = None
    save_error: str | None = None


def run_audit(
    root: Path,
    selected: list[str],
    *,
    warn_days: int | None = None,
    save: bool = True,
    db_path=None,
    on_result: Callable[[CheckResult], None] | None = None,
    on_status: Callable[[str], None] | None = None,
) -> AuditOutcome:
    """Audit a repository, reporting each check as it finishes.

    `on_result` and `on_status` are for progress only. They receive what already happened and
    return nothing, so no callback can alter a finding, a severity, or the recorded run.
    """
    started = time.monotonic()

    def status(message: str) -> None:
        if on_status is not None:
            on_status(message)

    try:
        status("reading the repository profile")
        profile = profile_repository(root)

        results: list[CheckResult] = []
        for result in iter_checks(root, selected, warn_days, profile):
            results.append(result)
            status(f"finished {result.check}")
            if on_result is not None:
                on_result(result)

        status("reading the test suite")
        suite = inspect_suite(root)
    except OSError as error:
        return AuditOutcome(error=f"could not audit {root}: {error}")

    duration = time.monotonic() - started
    report = Report(root=root.resolve(), profile=profile, results=results, suite=suite)

    run_id = None
    save_error = None
    if save:
        try:
            run_id = save_run(report, duration, db_path=db_path)
        except (OSError, sqlite3.Error) as error:
            # Same rule as the CLI: failing to record is a warning, never a changed verdict.
            save_error = str(error)

    return AuditOutcome(
        report=report, run_id=run_id, duration_s=duration, save_error=save_error
    )


def run_harden(
    root: Path,
    *,
    target_score: float = 90.0,
    max_iterations: int = 5,
    max_total_cost_usd: float = 10.0,
    backend: str | None = None,
    on_event: Callable[[HardenEvent], None] | None = None,
) -> HardenResult:
    """Raise a repository's mutation score, reporting each step as it happens.

    Runs in a thread for the reason in this module's docstring: `harden` calls `run_agent`,
    which calls `anyio.run()`, and that cannot happen inside Textual's event loop.

    The agent works in a temp copy and this returns a diff. Nothing here applies it.
    """
    return harden(
        root,
        target_score=target_score,
        max_iterations=max_iterations,
        max_total_cost_usd=max_total_cost_usd,
        backend=backend,
        on_event=on_event,
    )
