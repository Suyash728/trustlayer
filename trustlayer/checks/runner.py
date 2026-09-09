"""One dispatch table for the checks, shared by every surface that runs them.

`cli.py` needs the finished list; the terminal UI needs each result as it lands, so a long
audit shows progress instead of a frozen screen. Both come from `iter_checks` - two copies of
the dispatch would drift the moment a check is added, and the CLI and the UI would disagree
about what `--all` means.

Nothing here decides severity or evidence. It only chooses which checks to call and in what
order, and the order matters once: `composed` is last, because it deduplicates against the
findings the native checks already produced.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from trustlayer.checks.api_resolution import check_api_resolution
from trustlayer.checks.base import CheckResult, Finding
from trustlayer.checks.composed import check_composed
from trustlayer.checks.fail_open import check_fail_open
from trustlayer.checks.import_effects import check_import_effects
from trustlayer.checks.pinned_version import check_pinned_version
from trustlayer.checks.slopsquat import check_slopsquat
from trustlayer.checks.stale_models import check_stale_models
from trustlayer.detect import RepoProfile


DEFAULT_CHECKS = ("stale-models", "fail-open", "import-effects")
OPT_IN_CHECKS = ("api-resolution", "composed", "slopsquat", "pinned-version")
ALL_CHECKS = DEFAULT_CHECKS + OPT_IN_CHECKS


def select(only: str | None, run_all: bool) -> list[str]:
    """Resolve a check selection, raising ValueError on anything unusable."""
    if only and run_all:
        raise ValueError("--only and --all cannot be combined")
    if run_all:
        return list(ALL_CHECKS)
    if only is None:
        return list(DEFAULT_CHECKS)
    if only not in ALL_CHECKS:
        raise ValueError(f"unknown check {only!r}. Choose from: {', '.join(ALL_CHECKS)}")
    return [only]


def iter_checks(
    root: Path, selected: list[str], warn_days: int | None, profile: RepoProfile
) -> Iterator[CheckResult]:
    """Yield each CheckResult as it completes.

    `composed` runs last and needs everything before it, so results are accumulated as they
    are yielded rather than re-run.
    """
    produced: list[CheckResult] = []

    def emit(result: CheckResult) -> Iterator[CheckResult]:
        produced.append(result)
        yield result

    if "stale-models" in selected:
        yield from emit(check_stale_models(root, warn_within_days=warn_days))
    if "fail-open" in selected:
        for result in check_fail_open(root):
            yield from emit(result)
    if "import-effects" in selected:
        yield from emit(check_import_effects(root))
    if "api-resolution" in selected:
        for result in check_api_resolution(root):
            yield from emit(result)
    if "slopsquat" in selected:
        yield from emit(check_slopsquat(root, profile=profile))
    if "pinned-version" in selected:
        yield from emit(check_pinned_version(root, profile=profile))
    if "composed" in selected:
        native: list[Finding] = [f for result in produced for f in result.findings]
        for result in check_composed(root, native):
            yield from emit(result)


def run_checks(
    root: Path, selected: list[str], warn_days: int | None, profile: RepoProfile
) -> list[CheckResult]:
    """The finished list. `iter_checks` is the same work, reported as it happens."""
    return list(iter_checks(root, selected, warn_days, profile))
