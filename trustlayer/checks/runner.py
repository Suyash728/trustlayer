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
from dataclasses import replace
from pathlib import Path

from trustlayer.checks.api_resolution import check_api_resolution
from trustlayer.checks.base import CheckResult, Finding
from trustlayer.checks.composed import check_composed
from trustlayer.checks.fail_open import check_fail_open
from trustlayer.checks.gha_refs import check_gha_refs
from trustlayer.checks.import_effects import check_import_effects
from trustlayer.checks.lock_drift import check_lock_drift
from trustlayer.checks.pinned_version import check_pinned_version
from trustlayer.checks.slopsquat import check_slopsquat_all
from trustlayer.checks.stale_models import check_stale_models
from trustlayer.checks.test_tautology import check_test_tautology
from trustlayer.config import Config, load_config
from trustlayer.detect import RepoProfile


DEFAULT_CHECKS = ("stale-models", "fail-open", "import-effects", "test-tautology", "lock-drift")
OPT_IN_CHECKS = ("api-resolution", "composed", "slopsquat", "pinned-version", "gha-refs")
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
    root: Path,
    selected: list[str],
    warn_days: int | None,
    profile: RepoProfile,
    config: Config | None = None,
) -> Iterator[CheckResult]:
    """Yield each CheckResult as it completes.

    `composed` runs last and needs everything before it, so results are accumulated as they
    are yielded rather than re-run.

    Suppression (`[tool.trustlayer] exclude` and inline `trustlayer: ignore`) is applied here,
    once, so every surface agrees on what was hidden. The count travels on the result.
    """
    config = config if config is not None else load_config(root)
    produced: list[CheckResult] = []

    def emit(result: CheckResult) -> Iterator[CheckResult]:
        result = suppress(root, result, config)
        produced.append(result)
        yield result

    if "stale-models" in selected:
        yield from emit(check_stale_models(root, warn_within_days=warn_days))
    if "fail-open" in selected:
        for result in check_fail_open(root):
            yield from emit(result)
    if "import-effects" in selected:
        yield from emit(check_import_effects(root))
    if "test-tautology" in selected:
        yield from emit(check_test_tautology(root))
    if "lock-drift" in selected:
        yield from emit(check_lock_drift(root, profile=profile))
    if "api-resolution" in selected:
        for result in check_api_resolution(root):
            yield from emit(result)
    if "slopsquat" in selected:
        for result in check_slopsquat_all(root, profile=profile, config=config):
            yield from emit(result)
    if "pinned-version" in selected:
        yield from emit(check_pinned_version(root, profile=profile))
    if "gha-refs" in selected:
        yield from emit(check_gha_refs(root))
    if "composed" in selected:
        native: list[Finding] = [f for result in produced for f in result.findings]
        for result in check_composed(root, native):
            yield from emit(result)


def run_checks(
    root: Path,
    selected: list[str],
    warn_days: int | None,
    profile: RepoProfile,
    config: Config | None = None,
) -> list[CheckResult]:
    """The finished list. `iter_checks` is the same work, reported as it happens."""
    return list(iter_checks(root, selected, warn_days, profile, config))


def suppress(root: Path, result: CheckResult, config: Config) -> CheckResult:
    """Drop findings the repository asked to hide, and count them on the result.

    A note scoped to an excluded project (`"<path>: ..."`) is dropped as well - it is a
    caveat about code the repository asked not to hear about.
    """
    notes = [note for note in result.notes if not _note_is_excluded(note, config)]
    if notes != result.notes:
        result = replace(result, notes=notes)
    if not result.findings:
        return result
    kept = [
        finding
        for finding in result.findings
        if not config.is_excluded(finding.file)
        and not config.ignored_inline(root, finding.file, finding.line, finding.check)
    ]
    hidden = len(result.findings) - len(kept)
    if not hidden:
        return result
    return replace(result, findings=kept, suppressed=result.suppressed + hidden)


def _note_is_excluded(note: str, config: Config) -> bool:
    scope, separator, _ = note.partition(": ")
    if not separator or " " in scope or "/" not in scope:
        return False
    return config.is_excluded(scope)
