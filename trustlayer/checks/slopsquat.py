"""Slopsquat guard: scores declared dependencies against real registry state.

This deliberately reads *manifests*, not import statements. Import names and distribution
names differ - `yaml` ships as PyYAML, `cv2` as opencv-python - so scoring a bare import
name would manufacture 404s for perfectly real packages, which is exactly the false positive
this repo refuses to ship. `api-resolution` already owns the import path and does it
correctly, behind an interpreter probe.

Reading manifests is also what makes this check work with **no virtualenv at all**. That is
the point: the dangerous artifact is a `requirements.txt` an LLM emitted thirty seconds ago
and nobody has installed yet.

Scoring lives in `risk.py` and fetching in `registry.py`; this module only decides what to
scan, where each package was declared, and which scores are worth reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import posixpath

from trustlayer.checks.base import CheckResult, Finding, find_declaration_line, sort_findings
from trustlayer.deps import canonicalize_python_name
from trustlayer.detect import Language, RepoProfile, profile_repository
from trustlayer.registry import PackageFacts, fetch_many
from trustlayer.risk import Corpus, RiskScore, load_corpus, score_package


CHECK_NAME = "slopsquat:pypi"


# Stands in for a package that was never fetched because the corpus already answered for it.
# `score_package` short-circuits on corpus membership before it reads any of these fields.
_NOT_FETCHED = PackageFacts(name="", unreachable=True, error="not fetched: already in the corpus")


@dataclass(frozen=True)
class ScoredDependency:
    """One declared dependency with its score and the place it was declared."""

    risk: RiskScore
    file: str
    line: int
    declared_spec: str | None = None
    pinned: bool = False

    @property
    def name(self) -> str:
        return self.risk.name


@dataclass(frozen=True)
class ScanResult:
    """Everything `deps` renders and `check_slopsquat` adapts into findings."""

    scored: list[ScoredDependency] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    corpus: Corpus | None = None

    @property
    def reportable(self) -> list[ScoredDependency]:
        return [item for item in self.scored if item.risk.reportable]


def scan(
    root: Path,
    *,
    profile: RepoProfile | None = None,
    fetcher=None,
    offline: bool = False,
    db_path=None,
    corpus: Corpus | None = None,
    today=None,
) -> ScanResult:
    """Resolve and score every declared Python dependency in a repository."""
    try:
        packages = load_corpus() if corpus is None else corpus
    except (OSError, ValueError) as error:
        return ScanResult(skip_reason=f"top-packages corpus unreadable: {error}")

    resolved = profile if profile is not None else profile_repository(root)
    declarations = _declarations(root, resolved)
    if not declarations:
        return ScanResult(
            skip_reason="no declared Python dependencies found in any manifest",
            corpus=packages,
        )

    # Corpus membership short-circuits scoring, so fetching a popular package would spend a
    # request on an answer that cannot change the result. A manifest of ordinary
    # dependencies therefore needs no network at all.
    unknown = [name for name, _ in declarations if canonicalize_python_name(name) not in packages.downloads]
    facts = fetch_many(unknown, fetcher=fetcher, db_path=db_path, offline=offline) if unknown else {}

    scored = [
        ScoredDependency(
            risk=score_package(name, facts.get(name) or _NOT_FETCHED, packages, today=today),
            file=site.file,
            line=site.line,
            declared_spec=site.declared_spec,
            pinned=site.pinned,
        )
        for name, site in declarations
    ]
    scored.sort(key=_rank)

    unscorable = [item for item in scored if item.risk.score is None]
    if unscorable and len(unscorable) == len(scored):
        reason = unscorable[0].risk.factors[0].detail if unscorable[0].risk.factors else "registry unreachable"
        return ScanResult(skip_reason=f"no package could be scored: {reason}", corpus=packages)

    notes = [f"corpus: {packages.provenance}, vendored {packages.vendored_on}"]
    if unscorable:
        notes.append(
            f"{len(unscorable)} of {len(scored)} packages could not be scored "
            "(registry unreachable); they are reported as neither safe nor risky"
        )
    return ScanResult(scored=scored, notes=notes, corpus=packages)


def _rank(item: ScoredDependency) -> tuple:
    """Riskiest first; unscorable packages sort after everything that has a number."""
    score = item.risk.score
    return (0 if score is not None else 1, -(score or 0), item.name)


@dataclass(frozen=True)
class _Site:
    file: str
    line: int
    declared_spec: str | None
    pinned: bool


def _declarations(root: Path, profile: RepoProfile) -> list[tuple[str, _Site]]:
    """Every uniquely-named Python dependency, with the manifest line that declares it.

    Deduplicated by canonical name across projects: one package is one package, and the
    same fake name in two manifests is one problem, not two.
    """
    seen: set[str] = set()
    found: list[tuple[str, _Site]] = []

    for project in profile.projects:
        if project.language is not Language.PYTHON:
            continue
        for dependency in project.dependencies:
            canonical = canonicalize_python_name(dependency.name)
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)

            relative = (
                dependency.source
                if project.path == "."
                else posixpath.join(project.path, dependency.source)
            )
            found.append(
                (
                    dependency.name,
                    _Site(
                        file=relative,
                        line=find_declaration_line(root / relative, dependency.name),
                        declared_spec=dependency.declared_spec,
                        pinned=dependency.pinned,
                    ),
                )
            )
    return found


def check_slopsquat(
    root: Path,
    *,
    profile: RepoProfile | None = None,
    fetcher=None,
    offline: bool = False,
    db_path=None,
    corpus: Corpus | None = None,
    today=None,
) -> CheckResult:
    """Adapt a scan into the standard check shape."""
    result = scan(
        root,
        profile=profile,
        fetcher=fetcher,
        offline=offline,
        db_path=db_path,
        corpus=corpus,
        today=today,
    )
    if result.skip_reason:
        return CheckResult(CHECK_NAME, skipped=True, skip_reason=result.skip_reason)

    findings = [
        Finding(
            severity=item.risk.severity,
            check=CHECK_NAME,
            file=item.file,
            line=item.line,
            claim=_claim(item),
            verdict=item.risk.verdict,
            evidence=item.risk.evidence,
        )
        for item in result.reportable
    ]
    return CheckResult(CHECK_NAME, sort_findings(findings), notes=result.notes)


def _claim(item: ScoredDependency) -> str:
    return f"{item.name}{item.declared_spec or ''}"
