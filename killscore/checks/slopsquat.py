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
import re

from killscore.checks.base import CheckResult, Finding, find_declaration_line, sort_findings
from killscore.config import Config, load_config
from killscore.deps import read_javascript_declarations, read_json
from killscore.detect import Language, RepoProfile, profile_repository
from killscore.registry import PackageFacts, fetch_many
from killscore.risk import NPM, PYPI, Corpus, RiskScore, canonical_name, load_corpus, score_package


CHECK_NAME = "slopsquat:pypi"
NPM_CHECK_NAME = "slopsquat:npm"
CHECK_NAMES = {PYPI: CHECK_NAME, NPM: NPM_CHECK_NAME}

# package.json specs no registry can answer for. They are skipped with a note, never scored:
# a local path or a git URL "not existing on npm" is not evidence of anything.
NON_REGISTRY_PREFIXES = (
    "file:", "link:", "workspace:", "portal:", "patch:", "catalog:", "git+", "git:", "git@",
    "github:", "gitlab:", "bitbucket:", "gist:", "http:", "https:",
)
GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?$")


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
    ecosystem: str = PYPI

    @property
    def name(self) -> str:
        return self.risk.name


@dataclass(frozen=True)
class ScanResult:
    """Everything `deps` renders and `check_slopsquat` adapts into findings."""

    scored: list[ScoredDependency] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    corpus: Corpus | None = None  # the PyPI corpus; kept for existing callers
    corpora: dict[str, Corpus] = field(default_factory=dict)
    # The same notes, split by the ecosystem they are about, so each check result carries its own.
    ecosystem_notes: dict[str, list[str]] = field(default_factory=dict)

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
    config: Config | None = None,
    npm_corpus: Corpus | None = None,
) -> ScanResult:
    """Resolve and score every declared dependency: Python manifests and package.json.

    Each ecosystem is scored against its own corpus and registry, with the same additive,
    re-derivable factors. An injected `fetcher` stands in for every registry (it is a test
    or a simulation) and, as before, disables the cache.

    `[tool.killscore] exclude` is applied to declarations *before* anything is fetched, so
    an excluded fixture manifest costs no network and cannot fail a run.
    """
    try:
        packages = load_corpus() if corpus is None else corpus
    except (OSError, ValueError) as error:
        return ScanResult(skip_reason=f"top-packages corpus unreadable: {error}")

    resolved = profile if profile is not None else profile_repository(root)
    settings = config if config is not None else load_config(root)
    notes: list[str] = []

    found = {PYPI: _declarations(root, resolved), NPM: []}
    npm_found, skipped_specs = _npm_declarations(root, resolved)
    if npm_found:
        found[NPM] = npm_found
    skipped_names = sorted({name for name, file in skipped_specs if not settings.is_excluded(file)})
    if skipped_names:
        notes.append(
            f"{len(skipped_names)} package.json spec(s) not scored - not on a registry "
            f"(local path, workspace or git): {', '.join(skipped_names[:5])}"
        )

    corpora = {PYPI: packages}
    if found[NPM]:
        try:
            corpora[NPM] = npm_corpus if npm_corpus is not None else load_corpus(ecosystem=NPM)
        except (OSError, ValueError) as error:
            notes.append(f"npm dependencies not scored: npm corpus unreadable ({error})")
            found[NPM] = []

    excluded = 0
    scored: list[ScoredDependency] = []
    for ecosystem, declarations in found.items():
        kept = [(name, site) for name, site in declarations if not settings.is_excluded(site.file)]
        excluded += len(declarations) - len(kept)
        if not kept:
            continue
        table = corpora[ecosystem]
        # Corpus membership short-circuits scoring, so fetching a popular package would
        # spend a request on an answer that cannot change the result. A manifest of
        # ordinary dependencies therefore needs no network at all.
        unknown = [name for name, _ in kept if table.canonical(name) not in table.downloads]
        facts = (
            fetch_many(unknown, fetcher=fetcher, db_path=db_path, offline=offline, ecosystem=ecosystem)
            if unknown
            else {}
        )
        scored.extend(
            ScoredDependency(
                risk=score_package(name, facts.get(name) or _NOT_FETCHED, table, today=today),
                file=site.file,
                line=site.line,
                declared_spec=site.declared_spec,
                pinned=site.pinned,
                ecosystem=ecosystem,
            )
            for name, site in kept
        )

    if not scored:
        return ScanResult(
            skip_reason="no declared dependencies found in any manifest (Python or package.json)",
            corpus=packages,
            corpora=corpora,
            notes=notes,
        )
    scored.sort(key=_rank)

    unscorable = [item for item in scored if item.risk.score is None]
    if len(unscorable) == len(scored):
        reason = unscorable[0].risk.factors[0].detail if unscorable[0].risk.factors else "registry unreachable"
        return ScanResult(
            skip_reason=f"no package could be scored: {reason}", corpus=packages, corpora=corpora
        )

    split: dict[str, list[str]] = {}
    for ecosystem, table in corpora.items():
        if any(item.ecosystem == ecosystem for item in scored):
            split.setdefault(ecosystem, []).append(
                f"corpus: {table.provenance}, vendored {table.vendored_on}"
            )
    shared: list[str] = []
    if excluded:
        shared.append(f"{excluded} declaration(s) not scored: excluded by {settings.source}")
    if unscorable:
        shared.append(
            f"{len(unscorable)} of {len(scored)} packages could not be scored "
            "(registry unreachable); they are reported as neither safe nor risky"
        )
    split.setdefault(NPM, []).extend(notes)  # every note gathered above is about package.json
    every = [note for ecosystem in (PYPI, NPM) for note in split.get(ecosystem, [])] + shared
    return ScanResult(
        scored=scored, notes=every, corpus=packages, corpora=corpora, ecosystem_notes=split
    )


def _rank(item: ScoredDependency) -> tuple:
    """Riskiest first; unscorable packages sort after everything that has a number."""
    score = item.risk.score
    return (0 if score is not None else 1, -(score or 0), item.ecosystem, item.name)


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
            canonical = canonical_name(dependency.name, PYPI)
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)

            # The name is wrong in the manifest, not in the lockfile that echoes it.
            declared = dependency.declared_in or dependency.source
            relative = declared if project.path == "." else posixpath.join(project.path, declared)
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


def npm_registry_name(name: str, spec: str) -> str | None:
    """The registry package a package.json entry installs, or None when it is not on npm.

    `"lodash": "^4"` installs `lodash`; the alias `"my-lodash": "npm:lodash@^4"` installs
    `lodash` - so the alias target is what gets scored, never the local key.
    """
    spec = spec.strip()
    if spec.startswith("npm:"):
        target = spec[4:]
        at = target.find("@", 1)  # a leading @ is a scope, not a version separator
        return (target[:at] if at > 0 else target).strip() or None
    if spec.startswith(NON_REGISTRY_PREFIXES) or "://" in spec or GITHUB_SHORTHAND_RE.match(spec):
        return None
    return name.strip() or None


def _npm_declarations(
    root: Path, profile: RepoProfile
) -> tuple[list[tuple[str, _Site]], set[tuple[str, str]]]:
    """Every uniquely-named npm dependency, plus `(name, file)` for specs not on a registry."""
    seen: set[str] = set()
    found: list[tuple[str, _Site]] = []
    skipped: set[tuple[str, str]] = set()

    for project in profile.projects:
        if project.language is not Language.JAVASCRIPT:
            continue
        relative = posixpath.join(project.path, "package.json") if project.path != "." else "package.json"
        manifest = read_json(root / relative)
        if manifest is None:
            continue
        for declaration in read_javascript_declarations(manifest):
            target = npm_registry_name(declaration.name, declaration.spec)
            if target is None:
                skipped.add((declaration.name, relative))
                continue
            if target in seen:
                continue
            seen.add(target)
            found.append(
                (
                    target,
                    _Site(
                        file=relative,
                        line=_json_key_line(root / relative, declaration.name),
                        declared_spec=declaration.spec,
                        pinned=False,
                    ),
                )
            )
    return found, skipped


def _json_key_line(path: Path, key: str) -> int:
    """The line a package.json key is declared on; 1 when it cannot be located."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return 1
    needle = f'"{key}"'
    return next((number for number, line in enumerate(lines, start=1) if needle in line), 1)


def check_slopsquat(root: Path, **kwargs) -> CheckResult:
    """The PyPI result alone - the original single-result shape."""
    return check_slopsquat_all(root, **kwargs)[0]


def check_slopsquat_all(
    root: Path,
    *,
    profile: RepoProfile | None = None,
    fetcher=None,
    offline: bool = False,
    db_path=None,
    corpus: Corpus | None = None,
    today=None,
    config: Config | None = None,
    npm_corpus: Corpus | None = None,
) -> list[CheckResult]:
    """One scan, one result per ecosystem, so npm findings are grouped and named as npm.

    `slopsquat:npm` only appears when a package.json declares something: a Python-only
    repository is not told about an ecosystem it does not use.
    """
    result = scan(
        root,
        profile=profile,
        fetcher=fetcher,
        offline=offline,
        db_path=db_path,
        corpus=corpus,
        today=today,
        config=config,
        npm_corpus=npm_corpus,
    )
    if result.skip_reason:
        return [CheckResult(CHECK_NAME, skipped=True, skip_reason=result.skip_reason)]

    findings = scan_findings(result)
    present = {item.ecosystem for item in result.scored}
    shared = [
        note
        for note in result.notes
        if note not in result.ecosystem_notes.get(PYPI, []) + result.ecosystem_notes.get(NPM, [])
    ]
    results = [
        CheckResult(
            CHECK_NAME,
            [f for f in findings if f.check == CHECK_NAME],
            notes=result.ecosystem_notes.get(PYPI, []) + shared,
        )
        if PYPI in present
        else CheckResult(CHECK_NAME, skipped=True, skip_reason="no declared Python dependencies")
    ]
    if NPM in present:
        results.append(
            CheckResult(
                NPM_CHECK_NAME,
                [f for f in findings if f.check == NPM_CHECK_NAME],
                notes=result.ecosystem_notes.get(NPM, []) + ([] if PYPI in present else shared),
            )
        )
    return results


def scan_findings(result: ScanResult) -> list[Finding]:
    """The reportable scores as findings. `deps --format sarif` and the audit check share it."""
    findings = [
        Finding(
            severity=item.risk.severity,
            check=CHECK_NAMES[item.ecosystem],
            file=item.file,
            line=item.line,
            claim=_claim(item),
            verdict=item.risk.verdict,
            evidence=item.risk.evidence,
        )
        for item in result.reportable
    ]
    return sort_findings(findings)


def _claim(item: ScoredDependency) -> str:
    if item.ecosystem == NPM:
        return f"{item.name}@{item.declared_spec}" if item.declared_spec else item.name
    return f"{item.name}{item.declared_spec or ''}"
