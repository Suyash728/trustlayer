"""Deterministic dependency risk scoring.

No LLM produces any part of a score. Every factor is a fixed number of points earned by a
fact fetched from a registry, and every factor carries the sentence that justifies it, so a
human can re-derive the total by hand from the evidence lines alone.

Two invariants hold the false-positive rate down, and both are pinned by tests:

1. **Typo-adjacency alone never reaches MEDIUM.** Adjacency is worth 25 and MEDIUM starts at
   40, so a legitimate package that happens to sit one edit from a popular one cannot be
   escalated by that fact by itself. It only matters when the package is *also* young, or
   barely downloaded, or maintained by one account.
2. **Unavailable data contributes zero points and says so.** A factor that could not be
   measured adds nothing and records why. Unknown is not suspicious; conflating the two is
   how a scanner starts crying wolf.

A package that is itself in the vendored top-N corpus short-circuits to 0. That single rule
removes the largest class of false positives before any factor is evaluated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
import json
from pathlib import Path

from trustlayer.checks.base import Severity
from trustlayer.deps import canonicalize_python_name
from trustlayer.registry import PackageFacts


DEFAULT_CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "top_pypi_packages.json"
PACKAGED_CORPUS_PATH = Path(__file__).resolve().parent / "data" / "top_pypi_packages.json"

MAX_SCORE = 100
NONEXISTENT_SCORE = 100

HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40
LOW_THRESHOLD = 20

# Adjacency is deliberately worth less than MEDIUM_THRESHOLD. See invariant 1.
ADJACENT_DISTANCE_1_POINTS = 25
ADJACENT_DISTANCE_2_POINTS = 12
MAX_TYPO_DISTANCE = 2


@dataclass(frozen=True)
class Factor:
    """One scored observation. `points` is what it added; `detail` is why."""

    name: str
    points: int
    detail: str


@dataclass(frozen=True)
class Neighbour:
    """A popular package the candidate is typo-adjacent to."""

    name: str
    distance: int
    downloads: int


@dataclass(frozen=True)
class RiskScore:
    name: str
    score: int | None  # None when the registry could not be reached: no claim is made
    severity: Severity | None  # None when the score is below the reporting threshold
    verdict: str
    factors: list[Factor] = field(default_factory=list)
    neighbour: Neighbour | None = None

    @property
    def reportable(self) -> bool:
        return self.severity is not None

    @property
    def evidence(self) -> list[str]:
        """The factor details, in the order they were scored, prefixed with the total."""
        head = "not scorable - the registry could not be reached" if self.score is None else (
            f"risk score {self.score}/100 "
            f"({'+'.join(str(f.points) for f in self.factors if f.points) or '0'})"
        )
        return [head, *(factor.detail for factor in self.factors)]


@dataclass(frozen=True)
class Corpus:
    """The vendored top-N snapshot: a typo target list and an offline popularity baseline."""

    downloads: dict[str, int]  # canonical name -> monthly downloads at snapshot time
    source: str = ""
    upstream_last_update: str = ""
    vendored_on: str = ""

    def __contains__(self, name: str) -> bool:
        return canonicalize_python_name(name) in self.downloads

    def __len__(self) -> int:
        return len(self.downloads)

    @property
    def provenance(self) -> str:
        parts = [part for part in (self.source, self.upstream_last_update) if part]
        return f"top {len(self.downloads)} PyPI packages" + (f" ({', '.join(parts)})" if parts else "")


def load_corpus(path: Path | None = None) -> Corpus:
    """Read the vendored top-packages snapshot. Raises OSError if it is missing."""
    source = path or _corpus_path()
    data = json.loads(source.read_text(encoding="utf-8"))

    downloads: dict[str, int] = {}
    for entry in data.get("packages") or []:
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        count = entry.get("downloads")
        downloads[canonicalize_python_name(name)] = count if isinstance(count, int) else 0

    return Corpus(
        downloads=downloads,
        source=str(data.get("source") or ""),
        upstream_last_update=str(data.get("upstream_last_update") or ""),
        vendored_on=str(data.get("vendored_on") or ""),
    )


def _corpus_path() -> Path:
    if DEFAULT_CORPUS_PATH.is_file():
        return DEFAULT_CORPUS_PATH
    return PACKAGED_CORPUS_PATH


def edit_distance(left: str, right: str, max_distance: int | None = None) -> int:
    """Damerau-Levenshtein distance, optimal string alignment variant.

    Plain Levenshtein is the wrong metric for this problem. It scores a transposition as two
    edits, so `reqeusts` reads as distance 2 from `requests` - the same as a package that
    differs by two unrelated characters. Transposing adjacent keys is the single most common
    way a name is mistyped and a well-known squatting vector, so counting it as one edit is
    what makes the adjacency factor mean anything.

    OSA rather than full Damerau: it forbids editing a substring twice, which is a
    restriction nobody notices at distance 2 and keeps the walk to three rows.

    `max_distance` is an early exit. Once every cell in a row exceeds it, no later row can
    come back under it, so the walk stops and returns max_distance + 1.
    """
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    if max_distance is not None and abs(len(left) - len(right)) > max_distance:
        return max_distance + 1

    before_previous: list[int] = []
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            cost = left_char != right_char
            best = min(
                previous[j] + 1,  # deletion
                current[j - 1] + 1,  # insertion
                previous[j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and left_char == right[j - 2]
                and left[i - 2] == right_char
            ):
                best = min(best, before_previous[j - 2] + 1)  # transposition
            current.append(best)
        if max_distance is not None and min(current) > max_distance:
            return max_distance + 1
        before_previous, previous = previous, current

    return previous[-1]


def nearest_popular(
    name: str, corpus: Corpus, max_distance: int = MAX_TYPO_DISTANCE
) -> Neighbour | None:
    """The closest popular package within `max_distance` edits, or None.

    Both sides are canonicalized first (PEP 503), so `pytest_cov` and `pytest-cov` are the
    same string at distance 0 rather than a phantom typo. Ties break toward the more
    downloaded package: that is the one an attacker would be imitating, and it makes the
    evidence line deterministic.
    """
    candidate = canonicalize_python_name(name)
    if not candidate or candidate in corpus.downloads:
        return None

    best: Neighbour | None = None
    for popular, downloads in corpus.downloads.items():
        if abs(len(popular) - len(candidate)) > max_distance:
            continue
        distance = edit_distance(candidate, popular, max_distance=max_distance)
        if distance == 0 or distance > max_distance:
            continue
        if best is None or (distance, -downloads, popular) < (best.distance, -best.downloads, best.name):
            best = Neighbour(name=popular, distance=distance, downloads=downloads)
    return best


def score_package(
    name: str, facts: PackageFacts, corpus: Corpus, *, today: date | None = None
) -> RiskScore:
    """Score one package. Pure: every input is already resolved, nothing is fetched here."""
    now = today or datetime.now(tz=UTC).date()
    canonical = canonicalize_python_name(name)

    if canonical in corpus.downloads:
        downloads = corpus.downloads[canonical]
        return RiskScore(
            name=name,
            score=0,
            severity=None,
            verdict="popular-package",
            factors=[
                Factor(
                    "corpus",
                    0,
                    f"in the vendored {corpus.provenance} at {downloads:,} downloads - not scored further",
                )
            ],
        )

    if facts.unreachable:
        return RiskScore(
            name=name,
            score=None,
            severity=None,
            verdict="unscorable",
            factors=[Factor("registry", 0, f"registry could not be reached: {facts.error or 'unknown error'}")],
        )

    if facts.exists is False:
        # Adjacency is still computed here even though the score is already maxed. It costs
        # nothing and it names what the model probably meant - and therefore what an
        # attacker would register to catch this exact typo.
        neighbour = nearest_popular(name, corpus)
        factors = [
            Factor("registry", NONEXISTENT_SCORE, f"{facts.url} returned 404 - no such project"),
            Factor(
                "installability",
                0,
                "nothing on the index resolves this name, so `pip install` would fail "
                "or fetch whatever an attacker registers under it next",
            ),
        ]
        if neighbour is not None:
            factors.append(
                Factor(
                    "typo-adjacency",
                    0,
                    f"{neighbour.distance} edit(s) from '{neighbour.name}' "
                    f"({neighbour.downloads:,} downloads) - the likely intended package",
                )
            )
        return RiskScore(
            name=name,
            score=NONEXISTENT_SCORE,
            severity=Severity.HIGH,
            verdict="nonexistent-package",
            factors=factors,
            neighbour=neighbour,
        )

    factors = [
        _age_factor(facts, now),
        _release_factor(facts),
        _maintainer_factor(facts),
        _download_factor(facts),
    ]
    neighbour = nearest_popular(name, corpus)
    factors.append(_adjacency_factor(neighbour, corpus))
    factors.extend(_hygiene_factors(facts))

    score = min(sum(factor.points for factor in factors), MAX_SCORE)
    return RiskScore(
        name=name,
        score=score,
        severity=severity_for(score),
        verdict=_verdict_for(score),
        factors=factors,
        neighbour=neighbour,
    )


def severity_for(score: int) -> Severity | None:
    if score >= HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    if score >= LOW_THRESHOLD:
        return Severity.LOW
    return None


def _verdict_for(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high-risk-dependency"
    if score >= MEDIUM_THRESHOLD:
        return "suspicious-dependency"
    if score >= LOW_THRESHOLD:
        return "unfamiliar-dependency"
    return "ordinary-dependency"


def _age_factor(facts: PackageFacts, today: date) -> Factor:
    if facts.first_release is None:
        return Factor("age", 0, "age: unavailable (no release timestamp on the registry record)")

    days = (today - facts.first_release).days
    if days < 30:
        points = 30
    elif days < 90:
        points = 20
    elif days < 365:
        points = 10
    else:
        points = 0
    return Factor("age", points, f"first published {facts.first_release} ({days} days ago)")


def _release_factor(facts: PackageFacts) -> Factor:
    if facts.release_count is None:
        return Factor("releases", 0, "release history: unavailable")
    if facts.release_count <= 1:
        points = 15
    elif facts.release_count <= 3:
        points = 8
    else:
        points = 0
    return Factor("releases", points, f"{facts.release_count} release(s) published")


def _maintainer_factor(facts: PackageFacts) -> Factor:
    if facts.maintainer_count is None:
        return Factor("maintainers", 0, "maintainers: unavailable (registry exposes no ownership record)")
    points = 10 if facts.maintainer_count <= 1 else 0
    return Factor("maintainers", points, f"{facts.maintainer_count} maintainer account(s) on the project")


def _download_factor(facts: PackageFacts) -> Factor:
    if facts.downloads_last_month is None:
        return Factor("downloads", 0, f"downloads: unavailable ({facts.downloads_note or 'not published'})")
    count = facts.downloads_last_month
    if count < 1_000:
        points = 20
    elif count < 10_000:
        points = 10
    else:
        points = 0
    return Factor("downloads", points, f"{count:,} downloads in the last month")


def _adjacency_factor(neighbour: Neighbour | None, corpus: Corpus) -> Factor:
    if neighbour is None:
        return Factor("typo-adjacency", 0, f"no package within {MAX_TYPO_DISTANCE} edits in the {corpus.provenance}")
    points = ADJACENT_DISTANCE_1_POINTS if neighbour.distance == 1 else ADJACENT_DISTANCE_2_POINTS
    return Factor(
        "typo-adjacency",
        points,
        f"{neighbour.distance} edit(s) from '{neighbour.name}' ({neighbour.downloads:,} downloads)",
    )


def _hygiene_factors(facts: PackageFacts) -> list[Factor]:
    factors: list[Factor] = []
    if facts.yanked:
        factors.append(Factor("yanked", 10, "the latest release is yanked on the index"))
    if facts.vulnerability_count:
        factors.append(
            Factor("vulnerabilities", 5, f"{facts.vulnerability_count} advisory record(s) on the index")
        )
    return factors
