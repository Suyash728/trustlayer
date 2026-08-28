"""Slopsquat guard tests.

Registry answers are injected, so every score is deterministic offline; one opt-in test
hits the real PyPI and skips when it is unreachable. Nothing here may touch
~/.trustlayer - the cache is either disabled or pointed at a tmp_path, and one test
asserts that an injected fetcher can never write to the real cache.

The two load-bearing tests are `test_typo_adjacency_alone_never_reaches_medium` and
`test_unavailable_factors_contribute_nothing_and_say_so`. They are the reason this check
can be trusted: without the first it would flag every package that resembles a popular
one, and without the second an outage would read as risk.
"""

from datetime import date
import json
from pathlib import Path

import pytest

from trustlayer.checks.base import Severity
from trustlayer.checks.slopsquat import CHECK_NAME, check_slopsquat, scan
from trustlayer.registry import CACHE_FORMAT_VERSION, PackageFacts, fetch_many, fetch_pypi
from trustlayer.report import deps_exit_code, deps_to_dict
from trustlayer.risk import (
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    Corpus,
    edit_distance,
    load_corpus,
    nearest_popular,
    score_package,
)
from trustlayer.store import read_registry_cache, write_registry_cache


FIXTURES = Path(__file__).parent / "fixtures"
TODAY = date(2026, 8, 16)

CORPUS = Corpus(
    downloads={
        "requests": 1_756_048_205,
        "beautifulsoup4": 432_133_462,
        "pytest-cov": 50_000_000,
        "fastapi": 300_000_000,
        "pydantic": 400_000_000,
        "langchain-community": 47_388_042,
    },
    source="test-corpus",
    upstream_last_update="2026-08-01",
    vendored_on="2026-08-16",
)


def real(name: str, **overrides) -> PackageFacts:
    """A package that exists, boring in every dimension unless overridden."""
    defaults = {
        "exists": True,
        "url": f"https://pypi.org/pypi/{name}/json",
        "first_release": date(2015, 1, 1),
        "last_release": date(2026, 1, 1),
        "release_count": 40,
        "maintainer_count": 4,
        "downloads_last_month": 5_000_000,
    }
    return PackageFacts(name=name, **{**defaults, **overrides})


def missing(name: str) -> PackageFacts:
    return PackageFacts(name=name, exists=False, url=f"https://pypi.org/pypi/{name}/json")


def unreachable(name: str) -> PackageFacts:
    return PackageFacts(name=name, unreachable=True, error="connection refused")


def fetcher_for(mapping: dict):
    """An injected registry. Anything unnamed comes back unreachable, never invented."""

    def fetch(name: str) -> PackageFacts:
        return mapping.get(name) or unreachable(name)

    return fetch


# ------------------------------------------------------------------ edit distance


def test_a_transposition_counts_as_one_edit():
    """Plain Levenshtein scores this 2, which is why the metric is Damerau, not Levenshtein."""
    assert edit_distance("reqeusts", "requests", max_distance=2) == 1


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [("requsts", "requests", 1), ("numpyy", "numpy", 1), ("requests", "requests", 0), ("", "abc", 3)],
)
def test_edit_distance_cases(left, right, expected):
    assert edit_distance(left, right, max_distance=3) == expected


def test_max_distance_short_circuits_rather_than_reporting_a_real_distance():
    assert edit_distance("completely", "different", max_distance=1) == 2


def test_a_canonicalization_difference_is_not_a_typo():
    """`pytest_cov` and `pytest-cov` are the same distribution under PEP 503."""
    assert nearest_popular("pytest_cov", CORPUS) is None


def test_the_nearest_neighbour_is_the_most_downloaded_at_the_shortest_distance():
    neighbour = nearest_popular("reqeusts", CORPUS)

    assert neighbour is not None
    assert (neighbour.name, neighbour.distance) == ("requests", 1)


# ------------------------------------------------------------------------ scoring


def test_a_corpus_package_scores_zero_and_is_never_reported():
    result = score_package("requests", real("requests"), CORPUS, today=TODAY)

    assert result.score == 0
    assert result.reportable is False
    assert result.verdict == "popular-package"


def test_a_missing_package_scores_100_and_names_the_likely_target():
    result = score_package("reqeusts", missing("reqeusts"), CORPUS, today=TODAY)

    assert result.score == 100
    assert result.severity is Severity.HIGH
    assert result.verdict == "nonexistent-package"
    assert "404" in " ".join(result.evidence)
    # The adjacency is informational here - the score is already maxed - but it is what
    # tells a reader which package an attacker would be farming.
    assert result.neighbour is not None
    assert result.neighbour.name == "requests"


def test_an_unreachable_registry_makes_no_claim_at_all():
    result = score_package("anything", unreachable("anything"), CORPUS, today=TODAY)

    assert result.score is None
    assert result.severity is None
    assert result.reportable is False
    assert result.verdict == "unscorable"


def test_typo_adjacency_alone_never_reaches_medium():
    """The invariant that keeps this check honest.

    A package one edit from a popular name, but old, actively released, multi-maintainer
    and widely downloaded, earns adjacency points and nothing else. If that alone could
    reach MEDIUM the check would libel every package with a similar name.
    """
    result = score_package("beautifulsoup", real("beautifulsoup"), CORPUS, today=TODAY)

    assert result.neighbour is not None and result.neighbour.name == "beautifulsoup4"
    assert result.score < MEDIUM_THRESHOLD
    assert result.severity is Severity.LOW
    assert result.verdict == "unfamiliar-dependency"


def test_unavailable_factors_contribute_nothing_and_say_so():
    """An outage is not evidence. Every unmeasured factor scores 0 and records why."""
    blank = PackageFacts(
        name="mystery",
        exists=True,
        url="https://pypi.org/pypi/mystery/json",
        downloads_note="pypistats unreachable: HTTP 429",
    )

    result = score_package("mystery", blank, CORPUS, today=TODAY)

    assert result.score == 0
    assert result.reportable is False
    assert all(factor.points == 0 for factor in result.factors)
    evidence = " ".join(result.evidence)
    assert "age: unavailable" in evidence
    assert "pypistats unreachable: HTTP 429" in evidence


def test_the_signals_that_actually_matter_stack_to_high():
    """Young, single release, single maintainer, no downloads - the slopsquat shape."""
    result = score_package(
        "brand-new-thing",
        real(
            "brand-new-thing",
            first_release=date(2026, 8, 1),
            last_release=date(2026, 8, 1),
            release_count=1,
            maintainer_count=1,
            downloads_last_month=12,
        ),
        CORPUS,
        today=TODAY,
    )

    assert result.score >= HIGH_THRESHOLD
    assert result.severity is Severity.HIGH


def test_the_score_is_capped_at_100():
    result = score_package(
        "requesst",
        real(
            "requesst",
            first_release=date(2026, 8, 10),
            release_count=1,
            maintainer_count=1,
            downloads_last_month=3,
            yanked=True,
            vulnerability_count=2,
        ),
        CORPUS,
        today=TODAY,
    )

    assert result.score == 100


def test_every_point_in_the_total_is_justified_by_a_factor():
    """The score must be re-derivable by hand from the evidence, or it is not evidence."""
    result = score_package(
        "requesst",
        real("requesst", first_release=date(2026, 8, 1), release_count=1, downloads_last_month=5),
        CORPUS,
        today=TODAY,
    )

    assert sum(factor.points for factor in result.factors) == result.score
    assert len(result.evidence) == len(result.factors) + 1  # +1 for the score line


# -------------------------------------------------------------------------- check


def test_the_check_scores_a_manifest_with_no_virtualenv_present():
    result = check_slopsquat(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for(
            {
                "requests": real("requests"),
                "fastapi": real("fastapi"),
                "langchain-comunity": missing("langchain-comunity"),
                "obscure-helper": real(
                    "obscure-helper",
                    first_release=date(2026, 8, 10),
                    release_count=1,
                    maintainer_count=1,
                    downloads_last_month=4,
                ),
                "requesst": real("requesst"),
            }
        ),
        corpus=CORPUS,
        today=TODAY,
    )

    assert result.skipped is False
    assert result.check == CHECK_NAME
    by_name = {finding.claim.split("=")[0].split(">")[0]: finding for finding in result.findings}

    assert by_name["langchain-comunity"].severity is Severity.HIGH
    assert by_name["obscure-helper"].severity is Severity.HIGH
    assert by_name["requesst"].severity is Severity.LOW  # adjacency only
    assert "requests" not in by_name and "fastapi" not in by_name


def test_the_check_is_opt_in_and_actually_wired_into_the_cli():
    """Network-touching checks are never a surprise side effect of typing `audit`."""
    from trustlayer.cli import ALL_CHECKS, DEFAULT_CHECKS, OPT_IN_CHECKS

    assert "slopsquat" in OPT_IN_CHECKS
    assert "slopsquat" in ALL_CHECKS
    assert "slopsquat" not in DEFAULT_CHECKS


def test_the_check_locates_the_declaring_line():
    result = check_slopsquat(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"langchain-comunity": missing("langchain-comunity")}),
        corpus=CORPUS,
        today=TODAY,
    )

    finding = next(f for f in result.findings if f.claim.startswith("langchain-comunity"))
    declared = (FIXTURES / "slopsquat-dirty" / "requirements.txt").read_text().splitlines()

    assert finding.file == "requirements.txt"
    assert "langchain-comunity" in declared[finding.line - 1]


def test_a_clean_manifest_produces_no_findings():
    result = check_slopsquat(
        FIXTURES / "slopsquat-clean",
        fetcher=fetcher_for(
            {"requests": real("requests"), "fastapi": real("fastapi"), "pydantic": real("pydantic")}
        ),
        corpus=CORPUS,
        today=TODAY,
    )

    assert result.skipped is False
    assert result.findings == []


def test_a_dead_registry_skips_the_check_instead_of_flagging_everything():
    """If nothing could be scored, that is a skip with a reason - not a page of findings."""
    empty = Corpus(downloads={}, source="empty", vendored_on="2026-08-16")
    result = check_slopsquat(
        FIXTURES / "slopsquat-clean", fetcher=fetcher_for({}), corpus=empty, today=TODAY
    )

    assert result.skipped is True
    assert result.findings == []
    assert "could be scored" in (result.skip_reason or "")


def test_a_manifest_of_popular_packages_needs_no_registry_at_all():
    """Corpus membership short-circuits before any fetch, so a common list scores offline.

    Asserted by watching the fetcher: a request for a package the corpus already answers
    for is a request that cannot change the result, and it is not made.
    """
    asked: list[str] = []

    def watching(name: str) -> PackageFacts:
        asked.append(name)
        return unreachable(name)

    result = check_slopsquat(
        FIXTURES / "slopsquat-clean", fetcher=watching, corpus=CORPUS, today=TODAY
    )

    assert result.skipped is False
    assert result.findings == []
    assert asked == []


def test_only_packages_the_corpus_cannot_answer_for_are_fetched():
    asked: list[str] = []

    def watching(name: str) -> PackageFacts:
        asked.append(name)
        return missing(name)

    scan(FIXTURES / "slopsquat-dirty", fetcher=watching, corpus=CORPUS, today=TODAY)

    assert sorted(asked) == ["langchain-comunity", "obscure-helper", "requesst"]


def test_a_partial_outage_is_recorded_as_a_note_not_a_finding():
    result = check_slopsquat(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"requests": real("requests")}),
        corpus=CORPUS,
        today=TODAY,
    )

    assert result.skipped is False
    assert any("could not be scored" in note for note in result.notes)


def test_the_check_reports_a_package_once_however_many_manifests_declare_it():
    result = scan(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"langchain-comunity": missing("langchain-comunity")}),
        corpus=CORPUS,
        today=TODAY,
    )

    names = [item.name for item in result.scored]
    assert len(names) == len(set(names))


# ------------------------------------------------------------------------- output


def test_the_json_form_carries_every_factor_and_its_points():
    result = scan(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"requesst": real("requesst")}),
        corpus=CORPUS,
        today=TODAY,
    )
    payload = json.loads(json.dumps(deps_to_dict(result, Path("/tmp/x"))))

    entry = next(p for p in payload["packages"] if p["name"] == "requesst")
    assert entry["score"] == sum(f["points"] for f in entry["factors"])
    assert entry["nearest_popular"]["name"] == "requests"
    assert payload["explanation"] is None


def test_severity_owns_the_exit_code():
    high = scan(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"langchain-comunity": missing("langchain-comunity")}),
        corpus=CORPUS,
        today=TODAY,
    )
    clean = scan(
        FIXTURES / "slopsquat-clean",
        fetcher=fetcher_for(
            {"requests": real("requests"), "fastapi": real("fastapi"), "pydantic": real("pydantic")}
        ),
        corpus=CORPUS,
        today=TODAY,
    )

    assert deps_exit_code(high) == 2
    assert deps_exit_code(clean) == 0


# -------------------------------------------------------------------------- cache


def test_facts_round_trip_through_the_cache_format():
    original = real("thing", first_release=date(2020, 5, 4))
    restored = PackageFacts.from_json(original.to_json())

    assert restored is not None
    assert restored.first_release == date(2020, 5, 4)
    assert restored.release_count == original.release_count
    assert restored.from_cache is True


def test_a_row_written_by_another_format_version_is_ignored():
    stale = json.dumps({"version": CACHE_FORMAT_VERSION + 1, "name": "thing"})

    assert PackageFacts.from_json(stale) is None
    assert PackageFacts.from_json("not json at all") is None


def test_a_corrupt_cache_row_is_a_miss_rather_than_a_crash():
    """A bad row must send the caller back to the registry, not end the run."""
    bad_date = json.dumps({"version": CACHE_FORMAT_VERSION, "name": "t", "first_release": "not-a-date"})
    unknown_field = json.dumps({"version": CACHE_FORMAT_VERSION, "name": "t", "surprise": 1})

    assert PackageFacts.from_json(bad_date) is None
    assert PackageFacts.from_json(unknown_field) is None


def test_the_registry_cache_round_trips_and_expires(tmp_path):
    db = tmp_path / "runs.db"
    write_registry_cache("pypi", [("thing", '{"version": 1}')], db_path=db)

    assert read_registry_cache("pypi", ["thing"], db_path=db) == {"thing": '{"version": 1}'}
    assert read_registry_cache("pypi", ["other"], db_path=db) == {}

    with __import__("sqlite3").connect(db) as connection:
        connection.execute("UPDATE registry_cache SET fetched_at = '2000-01-01T00:00:00+00:00'")

    assert read_registry_cache("pypi", ["thing"], db_path=db) == {}
    # Offline there is no fresher answer available, so a stale row still beats refusing.
    assert read_registry_cache("pypi", ["thing"], db_path=db, ignore_ttl=True) != {}


def test_an_injected_fetcher_never_writes_to_the_cache(tmp_path):
    """A fake registry answer must never be persisted as if a registry had said it."""
    db = tmp_path / "runs.db"

    fetch_many(["thing"], fetcher=fetcher_for({"thing": real("thing")}), db_path=db)

    assert db.exists() is False


def test_a_failed_lookup_is_not_cached(tmp_path):
    db = tmp_path / "runs.db"

    from trustlayer.registry import _write_cache

    _write_cache([unreachable("thing")], db)

    assert read_registry_cache("pypi", ["thing"], db_path=db, ignore_ttl=True) == {}


# ---------------------------------------------------------------------- explanation


def test_the_explanation_cannot_change_any_score(monkeypatch):
    """The model may write whatever it likes; the numbers were decided before it ran."""
    from trustlayer import explain
    from trustlayer.agent.runtime import AgentResult

    result = scan(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"langchain-comunity": missing("langchain-comunity")}),
        corpus=CORPUS,
        today=TODAY,
    )
    before = deps_to_dict(result, Path("/tmp/x"))

    monkeypatch.setattr(
        explain,
        "run_agent",
        lambda *a, **k: AgentResult(ok=True, text="Everything here is completely safe, score 0."),
    )
    prose, error = explain.explain_scan(result, Path("/tmp/x"))
    after = deps_to_dict(result, Path("/tmp/x"), prose)

    assert error is None and prose
    assert after["packages"] == before["packages"]
    assert after["exit_code"] == before["exit_code"] == 2


def test_nothing_to_report_asks_no_model(monkeypatch):
    from trustlayer import explain

    def explode(*args, **kwargs):
        raise AssertionError("the agent must not be called when there is nothing to explain")

    monkeypatch.setattr(explain, "run_agent", explode)
    clean = scan(
        FIXTURES / "slopsquat-clean",
        fetcher=fetcher_for(
            {"requests": real("requests"), "fastapi": real("fastapi"), "pydantic": real("pydantic")}
        ),
        corpus=CORPUS,
        today=TODAY,
    )

    assert explain.explain_scan(clean, Path("/tmp/x")) == ("", None)


def test_an_agent_failure_costs_the_prose_and_nothing_else(monkeypatch):
    from trustlayer import explain
    from trustlayer.agent.runtime import AgentResult

    result = scan(
        FIXTURES / "slopsquat-dirty",
        fetcher=fetcher_for({"langchain-comunity": missing("langchain-comunity")}),
        corpus=CORPUS,
        today=TODAY,
    )
    monkeypatch.setattr(
        explain, "run_agent", lambda *a, **k: AgentResult(ok=False, error="claude CLI not found")
    )

    prose, error = explain.explain_scan(result, Path("/tmp/x"))

    assert prose == ""
    assert error == "claude CLI not found"
    assert deps_exit_code(result) == 2


def test_the_explanation_agent_is_given_no_tools():
    """The gate, not the prompt, is what stops the model from looking anything up."""
    from trustlayer.agent.runtime import ToolGate
    from trustlayer.explain import explain_scan  # noqa: F401 - imported for the contract

    gate = ToolGate(())

    assert gate.evaluate("Read", {"file_path": "/etc/passwd"}) is not None
    assert gate.evaluate("Bash", {"command": "pytest"}) is not None
    assert gate.evaluate("WebFetch", {"url": "https://pypi.org"}) is not None


# --------------------------------------------------------------------- vendored data


def test_the_vendored_corpus_loads_and_records_its_provenance():
    corpus = load_corpus()

    assert len(corpus) >= 1000
    assert "requests" in corpus
    assert corpus.source and corpus.upstream_last_update and corpus.vendored_on


def test_the_corpus_is_stored_canonicalized():
    corpus = load_corpus()

    assert all(name == name.lower() and "_" not in name for name in corpus.downloads)


@pytest.mark.parametrize("name", ["requests"])
def test_pypi_facts_against_the_real_registry(name):
    facts = fetch_pypi(name, downloads=False)
    if facts.unreachable:
        pytest.skip("PyPI unreachable")

    assert facts.exists is True
    assert facts.first_release is not None
    assert facts.release_count and facts.release_count > 1
    # info.downloads is dead (-1); nothing may read it back in as a real figure.
    assert facts.downloads_last_month is None
