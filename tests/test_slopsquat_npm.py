"""npm in `deps` / `slopsquat`: same additive, re-derivable score as PyPI, npm's own facts.

Registry shapes here were probed from registry.npmjs.org and api.npmjs.org on 2026-11-20
(see the registry.py docstring). Every test is offline: registries are stubbed.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from trustlayer import registry
from trustlayer.checks.base import Severity
from trustlayer.checks.slopsquat import (
    NPM_CHECK_NAME,
    check_slopsquat_all,
    npm_registry_name,
    scan,
    scan_findings,
)
from trustlayer.registry import PackageFacts, fetch_many, fetch_npm
from trustlayer.risk import (
    MEDIUM_THRESHOLD,
    NPM,
    Corpus,
    load_corpus,
    score_package,
)


FIXTURES = Path(__file__).parent / "fixtures"
TODAY = date(2026, 11, 20)
NPM_CORPUS = Corpus(
    downloads={"react": 1_062_397_870, "lodash": 859_549_356, "express": 826_990_589,
               "@types/node": 2_619_507_874, "debug": 3_941_168_743},
    source="test",
    ecosystem=NPM,
)


def facts(name, **kwargs) -> PackageFacts:
    return PackageFacts(name=name, ecosystem="npm", url=f"https://registry.npmjs.org/{name}", **kwargs)


ESTABLISHED = {
    "exists": True, "first_release": date(2015, 1, 1), "release_count": 40,
    "maintainer_count": 3, "downloads_last_month": 2_000_000,
}
REGISTRY = {
    "lodahs": facts("lodahs", exists=False),
    "@types/nodee": facts("@types/nodee", exists=False),
    "expresss": facts("expresss", exists=False),
    "crossenv": facts("crossenv", exists=True, security_holding=True, release_count=4),
    "azure-sdk-v4": facts("azure-sdk-v4", exists=True, unpublished=True),
    "fresh-helper": facts(
        "fresh-helper", exists=True, first_release=date(2026, 11, 10), release_count=1,
        maintainer_count=1, downloads_last_month=40,
    ),
}


def fake_registry(name: str) -> PackageFacts:
    return REGISTRY.get(name) or facts(name, **ESTABLISHED)


# ---------------------------------------------------------------- spec handling


@pytest.mark.parametrize(
    ("name", "spec", "expected"),
    [
        ("lodash", "^4.17.21", "lodash"),
        ("@types/node", "^20", "@types/node"),
        ("my-lodash", "npm:lodash@^4", "lodash"),  # the alias target is what installs
        ("my-types", "npm:@types/node@^20", "@types/node"),
        ("bare-alias", "npm:left-pad", "left-pad"),
        ("local", "file:../local", None),
        ("ws", "workspace:*", None),
        ("linked", "link:../x", None),
        ("gh", "github:user/repo", None),
        ("shorthand", "user/repo#main", None),
        ("git", "git+https://github.com/u/r.git", None),
        ("tarball", "https://example.com/x.tgz", None),
    ],
)
def test_only_registry_specs_are_scored(name, spec, expected):
    assert npm_registry_name(name, spec) == expected


# ------------------------------------------------------------- the score itself


def test_a_corpus_hit_short_circuits_and_is_case_sensitive():
    assert score_package("react", facts("react"), NPM_CORPUS).verdict == "popular-package"
    # npm does not fold case: `React` is not `react`, so it is not waved through.
    assert "React" not in NPM_CORPUS


def test_a_definitive_404_is_100_and_names_the_likely_intent():
    risk = score_package("lodahs", REGISTRY["lodahs"], NPM_CORPUS, today=TODAY)

    assert (risk.score, risk.severity, risk.verdict) == (100, Severity.HIGH, "nonexistent-package")
    assert "`npm install` would fail" in " ".join(risk.evidence)
    assert risk.neighbour.name == "lodash"


def test_an_unpublished_package_is_definitive():
    risk = score_package("azure-sdk-v4", REGISTRY["azure-sdk-v4"], NPM_CORPUS, today=TODAY)

    assert (risk.score, risk.verdict) == (100, "unpublished-package")
    assert "registered again" in " ".join(risk.evidence)


def test_a_security_holding_package_is_definitive():
    risk = score_package("crossenv", REGISTRY["crossenv"], NPM_CORPUS, today=TODAY)

    assert (risk.score, risk.verdict) == (100, "security-holding-package")


def test_typo_adjacency_alone_stays_under_medium_on_npm_too():
    """Invariant 1, npm twin: a real, established package one edit from a popular one."""
    risk = score_package("debgu", facts("debgu", **ESTABLISHED), NPM_CORPUS, today=TODAY)

    assert risk.neighbour is not None and risk.neighbour.distance == 1
    assert risk.score < MEDIUM_THRESHOLD


def test_unmeasurable_factors_score_zero_and_say_why_on_npm_too():
    """Invariant 2, npm twin."""
    risk = score_package("mystery", facts("mystery", exists=True), NPM_CORPUS, today=TODAY)

    assert risk.score == 0
    assert any("unavailable" in line for line in risk.evidence)


def test_a_young_single_maintainer_unknown_package_adds_up():
    risk = score_package("fresh-helper", REGISTRY["fresh-helper"], NPM_CORPUS, today=TODAY)

    assert risk.score == 30 + 15 + 10 + 20  # age + releases + maintainers + downloads
    assert risk.severity is Severity.HIGH


def test_a_deprecated_latest_version_is_a_hygiene_factor():
    deprecated = facts("old-thing", deprecated_note="use something-else", **ESTABLISHED)
    risk = score_package("old-thing", deprecated, NPM_CORPUS, today=TODAY)

    assert risk.score == 10
    assert any("deprecated on the registry: use something-else" in line for line in risk.evidence)


# ------------------------------------------------------------------ the scan


def test_the_scan_scores_package_json_with_npm_names_and_npm_check():
    result = scan(
        FIXTURES / "slopsquat-npm-dirty", fetcher=fake_registry, npm_corpus=NPM_CORPUS, today=TODAY
    )
    by_name = {item.name: item for item in result.scored}

    assert "my-express" not in by_name and by_name["expresss"].risk.verdict == "nonexistent-package"
    assert by_name["react"].risk.verdict == "popular-package"
    assert by_name["@types/nodee"].risk.neighbour.name == "@types/node"
    assert {"local-thing", "forked"}.isdisjoint(by_name)
    assert any("2 package.json spec(s) not scored" in note for note in result.notes)
    assert all(item.ecosystem == "npm" for item in result.scored)

    findings = scan_findings(result)
    assert {f.check for f in findings} == {NPM_CHECK_NAME}
    assert {f.verdict for f in findings} >= {
        "nonexistent-package", "unpublished-package", "security-holding-package",
    }
    lodahs = next(f for f in findings if f.claim.startswith("lodahs"))
    assert lodahs.claim == "lodahs@^4.17.21"
    assert lodahs.file == "package.json" and lodahs.line == 7


def test_a_clean_package_json_needs_no_network():
    def never(name):
        raise AssertionError(f"fetched {name} although it is in the corpus")

    result = scan(FIXTURES / "slopsquat-npm-clean", fetcher=never, npm_corpus=NPM_CORPUS, today=TODAY)
    assert scan_findings(result) == []


def test_npm_findings_get_their_own_check_result():
    results = check_slopsquat_all(
        FIXTURES / "slopsquat-npm-dirty", fetcher=fake_registry, npm_corpus=NPM_CORPUS, today=TODAY
    )
    by_check = {result.check: result for result in results}

    assert by_check["slopsquat:pypi"].skipped  # no Python manifest here
    assert by_check[NPM_CHECK_NAME].findings


def test_a_python_only_repo_is_not_told_about_npm():
    results = check_slopsquat_all(
        FIXTURES / "slopsquat-clean", fetcher=fake_registry, today=TODAY
    )
    assert [result.check for result in results] == ["slopsquat:pypi"]


def test_offline_mode_is_deterministic(tmp_path):
    db = tmp_path / "runs.db"
    first = scan(FIXTURES / "slopsquat-npm-dirty", offline=True, db_path=db, npm_corpus=NPM_CORPUS, today=TODAY)
    second = scan(FIXTURES / "slopsquat-npm-dirty", offline=True, db_path=db, npm_corpus=NPM_CORPUS, today=TODAY)

    assert [(i.name, i.risk.score, i.risk.verdict) for i in first.scored] == [
        (i.name, i.risk.score, i.risk.verdict) for i in second.scored
    ]
    # With no cache, anything outside the corpus is unscorable - never guessed at.
    assert {i.risk.verdict for i in first.scored if i.name != "react"} == {"unscorable"}


# ------------------------------------------------------------- the registry


class _Answer:
    def __init__(self, data=None, not_found=False, error=None):
        self.data, self.not_found, self.error = data, not_found, error


def _serve(monkeypatch, pages: dict[str, _Answer]):
    seen = []

    def get_json(url, timeout):
        seen.append(url)
        return pages[url]

    monkeypatch.setattr(registry, "_get_json", get_json)
    return seen


def test_fetch_npm_reads_the_probed_shape(monkeypatch):
    seen = _serve(
        monkeypatch,
        {
            "https://registry.npmjs.org/@scope%2Fpkg": _Answer(
                {
                    "name": "@scope/pkg",
                    "dist-tags": {"latest": "2.0.0"},
                    "time": {"created": "2014-03-14T09:09:20.762Z", "1.0.0": "2014-03-14T09:09:20.762Z",
                             "2.0.0": "2020-01-01T00:00:00.000Z"},
                    "versions": {"1.0.0": {}, "2.0.0": {"deprecated": "use other"}},
                    "maintainers": [{"name": "a"}, {"name": "b"}],
                }
            ),
            "https://api.npmjs.org/downloads/point/last-month/@scope%2Fpkg": _Answer(
                {"downloads": 1234, "package": "@scope/pkg"}
            ),
        },
    )
    got = fetch_npm("@scope/pkg")

    assert seen[0] == "https://registry.npmjs.org/@scope%2Fpkg"
    assert (got.exists, got.release_count, got.maintainer_count) == (True, 2, 2)
    assert got.first_release == date(2014, 3, 14) and got.last_release == date(2020, 1, 1)
    assert got.deprecated_note == "use other"
    assert got.downloads_last_month == 1234
    assert not got.unpublished and not got.security_holding


def test_fetch_npm_recognises_unpublished_and_holding_packages(monkeypatch):
    _serve(
        monkeypatch,
        {
            "https://registry.npmjs.org/gone": _Answer(
                {"_id": "gone", "name": "gone",
                 "time": {"created": "2022-03-09T10:08:53.909Z",
                          "unpublished": {"time": "2022-03-09T10:08:53.909Z", "versions": ["99.10.11"]}}}
            ),
            "https://registry.npmjs.org/held": _Answer(
                {"name": "held", "description": "security holding package",
                 "dist-tags": {"latest": "0.0.1-security"}, "time": {}, "versions": {"0.0.1-security": {}}}
            ),
            "https://registry.npmjs.org/coincidence": _Answer(
                {"name": "coincidence", "description": "a real library",
                 "dist-tags": {"latest": "2.0.0-security"}, "time": {}, "versions": {"2.0.0-security": {}}}
            ),
            "https://api.npmjs.org/downloads/point/last-month/held": _Answer(not_found=True),
            "https://api.npmjs.org/downloads/point/last-month/coincidence": _Answer(error="timeout"),
        },
    )

    assert fetch_npm("gone").unpublished is True
    assert fetch_npm("held").security_holding is True
    # Both conditions are required: a version string alone is not npm's takeover marker.
    coincidence = fetch_npm("coincidence")
    assert coincidence.security_holding is False
    assert coincidence.downloads_last_month is None and "unreachable" in coincidence.downloads_note


def test_an_empty_deprecation_message_means_un_deprecated(monkeypatch):
    _serve(
        monkeypatch,
        {
            "https://registry.npmjs.org/back": _Answer(
                {"name": "back", "dist-tags": {"latest": "1.0.0"}, "time": {},
                 "versions": {"1.0.0": {"deprecated": ""}}}
            ),
        },
    )
    assert fetch_npm("back", downloads=False).deprecated_note is None


def test_a_404_and_an_outage_stay_different_claims(monkeypatch):
    _serve(
        monkeypatch,
        {
            "https://registry.npmjs.org/nope": _Answer(not_found=True),
            "https://registry.npmjs.org/flaky": _Answer(error="timed out"),
        },
    )
    assert fetch_npm("nope").exists is False
    flaky = fetch_npm("flaky")
    assert flaky.exists is None and flaky.unreachable


def test_npm_and_pypi_caches_do_not_collide(tmp_path, monkeypatch):
    """Same name, two registries: `requests` on npm is not `requests` on PyPI."""
    db = tmp_path / "runs.db"
    registry._write_cache([facts("Requests", exists=False)], db, "npm")

    npm_hit = fetch_many(["Requests"], db_path=db, offline=True, ecosystem="npm")["Requests"]
    pypi_miss = fetch_many(["Requests"], db_path=db, offline=True, ecosystem="pypi")["Requests"]
    npm_case_miss = fetch_many(["requests"], db_path=db, offline=True, ecosystem="npm")["requests"]

    assert npm_hit.exists is False and npm_hit.from_cache
    assert pypi_miss.unreachable and npm_case_miss.unreachable


def test_the_vendored_npm_corpus_loads_with_npm_rules():
    corpus = load_corpus(ecosystem=NPM)

    assert corpus.ecosystem == NPM and len(corpus) > 1000
    assert "react" in corpus and "@types/node" in corpus
    assert "top" in corpus.provenance and "npm" in corpus.provenance


def test_notes_land_on_the_ecosystem_they_describe():
    results = check_slopsquat_all(
        FIXTURES / "slopsquat-npm-dirty", fetcher=fake_registry, npm_corpus=NPM_CORPUS, today=TODAY
    )
    npm_notes = next(r for r in results if r.check == NPM_CHECK_NAME).notes

    assert any("npm packages" in note or "corpus: top" in note for note in npm_notes)
    assert any("not on a registry" in note for note in npm_notes)


def test_an_excluded_manifest_leaves_no_note_behind(tmp_path):
    from trustlayer.config import Config

    fixture = tmp_path / "fixtures" / "app"
    fixture.mkdir(parents=True)
    (fixture / "package.json").write_text('{"dependencies": {"local": "file:../x", "react": "^18"}}')
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")

    result = scan(tmp_path, fetcher=fake_registry, npm_corpus=NPM_CORPUS, config=Config(exclude=("fixtures",)))

    assert not any("not on a registry" in note for note in result.notes)
