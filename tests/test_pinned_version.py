"""Pinned-version tests.

Registry answers are injected so nothing here needs the network. The load-bearing test is
`test_pep440_equivalence_is_not_a_missing_version`: `==1.0` legitimately resolves to a
release published as `1.0.0`, and string equality would report that correct pin as missing.
"""

from pathlib import Path

import pytest

from trustlayer.checks.base import Severity
from trustlayer.checks.pinned_version import CHECK_NAME, check_pinned_version
from trustlayer.registry import PackageFacts, _yanked_versions


FIXTURES = Path(__file__).parent / "fixtures"


def package(name: str, versions, yanked=None, **overrides) -> PackageFacts:
    defaults = {
        "exists": True,
        "url": f"https://pypi.org/pypi/{name}/json",
        "versions": list(versions),
        "yanked_versions": dict(yanked or {}),
    }
    return PackageFacts(name=name, **{**defaults, **overrides})


def fetcher_for(mapping):
    def fetch(name: str) -> PackageFacts:
        return mapping.get(name) or PackageFacts(name=name, unreachable=True, error="not in fixture")

    return fetch


def run(tmp_path, requirements: str, mapping):
    (tmp_path / "requirements.txt").write_text(requirements)
    return check_pinned_version(tmp_path, fetcher=fetcher_for(mapping))


# -------------------------------------------------------------------------- silence


def test_pep440_equivalence_is_not_a_missing_version(tmp_path):
    """`==1.0` resolves to a release published as `1.0.0`. String equality would misreport it."""
    result = run(tmp_path, "acme==1.0\n", {"acme": package("acme", ["1.0.0", "2.0.0"])})

    assert result.findings == []


@pytest.mark.parametrize(
    ("pinned", "published"),
    [
        ("1.0", "1.0.0"),
        ("1.0.0", "1.0"),
        ("1.0.0.0", "1.0"),
        ("2020.1", "2020.1.0"),
    ],
)
def test_equivalent_spellings_all_resolve(tmp_path, pinned, published):
    result = run(tmp_path, f"acme=={pinned}\n", {"acme": package("acme", [published])})

    assert result.findings == []


def test_a_pin_that_is_not_a_pep440_version_is_left_alone(tmp_path):
    """An unparseable pin gets no verdict rather than a guessed one."""
    result = run(tmp_path, "acme==not-a-version\n", {"acme": package("acme", ["1.0.0"])})

    assert result.findings == []


def test_a_package_that_does_not_exist_is_slopsquats_finding_not_ours(tmp_path):
    """Two checks reporting one problem twice would inflate the counts."""
    result = run(
        tmp_path,
        "ghostpkg==1.0.0\n",
        {"ghostpkg": PackageFacts(name="ghostpkg", exists=False, url="https://pypi.org/pypi/ghostpkg/json")},
    )

    assert result.findings == []


def test_an_unreachable_registry_makes_no_claim(tmp_path):
    result = run(tmp_path, "acme==1.0.0\nother==2.0.0\n", {"acme": package("acme", ["1.0.0"])})

    assert result.findings == []
    assert any("could not be checked" in note for note in result.notes)


def test_every_pin_unreachable_skips_the_check(tmp_path):
    result = run(tmp_path, "acme==1.0.0\n", {})

    assert result.skipped is True
    assert "registry unreachable" in (result.skip_reason or "")


def test_an_unpinned_spec_is_not_this_checks_business(tmp_path):
    """Detection already reports it as unpinned-dependency."""
    (tmp_path / "requirements.txt").write_text("acme>=1.0\nother~=2.0\n")
    result = check_pinned_version(tmp_path, fetcher=fetcher_for({}))

    assert result.skipped is True
    assert "no concrete Python version pins" in (result.skip_reason or "")


def test_a_valid_pin_reports_nothing(tmp_path):
    result = run(tmp_path, "acme==1.2.3\n", {"acme": package("acme", ["1.0.0", "1.2.3", "2.0.0"])})

    assert result.findings == []


# ------------------------------------------------------------------------- findings


def test_a_version_the_index_does_not_have_is_high(tmp_path):
    result = run(tmp_path, "acme==0.999.0\n", {"acme": package("acme", ["1.0.0", "2.0.0"])})

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.verdict == "nonexistent-version"
    assert finding.check == CHECK_NAME
    assert finding.claim == "acme==0.999.0"
    evidence = " ".join(finding.evidence)
    assert "2 versions" in evidence
    assert "2.0.0" in evidence  # the newest real versions, as a usable hint


def test_a_yanked_version_is_medium_and_carries_the_reason(tmp_path):
    result = run(
        tmp_path,
        "acme==1.0.0\n",
        {"acme": package("acme", ["1.0.0", "1.0.1"], yanked={"1.0.0": "Broken release"})},
    )

    finding = result.findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.verdict == "yanked-version"
    assert "Broken release" in " ".join(finding.evidence)


def test_a_yank_with_no_recorded_reason_says_so(tmp_path):
    """PyPI frequently records a null reason on a genuine yank."""
    result = run(tmp_path, "acme==1.0.0\n", {"acme": package("acme", ["1.0.0"], yanked={"1.0.0": ""})})

    assert "no reason recorded" in " ".join(result.findings[0].evidence)


def test_a_yank_is_matched_through_pep440_equivalence(tmp_path):
    """Pinning `2.0` must find the yank recorded against `2.0.0`."""
    result = run(tmp_path, "acme==2.0\n", {"acme": package("acme", ["2.0.0"], yanked={"2.0.0": "Bad"})})

    assert result.findings[0].verdict == "yanked-version"
    assert "yanked 2.0.0" in " ".join(result.findings[0].evidence)


def test_the_finding_points_at_the_declaring_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("# comment\nrequests==2.32.3\nacme==9.9.9\n")
    result = check_pinned_version(
        tmp_path,
        fetcher=fetcher_for(
            {"requests": package("requests", ["2.32.3"]), "acme": package("acme", ["1.0.0"])}
        ),
    )

    assert result.findings[0].line == 3


def test_the_check_is_opt_in():
    """It contacts registries, so it is never a surprise side effect of `audit`."""
    from trustlayer.cli import DEFAULT_CHECKS, OPT_IN_CHECKS

    assert "pinned-version" in OPT_IN_CHECKS
    assert "pinned-version" not in DEFAULT_CHECKS


# ------------------------------------------------------- yanked parsing from the index


def test_only_a_fully_yanked_release_counts_as_yanked():
    """A partially-yanked release still has something installable."""
    releases = {
        "1.0.0": [{"yanked": True, "yanked_reason": "Broken"}, {"yanked": True, "yanked_reason": "Broken"}],
        "1.1.0": [{"yanked": True, "yanked_reason": "x"}, {"yanked": False, "yanked_reason": None}],
        "1.2.0": [{"yanked": False, "yanked_reason": None}],
    }

    assert _yanked_versions(releases) == {"1.0.0": "Broken"}


def test_a_version_with_no_files_is_not_reported_as_yanked():
    """Empty file lists are real on PyPI - numpy has 14 - and say nothing about yanking."""
    assert _yanked_versions({"1.0.0": []}) == {}


def test_a_null_yank_reason_becomes_an_empty_string_not_a_crash():
    assert _yanked_versions({"1.0.0": [{"yanked": True, "yanked_reason": None}]}) == {"1.0.0": ""}


# ------------------------------------------------------------------------- cache v2


def test_the_new_fields_round_trip_through_the_cache():
    original = package("acme", ["1.0.0", "2.0.0"], yanked={"1.0.0": "Broken"})
    restored = PackageFacts.from_json(original.to_json())

    assert restored is not None
    assert restored.versions == ["1.0.0", "2.0.0"]
    assert restored.yanked_versions == {"1.0.0": "Broken"}


def test_a_version_1_cache_row_is_ignored_rather_than_misread():
    """Rows written before the versions field existed must miss, not deserialize half-empty."""
    import json

    stale = json.dumps({"version": 1, "name": "acme", "exists": True})

    assert PackageFacts.from_json(stale) is None
