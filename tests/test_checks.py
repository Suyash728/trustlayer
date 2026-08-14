"""L2 check tests, run against real fixture directories under tests/fixtures/.

The PyPI lookup is injected so verdicts are deterministic offline; one opt-in test hits the
real registry and skips when it is unreachable. Nothing else is stubbed.
"""

from datetime import date
from pathlib import Path
import sys

import pytest

from trustlayer.checks.api_resolution import (
    check_python_apis,
    check_typescript_apis,
    pypi_package_exists,
    rank_similar_names,
)
from trustlayer.checks.base import Severity
from trustlayer.checks.composed import (
    NATIVE_VERDICT_BUCKETS,
    _deduplicate,
    _parse_eslint,
    _parse_knip,
    _parse_ruff,
    _parse_semgrep,
    _parse_vulture,
    check_composed,
)
from trustlayer.checks.fail_open import check_python_fail_open, check_typescript_fail_open
from trustlayer.checks.stale_models import check_stale_models, load_registry


FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = FIXTURES.parents[1]
TODAY = date(2026, 8, 2)

def NEVER_ON_PYPI(name):
    return False


def ALWAYS_ON_PYPI(name):
    return True


def PYPI_UNREACHABLE(name):
    return None


def verdicts(result):
    return sorted(f.verdict for f in result.findings)


def by_verdict(result, verdict):
    return [f for f in result.findings if f.verdict == verdict]


# --------------------------------------------------------------------------------- L2a


def test_api_resolution_reports_missing_attributes_with_version_and_real_names():
    result = check_python_apis(
        FIXTURES / "api-dirty", pypi_lookup=NEVER_ON_PYPI, interpreter=Path(sys.executable)
    )

    missing = by_verdict(result, "missing-attribute")
    claims = {f.claim for f in missing}
    assert "yaml.safe_loadd()" in claims
    assert "rich.console.ConsoleeX" in claims
    assert all(f.severity is Severity.HIGH for f in missing)

    evidence = "\n".join(next(f for f in missing if f.claim == "yaml.safe_loadd()").evidence)
    # The distribution name differs from the import name; the evidence must show the real one.
    assert "PyYAML" in evidence
    assert "safe_load" in evidence


def test_unresolvable_package_absent_from_pypi_is_the_highest_severity():
    result = check_python_apis(
        FIXTURES / "api-dirty", pypi_lookup=NEVER_ON_PYPI, interpreter=Path(sys.executable)
    )

    slopsquat = by_verdict(result, "possible-slopsquat")
    assert len(slopsquat) == 1
    assert slopsquat[0].severity is Severity.HIGH
    assert "404" in "\n".join(slopsquat[0].evidence)


def test_a_network_failure_never_reads_as_a_slopsquat():
    """"Cannot reach PyPI" and "this package does not exist" are different claims."""
    result = check_python_apis(
        FIXTURES / "api-dirty", pypi_lookup=PYPI_UNREACHABLE, interpreter=Path(sys.executable)
    )

    assert by_verdict(result, "possible-slopsquat") == []
    unresolvable = by_verdict(result, "unresolvable")
    assert len(unresolvable) == 1
    assert unresolvable[0].severity is Severity.LOW


def test_a_package_that_exists_on_pypi_is_merely_not_installed():
    result = check_python_apis(
        FIXTURES / "api-dirty", pypi_lookup=ALWAYS_ON_PYPI, interpreter=Path(sys.executable)
    )

    not_installed = by_verdict(result, "not-installed")
    assert len(not_installed) == 1
    assert not_installed[0].severity is Severity.MEDIUM


def test_api_resolution_is_silent_on_a_repo_whose_imports_are_all_real():
    result = check_python_apis(
        FIXTURES / "api-clean", pypi_lookup=NEVER_ON_PYPI, interpreter=Path(sys.executable)
    )

    assert result.skipped is False
    assert result.findings == []


def test_api_resolution_skips_rather_than_guessing_when_there_is_no_environment():
    result = check_python_apis(FIXTURES / "api-clean", pypi_lookup=NEVER_ON_PYPI)

    assert result.skipped is True
    assert "no virtualenv" in result.skip_reason


def test_typescript_resolution_reports_unresolvable_without_node_modules():
    result = check_typescript_apis(FIXTURES / "failopen-dirty")

    assert result.skipped is False
    assert verdicts(result) == ["unresolvable"]
    assert "node_modules" in result.findings[0].evidence[0]


def test_rank_similar_names_puts_the_real_name_first():
    ranked = rank_similar_names("safe_loadd", ["dump", "safe_load", "safe_load_all", "load"])

    assert ranked[0][0] == "safe_load"


@pytest.mark.parametrize("name", ["requests"])
def test_pypi_lookup_against_the_real_registry(name):
    result = pypi_package_exists(name, timeout=8)
    if result is None:
        pytest.skip("PyPI unreachable")
    assert result is True


# --------------------------------------------------------------------------------- L2b


def test_registry_seeds_the_recorded_models_and_marks_them_unverified():
    registry = {model.model_id: model for model in load_registry()}

    assert registry["llama-3.3-70b-versatile"].successor == "openai/gpt-oss-120b"
    assert registry["llama-3.3-70b-versatile"].deprecated_on == date(2026, 6, 17)
    # These are Google Gemini API embedding IDs, not OpenAI's.
    assert registry["text-embedding-004"].provider == "google"
    assert registry["gemini-2.5-flash"].successor == "gemini-3.5-flash"
    assert all(model.verified is False for model in registry.values())


def test_retired_models_are_found_in_source_and_env_files():
    result = check_stale_models(FIXTURES / "models-dirty", today=TODAY)

    claims = {f.claim for f in result.findings}
    assert "llama-3.3-70b-versatile" in claims
    assert "gemini-2.0-flash-001" in claims  # matched by the wildcard entry
    assert "text-embedding-004" in claims
    assert "llama-3.1-8b-instant" in claims  # from .env.example
    assert all(f.severity is Severity.HIGH for f in result.findings)


def test_a_scheduled_retirement_is_silent_until_the_window_is_requested():
    without = check_stale_models(FIXTURES / "models-dirty", today=TODAY)
    assert "gemini-2.5-flash" not in {f.claim for f in without.findings}

    within = check_stale_models(FIXTURES / "models-dirty", today=TODAY, warn_within_days=90)
    scheduled = by_verdict(within, "scheduled-retirement")
    assert [f.claim for f in scheduled] == ["gemini-2.5-flash"]
    assert scheduled[0].severity is Severity.MEDIUM
    assert "75 days from now" in scheduled[0].evidence[0]


def test_a_retirement_beyond_the_window_stays_silent():
    result = check_stale_models(FIXTURES / "models-dirty", today=TODAY, warn_within_days=30)

    assert by_verdict(result, "scheduled-retirement") == []


def test_evidence_says_the_entry_is_unverified():
    result = check_stale_models(FIXTURES / "models-dirty", today=TODAY)

    assert any("UNVERIFIED" in line for line in result.findings[0].evidence)


def test_near_miss_model_ids_do_not_match():
    result = check_stale_models(FIXTURES / "models-clean", today=TODAY, warn_within_days=365)

    # "gemini-embedding-001" must not match "embedding-001" or "gemini-embedding-exp-*".
    assert result.findings == []


# --------------------------------------------------------------------------------- L2c


def test_fail_open_finds_every_defect_shape_in_python():
    result = check_python_fail_open(FIXTURES / "failopen-dirty")

    assert verdicts(result) == [
        "cors-wildcard-with-credentials",
        "env-default-degrades-url",
        "env-default-degrades-url",
        "gate-fails-open",
        "swallowed-exception",
        "swallowed-exception",
    ]
    high = {f.verdict for f in result.findings if f.severity is Severity.HIGH}
    assert high == {"env-default-degrades-url", "gate-fails-open"}


def test_fail_open_finds_every_defect_shape_in_typescript():
    result = check_typescript_fail_open(FIXTURES / "failopen-dirty")

    assert verdicts(result) == [
        "cors-wildcard-with-credentials",
        "env-default-degrades-url",
        "gate-fails-open",
        "swallowed-exception",
    ]


def test_every_finding_carries_the_source_line_and_a_failure_mode():
    result = check_python_fail_open(FIXTURES / "failopen-dirty")

    for finding in result.findings:
        assert len(finding.evidence) == 2
        assert finding.evidence[0].startswith(f"{finding.line}:")
        assert finding.evidence[1].endswith(".")


def test_zero_false_positives_on_the_clean_python_fixture():
    assert check_python_fail_open(FIXTURES / "failopen-clean").findings == []


def test_zero_false_positives_on_the_clean_typescript_fixture():
    assert check_typescript_fail_open(FIXTURES / "failopen-clean").findings == []


# --------------------------------------------------------------------------------- L2d


def _composed_fixture(name):
    return (FIXTURES / "composed" / name).read_text()


def test_ruff_parser_reads_real_ruff_output():
    findings = _parse_ruff(_composed_fixture("ruff-output.json"), REPO_ROOT)

    assert {f.verdict for f in findings} == {"S110", "E722"}
    assert all(f.check == "composed:ruff" for f in findings)
    assert all(f.line > 0 for f in findings)


def test_semgrep_parser_reads_real_semgrep_output():
    findings = _parse_semgrep(_composed_fixture("semgrep-output.json"), REPO_ROOT)

    assert len(findings) == 1
    assert findings[0].line == 11
    assert findings[0].severity is Severity.MEDIUM  # semgrep ERROR


def test_vulture_parser_reads_real_vulture_output():
    findings = _parse_vulture(_composed_fixture("vulture-output.txt"), REPO_ROOT)

    assert len(findings) >= 5
    assert all(f.verdict == "dead-code" for f in findings)
    assert all(f.severity is Severity.LOW for f in findings)


def test_eslint_parser_reads_real_eslint_output():
    findings = _parse_eslint(_composed_fixture("eslint-output.json"), REPO_ROOT)

    assert len(findings) >= 1
    assert all(f.check == "composed:eslint" for f in findings)


def test_knip_parser_reads_real_knip_output():
    findings = _parse_knip(_composed_fixture("knip-output.json"), REPO_ROOT)

    assert any("eslint" in f.claim for f in findings)


def test_linter_paths_are_relative_even_when_the_root_is_relative():
    """Linters emit absolute paths; if they are not normalized, dedup keys never match."""
    relative_root = Path("tests/fixtures/failopen-dirty")
    findings = _parse_ruff(_composed_fixture("ruff-output.json"), relative_root)

    assert findings
    assert all(f.file == "app.py" for f in findings)


def test_a_missing_linter_skips_with_a_reason_instead_of_failing():
    results = {result.check: result for result in check_composed(FIXTURES / "failopen-clean")}

    for tool in ("semgrep", "vulture", "eslint", "knip"):
        result = results[f"composed:{tool}"]
        assert result.skipped is True
        assert result.skip_reason
        assert result.findings == []


def test_composed_findings_are_deduplicated_against_native_ones():
    root = FIXTURES / "failopen-dirty"
    native = check_python_fail_open(root).findings
    swallowed = [f for f in native if f.verdict == "swallowed-exception"]
    assert swallowed, "fixture must contain swallowed exceptions for this test to mean anything"

    # Both sides must be relative to the same root, which is how the CLI calls them.
    ruff_findings = _parse_ruff(_composed_fixture("ruff-output.json"), root)
    assert {(f.file, f.line) for f in ruff_findings} & {(f.file, f.line) for f in swallowed}

    seen = {
        (f.file, f.line, NATIVE_VERDICT_BUCKETS.get(f.verdict, f.verdict)) for f in native
    }
    kept, dropped = _deduplicate(ruff_findings, seen, "composed:ruff")

    assert dropped >= 1, "ruff S110/E722 duplicate the native swallowed-exception findings"
    assert len(kept) == len(ruff_findings) - dropped
    assert all(f.verdict not in {"S110", "E722"} for f in kept)
