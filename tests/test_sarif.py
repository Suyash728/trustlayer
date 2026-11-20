"""SARIF 2.1.0 output, `--fail-on`, and `--baseline`.

SARIF is a translation of findings that already exist; none of these may change a verdict.
Validated once by hand against https://json.schemastore.org/sarif-2.1.0.json (0 errors on
2026-11-20); these tests pin the structure that validation depends on, offline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from killscore import cli
from killscore.checks.base import CheckResult, Finding, Severity
from killscore.config import ConfigError, apply_baseline, load_baseline
from killscore.report import EXIT_CLEAN, EXIT_HIGH, EXIT_MEDIUM, exit_code_for
from killscore.sarif import FINGERPRINT_KEY, fingerprint, to_sarif


FIXTURES = Path(__file__).parent / "fixtures"


def finding(severity=Severity.HIGH, check="fail-open:python", verdict="swallowed", line=3, file="app.py"):
    return Finding(severity, check, file, line, "except Exception: pass", verdict, ["line 3", ""])


def run(log: dict) -> dict:
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    return log["runs"][0]


def test_levels_map_from_severity():
    log = to_sarif(
        [finding(Severity.HIGH, verdict="a"), finding(Severity.MEDIUM, verdict="b"),
         finding(Severity.LOW, verdict="c")],
        exit_code=2,
    )
    assert [r["level"] for r in run(log)["results"]] == ["error", "warning", "note"]


def test_one_rule_per_check_and_verdict_with_a_valid_index():
    findings = [finding(line=1), finding(line=9), finding(verdict="other")]
    sarif_run = run(to_sarif(findings, exit_code=2))

    rules = sarif_run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["fail-open:python/swallowed", "fail-open:python/other"]
    for result in sarif_run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_locations_are_repo_relative_and_never_absolute():
    result = run(to_sarif([finding(file="src/app.py", line=0)], exit_code=2))["results"][0]
    location = result["locations"][0]["physicalLocation"]

    assert location["artifactLocation"] == {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"}
    assert location["region"]["startLine"] == 1  # SARIF lines are 1-based; 0 is invalid
    assert "originalUriBaseIds" not in run(to_sarif([finding()], exit_code=2))


def test_the_fingerprint_ignores_the_line_like_diff_does():
    moved = [finding(line=3), finding(line=40)]
    prints = [r["partialFingerprints"][FINGERPRINT_KEY] for r in run(to_sarif(moved, exit_code=2))["results"]]

    assert prints[0] == prints[1] == fingerprint(moved[0])
    assert fingerprint(finding(verdict="x")) != fingerprint(finding(verdict="y"))


def test_the_message_carries_the_evidence():
    text = run(to_sarif([finding()], exit_code=2))["results"][0]["message"]["text"]

    assert text.startswith("except Exception: pass: swallowed")
    assert "- line 3" in text


def test_skipped_checks_and_notes_become_notifications():
    results = [
        CheckResult("composed:vulture", skipped=True, skip_reason="vulture is not installed"),
        CheckResult("slopsquat:pypi", notes=["corpus: top 2000"], suppressed=2),
    ]
    invocation = run(to_sarif([], results=results, exit_code=0))["invocations"][0]
    texts = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]

    assert "composed:vulture skipped: vulture is not installed" in texts
    assert "corpus: top 2000" in texts
    assert any("2 finding(s) suppressed" in t for t in texts)
    assert invocation["executionSuccessful"] is True and invocation["exitCode"] == 0


def test_security_severity_only_on_supply_chain_and_failure_checks():
    rules = run(
        to_sarif([finding(check="slopsquat:pypi"), finding(check="stale-models")], exit_code=2)
    )["tool"]["driver"]["rules"]
    by_id = {rule["id"].split("/")[0]: rule for rule in rules}

    assert by_id["slopsquat:pypi"]["properties"]["security-severity"] == "8.0"
    assert "security-severity" not in by_id["stale-models"]["properties"]


# ------------------------------------------------------------------- --fail-on


@pytest.mark.parametrize(
    ("severities", "fail_on", "expected"),
    [
        ({Severity.HIGH}, "high", EXIT_HIGH),
        ({Severity.HIGH}, "low", EXIT_HIGH),  # no threshold hides a HIGH
        ({Severity.MEDIUM}, "high", EXIT_CLEAN),
        ({Severity.MEDIUM}, "medium", EXIT_MEDIUM),
        ({Severity.LOW}, "medium", EXIT_CLEAN),  # the historical default
        ({Severity.LOW}, "low", EXIT_MEDIUM),
        (set(), "low", EXIT_CLEAN),
    ],
)
def test_fail_on_thresholds(severities, fail_on, expected):
    assert exit_code_for(severities, fail_on) == expected


def test_an_unknown_threshold_is_refused():
    with pytest.raises(ValueError):
        exit_code_for({Severity.HIGH}, "critical")


# -------------------------------------------------------------------- --baseline


def test_the_audit_json_is_the_baseline_format(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"findings": [
        {"check": "fail-open:python", "file": "app.py", "claim": "except Exception: pass",
         "verdict": "swallowed", "line": 99},
    ]}))
    known = load_baseline(path)

    results, hidden = apply_baseline(
        [CheckResult("fail-open:python", findings=[finding(line=3), finding(verdict="new")])], known
    )
    assert hidden == 1  # the moved finding is still known
    assert [f.verdict for f in results[0].findings] == ["new"]


@pytest.mark.parametrize("content", ["not json", "[]", '{"findings": [{"check": "x"}]}'])
def test_a_malformed_baseline_is_an_error(tmp_path, content):
    path = tmp_path / "baseline.json"
    path.write_text(content)
    with pytest.raises(ConfigError):
        load_baseline(path)


# --------------------------------------------------------------------- the CLI


def _cli(monkeypatch, capsys, *args):
    monkeypatch.setattr("sys.argv", ["killscore", *args])
    code = cli.main_entry()
    return code, capsys.readouterr().out


def test_audit_writes_only_sarif_to_stdout(monkeypatch, capsys):
    code, out = _cli(monkeypatch, capsys, "audit", str(FIXTURES / "failopen-dirty"), "--no-save", "--format", "sarif")

    log = json.loads(out)
    assert code == 2
    assert log["runs"][0]["invocations"][0]["exitCode"] == 2
    assert log["runs"][0]["results"]


def test_fail_on_never_hides_a_high_finding(monkeypatch, capsys):
    code, _ = _cli(monkeypatch, capsys, "audit", str(FIXTURES / "failopen-dirty"), "--no-save", "--fail-on", "high")
    assert code == 2


def test_fail_on_high_lets_medium_findings_pass(monkeypatch, capsys):
    medium = CheckResult("stale-models", findings=[finding(Severity.MEDIUM, check="stale-models")])
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: [medium])
    target = str(FIXTURES / "models-clean")

    assert _cli(monkeypatch, capsys, "audit", target, "--no-save")[0] == 1
    assert _cli(monkeypatch, capsys, "audit", target, "--no-save", "--fail-on", "high")[0] == 0


def test_a_baseline_of_the_same_run_makes_it_clean(monkeypatch, capsys, tmp_path):
    target = str(FIXTURES / "failopen-dirty")
    _, out = _cli(monkeypatch, capsys, "audit", target, "--no-save", "--format", "json")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(out)

    code, text = _cli(monkeypatch, capsys, "audit", target, "--no-save", "--baseline", str(baseline))

    assert code == 0
    assert "baselined" in text and "known finding(s)" in text


@pytest.mark.parametrize(
    "args",
    [
        ("--json", "--format", "sarif"),
        ("--format", "xml"),
        ("--fail-on", "critical"),
    ],
)
def test_bad_output_options_are_operational_errors(monkeypatch, capsys, args):
    code, _ = _cli(monkeypatch, capsys, "audit", str(FIXTURES / "models-clean"), "--no-save", *args)
    assert code == 3


def test_deps_writes_sarif_too(monkeypatch, capsys):
    code, out = _cli(monkeypatch, capsys, "deps", str(FIXTURES / "slopsquat-clean"), "--no-network", "--format", "sarif")

    assert code == 0
    assert json.loads(out)["runs"][0]["results"] == []
