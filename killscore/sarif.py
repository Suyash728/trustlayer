"""SARIF 2.1.0 output, for GitHub code scanning and any other SARIF consumer.

A pure translation of findings that already exist: nothing here computes or changes a
severity, a verdict or an exit code. The mapping:

- rule      one per `(check, verdict)`, id `<check>/<verdict>` - the verdict vocabulary is
            closed per check, so the rule set is stable across runs
- level     high -> error, medium -> warning, low -> note
- location  the repo-relative file and line, against `%SRCROOT%`; no absolute local path is
            written, so the file can be uploaded without leaking the machine's layout
- identity  `partialFingerprints` hashes `(check, file, claim, verdict)` - the same line-free
            identity `killscore diff` uses - so a finding that moves is not a new alert
- skipped   each skipped check becomes a `toolExecutionNotification`, so "no results" and
            "this check could not run" stay distinguishable in the upload

`security-severity` (which makes GitHub file an alert under security) is set only for the
checks that are about supply chain or failure handling, not for every finding.
"""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json

from killscore import __version__
from killscore.checks.base import CheckResult, Finding, Severity


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Suyash728/killscore"
FINGERPRINT_KEY = "killscoreIdentity/v1"

LEVELS = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0"}
SECURITY_CHECK_FAMILIES = ("slopsquat", "fail-open", "pinned-version", "gha-refs")


def rule_id(finding: Finding) -> str:
    return f"{finding.check}/{finding.verdict}"


def fingerprint(finding: Finding) -> str:
    # \x1f (unit separator) cannot appear in any of the parts, so the join is unambiguous.
    identity = f"{finding.check}\x1f{finding.file}\x1f{finding.claim}\x1f{finding.verdict}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def to_sarif(
    findings: Iterable[Finding],
    *,
    results: Iterable[CheckResult] = (),
    exit_code: int,
    notes: Iterable[str] = (),
) -> dict:
    """One SARIF log with one run. `results` supplies skipped checks and per-check notes."""
    ordered = list(findings)
    rules: dict[str, dict] = {}
    for finding in ordered:
        identifier = rule_id(finding)
        if identifier not in rules:
            rules[identifier] = _rule(finding)

    rule_index = {identifier: index for index, identifier in enumerate(rules)}
    notifications = _notifications(results, notes)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "killscore",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        # 3 is the operational-error code; anything else means the tool ran.
                        "executionSuccessful": exit_code != 3,
                        "exitCode": exit_code,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "columnKind": "unicodeCodePoints",
                "results": [_result(finding, rule_index) for finding in ordered],
            }
        ],
    }


def render_sarif(log: dict) -> str:
    return json.dumps(log, indent=2)


def _rule(finding: Finding) -> dict:
    family = finding.check.split(":", 1)[0]
    properties: dict = {"tags": ["killscore", family]}
    if family in SECURITY_CHECK_FAMILIES:
        properties["tags"].append("security")
        properties["security-severity"] = SECURITY_SEVERITY[finding.severity]
    return {
        "id": rule_id(finding),
        "name": _camel(f"{finding.check} {finding.verdict}"),
        "shortDescription": {"text": f"{finding.check}: {finding.verdict}"},
        "fullDescription": {
            "text": (
                f"killscore check `{finding.check}` reported `{finding.verdict}`. Every "
                "result carries the evidence it was decided on; no model decides a verdict."
            )
        },
        "helpUri": f"{INFORMATION_URI}#{family}",
        "defaultConfiguration": {"level": LEVELS[finding.severity]},
        "properties": properties,
    }


def _result(finding: Finding, rule_index: dict[str, int]) -> dict:
    evidence = [line for line in finding.evidence if line]
    text = f"{finding.claim}: {finding.verdict}"
    if evidence:
        text += "\n" + "\n".join(f"- {line}" for line in evidence)
    return {
        "ruleId": rule_id(finding),
        "ruleIndex": rule_index[rule_id(finding)],
        "level": LEVELS[finding.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(finding)},
        "properties": {
            "killscoreSeverity": finding.severity.value,
            "claim": finding.claim,
            "evidence": evidence,
        },
    }


def _notifications(results: Iterable[CheckResult], notes: Iterable[str]) -> list[dict]:
    out: list[dict] = []
    for result in results:
        if result.skipped:
            out.append(
                {
                    "level": "warning",
                    "message": {"text": f"{result.check} skipped: {result.skip_reason}"},
                    "descriptor": {"id": result.check},
                }
            )
        for note in result.notes:
            out.append(
                {"level": "note", "message": {"text": note}, "descriptor": {"id": result.check}}
            )
        if result.suppressed:
            out.append(
                {
                    "level": "note",
                    "message": {
                        "text": f"{result.suppressed} finding(s) suppressed by exclude/inline ignore"
                    },
                    "descriptor": {"id": result.check},
                }
            )
    out.extend({"level": "note", "message": {"text": note}} for note in notes)
    return out


def _camel(text: str) -> str:
    words = [word for word in "".join(c if c.isalnum() else " " for c in text).split() if word]
    return "".join(word[:1].upper() + word[1:] for word in words)
