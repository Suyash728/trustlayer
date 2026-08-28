"""The report layer.

Groups findings by check, worst first, and renders them as plain text: no boxes, no emoji,
colour on severity and nothing else. Also owns the JSON form and the exit code, which is
what makes the audit callable from a pre-commit hook.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import textwrap
from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

from trustlayer.checks.base import SEVERITY_ORDER, CheckResult, Finding, Severity, sort_findings
from trustlayer.detect import RepoProfile
from trustlayer.suite import SuiteState


if TYPE_CHECKING:
    # Import-time only. At runtime this would close a cycle:
    # report -> checks.slopsquat -> registry -> store -> report.
    from trustlayer.checks.slopsquat import ScanResult
    from trustlayer.explain import Explanation


JSON_SCHEMA_VERSION = 1

EXIT_CLEAN = 0
EXIT_MEDIUM = 1
EXIT_HIGH = 2
EXIT_ERROR = 3

SEVERITY_STYLES = {Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan"}
LABEL_WIDTH = 7
INDENT = "  "


@dataclass(frozen=True)
class Report:
    root: Path
    profile: RepoProfile
    results: list[CheckResult]
    suite: SuiteState

    @property
    def findings(self) -> list[Finding]:
        return sort_findings([f for result in self.results for f in result.findings])

    @property
    def groups(self) -> list[tuple[str, list[Finding]]]:
        """Findings by check. Worst group first; worst finding first inside each group."""
        buckets: dict[str, list[Finding]] = {}
        for result in self.results:
            if result.findings:
                buckets.setdefault(result.check, []).extend(result.findings)

        ordered = [(check, sort_findings(items)) for check, items in buckets.items()]
        ordered.sort(key=lambda pair: (SEVERITY_ORDER[pair[1][0].severity], pair[0]))
        return ordered

    @property
    def counts(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def skipped(self) -> list[CheckResult]:
        return [result for result in self.results if result.skipped]

    @property
    def exit_code(self) -> int:
        counts = self.counts
        if counts[Severity.HIGH]:
            return EXIT_HIGH
        if counts[Severity.MEDIUM]:
            return EXIT_MEDIUM
        return EXIT_CLEAN


def render_text(report: Report, console: Console) -> None:
    """Print the human report. Every user-supplied string goes through Text, never markup."""
    console.print(Text(f"trustlayer audit  {report.root}"))
    console.print(Text(_profile_line(report.profile)))
    console.print()

    for check, findings in report.groups:
        console.print(Text(check))
        for finding in findings:
            _print_finding(finding, console)
        console.print()

    _print_skipped(report, console)
    _print_suite(report, console)
    _print_summary(report, console)


def _profile_line(profile: RepoProfile) -> str:
    languages = ", ".join(language.value for language in profile.languages) or "no language detected"
    pinned = sum(project.pinned_count for project in profile.projects)
    total = sum(len(project.dependencies) for project in profile.projects)

    parts = [
        languages,
        f"{len(profile.projects)} project{'s' if len(profile.projects) != 1 else ''}",
        f"{pinned}/{total} pinned",
    ]
    if profile.findings:
        parts.append(f"{len(profile.findings)} profile finding{'s' if len(profile.findings) != 1 else ''}")
    return "  |  ".join(parts)


def _print_finding(finding: Finding, console: Console) -> None:
    # Build by appending spans: a base style on Text() would colour the whole line, and
    # only the severity label is allowed to carry colour.
    label = Text(INDENT)
    label.append(
        f"{finding.severity.value.upper():<{LABEL_WIDTH}}", style=SEVERITY_STYLES[finding.severity]
    )
    label.append(f"{finding.file}:{finding.line}  {finding.claim}")
    console.print(label)

    pad = INDENT + " " * LABEL_WIDTH
    console.print(Text(f"{pad}{finding.verdict}"))

    # Wrap by hand so continuation lines stay under the evidence indent instead of
    # falling back to column 0. break_long_words=False keeps URLs copy-pasteable.
    prefix = pad + INDENT
    width = max(console.width - len(prefix), 20)
    for line in finding.evidence:
        if not line:
            continue
        for wrapped in textwrap.wrap(line, width=width, break_long_words=False, break_on_hyphens=False) or [""]:
            console.print(Text(f"{prefix}{wrapped}"))


def _print_skipped(report: Report, console: Console) -> None:
    skipped = report.skipped
    if not skipped:
        return
    console.print(Text("skipped"))
    width = max(len(result.check) for result in skipped)
    for result in skipped:
        console.print(Text(f"{INDENT}{result.check:<{width}}  {result.skip_reason or ''}"))
    console.print()


def _print_suite(report: Report, console: Console) -> None:
    suite = report.suite
    parts = [
        f"{suite.test_files} file{'s' if suite.test_files != 1 else ''}",
        f"{suite.tests} test{'s' if suite.tests != 1 else ''}",
    ]
    if suite.coverage_percent is None:
        parts.append("coverage unavailable")
    else:
        parts.append(f"coverage {_percent(suite.coverage_percent)} ({suite.coverage_source})")

    console.print(Text("tests  " + "  |  ".join(parts)))
    for note in suite.notes:
        console.print(Text(f"{INDENT}{note}"))

    if suite.harden_suggested:
        console.print(
            Text(f"coverage is {_percent(suite.coverage_percent)} - run `trustlayer harden` to raise it")
        )
    console.print()


def _percent(value: float | None) -> str:
    if value is None:
        return "unavailable"
    return f"{value:.0f}%" if float(value).is_integer() else f"{value:.1f}%"


def _print_summary(report: Report, console: Console) -> None:
    counts = report.counts
    summary = Text()
    for index, severity in enumerate(Severity):
        if index:
            summary.append("  |  ")
        summary.append(f"{counts[severity]} {severity.value}", style=SEVERITY_STYLES[severity] if counts[severity] else "")
    console.print(summary)


def to_dict(report: Report) -> dict:
    """The machine form. Versioned so consumers can branch on shape changes."""
    counts = report.counts
    return {
        "version": JSON_SCHEMA_VERSION,
        "root": str(report.root),
        "exit_code": report.exit_code,
        "summary": {
            "high": counts[Severity.HIGH],
            "medium": counts[Severity.MEDIUM],
            "low": counts[Severity.LOW],
            "total": len(report.findings),
        },
        "checks": [
            {
                "check": result.check,
                "skipped": result.skipped,
                "skip_reason": result.skip_reason,
                "notes": list(result.notes),
                "findings": len(result.findings),
            }
            for result in report.results
        ],
        "findings": [
            {
                "severity": finding.severity.value,
                "check": finding.check,
                "file": finding.file,
                "line": finding.line,
                "claim": finding.claim,
                "verdict": finding.verdict,
                "evidence": list(finding.evidence),
            }
            for finding in report.findings
        ],
        "suite": {
            "test_files": report.suite.test_files,
            "tests": report.suite.tests,
            "coverage_percent": report.suite.coverage_percent,
            "coverage_source": report.suite.coverage_source,
            "harden_suggested": report.suite.harden_suggested,
            "notes": list(report.suite.notes),
        },
        "profile": {
            "languages": [language.value for language in report.profile.languages],
            "projects": [
                {
                    "path": project.path,
                    "language": project.language.value,
                    "manifests": list(project.manifests),
                    "lockfile": project.lockfile,
                    "runners": [{"name": r.name, "evidence": r.evidence} for r in project.runners],
                    "dependencies": [
                        {
                            "name": d.name,
                            "version": d.version,
                            "pinned": d.pinned,
                            "declared_spec": d.declared_spec,
                            "source": d.source,
                        }
                        for d in project.dependencies
                    ],
                }
                for project in report.profile.projects
            ],
            "findings": [
                {"kind": f.kind, "project": f.project, "detail": f.detail}
                for f in report.profile.findings
            ],
        },
    }


def render_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2)


def deps_exit_code(result: ScanResult) -> int:
    """Severity owns the exit code here exactly as it does for `audit`."""
    severities = {item.risk.severity for item in result.reportable}
    if Severity.HIGH in severities:
        return EXIT_HIGH
    if Severity.MEDIUM in severities:
        return EXIT_MEDIUM
    return EXIT_CLEAN


def render_deps(
    result: ScanResult, root: Path, console: Console, explanation: Explanation | None = None
) -> None:
    """The ranked score table for `trustlayer deps`. Riskiest first."""
    console.print(Text(f"trustlayer deps  {root}"))
    console.print(Text(f"{len(result.scored)} package{'s' if len(result.scored) != 1 else ''} scored"))
    for note in result.notes:
        console.print(Text(f"{INDENT}{note}"))
    console.print()

    for item in result.reportable:
        _print_scored(item, console)

    cleared = [item for item in result.scored if not item.risk.reportable and item.risk.score is not None]
    if cleared:
        console.print(Text("cleared"))
        width = max(len(item.name) for item in cleared)
        for item in cleared:
            console.print(Text(f"{INDENT}{item.name:<{width}}  {item.risk.score:>3}  {item.risk.verdict}"))
        console.print()

    unscorable = [item for item in result.scored if item.risk.score is None]
    if unscorable:
        console.print(Text("not scored"))
        width = max(len(item.name) for item in unscorable)
        for item in unscorable:
            detail = item.risk.factors[0].detail if item.risk.factors else "registry unreachable"
            console.print(Text(f"{INDENT}{item.name:<{width}}  {detail}"))
        console.print()

    if explanation is not None:
        console.print(Text("explanation"))
        width = max(console.width - len(INDENT), 20)
        for paragraph in explanation.text.splitlines():
            for wrapped in textwrap.wrap(paragraph, width=width) or [""]:
                console.print(Text(f"{INDENT}{wrapped}"))
        console.print(Text(f"{INDENT}({explanation.attribution})"))
        console.print()

    _print_deps_summary(result, console)


def _print_scored(item, console: Console) -> None:
    severity = item.risk.severity
    label = Text(INDENT)
    label.append(f"{severity.value.upper():<{LABEL_WIDTH}}", style=SEVERITY_STYLES[severity])
    label.append(f"{item.risk.score:>3}  {item.name}{item.declared_spec or ''}  {item.file}:{item.line}")
    console.print(label)

    pad = INDENT + " " * LABEL_WIDTH
    console.print(Text(f"{pad}{item.risk.verdict}"))

    prefix = pad + INDENT
    width = max(console.width - len(prefix), 20)
    for line in item.risk.evidence[1:]:  # [0] is the score line, already shown in the label
        for wrapped in textwrap.wrap(line, width=width, break_long_words=False, break_on_hyphens=False) or [""]:
            console.print(Text(f"{prefix}{wrapped}"))
    console.print()


def _print_deps_summary(result: ScanResult, console: Console) -> None:
    counts = {severity: 0 for severity in Severity}
    for item in result.reportable:
        counts[item.risk.severity] += 1

    summary = Text()
    for index, severity in enumerate(Severity):
        if index:
            summary.append("  |  ")
        summary.append(
            f"{counts[severity]} {severity.value}", style=SEVERITY_STYLES[severity] if counts[severity] else ""
        )
    console.print(summary)


def deps_to_dict(result: ScanResult, root: Path, explanation: Explanation | None = None) -> dict:
    """The machine form of a dependency scan, including every factor and its points."""
    return {
        "version": JSON_SCHEMA_VERSION,
        "root": str(root),
        "exit_code": deps_exit_code(result),
        "corpus": {
            "source": result.corpus.source if result.corpus else "",
            "packages": len(result.corpus) if result.corpus else 0,
            "upstream_last_update": result.corpus.upstream_last_update if result.corpus else "",
            "vendored_on": result.corpus.vendored_on if result.corpus else "",
        },
        "notes": list(result.notes),
        "packages": [
            {
                "name": item.name,
                "declared_spec": item.declared_spec,
                "pinned": item.pinned,
                "file": item.file,
                "line": item.line,
                "score": item.risk.score,
                "severity": item.risk.severity.value if item.risk.severity else None,
                "verdict": item.risk.verdict,
                "nearest_popular": (
                    {
                        "name": item.risk.neighbour.name,
                        "distance": item.risk.neighbour.distance,
                        "downloads": item.risk.neighbour.downloads,
                    }
                    if item.risk.neighbour
                    else None
                ),
                "factors": [
                    {"name": f.name, "points": f.points, "detail": f.detail} for f in item.risk.factors
                ],
            }
            for item in result.scored
        ],
        # Prose, never a verdict. The scores above are computed before this is requested.
        "explanation": (
            {
                "text": explanation.text,
                "backend": explanation.backend,
                "model": explanation.model,
                "input_tokens": explanation.input_tokens,
                "output_tokens": explanation.output_tokens,
                "duration_ms": explanation.duration_ms,
            }
            if explanation is not None
            else None
        ),
    }


def render_deps_json(
    result: ScanResult, root: Path, explanation: Explanation | None = None
) -> str:
    return json.dumps(deps_to_dict(result, root, explanation), indent=2)


def render_registry(registry: list, console: Console, today) -> None:
    """Plain-text model registry for `trustlayer models --list`."""
    if not registry:
        console.print(Text("the deprecation registry is empty"))
        return

    rows = [
        (
            model.model_id,
            model.provider,
            str(model.deprecated_on) if model.deprecated_on else "no date",
            model.status(today),
            model.successor or "no successor recorded",
            model.source_url if (model.verified and model.source_url) else "UNVERIFIED",
        )
        for model in registry
    ]
    widths = [max(len(row[column]) for row in rows) for column in range(5)]

    for row in rows:
        line = Text()
        for column in range(5):
            line.append(f"{row[column]:<{widths[column]}}  ")
        line.append(row[5], style="yellow" if row[5] == "UNVERIFIED" else "")
        console.print(line)

    unverified = sum(1 for row in rows if row[5] == "UNVERIFIED")
    console.print()
    if unverified:
        console.print(
            Text(
                f"{unverified} of {len(rows)} entries are UNVERIFIED: seeded from a maintainer note, "
                "not confirmed against a vendor deprecation page."
            )
        )
    console.print(Text("This registry is hand-maintained and goes stale. See README.md."))
