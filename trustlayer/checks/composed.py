"""Wraps third-party linters and normalizes their output into the TrustLayer finding shape.

A missing linter is never an audit failure - it is a skip with a reason. Findings that the
native checks already reported are dropped so the same defect is not counted twice.

Output shapes were captured from real runs, not from memory:
  ruff 0.16.1     [{code, name, filename, location:{row,col}, message, url, severity}]
  semgrep 1.172.0 {version, results:[{check_id, path, start:{line}, extra:{severity,message,lines}}]}
  vulture 2.x     "path:line: message (NN% confidence)" plain text
  eslint 9.x      [{filePath, messages:[{ruleId, severity, message, line, column}]}]
  knip 5.x        {issues:[{file, dependencies:[{name}], exports:[], unlisted:[], ...}]}
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil

from trustlayer.checks.base import (
    CheckResult,
    Finding,
    Severity,
    relative_to,
    run_tool,
    sort_findings,
)


CHECK_PREFIX = "composed"
TOOL_TIMEOUT_SECONDS = 180

VULTURE_LINE_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+): (?P<message>.+)$")
SEMGREP_CONFIG_NAMES = (".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml", ".semgrep")

# Coarse buckets shared with the native checks, so the same defect is reported once.
NATIVE_VERDICT_BUCKETS = {
    "swallowed-exception": "swallowed-exception",
    "cors-wildcard-with-credentials": "cors",
    "env-default-degrades-url": "env-default",
    "gate-fails-open": "gate",
    "missing-attribute": "api",
    "missing-export": "api",
    "possible-slopsquat": "api",
    "not-installed": "api",
    "unresolved-import": "api",
}
EXTERNAL_RULE_BUCKETS = {
    "S110": "swallowed-exception",  # try-except-pass
    "S112": "swallowed-exception",  # try-except-continue
    "E722": "swallowed-exception",  # bare except
    "BLE001": "swallowed-exception",
    "no-empty": "swallowed-exception",
    "no-unsafe-finally": "swallowed-exception",
}
RUFF_SECURITY_PREFIX = "S"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    language: str  # "python" | "typescript"
    arguments: list[str]
    parser: Callable[[str, Path], list[Finding]]


def check_composed(root: Path, existing: list[Finding] | None = None) -> list[CheckResult]:
    """Run every available linter. Missing tools skip; they never fail the audit."""
    seen = {
        (finding.file, finding.line, NATIVE_VERDICT_BUCKETS.get(finding.verdict, finding.verdict))
        for finding in (existing or [])
    }
    return [_run_spec(root, spec, seen) for spec in _tool_specs(root)]


def _tool_specs(root: Path) -> list[ToolSpec]:
    return [
        ToolSpec("ruff", "python", ["check", "--no-cache", "--output-format=json", "."], _parse_ruff),
        ToolSpec("semgrep", "python", _semgrep_arguments(root), _parse_semgrep),
        ToolSpec("vulture", "python", ["."], _parse_vulture),
        ToolSpec("eslint", "typescript", ["--format", "json", "."], _parse_eslint),
        ToolSpec("knip", "typescript", ["--reporter", "json"], _parse_knip),
    ]


def _run_spec(root: Path, spec: ToolSpec, seen: set[tuple[str, int, str]]) -> CheckResult:
    check = f"{CHECK_PREFIX}:{spec.name}"

    if not spec.arguments:
        return CheckResult(
            check,
            skipped=True,
            skip_reason=(
                f"no semgrep config found in {root.resolve().name}; add one of "
                f"{', '.join(SEMGREP_CONFIG_NAMES[:3])} (running --config=auto needs network and metrics)"
            ),
        )

    executable = _resolve_executable(root, spec.name, spec.language)
    if executable is None:
        return CheckResult(check, skipped=True, skip_reason=f"{spec.name} is not installed")

    run = run_tool([executable, *spec.arguments], cwd=root, timeout=TOOL_TIMEOUT_SECONDS)
    if run.error:
        return CheckResult(check, skipped=True, skip_reason=run.error)

    # Linters exit non-zero when they find something, so exit code alone is not failure.
    try:
        findings = spec.parser(run.stdout, root)
    except (ValueError, KeyError, TypeError) as error:
        detail = (run.stderr.strip().splitlines() or [""])[-1]
        return CheckResult(
            check,
            skipped=True,
            skip_reason=f"could not parse {spec.name} output: {error}. {detail}".strip(),
        )

    kept, dropped = _deduplicate(findings, seen, check)
    notes = []
    if dropped:
        notes.append(f"{dropped} finding(s) dropped as duplicates of native checks")
    if spec.name == "semgrep":
        notes.append("semgrep only scans git-tracked files by default; untracked files are skipped")
    return CheckResult(check, sort_findings(kept), notes=notes)


def _deduplicate(
    findings: list[Finding], seen: set[tuple[str, int, str]], check: str
) -> tuple[list[Finding], int]:
    kept: list[Finding] = []
    dropped = 0
    for finding in findings:
        bucket = EXTERNAL_RULE_BUCKETS.get(finding.verdict)
        key = (finding.file, finding.line, bucket or f"{check}:{finding.verdict}")
        if bucket and key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(finding)
    return kept, dropped


def _resolve_executable(root: Path, name: str, language: str) -> str | None:
    """Prefer the audited repo's own tool over whatever is on our PATH."""
    if language == "python":
        candidates = [root / ".venv" / "bin" / name, root / "venv" / "bin" / name]
    else:
        candidates = [root / "node_modules" / ".bin" / name]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def _semgrep_arguments(root: Path) -> list[str]:
    """Empty list signals "no config", which becomes a skip rather than a network fetch."""
    for name in SEMGREP_CONFIG_NAMES:
        if (root / name).exists():
            return ["--json", "--quiet", "--metrics=off", f"--config={name}", "."]
    return []


def _relative(path_text: str, root: Path) -> str:
    """Linters emit absolute paths; the root may be relative. Resolve so dedup keys match."""
    return relative_to(Path(path_text), root.resolve())


def _parse_ruff(stdout: str, root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    findings = []
    for item in json.loads(stdout):
        code = item.get("code") or "ruff"
        severity = Severity.MEDIUM if code.startswith(RUFF_SECURITY_PREFIX) else Severity.LOW
        findings.append(
            Finding(
                severity=severity,
                check=f"{CHECK_PREFIX}:ruff",
                file=_relative(item["filename"], root),
                line=(item.get("location") or {}).get("row", 1),
                claim=f"{code} {item.get('name', '')}".strip(),
                verdict=code,
                evidence=[item.get("message", ""), item.get("url") or ""],
            )
        )
    return findings


def _parse_semgrep(stdout: str, root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    payload = json.loads(stdout)
    findings = []
    for result in payload.get("results") or []:
        extra = result.get("extra") or {}
        level = str(extra.get("severity", "")).upper()
        severity = Severity.MEDIUM if level == "ERROR" else Severity.LOW
        findings.append(
            Finding(
                severity=severity,
                check=f"{CHECK_PREFIX}:semgrep",
                file=_relative(result.get("path", ""), root),
                line=(result.get("start") or {}).get("line", 1),
                claim=result.get("check_id", "semgrep"),
                verdict=result.get("check_id", "semgrep"),
                evidence=[extra.get("message", ""), (extra.get("lines") or "").strip()],
            )
        )
    return findings


def _parse_vulture(stdout: str, root: Path) -> list[Finding]:
    findings = []
    for line in stdout.splitlines():
        match = VULTURE_LINE_RE.match(line.strip())
        if not match:
            continue
        findings.append(
            Finding(
                severity=Severity.LOW,
                check=f"{CHECK_PREFIX}:vulture",
                file=_relative(match.group("path"), root),
                line=int(match.group("line")),
                claim=match.group("message"),
                verdict="dead-code",
                evidence=[match.group("message")],
            )
        )
    return findings


def _parse_eslint(stdout: str, root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    findings = []
    for entry in json.loads(stdout):
        for message in entry.get("messages") or []:
            rule = message.get("ruleId") or "parse-error"
            findings.append(
                Finding(
                    severity=Severity.MEDIUM if message.get("severity") == 2 else Severity.LOW,
                    check=f"{CHECK_PREFIX}:eslint",
                    file=_relative(entry.get("filePath", ""), root),
                    line=message.get("line", 1),
                    claim=rule,
                    verdict=rule,
                    evidence=[message.get("message", "")],
                )
            )
    return findings


def _parse_knip(stdout: str, root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    payload = json.loads(stdout)
    categories = ("dependencies", "devDependencies", "exports", "files", "unlisted", "unresolved")
    findings = []

    for issue in payload.get("issues") or []:
        file = issue.get("file", "")
        for category in categories:
            for entry in issue.get(category) or []:
                name = entry.get("name") if isinstance(entry, dict) else str(entry)
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        check=f"{CHECK_PREFIX}:knip",
                        file=file,
                        line=1,
                        claim=f"{category}: {name}",
                        verdict=f"knip-{category}",
                        evidence=[f"knip reports {name!r} as an unused or unresolved {category[:-1]}"],
                    )
                )
    return findings
