"""Deprecated model ID detector.

Matches string literals and config values against a hand-maintained registry. The registry
goes stale by design - see README.md - so every finding reports the recorded date, the
successor, and whether the entry was ever verified against a vendor notice.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
import re
import tomllib

from trustlayer.checks.base import (
    CheckResult,
    Finding,
    Severity,
    iter_files,
    read_source,
    relative_to,
    sort_findings,
)


CHECK_NAME = "stale-models"

DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "data" / "model_deprecations.toml"
PACKAGED_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "data" / "model_deprecations.toml"

SCANNED_SUFFIXES = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".sh",
    }
)
ENV_FILE_RE = re.compile(r"^\.env(\..+)?$|^.+\.env$")
ID_BOUNDARY = r"[A-Za-z0-9._\-]"


@dataclass(frozen=True)
class DeprecatedModel:
    model_id: str  # may contain a "*" wildcard
    provider: str
    deprecated_on: date | None
    successor: str
    source_url: str
    verified: bool

    def status(self, today: date) -> str:
        if self.deprecated_on is None:
            return "retired"  # recorded as retired, date unknown
        return "retired" if self.deprecated_on <= today else "scheduled"

    def days_until(self, today: date) -> int | None:
        return None if self.deprecated_on is None else (self.deprecated_on - today).days


def load_registry(path: Path | None = None) -> list[DeprecatedModel]:
    """Read the deprecation registry. Raises FileNotFoundError if it is missing."""
    source = path or _registry_path()
    data = tomllib.loads(source.read_text(encoding="utf-8"))

    models = []
    for model_id, entry in (data.get("models") or {}).items():
        deprecated_on = entry.get("deprecated_on")
        models.append(
            DeprecatedModel(
                model_id=model_id,
                provider=entry.get("provider", "unknown"),
                deprecated_on=deprecated_on if isinstance(deprecated_on, date) else None,
                successor=entry.get("successor", ""),
                source_url=entry.get("source_url", ""),
                verified=bool(entry.get("verified", False)),
            )
        )
    models.sort(key=lambda model: (model.provider, model.model_id))
    return models


def _registry_path() -> Path:
    if DEFAULT_REGISTRY_PATH.is_file():
        return DEFAULT_REGISTRY_PATH
    return PACKAGED_REGISTRY_PATH


def check_stale_models(
    root: Path,
    *,
    today: date | None = None,
    warn_within_days: int | None = None,
    registry_path: Path | None = None,
) -> CheckResult:
    """Scan for deprecated model IDs.

    Retired models are always reported. Models with a future retirement date are reported
    only when `warn_within_days` is set and the date falls inside that window.
    """
    now = today or datetime.now(tz=UTC).date()
    try:
        registry = load_registry(registry_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return CheckResult(CHECK_NAME, skipped=True, skip_reason=f"registry unreadable: {error}")

    if not registry:
        return CheckResult(CHECK_NAME, skipped=True, skip_reason="registry is empty")

    patterns = [(model, _pattern_for(model.model_id)) for model in registry]
    registry_file = (registry_path or _registry_path()).resolve()

    findings: list[Finding] = []
    for path in iter_files(root, _is_scannable):
        if path.resolve() == registry_file:
            continue  # the registry lists every ID by definition
        source = read_source(path)
        if source is None:
            continue
        relative = relative_to(path, root)
        for text, line in _candidate_strings(path, source):
            for model, pattern in patterns:
                match = pattern.search(text)
                if match:
                    finding = _build_finding(model, match.group(0), relative, line, now, warn_within_days)
                    if finding is not None:
                        findings.append(finding)

    return CheckResult(CHECK_NAME, sort_findings(findings))


def _build_finding(
    model: DeprecatedModel,
    matched: str,
    file: str,
    line: int,
    today: date,
    warn_within_days: int | None,
) -> Finding | None:
    status = model.status(today)
    days = model.days_until(today)

    if status == "scheduled":
        if warn_within_days is None or days is None or days > warn_within_days:
            return None
        severity = Severity.MEDIUM
        verdict = "scheduled-retirement"
        when = f"{model.provider} retires this model on {model.deprecated_on} ({days} days from now)"
    else:
        severity = Severity.HIGH
        verdict = "retired-model"
        when = (
            f"{model.provider} retired this model on {model.deprecated_on}"
            f" ({abs(days)} days ago)"
            if days is not None
            else f"{model.provider} lists this model as retired; no date recorded"
        )

    evidence = [when]
    evidence.append(
        f"successor: {model.successor}" if model.successor else "successor: none recorded by the vendor"
    )
    if model.verified and model.source_url:
        evidence.append(f"source: {model.source_url}")
    else:
        evidence.append("source: UNVERIFIED - seeded from a maintainer note, no vendor page recorded")
    if model.model_id != matched:
        evidence.append(f"matched registry pattern {model.model_id!r}")

    return Finding(
        severity=severity,
        check=CHECK_NAME,
        file=file,
        line=line,
        claim=matched,
        verdict=verdict,
        evidence=evidence,
    )


def _pattern_for(model_id: str) -> re.Pattern[str]:
    body = f"{ID_BOUNDARY}*".join(re.escape(part) for part in model_id.split("*"))
    return re.compile(rf"(?<!{ID_BOUNDARY}){body}(?!{ID_BOUNDARY})")


def _is_scannable(path: Path) -> bool:
    return path.suffix in SCANNED_SUFFIXES or bool(ENV_FILE_RE.match(path.name))


def _candidate_strings(path: Path, source: str) -> list[tuple[str, int]]:
    """Python is read via AST so comments cannot match; everything else is line-scanned."""
    if path.suffix == ".py":
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return _lines(source)
        return [
            (node.value, node.lineno)
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
    return _lines(source)


def _lines(source: str) -> list[tuple[str, int]]:
    return [(line, number) for number, line in enumerate(source.splitlines(), start=1) if line.strip()]
