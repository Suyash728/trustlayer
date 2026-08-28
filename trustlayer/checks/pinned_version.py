"""Pinned versions that do not exist, or that the maintainer withdrew.

Models invent version numbers as readily as package names. `fastapi==0.999.0` names a real,
popular, correct package and still cannot be installed, so neither `slopsquat` nor
`api-resolution` sees it: one asks whether the project exists, the other whether the import
resolves, and the answer to both is yes.

Unlike `slopsquat`, this cannot short-circuit on the top-packages corpus. A hallucinated
version of a *popular* package is the common case, not the rare one, so every concrete pin is
resolved against the index.

Comparison is PEP 440, via `packaging`, not string equality. `==1.0` legitimately matches a
release published as `1.0.0`, and reporting that as missing would be a false positive on
correct code. A pin that cannot be parsed at all is left alone rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import posixpath

from packaging.version import InvalidVersion, Version

from trustlayer.checks.base import (
    CheckResult,
    Finding,
    Severity,
    find_declaration_line,
    sort_findings,
)
from trustlayer.detect import Language, RepoProfile, profile_repository
from trustlayer.registry import fetch_many


CHECK_NAME = "pinned-version"

MAX_SUGGESTED_VERSIONS = 3


@dataclass(frozen=True)
class _Pin:
    name: str
    version: str
    file: str
    line: int
    source: str


def check_pinned_version(
    root: Path,
    *,
    profile: RepoProfile | None = None,
    fetcher=None,
    offline: bool = False,
    db_path=None,
) -> CheckResult:
    """Resolve every concrete version pin against the index."""
    resolved = profile if profile is not None else profile_repository(root)
    pins = _pins(root, resolved)
    if not pins:
        return CheckResult(
            CHECK_NAME,
            skipped=True,
            skip_reason="no concrete Python version pins found (unpinned specs are reported by detection)",
        )

    facts = fetch_many([pin.name for pin in pins], fetcher=fetcher, db_path=db_path, offline=offline)

    findings: list[Finding] = []
    unreachable = 0
    for pin in pins:
        package = facts.get(pin.name)
        if package is None or package.unreachable:
            unreachable += 1
            continue
        if package.exists is not True:
            continue  # the project itself is missing; that is slopsquat's finding, not ours
        finding = _judge(pin, package)
        if finding is not None:
            findings.append(finding)

    notes = []
    if unreachable:
        notes.append(
            f"{unreachable} of {len(pins)} pins could not be checked (registry unreachable); "
            "they are reported as neither valid nor invalid"
        )
    if unreachable == len(pins):
        return CheckResult(
            CHECK_NAME, skipped=True, skip_reason="no pin could be checked: registry unreachable"
        )

    return CheckResult(CHECK_NAME, sort_findings(findings), notes=notes)


def _judge(pin: _Pin, package) -> Finding | None:
    comparable, spelling = _locate(pin.version, package.versions)
    if not comparable:
        return None  # an unparseable pin is left alone rather than guessed at

    if spelling is None:
        return Finding(
            severity=Severity.HIGH,
            check=CHECK_NAME,
            file=pin.file,
            line=pin.line,
            claim=f"{pin.name}=={pin.version}",
            verdict="nonexistent-version",
            evidence=[
                (
                    f"{package.url} lists {len(package.versions)} versions and none of "
                    f"them is {pin.version}"
                ),
                f"newest published: {', '.join(_newest(package.versions))}",
                f"pinned in {pin.source}, so `pip install` resolves nothing and fails outright",
            ],
        )

    reason = package.yanked_versions.get(spelling)
    if reason is None:
        return None  # the version exists and stands

    return Finding(
        severity=Severity.MEDIUM,
        check=CHECK_NAME,
        file=pin.file,
        line=pin.line,
        claim=f"{pin.name}=={pin.version}",
        verdict="yanked-version",
        evidence=[
            f"the maintainer yanked {spelling} on the index: {reason or 'no reason recorded'}",
            (
                "it still installs when pinned exactly, which is why this is not a build "
                "break - but the release was withdrawn for a reason"
            ),
            f"newest published: {', '.join(_newest(package.versions))}",
        ],
    )


def _locate(pinned: str, versions: list[str]) -> tuple[bool, str | None]:
    """(comparable, the index's own spelling).

    `comparable` is False when the pin is not a PEP 440 version at all, in which case the
    check stays silent rather than inventing a verdict.
    """
    try:
        target = Version(pinned)
    except InvalidVersion:
        return False, None

    for candidate in versions:
        try:
            if Version(candidate) == target:
                return True, candidate
        except InvalidVersion:
            continue
    return True, None


def _newest(versions: list[str]) -> list[str]:
    parsed = []
    for candidate in versions:
        try:
            parsed.append((Version(candidate), candidate))
        except InvalidVersion:
            continue
    parsed.sort(reverse=True)
    return [name for _, name in parsed[:MAX_SUGGESTED_VERSIONS]] or ["none"]


def _pins(root: Path, profile: RepoProfile) -> list[_Pin]:
    """Every uniquely-named Python dependency resolved to a concrete version."""
    seen: set[str] = set()
    pins: list[_Pin] = []

    for project in profile.projects:
        if project.language is not Language.PYTHON:
            continue
        for dependency in project.dependencies:
            if not dependency.version or dependency.name in seen:
                continue
            seen.add(dependency.name)
            relative = (
                dependency.source
                if project.path == "."
                else posixpath.join(project.path, dependency.source)
            )
            pins.append(
                _Pin(
                    name=dependency.name,
                    version=dependency.version,
                    file=relative,
                    line=find_declaration_line(root / relative, dependency.name),
                    source=dependency.source,
                )
            )
    return pins
