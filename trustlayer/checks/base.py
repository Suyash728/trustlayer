"""Shared contract for TrustLayer checks.

Every finding carries evidence a human can re-derive by hand: a resolved version, a real
exported name, a source line. No LLM produces any verdict in this package.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
import subprocess

from trustlayer.detect import SKIP_DIRECTORY_NAMES


DEFAULT_TIMEOUT_SECONDS = 60

PYTHON_SUFFIXES = (".py",)
TYPESCRIPT_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


@dataclass(frozen=True)
class Finding:
    severity: Severity
    check: str  # "api-resolution" | "stale-models" | "fail-open" | "composed:ruff"
    file: str  # repo-relative
    line: int
    claim: str  # what the code asserts, e.g. "httpx.AsyncClientX"
    verdict: str  # closed vocabulary, defined per check
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CheckResult:
    check: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    notes: list[str] = field(default_factory=list)  # caveats that are not findings

    @property
    def counts(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by location, so output is stable across runs."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line, f.claim))


@dataclass(frozen=True)
class ToolRun:
    """The result of shelling out. Never raises; a failed launch is data, not an exception."""

    ok: bool
    stdout: str
    stderr: str
    returncode: int | None = None
    error: str | None = None  # why it could not run at all


def run_tool(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    stdin: str | None = None,
) -> ToolRun:
    """Run a subprocess with a mandatory explicit timeout (CLAUDE.md rule)."""
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return ToolRun(False, "", "", None, f"{command[0]} not found")
    except subprocess.TimeoutExpired:
        return ToolRun(False, "", "", None, f"{command[0]} timed out after {timeout}s")
    except OSError as error:
        return ToolRun(False, "", "", None, f"{command[0]} could not run: {error}")

    return ToolRun(
        ok=completed.returncode == 0,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        returncode=completed.returncode,
    )


def iter_files(root: Path, predicate: Callable[[Path], bool]) -> Iterator[Path]:
    """Walk a repository, skipping the same noise directories detection skips."""
    queue: deque[Path] = deque([root])
    while queue:
        current = queue.popleft()
        try:
            children = sorted(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name.startswith(".") or child.name in SKIP_DIRECTORY_NAMES:
                    continue
                queue.append(child)
            elif predicate(child):
                yield child


def iter_source_files(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    return iter_files(root, lambda path: path.suffix in suffixes)


def relative_to(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def read_source(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
