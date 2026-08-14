"""Mutation-testing command helpers and mutmut output parsing.

This is the only module that parses mutmut output. `apps/api/app/services/mutation.py`
re-exports it, so the architecture rule in CLAUDE.md ("all mutmut parsing lives here")
still holds while the dependency points from the API app into the `trustlayer` package
rather than the other way around.

mutmut 3.6.0 output format (verified, see CLAUDE.md):
  `mutmut results --all true` -> `<module>.x_<funcname>__mutmut_<N>: <status>`
  `mutmut show <id>` diffs the FUNCTION in isolation, so @@ hunk offsets are relative to
  the function body and never to the file. Line numbers are located by matching the
  removed line's text against the real source.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
import subprocess


DEFAULT_TIMEOUT_SECONDS = 60
MUTATION_TIMEOUT_SECONDS = 1800  # a full `mutmut run` is minutes, not seconds

RESULT_LINE_RE = re.compile(r"^(?P<id>[\w.]+__mutmut_\d+): (?P<status>\w+)$")
FUNCTION_NAME_RE = re.compile(r"\.x_(?P<name>.+)__mutmut_\d+$")

KILLED_STATUSES = frozenset({"killed", "timeout"})
SURVIVED_STATUSES = frozenset({"survived"})

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Survivor:
    id: str
    file: str
    line: int | None
    diff: str

    @property
    def function(self) -> str | None:
        """The function this mutant lives in, from its mutmut ID."""
        match = FUNCTION_NAME_RE.search(self.id)
        return match.group("name") if match else None


@dataclass(frozen=True)
class MutationRun:
    """The normalized shape CLAUDE.md specifies for this module."""

    score: float  # killed / (killed + survived), as a percentage
    killed: int
    survived: int
    total: int  # every mutant reported, including statuses that are neither
    survivors: list[Survivor] = field(default_factory=list)


def get_survivors(repo_path: str | Path) -> list[Survivor]:
    """Return the surviving mutmut mutants for a repository."""
    repository = Path(repo_path)
    results = _run_mutmut(repository, ["results", "--all", "true"])
    survivor_ids = _parse_survivor_ids(results)

    return [
        _parse_survivor(repository, mutant_id, _run_mutmut(repository, ["show", mutant_id]))
        for mutant_id in survivor_ids
    ]


def get_mutation_run(repo_path: str | Path, executable: str | Path = "mutmut") -> MutationRun:
    """Return the score and the survivors from an already-completed mutmut run."""
    repository = Path(repo_path)
    results = _run_mutmut(repository, ["results", "--all", "true"], executable)
    killed, survived, total = _parse_counts(results)

    survivors = [
        _parse_survivor(repository, mutant_id, _run_mutmut(repository, ["show", mutant_id], executable))
        for mutant_id in _parse_survivor_ids(results)
    ]
    return MutationRun(
        score=_score(killed, survived),
        killed=killed,
        survived=survived,
        total=total,
        survivors=survivors,
    )


def run_mutation(
    repo_path: str | Path,
    timeout: float = MUTATION_TIMEOUT_SECONDS,
    executable: str | Path = "mutmut",
) -> MutationRun:
    """Execute `mutmut run`, then read the results. Every subprocess has a timeout."""
    repository = Path(repo_path)
    try:
        subprocess.run(
            [str(executable), "run"],
            cwd=repository,
            capture_output=True,
            check=False,  # mutmut exits non-zero when mutants survive; that is data
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(f"mutmut run exceeded {timeout}s in {repository}") from error

    return get_mutation_run(repository, executable)


def _score(killed: int, survived: int) -> float:
    decided = killed + survived
    return round(killed / decided * 100, 1) if decided else 0.0


def _parse_counts(results: str) -> tuple[int, int, int]:
    killed = survived = total = 0
    for raw_line in results.splitlines():
        match = RESULT_LINE_RE.fullmatch(raw_line.strip())
        if not match:
            continue
        total += 1
        status = match.group("status")
        if status in KILLED_STATUSES:
            killed += 1
        elif status in SURVIVED_STATUSES:
            survived += 1
    return killed, survived, total


def _run_mutmut(repo_path: Path, arguments: list[str], executable: str | Path = "mutmut") -> str:
    completed = subprocess.run(
        [str(executable), *arguments],
        cwd=repo_path,
        capture_output=True,
        check=True,
        text=True,
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    return completed.stdout


def _parse_survivor_ids(results: str) -> list[str]:
    survivor_ids: list[str] = []
    for raw_line in results.splitlines():
        match = RESULT_LINE_RE.fullmatch(raw_line.strip())
        if match and match.group("status") == "survived":
            survivor_ids.append(match.group("id"))
    return survivor_ids


def _parse_survivor(repo_path: Path, mutant_id: str, show_output: str) -> Survivor:
    diff_start = show_output.find("--- ")
    if diff_start == -1:
        raise ValueError(f"mutmut show output for {mutant_id} did not include a diff")

    diff = show_output[diff_start:]
    file_path, removed_line = _parse_diff(diff)
    line_number = _find_source_line(repo_path, file_path, removed_line, mutant_id)
    if line_number is None:
        logger.warning("Could not locate mutated line for survivor %s", mutant_id)
    return Survivor(id=mutant_id, file=file_path, line=line_number, diff=diff)


def _parse_diff(diff: str) -> tuple[str, str]:
    lines = diff.splitlines()
    file_path = lines[0].removeprefix("--- ")

    for diff_line in lines[1:]:
        if diff_line.startswith("-") and not diff_line.startswith("--- "):
            return file_path, diff_line[1:].strip()

    raise ValueError("mutmut diff did not include a removed line")


def _find_source_line(repo_path: Path, file_path: str, removed_line: str, mutant_id: str) -> int | None:
    try:
        source = (repo_path / file_path).read_text()
    except OSError:
        return None

    matches = [
        line_number
        for line_number, source_line in enumerate(source.splitlines(), start=1)
        if source_line.strip() == removed_line
    ]
    if len(matches) <= 1:
        return matches[0] if matches else None

    function_match = FUNCTION_NAME_RE.search(mutant_id)
    if not function_match:
        return None

    function_name = function_match.group("name")
    try:
        syntax_tree = ast.parse(source)
    except SyntaxError:
        return None

    for node in ast.walk(syntax_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            return next(
                (
                    line_number
                    for line_number in matches
                    if node.lineno <= line_number <= node.end_lineno
                ),
                None,
            )
    return None
