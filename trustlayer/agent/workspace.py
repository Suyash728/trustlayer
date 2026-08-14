"""Temp-copy sandbox.

The agent never writes to the user's repository. It writes to a copy, and the run ends by
printing a diff for review rather than applying anything. This is the whole reason a
harden run cannot leave a repo in a state the user did not approve.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import difflib
from pathlib import Path
import shutil
import tempfile


# .git is excluded deliberately: without it the agent cannot commit even if it escapes
# the tool gate, and mutmut does not need it.
EXCLUDED = shutil.ignore_patterns(
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "mutants",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "*.egg-info",
)

DIFFABLE_SUFFIXES = frozenset({".py", ".toml", ".cfg", ".ini", ".txt", ".md", ".json", ".yaml", ".yml"})
MAX_DIFF_BYTES = 400_000


@dataclass(frozen=True)
class Workspace:
    """A throwaway copy of a repository that the agent is allowed to modify."""

    source: Path  # the user's real repository, never written to
    path: Path  # the copy the agent works in

    def contains(self, candidate: Path | str) -> bool:
        """True when a path resolves inside the workspace. Used by the permission gate."""
        try:
            resolved = Path(candidate).resolve()
        except (OSError, RuntimeError):
            return False
        return resolved == self.path.resolve() or self.path.resolve() in resolved.parents


@contextmanager
def workspace(source: Path | str, keep: bool = False) -> Iterator[Workspace]:
    """Copy a repository to a temp dir for the duration of a run.

    `keep=True` leaves the copy on disk so a crashed run can still be inspected; the path
    is always reported by the caller either way.
    """
    origin = Path(source).resolve()
    if not origin.is_dir():
        raise NotADirectoryError(f"{origin} is not a directory")

    root = Path(tempfile.mkdtemp(prefix="trustlayer-harden-"))
    destination = root / origin.name
    shutil.copytree(origin, destination, ignore=EXCLUDED, symlinks=False)

    try:
        yield Workspace(source=origin, path=destination)
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)


def diff_workspace(space: Workspace) -> str:
    """Unified diff of the workspace against the untouched original.

    Pure difflib, no subprocess: the diff is a report, and a report should not need
    another tool to exist on the machine.
    """
    chunks: list[str] = []
    for relative in sorted(_diffable_paths(space)):
        original = space.source / relative
        current = space.path / relative
        before = _read(original)
        after = _read(current)
        if before == after:
            continue
        chunks.extend(
            difflib.unified_diff(
                before,
                after,
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
                lineterm="",
            )
        )
        chunks.append("")

    diff = "\n".join(chunks)
    if len(diff) > MAX_DIFF_BYTES:
        return diff[:MAX_DIFF_BYTES] + f"\n... diff truncated at {MAX_DIFF_BYTES} bytes"
    return diff


def _diffable_paths(space: Workspace) -> set[Path]:
    paths: set[Path] = set()
    for root in (space.source, space.path):
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in DIFFABLE_SUFFIXES:
                continue
            relative = path.relative_to(root)
            # Paths excluded from the copy are absent on one side only. Without this they
            # render as deletions the agent never made, which would poison the review.
            if any(part in _SKIP_PARTS or part.endswith(_SKIP_SUFFIXES) for part in relative.parts):
                continue
            paths.add(relative)
    return paths


_SKIP_PARTS = frozenset(
    {".git", ".venv", "venv", "node_modules", "mutants", "__pycache__", ".pytest_cache"}
)
_SKIP_SUFFIXES = (".egg-info",)


def _read(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
