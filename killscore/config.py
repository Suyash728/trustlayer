"""Per-repository configuration: what to exclude, and inline suppressions.

Read from `[tool.killscore]` in the audited root's `pyproject.toml`, or from the top level
of a `.killscore.toml` (for repositories that are not Python). Only two knobs exist:

    [tool.killscore]
    exclude = ["tests/fixtures", "vendor/**", "*.generated.py"]

and an inline comment on the line a finding points at:

    model = "gemini-1.0-pro"  # killscore: ignore[stale-models]

A suppressed finding is never silent: every surface reports how many were suppressed and
why, so "clean" can never quietly mean "everything was ignored". Suppression never changes
how a finding is computed - it only decides whether a computed finding is shown.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import fnmatch
import json
from pathlib import Path, PurePosixPath
import re
import tomllib
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from killscore.checks.base import CheckResult


CONFIG_FILES = ("pyproject.toml", ".killscore.toml")

# `killscore: ignore` or `killscore: ignore[check, other-check]`, after # or //.
INLINE_IGNORE_RE = re.compile(r"(?:#|//)\s*killscore:\s*ignore(?:\[(?P<checks>[^\]]*)\])?")


class ConfigError(ValueError):
    """The configuration exists but cannot be used. An operational error, never a verdict."""


@dataclass(frozen=True)
class Config:
    exclude: tuple[str, ...] = ()
    source: str | None = None  # which file the settings came from, for the report
    _line_cache: dict[str, list[str]] = field(default_factory=dict, compare=False, repr=False)

    def is_excluded(self, relative: str) -> bool:
        return any(_matches(relative, pattern) for pattern in self.exclude)

    def ignored_inline(self, root: Path, relative: str, line: int, check: str) -> bool:
        """True when the finding's own line carries a matching `killscore: ignore`."""
        lines = self._line_cache.get(relative)
        if lines is None:
            try:
                lines = (root / relative).read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError, ValueError):
                lines = []
            self._line_cache[relative] = lines
        if not 1 <= line <= len(lines):
            return False
        match = INLINE_IGNORE_RE.search(lines[line - 1])
        if match is None:
            return False
        named = match.group("checks")
        if named is None:
            return True  # a bare `killscore: ignore` covers every check on that line
        wanted = [name.strip() for name in named.split(",") if name.strip()]
        # `ignore[api-resolution]` covers `api-resolution:python`.
        return any(check == name or check.startswith(f"{name}:") for name in wanted)


def load_config(root: Path) -> Config:
    """Read the first config file that carries killscore settings. Missing is not an error."""
    for name in CONFIG_FILES:
        path = root / name
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as error:
            raise ConfigError(f"could not read {name}: {error}") from error
        except tomllib.TOMLDecodeError as error:
            if name == "pyproject.toml":
                continue  # a broken pyproject is the detect layer's problem, not ours
            raise ConfigError(f"{name} is not valid TOML: {error}") from error

        table = (data.get("tool") or {}).get("killscore") if name == "pyproject.toml" else data
        if not table:
            continue
        return Config(exclude=_patterns(table, name), source=name)
    return Config()


def _patterns(table: object, source: str) -> tuple[str, ...]:
    if not isinstance(table, dict):
        raise ConfigError(f"[tool.killscore] in {source} must be a table")
    unknown = sorted(set(table) - {"exclude"})
    if unknown:
        # A typo like `excludes` must not silently exclude nothing.
        raise ConfigError(f"unknown killscore setting(s) in {source}: {', '.join(unknown)}")
    raw = table.get("exclude", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise ConfigError(f"`exclude` in {source} must be a list of non-empty strings")
    return tuple(item.strip().strip("/") for item in raw)


def _matches(relative: str, pattern: str) -> bool:
    """A glob on the repo-relative POSIX path; a plain directory pattern covers its contents."""
    path = PurePosixPath(relative)
    if fnmatch.fnmatchcase(relative, pattern):
        return True
    # `tests/fixtures` (or `tests/fixtures/**`) excludes everything below it.
    prefix = pattern.removesuffix("/**")
    return any(fnmatch.fnmatchcase(parent.as_posix(), prefix) for parent in path.parents if parent.parts)


# --------------------------------------------------------------------------- baselines


def load_baseline(path: Path) -> set[tuple[str, str, str, str]]:
    """Known findings from a previous `killscore audit --format json` run.

    The audit's own JSON is the baseline format, so creating one is just
    `killscore audit . --format json > .killscore-baseline.json`. Identity is
    `(check, file, claim, verdict)` - the line-free identity `killscore diff` uses, so a
    known finding that moved is still known.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigError(f"could not read baseline {path}: {error}") from error
    except ValueError as error:
        raise ConfigError(f"baseline {path} is not JSON: {error}") from error
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise ConfigError(f"baseline {path} has no `findings` list; create it with --format json")
    known = set()
    for item in findings:
        try:
            known.add((item["check"], item["file"], item["claim"], item["verdict"]))
        except (KeyError, TypeError) as error:
            raise ConfigError(f"baseline {path} has a malformed finding: {item!r}") from error
    return known


def apply_baseline(
    results: list[CheckResult], known: set[tuple[str, str, str, str]]
) -> tuple[list[CheckResult], int]:
    """Hide findings the baseline already knows. Returns the new results and how many."""
    hidden = 0
    filtered = []
    for result in results:
        kept = [
            f for f in result.findings if (f.check, f.file, f.claim, f.verdict) not in known
        ]
        hidden += len(result.findings) - len(kept)
        filtered.append(replace(result, findings=kept) if len(kept) != len(result.findings) else result)
    return filtered, hidden
