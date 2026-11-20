"""Manifest and lockfile disagree: the lock was generated from a different manifest.

An agent that adds a dependency to pyproject.toml or package.json and never re-locks leaves
a repository whose `uv sync --locked` / `npm ci` refuses to install - or, worse, whose lock
still pins a version the manifest now forbids. This check compares what each lockfile says
it was generated from against the manifest as it is now. No range arithmetic is invented:

- **uv.lock** records the root package's own requirements under `[package.metadata]
  requires-dist` (and `requires-dev` for dependency groups). Specifier sets are compared
  with PEP 440 normalisation via `packaging`, and each locked version is checked against
  the declared specifier - the same `packaging` comparison `pinned-version` relies on.
- **package-lock.json** (lockfileVersion 2/3) records the root manifest's specs verbatim
  under `packages[""]`; **pnpm-lock.yaml** (v6+) under `importers["."]` as `specifier`.
  Those are compared as strings, which is exactly what `npm ci` and `pnpm install
  --frozen-lockfile` do. npm semver ranges are never evaluated here.

Silent by design on: requirements with environment markers (whether they apply depends on
the machine), `dynamic` dependencies, poetry.lock (its content hash is not re-derivable
without poetry), npm lockfile v1 and pnpm < v6 (no root specs recorded), and yarn.lock.
"""

from __future__ import annotations

import json
from pathlib import Path
import posixpath
import tomllib

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
import yaml

from killscore.checks.base import (
    CheckResult,
    Finding,
    Severity,
    find_declaration_line,
    sort_findings,
)
from killscore.detect import Language, RepoProfile, profile_repository


CHECK_NAME = "lock-drift"
NPM_GROUPS = ("dependencies", "devDependencies", "optionalDependencies")


def check_lock_drift(root: Path, *, profile: RepoProfile | None = None) -> CheckResult:
    resolved = profile if profile is not None else profile_repository(root)
    findings: list[Finding] = []
    notes: list[str] = []
    compared = 0

    for project in resolved.projects:
        if not project.lockfile:
            continue
        base = root if project.path == "." else root / project.path
        prefix = "" if project.path == "." else project.path
        lock = project.lockfile
        if project.language is Language.PYTHON and lock == "uv.lock":
            outcome = _uv(base, prefix)
        elif project.language is Language.JAVASCRIPT and lock == "package-lock.json":
            outcome = _package_lock(base, prefix)
        elif project.language is Language.JAVASCRIPT and lock == "pnpm-lock.yaml":
            outcome = _pnpm_lock(base, prefix)
        else:
            notes.append(f"{posixpath.join(prefix, lock)}: not compared (format records no source specs)")
            continue
        if isinstance(outcome, str):
            notes.append(f"{posixpath.join(prefix, lock)}: {outcome}")
            continue
        compared += 1
        findings.extend(outcome)

    if not compared:
        return CheckResult(
            CHECK_NAME,
            skipped=True,
            skip_reason="no comparable manifest + lockfile pair (uv.lock, package-lock.json v2+, pnpm v6+)",
            notes=notes,
        )
    return CheckResult(CHECK_NAME, sort_findings(findings), notes=notes)


# ------------------------------------------------------------------------- uv.lock


def _uv(base: Path, prefix: str) -> list[Finding] | str:
    try:
        manifest = tomllib.loads((base / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((base / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        return f"not compared: {error}"

    project = manifest.get("project")
    if not isinstance(project, dict) or not project.get("name"):
        return "not compared: pyproject.toml has no [project] name"
    if "dependencies" in (project.get("dynamic") or []):
        return "not compared: dependencies are dynamic"

    name = canonicalize_name(str(project["name"]))
    packages = [p for p in lock.get("package") or [] if isinstance(p, dict)]
    root_entry = next(
        (p for p in packages if canonicalize_name(str(p.get("name", ""))) == name and _is_local(p)),
        None,
    )
    if root_entry is None:
        return f"not compared: uv.lock has no local entry for {name}"
    # One name can be locked at several versions: uv forks the resolution for conflicting
    # groups or extras (openai-python locks pydantic 1.10.26 *and* 2.12.5). A dict keyed by
    # name silently kept the last one and accused the other group's spec.
    locked_versions: dict[str, set[str]] = {}
    for package in packages:
        if not _is_local(package):
            key = canonicalize_name(str(package.get("name", "")))
            locked_versions.setdefault(key, set()).add(str(package.get("version", "")))
    metadata = root_entry.get("metadata") if isinstance(root_entry.get("metadata"), dict) else {}

    manifest_file = posixpath.join(prefix, "pyproject.toml") if prefix else "pyproject.toml"
    findings: list[Finding] = []

    groups = [("dependencies", project.get("dependencies") or [], metadata.get("requires-dist") or [])]
    declared_groups = manifest.get("dependency-groups") or {}
    locked_groups = metadata.get("requires-dev") or {}
    if isinstance(declared_groups, dict):
        for group, entries in sorted(declared_groups.items()):
            locked = locked_groups.get(group, []) if isinstance(locked_groups, dict) else []
            groups.append((f"dependency group '{group}'", entries, locked))

    for label, declared_raw, locked_raw in groups:
        declared = _parse_requirements(declared_raw)
        locked = _parse_locked(locked_raw)
        for key, requirement in declared.items():
            line = find_declaration_line(base / "pyproject.toml", requirement.name)
            if key not in locked:
                findings.append(_finding(
                    Severity.MEDIUM, manifest_file, line, str(requirement), "declared-not-locked",
                    f"{label} declares {requirement} but uv.lock was generated without it",
                    "`uv sync --locked` refuses this tree; run `uv lock` and commit the result",
                ))
                continue
            spec, extras = locked[key]
            if _normal(requirement.specifier) != _normal(spec) or set(requirement.extras) != extras:
                findings.append(_finding(
                    Severity.MEDIUM, manifest_file, line, str(requirement), "spec-drift",
                    f"pyproject.toml declares `{requirement}`; uv.lock was generated from "
                    f"`{requirement.name}{_extras(extras)}{spec}`",
                    "the lock describes a different manifest; run `uv lock` and commit the result",
                ))
            versions = sorted(v for v in locked_versions.get(key, set()) if v)
            if (
                versions
                and requirement.specifier
                and not any(_satisfies(requirement.specifier, v) for v in versions)
            ):
                pinned = " and ".join(versions)
                findings.append(_finding(
                    Severity.MEDIUM, manifest_file, line, str(requirement), "locked-version-violates-spec",
                    f"uv.lock pins {requirement.name} {pinned}, which `{requirement.specifier}` excludes "
                    "(PEP 440, via packaging)",
                    "installing from the lock gives a version the manifest forbids",
                ))
        for key in sorted(set(locked) - set(declared)):
            if key in _marker_names(declared_raw):
                continue
            findings.append(_finding(
                Severity.MEDIUM, manifest_file, 1, key, "locked-not-declared",
                f"uv.lock still records {key} in {label}, but pyproject.toml no longer declares it",
                "the lock is stale; run `uv lock` and commit the result",
            ))
    return findings


def _is_local(package: dict) -> bool:
    source = package.get("source")
    return isinstance(source, dict) and ("editable" in source or "virtual" in source)


def _parse_requirements(raw: object) -> dict[str, Requirement]:
    """Declared requirements without markers, keyed by canonical name."""
    found: dict[str, Requirement] = {}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, str):
            continue  # e.g. {include-group = "..."} - not a requirement
        try:
            requirement = Requirement(item)
        except InvalidRequirement:
            continue
        if requirement.marker is not None or requirement.url:
            continue
        found[canonicalize_name(requirement.name)] = requirement
    return found


def _marker_names(raw: object) -> set[str]:
    names = set()
    for item in raw if isinstance(raw, list) else []:
        try:
            requirement = Requirement(item) if isinstance(item, str) else None
        except InvalidRequirement:
            continue
        if requirement is not None and (requirement.marker is not None or requirement.url):
            names.add(canonicalize_name(requirement.name))
    return names


def _parse_locked(raw: object) -> dict[str, tuple[SpecifierSet, set[str]]]:
    found: dict[str, tuple[SpecifierSet, set[str]]] = {}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict) or "marker" in item or "url" in item or "path" in item:
            continue
        try:
            spec = SpecifierSet(str(item.get("specifier") or ""))
        except InvalidSpecifier:
            continue
        extras = item.get("extras") if isinstance(item.get("extras"), list) else []
        found[canonicalize_name(str(item.get("name", "")))] = (spec, {str(e) for e in extras})
    return found


def _normal(spec: SpecifierSet) -> str:
    return ",".join(sorted(str(s) for s in spec))


def _extras(extras: set[str]) -> str:
    return f"[{','.join(sorted(extras))}]" if extras else ""


def _satisfies(spec: SpecifierSet, version: str) -> bool:
    try:
        return spec.contains(Version(version), prereleases=True)
    except InvalidVersion:
        return True  # unparseable: no claim


# -------------------------------------------------------------- npm and pnpm


def _package_lock(base: Path, prefix: str) -> list[Finding] | str:
    manifest, lock = _read_json(base / "package.json"), _read_json(base / "package-lock.json")
    if manifest is None or lock is None:
        return "not compared: package.json or package-lock.json unreadable"
    if not isinstance(lock.get("lockfileVersion"), int) or lock["lockfileVersion"] < 2:
        return "not compared: lockfileVersion 1 records no root specs"
    root_entry = (lock.get("packages") or {}).get("")
    if not isinstance(root_entry, dict):
        return 'not compared: package-lock.json has no packages[""] entry'
    recorded = {
        group: dict(root_entry.get(group) or {}) for group in NPM_GROUPS
    }
    return _compare_npm(base, prefix, manifest, recorded, "package-lock.json", "npm ci")


def _pnpm_lock(base: Path, prefix: str) -> list[Finding] | str:
    manifest = _read_json(base / "package.json")
    try:
        lock = yaml.safe_load((base / "pnpm-lock.yaml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        return f"not compared: {error}"
    if manifest is None or not isinstance(lock, dict):
        return "not compared: package.json or pnpm-lock.yaml unreadable"
    try:
        major = int(str(lock.get("lockfileVersion", "0")).split(".")[0])
    except ValueError:
        major = 0
    if major < 6:
        return "not compared: pnpm lockfile older than v6 records specs differently"
    # A workspace lockfile keys the root under `importers["."]`; a single-project v6 lockfile
    # has no `importers` and records the same specs at the top level (shadcn-ui/taxonomy).
    importers = lock.get("importers")
    importer = (importers.get(".") or {}) if isinstance(importers, dict) else lock
    recorded = {
        group: {
            name: entry.get("specifier")
            for name, entry in (importer.get(group) or {}).items()
            if isinstance(entry, dict)
        }
        for group in NPM_GROUPS
    }
    return _compare_npm(base, prefix, manifest, recorded, "pnpm-lock.yaml", "pnpm install --frozen-lockfile")


def _compare_npm(
    base: Path, prefix: str, manifest: dict, recorded: dict, lock_name: str, installer: str
) -> list[Finding]:
    manifest_file = posixpath.join(prefix, "package.json") if prefix else "package.json"
    text = _read_lines(base / "package.json")
    findings: list[Finding] = []
    for group in NPM_GROUPS:
        declared = {k: v for k, v in (manifest.get(group) or {}).items() if isinstance(v, str)}
        locked = recorded.get(group) or {}
        for name, spec in sorted(declared.items()):
            line = _line_of(text, f'"{name}"')
            if name not in locked:
                findings.append(_finding(
                    Severity.MEDIUM, manifest_file, line, f"{name}@{spec}", "declared-not-locked",
                    f"{group} declares {name}@{spec}, but {lock_name} was generated without it",
                    f"`{installer}` refuses this tree; re-run the install and commit the lockfile",
                ))
            elif str(locked[name]).strip() != spec.strip():
                findings.append(_finding(
                    Severity.MEDIUM, manifest_file, line, f"{name}@{spec}", "spec-drift",
                    f"package.json declares {name}@{spec}; {lock_name} was generated from {name}@{locked[name]}",
                    f"`{installer}` refuses a manifest and lockfile that disagree",
                ))
        for name in sorted(set(locked) - set(declared)):
            findings.append(_finding(
                Severity.MEDIUM, manifest_file, 1, f"{name}@{locked[name]}", "locked-not-declared",
                f"{lock_name} still records {name} in {group}, but package.json no longer declares it",
                "the lockfile is stale; re-run the install and commit it",
            ))
    return findings


# ------------------------------------------------------------------- helpers


def _finding(severity, file, line, claim, verdict, *evidence) -> Finding:
    return Finding(severity, CHECK_NAME, file, line, claim, verdict, list(evidence))


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []


def _line_of(lines: list[str], needle: str) -> int:
    return next((number for number, line in enumerate(lines, start=1) if needle in line), 1)
