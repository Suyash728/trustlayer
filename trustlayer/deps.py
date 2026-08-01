"""Manifest and lockfile readers.

Pure parsing helpers returning primitives (names, specs, versions). `detect.py` is the
only caller and owns all policy and model construction.
"""

from __future__ import annotations

import ast
import configparser
import json
from pathlib import Path
import re
import tomllib
from typing import NamedTuple

import yaml


PYTHON_LOCKFILES = ("uv.lock", "poetry.lock")
JAVASCRIPT_LOCKFILES = ("pnpm-lock.yaml", "package-lock.json")

REQUIREMENTS_GLOB = "requirements*.txt"
MAX_REQUIREMENTS_DEPTH = 5

# PEP 508: name, optional [extras], then the remainder (specifier or @ direct reference).
REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[(?P<extras>[^\]]*)\])?\s*(?P<spec>.*)$"
)
# A single "==x" / "===x" clause is a pin. The excluded comma rejects ">=1,<2".
PINNED_PYTHON_RE = re.compile(r"^===?\s*(?P<version>[^\s,;]+)$")
EXACT_JS_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
BARE_POETRY_VERSION_RE = re.compile(r"^\d[0-9A-Za-z.+-]*$")
PNPM_PEER_SUFFIX_RE = re.compile(r"\(.*\)$")

NON_VERSION_PREFIXES = ("link:", "file:", "workspace:", "npm:", "catalog:")
PIP_OPTION_PREFIX = "-"


class Declaration(NamedTuple):
    """A dependency as written in a manifest, before any lockfile resolution."""

    name: str
    spec: str
    source: str


class Unparsed(NamedTuple):
    """A manifest TrustLayer could not resolve, and why."""

    source: str
    reason: str


def canonicalize_python_name(name: str) -> str:
    """Normalize a Python distribution name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def find_lockfiles(directory: Path, candidates: tuple[str, ...]) -> list[str]:
    """Return the candidate lockfiles present, in preference order."""
    return [name for name in candidates if (directory / name).is_file()]


def read_lock_versions(directory: Path, lockfile: str) -> dict[str, str]:
    """Map package name to concrete version from a lockfile.

    Python names are canonicalized; JavaScript names are kept verbatim.
    """
    try:
        text = (directory / lockfile).read_text(encoding="utf-8")
    except OSError:
        return {}

    if lockfile in PYTHON_LOCKFILES:
        return _read_toml_lock(text)
    if lockfile == "package-lock.json":
        return _read_package_lock(text)
    if lockfile == "pnpm-lock.yaml":
        return _read_pnpm_lock(text)
    return {}


def pinned_python_version(spec: str) -> str | None:
    """Return the concrete version a PEP 508 specifier pins to, else None."""
    match = PINNED_PYTHON_RE.match(spec.strip())
    if not match:
        return None
    version = match.group("version")
    return None if "*" in version else version


def pinned_javascript_version(spec: str) -> str | None:
    """Return the concrete version an npm range pins to, else None."""
    cleaned = spec.strip()
    return cleaned if EXACT_JS_VERSION_RE.match(cleaned) else None


def read_json(path: Path) -> dict | None:
    """Parse a JSON object file, returning None when unreadable or not an object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def read_python_declarations(
    directory: Path, manifests: list[str]
) -> tuple[list[Declaration], list[Unparsed]]:
    """Read declared dependencies from every Python manifest in a directory."""
    declarations: list[Declaration] = []
    unparsed: list[Unparsed] = []

    for manifest in manifests:
        path = directory / manifest
        if manifest == "pyproject.toml":
            found, failed = _read_pyproject(path)
        elif manifest == "setup.py":
            found, failed = _read_setup_py(path)
        elif manifest == "setup.cfg":
            found, failed = _read_setup_cfg(path)
        elif manifest.endswith(".txt"):
            found, failed = _read_requirements(path, directory, set(), 0)
        else:
            continue
        declarations.extend(found)
        unparsed.extend(failed)

    return declarations, unparsed


def read_javascript_declarations(package_json: dict) -> list[Declaration]:
    """Read declared dependencies from a parsed package.json."""
    declarations: list[Declaration] = []
    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = package_json.get(group)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if isinstance(name, str) and isinstance(spec, str):
                declarations.append(Declaration(name, spec, "package.json"))
    return declarations


def _read_toml_lock(text: str) -> dict[str, str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}

    versions: dict[str, str] = {}
    packages = data.get("package")
    if not isinstance(packages, list):
        return versions
    for package in packages:
        if not isinstance(package, dict):
            continue
        name, version = package.get("name"), package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            versions[canonicalize_python_name(name)] = version
    return versions


def _read_package_lock(text: str) -> dict[str, str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}

    versions: dict[str, str] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(key, str) or not key.startswith("node_modules/"):
                continue
            name = key[len("node_modules/") :]
            # Nested installs shadow a direct dep of a different package; skip them.
            if "/node_modules/" in name or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                versions[name] = version

    legacy = data.get("dependencies")  # lockfileVersion 1
    if isinstance(legacy, dict):
        for name, meta in legacy.items():
            if name in versions or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(name, str) and isinstance(version, str):
                versions[name] = version
    return versions


def _read_pnpm_lock(text: str) -> dict[str, str]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}

    versions: dict[str, str] = {}
    importers = data.get("importers")
    if isinstance(importers, dict):
        for importer in importers.values():
            if not isinstance(importer, dict):
                continue
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                entries = importer.get(group)
                if not isinstance(entries, dict):
                    continue
                for name, meta in entries.items():
                    raw = meta.get("version") if isinstance(meta, dict) else meta
                    version = _clean_pnpm_version(raw)
                    if isinstance(name, str) and version:
                        versions.setdefault(name, version)
    if versions:
        return versions

    packages = data.get("packages")  # older layouts key on "/name@version"
    if isinstance(packages, dict):
        for key in packages:
            name, _, raw = str(key).lstrip("/").rpartition("@")
            version = _clean_pnpm_version(raw)
            if name and version:
                versions.setdefault(name, version)
    return versions


def _clean_pnpm_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    # "18.2.0(react@18.2.0)" -> "18.2.0"
    cleaned = PNPM_PEER_SUFFIX_RE.sub("", value).strip()
    if not cleaned or cleaned.startswith(NON_VERSION_PREFIXES):
        return None
    return cleaned


def _read_pyproject(path: Path) -> tuple[list[Declaration], list[Unparsed]]:
    source = path.name
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [], [Unparsed(source, f"could not be parsed ({error})")]

    declarations: list[Declaration] = []

    project = data.get("project")
    if isinstance(project, dict):
        declarations.extend(_parse_requirement_list(project.get("dependencies"), source))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for specs in optional.values():
                declarations.extend(_parse_requirement_list(specs, source))

    groups = data.get("dependency-groups")  # PEP 735
    if isinstance(groups, dict):
        for specs in groups.values():
            declarations.extend(_parse_requirement_list(specs, source))

    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        declarations.extend(_parse_poetry_table(poetry.get("dependencies"), source))
        poetry_groups = poetry.get("group")
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if isinstance(group, dict):
                    declarations.extend(_parse_poetry_table(group.get("dependencies"), source))

    return declarations, []


def _parse_requirement_list(specs: object, source: str) -> list[Declaration]:
    if not isinstance(specs, list):
        return []
    declarations = []
    for spec in specs:
        # PEP 735 allows {include-group = "..."} entries; only strings are requirements.
        if not isinstance(spec, str):
            continue
        declaration = _parse_requirement(spec, source)
        if declaration:
            declarations.append(declaration)
    return declarations


def _parse_poetry_table(table: object, source: str) -> list[Declaration]:
    if not isinstance(table, dict):
        return []

    declarations = []
    for name, constraint in table.items():
        if not isinstance(name, str) or name == "python":
            continue
        if isinstance(constraint, dict):
            raw = constraint.get("version")
        elif isinstance(constraint, str):
            raw = constraint
        else:
            raw = None
        declarations.append(Declaration(name, _poetry_spec(raw), source))
    return declarations


def _poetry_spec(raw: object) -> str:
    """Convert a Poetry constraint to PEP 440 form. A bare version means exact in Poetry."""
    if not isinstance(raw, str):
        return ""
    cleaned = raw.strip()
    if BARE_POETRY_VERSION_RE.match(cleaned):
        return f"=={cleaned}"
    return cleaned


def _parse_requirement(text: str, source: str) -> Declaration | None:
    candidate = text.split(";", 1)[0].strip()  # drop environment markers
    if not candidate:
        return None

    match = REQUIREMENT_RE.match(candidate)
    if not match:
        return None

    spec = match.group("spec").strip()
    if spec.startswith("@"):
        spec = ""  # direct URL reference, not a version pin
    return Declaration(match.group("name"), spec, source)


def _read_requirements(
    path: Path, root: Path, seen: set[Path], depth: int
) -> tuple[list[Declaration], list[Unparsed]]:
    resolved = path.resolve()
    if depth > MAX_REQUIREMENTS_DEPTH or resolved in seen:
        return [], []
    seen.add(resolved)

    source = _relative_name(path, root)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], [Unparsed(source, "could not be read")]

    declarations: list[Declaration] = []
    unparsed: list[Unparsed] = []

    for line in _logical_lines(text):
        tokens = line.split()
        if not tokens:
            continue
        head = tokens[0]

        if head in ("-r", "--requirement") and len(tokens) > 1:
            nested = path.parent / tokens[1]
            found, failed = _read_requirements(nested, root, seen, depth + 1)
            declarations.extend(found)
            unparsed.extend(failed)
        elif head in ("-e", "--editable"):
            target = " ".join(tokens[1:]) or "."
            unparsed.append(Unparsed(source, f"editable install {target!r} has no resolvable version"))
        elif head.startswith(PIP_OPTION_PREFIX):
            continue  # index URLs, --no-binary, and friends
        else:
            requirement = " ".join(token for token in tokens if not token.startswith("--hash"))
            declaration = _parse_requirement(requirement, source)
            if declaration:
                declarations.append(declaration)

    return declarations, unparsed


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations and strip comments."""
    joined = text.replace("\\\n", " ")
    lines = []
    for raw in joined.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        # Only whitespace-preceded "#" starts a comment, so URL fragments survive.
        comment = re.search(r"\s#", line)
        if comment:
            line = line[: comment.start()].strip()
        if line:
            lines.append(line)
    return lines


def _read_setup_py(path: Path) -> tuple[list[Declaration], list[Unparsed]]:
    """Read install_requires via AST. setup.py is never executed."""
    source = path.name
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return [], [Unparsed(source, "could not be parsed")]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node) != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg != "install_requires":
                continue
            try:
                specs = ast.literal_eval(keyword.value)
            except (ValueError, TypeError):
                return [], [
                    Unparsed(source, "install_requires is not a literal (setup.py is never executed)")
                ]
            return _parse_requirement_list(list(specs), source), []
    return [], []


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _read_setup_cfg(path: Path) -> tuple[list[Declaration], list[Unparsed]]:
    source = path.name
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return [], [Unparsed(source, "could not be parsed")]

    raw = parser.get("options", "install_requires", fallback="")
    specs = [line.strip() for line in raw.splitlines() if line.strip()]
    return _parse_requirement_list(specs, source), []


def _relative_name(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
