"""Repository detection: languages, test runners, and pinned dependency versions.

`profile_repository` is the only public entry point. Everything downstream consumes the
returned `RepoProfile`; nothing else re-reads manifests or lockfiles.
"""

from __future__ import annotations

import ast
from collections import deque
from collections.abc import Iterator
import configparser
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
import tomllib

from trustlayer import deps


SKIP_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        ".tox",
        "node_modules",
        "mutants",
        ".next",
        "dist",
        "out",
        "build",
        "htmlcov",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
    }
)
MAX_SEARCH_DEPTH = 4
MAX_TEST_MODULE_SCAN = 40

PYTHON_MANIFEST_NAMES = ("pyproject.toml", "setup.py", "setup.cfg")
JAVASCRIPT_MANIFEST = "package.json"

VITEST_CONFIG_NAMES = (
    "vitest.config.ts",
    "vitest.config.js",
    "vitest.config.mts",
    "vitest.config.mjs",
    "vitest.config.cts",
    "vitest.config.cjs",
)
JEST_CONFIG_NAMES = (
    "jest.config.js",
    "jest.config.ts",
    "jest.config.cjs",
    "jest.config.mjs",
    "jest.config.json",
)


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None  # concrete version, or None when unresolvable
    pinned: bool
    declared_spec: str | None  # "^18.2.0", ">=8.0", "==1.2.3"
    source: str  # the file the version came from


@dataclass(frozen=True)
class TestRunner:
    name: str  # pytest | unittest | vitest | jest
    evidence: str  # why we believe it, e.g. "pyproject.toml [tool.pytest.ini_options]"


@dataclass(frozen=True)
class Project:
    """One manifest root inside the repository."""

    path: str  # repo-relative; "." for the root
    language: Language
    manifests: list[str]
    lockfile: str | None
    runners: list[TestRunner]
    dependencies: list[Dependency]

    @property
    def pinned_count(self) -> int:
        return sum(1 for dependency in self.dependencies if dependency.pinned)


@dataclass(frozen=True)
class Finding:
    kind: str
    project: str
    detail: str


@dataclass(frozen=True)
class RepoProfile:
    root: Path
    projects: list[Project] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def languages(self) -> list[Language]:
        seen = {project.language for project in self.projects}
        return [language for language in Language if language in seen]


def profile_repository(path: str | Path) -> RepoProfile:
    """Build a RepoProfile by reading a repository's manifests and lockfiles."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"{root} is not a directory")

    projects: list[Project] = []
    findings: list[Finding] = []

    for directory in _iter_candidate_directories(root):
        relative = _relative_path(directory, root)

        manifests = _python_manifests(directory)
        if manifests:
            project, project_findings = _build_python_project(directory, relative, manifests)
            projects.append(project)
            findings.extend(project_findings)

        if (directory / JAVASCRIPT_MANIFEST).is_file():
            built = _build_javascript_project(directory, relative)
            if built is None:
                findings.append(
                    Finding("unparsed-manifest", relative, "package.json could not be parsed")
                )
            else:
                project, project_findings = built
                projects.append(project)
                findings.extend(project_findings)

    return RepoProfile(root=root, projects=projects, findings=findings)


def _iter_candidate_directories(root: Path) -> Iterator[Path]:
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    while queue:
        directory, depth = queue.popleft()
        yield directory
        if depth >= MAX_SEARCH_DEPTH:
            continue
        try:
            children = sorted(directory.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink() or not child.is_dir():
                continue
            if child.name.startswith(".") or child.name in SKIP_DIRECTORY_NAMES:
                continue
            if child.name.endswith(".egg-info"):
                continue
            queue.append((child, depth + 1))


def _python_manifests(directory: Path) -> list[str]:
    manifests = [name for name in PYTHON_MANIFEST_NAMES if (directory / name).is_file()]
    manifests.extend(
        sorted(path.name for path in directory.glob(deps.REQUIREMENTS_GLOB) if path.is_file())
    )
    return manifests


def _build_python_project(
    directory: Path, relative: str, manifests: list[str]
) -> tuple[Project, list[Finding]]:
    findings: list[Finding] = []

    declarations, unparsed = deps.read_python_declarations(directory, manifests)
    for failure in unparsed:
        findings.append(Finding("unparsed-manifest", relative, f"{failure.source}: {failure.reason}"))

    lockfiles = deps.find_lockfiles(directory, deps.PYTHON_LOCKFILES)
    lockfile = lockfiles[0] if lockfiles else None
    lock_versions = deps.read_lock_versions(directory, lockfile) if lockfile else {}

    dependencies = _resolve(
        declarations,
        lock_versions,
        lockfile,
        key=deps.canonicalize_python_name,
        pin_from_spec=deps.pinned_python_version,
    )
    runners = _detect_python_runners(directory, declarations)
    findings.extend(_dependency_findings(relative, dependencies, lockfile, bool(declarations)))
    if not runners:
        findings.append(
            Finding("no-test-runner", relative, "no pytest or unittest signal in config or dependencies")
        )

    project = Project(
        path=relative,
        language=Language.PYTHON,
        manifests=manifests,
        lockfile=lockfile,
        runners=runners,
        dependencies=dependencies,
    )
    return project, findings + _extra_lockfile_findings(relative, lockfiles)


def _build_javascript_project(
    directory: Path, relative: str
) -> tuple[Project, list[Finding]] | None:
    package_json = deps.read_json(directory / JAVASCRIPT_MANIFEST)
    if package_json is None:
        return None

    findings: list[Finding] = []
    declarations = deps.read_javascript_declarations(package_json)

    lockfiles = deps.find_lockfiles(directory, deps.JAVASCRIPT_LOCKFILES)
    lockfile = lockfiles[0] if lockfiles else None
    lock_versions = deps.read_lock_versions(directory, lockfile) if lockfile else {}

    dependencies = _resolve(
        declarations,
        lock_versions,
        lockfile,
        key=lambda name: name,
        pin_from_spec=deps.pinned_javascript_version,
    )
    runners = _detect_javascript_runners(directory, package_json)
    findings.extend(_dependency_findings(relative, dependencies, lockfile, bool(declarations)))
    if not runners:
        findings.append(
            Finding("no-test-runner", relative, "no vitest or jest signal in config or dependencies")
        )

    project = Project(
        path=relative,
        language=Language.JAVASCRIPT,
        manifests=[JAVASCRIPT_MANIFEST],
        lockfile=lockfile,
        runners=runners,
        dependencies=dependencies,
    )
    return project, findings + _extra_lockfile_findings(relative, lockfiles)


def _resolve(
    declarations: list[deps.Declaration],
    lock_versions: dict[str, str],
    lockfile: str | None,
    key,
    pin_from_spec,
) -> list[Dependency]:
    """Turn declarations into dependencies, preferring lockfile versions over specs."""
    dependencies: list[Dependency] = []
    seen: set[str] = set()

    for declaration in declarations:
        identity = key(declaration.name)
        if identity in seen:  # a dep can appear in both runtime and dev groups
            continue
        seen.add(identity)

        locked = lock_versions.get(identity)
        if locked and lockfile:
            dependencies.append(
                Dependency(
                    name=declaration.name,
                    version=locked,
                    pinned=True,
                    declared_spec=declaration.spec or None,
                    source=lockfile,
                )
            )
            continue

        version = pin_from_spec(declaration.spec)
        dependencies.append(
            Dependency(
                name=declaration.name,
                version=version,
                pinned=version is not None,
                declared_spec=declaration.spec or None,
                source=declaration.source,
            )
        )
    return dependencies


def _dependency_findings(
    relative: str, dependencies: list[Dependency], lockfile: str | None, has_declarations: bool
) -> list[Finding]:
    findings = []
    if has_declarations and lockfile is None:
        findings.append(
            Finding("no-lockfile", relative, "no lockfile; versions resolved from manifests only")
        )
    for dependency in dependencies:
        if dependency.pinned:
            continue
        declared = dependency.declared_spec or "no version constraint"
        findings.append(
            Finding("unpinned-dependency", relative, f"{dependency.name} ({declared}) is not pinned")
        )
    return findings


def _extra_lockfile_findings(relative: str, lockfiles: list[str]) -> list[Finding]:
    if len(lockfiles) <= 1:
        return []
    ignored = ", ".join(lockfiles[1:])
    return [
        Finding("multiple-lockfiles", relative, f"using {lockfiles[0]}; also present: {ignored}")
    ]


def _detect_python_runners(
    directory: Path, declarations: list[deps.Declaration]
) -> list[TestRunner]:
    runners: list[TestRunner] = []

    pytest_evidence = _pytest_evidence(directory, declarations)
    if pytest_evidence:
        runners.append(TestRunner("pytest", pytest_evidence))

    unittest_evidence = _unittest_evidence(directory)
    if unittest_evidence:
        runners.append(TestRunner("unittest", unittest_evidence))

    return runners


def _pytest_evidence(directory: Path, declarations: list[deps.Declaration]) -> str | None:
    pyproject = directory / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        tool = data.get("tool")
        if isinstance(tool, dict) and isinstance(tool.get("pytest"), dict):
            return "pyproject.toml [tool.pytest.ini_options]"

    if (directory / "pytest.ini").is_file():
        return "pytest.ini"
    if _ini_has_section(directory / "tox.ini", "pytest"):
        return "tox.ini [pytest]"
    if _ini_has_section(directory / "setup.cfg", "tool:pytest"):
        return "setup.cfg [tool:pytest]"

    for declaration in declarations:
        if deps.canonicalize_python_name(declaration.name) == "pytest":
            return f"{declaration.source} dependency"
    return None


def _unittest_evidence(directory: Path) -> str | None:
    """unittest is stdlib: no config file, no dependency. Positive signals only."""
    for name in ("tox.ini", "Makefile", "noxfile.py"):
        path = directory / name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "-m unittest" in text:
            return f"{name} runs 'python -m unittest'"

    for path in _iter_test_modules(directory):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(_is_testcase_base(b) for b in node.bases):
                return f"{_relative_path(path, directory)} subclasses unittest.TestCase"
    return None


def _is_testcase_base(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr == "TestCase"
    if isinstance(node, ast.Name):
        return node.id == "TestCase"
    return False


def _iter_test_modules(directory: Path) -> Iterator[Path]:
    """Yield this project's own test modules.

    Stops at nested project roots: a child project's tests say nothing about which
    runner the parent uses.
    """
    scanned = 0
    queue: deque[tuple[Path, int]] = deque([(directory, 0)])
    while queue:
        current, depth = queue.popleft()
        try:
            children = sorted(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if depth >= MAX_SEARCH_DEPTH:
                    continue
                if child.name.startswith(".") or child.name in SKIP_DIRECTORY_NAMES:
                    continue
                if _is_project_root(child):
                    continue
                queue.append((child, depth + 1))
            elif _is_test_module_name(child.name):
                scanned += 1
                if scanned > MAX_TEST_MODULE_SCAN:
                    return
                yield child


def _is_project_root(directory: Path) -> bool:
    return bool(_python_manifests(directory)) or (directory / JAVASCRIPT_MANIFEST).is_file()


def _is_test_module_name(name: str) -> bool:
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _detect_javascript_runners(directory: Path, package_json: dict) -> list[TestRunner]:
    scripts = package_json.get("scripts")
    test_script = scripts.get("test", "") if isinstance(scripts, dict) else ""
    test_script = test_script if isinstance(test_script, str) else ""
    installed = _javascript_dependency_names(package_json)

    runners: list[TestRunner] = []

    # Deliberately no vite.config.ts introspection: finding a `test:` key there means
    # regexing TypeScript, which is guessing. The devDependency is the real signal.
    vitest_config = next((name for name in VITEST_CONFIG_NAMES if (directory / name).is_file()), None)
    if vitest_config:
        runners.append(TestRunner("vitest", vitest_config))
    elif "vitest" in installed:
        runners.append(TestRunner("vitest", "package.json dependency"))
    elif "vitest" in test_script:
        runners.append(TestRunner("vitest", "package.json scripts.test"))

    jest_config = next((name for name in JEST_CONFIG_NAMES if (directory / name).is_file()), None)
    if jest_config:
        runners.append(TestRunner("jest", jest_config))
    elif isinstance(package_json.get("jest"), dict):
        runners.append(TestRunner("jest", 'package.json "jest" key'))
    elif "jest" in installed:
        runners.append(TestRunner("jest", "package.json dependency"))
    elif "jest" in test_script:
        runners.append(TestRunner("jest", "package.json scripts.test"))

    return runners


def _javascript_dependency_names(package_json: dict) -> set[str]:
    names: set[str] = set()
    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = package_json.get(group)
        if isinstance(entries, dict):
            names.update(name for name in entries if isinstance(name, str))
    return names


def _ini_has_section(path: Path, section: str) -> bool:
    if not path.is_file():
        return False
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return False
    return parser.has_section(section)


def _relative_path(path: Path, root: Path) -> str:
    if path == root:
        return "."
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)
