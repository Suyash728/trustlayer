"""lock-drift: the lockfile was generated from a different manifest.

Every comparison is against what the lockfile itself records as its source - never an
evaluation of npm semver ranges.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import textwrap

import pytest

from trustlayer.checks.lock_drift import check_lock_drift


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"

PYPROJECT = """
[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "httpx>=0.27",
    "rich>=13.7",
    "uvicorn[standard]>=0.30",
    "tomli>=2; python_version < '3.11'",
]

[dependency-groups]
dev = ["pytest>=8.0"]
"""

UV_LOCK = """
version = 1
requires-python = ">=3.12"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }

[package.metadata]
requires-dist = [
    { name = "httpx", specifier = ">=0.27" },
    { name = "rich", specifier = ">=13.7" },
    { name = "tomli", marker = "python_full_version < '3.11'", specifier = ">=2" },
    { name = "uvicorn", extras = ["standard"], specifier = ">=0.30" },
]

[package.metadata.requires-dev]
dev = [{ name = "pytest", specifier = ">=8.0" }]

[[package]]
name = "httpx"
version = "0.28.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "rich"
version = "14.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "uvicorn"
version = "0.35.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.4.0"
source = { registry = "https://pypi.org/simple" }
"""


def write_uv(tmp_path: Path, pyproject: str = PYPROJECT, lock: str = UV_LOCK) -> Path:
    (tmp_path / "pyproject.toml").write_text(textwrap.dedent(pyproject))
    (tmp_path / "uv.lock").write_text(textwrap.dedent(lock))
    return tmp_path


def verdicts(result):
    return sorted((f.verdict, f.claim) for f in result.findings)


# --------------------------------------------------------------------- silence


def test_a_lock_in_sync_is_silent(tmp_path):
    result = check_lock_drift(write_uv(tmp_path))

    assert result.skipped is False
    assert result.findings == []


def test_trustlayers_own_lockfiles_are_in_sync():
    """Real-world shapes: this repo's uv.lock and its node helper's package-lock.json."""
    for path in (ROOT, ROOT / "trustlayer" / "checks" / "node"):
        result = check_lock_drift(path)
        assert result.skipped is False
        assert result.findings == [], result.findings


def test_spacing_and_ordering_of_specifiers_is_not_drift(tmp_path):
    pyproject = PYPROJECT.replace('"httpx>=0.27"', '"httpx >= 0.27, < 1"')
    lock = UV_LOCK.replace('{ name = "httpx", specifier = ">=0.27" }', '{ name = "httpx", specifier = "<1,>=0.27" }')

    assert check_lock_drift(write_uv(tmp_path, pyproject, lock)).findings == []


def test_a_marker_requirement_is_never_judged(tmp_path):
    pyproject = PYPROJECT.replace("\"tomli>=2; python_version < '3.11'\",", "")

    assert check_lock_drift(write_uv(tmp_path, pyproject)).findings == []


def test_dynamic_dependencies_are_not_compared(tmp_path):
    pyproject = '[project]\nname = "demo"\nversion = "0"\ndynamic = ["dependencies"]\n'
    result = check_lock_drift(write_uv(tmp_path, pyproject))

    assert result.skipped is True
    assert any("dynamic" in note for note in result.notes)


# ------------------------------------------------------------------------ drift


def test_a_dependency_added_without_relocking(tmp_path):
    pyproject = PYPROJECT.replace('"rich>=13.7",', '"rich>=13.7",\n    "pydantic>=2",')

    assert verdicts(check_lock_drift(write_uv(tmp_path, pyproject))) == [
        ("declared-not-locked", "pydantic>=2"),
    ]


def test_a_changed_specifier_and_a_lock_that_now_violates_it(tmp_path):
    pyproject = PYPROJECT.replace('"rich>=13.7"', '"rich>=15"')

    assert verdicts(check_lock_drift(write_uv(tmp_path, pyproject))) == [
        ("locked-version-violates-spec", "rich>=15"),
        ("spec-drift", "rich>=15"),
    ]


def test_changed_extras_are_drift(tmp_path):
    pyproject = PYPROJECT.replace('"uvicorn[standard]>=0.30"', '"uvicorn>=0.30"')

    assert verdicts(check_lock_drift(write_uv(tmp_path, pyproject))) == [
        ("spec-drift", "uvicorn>=0.30"),
    ]


def test_a_removed_dependency_left_in_the_lock(tmp_path):
    pyproject = PYPROJECT.replace('    "httpx>=0.27",\n', "")

    assert verdicts(check_lock_drift(write_uv(tmp_path, pyproject))) == [
        ("locked-not-declared", "httpx"),
    ]


def test_dependency_groups_are_compared_too(tmp_path):
    pyproject = PYPROJECT.replace('dev = ["pytest>=8.0"]', 'dev = ["pytest>=8.0", "ruff>=0.6"]')

    assert verdicts(check_lock_drift(write_uv(tmp_path, pyproject))) == [
        ("declared-not-locked", "ruff>=0.6"),
    ]


def test_the_finding_points_at_the_manifest_line(tmp_path):
    pyproject = PYPROJECT.replace('"rich>=13.7"', '"rich>=15"')
    finding = check_lock_drift(write_uv(tmp_path, pyproject)).findings[0]

    assert finding.file == "pyproject.toml"
    assert (tmp_path / "pyproject.toml").read_text().splitlines()[finding.line - 1].strip().startswith('"rich')


# ------------------------------------------------------------------ npm / pnpm


def test_package_lock_drift(tmp_path):
    source = ROOT / "trustlayer" / "checks" / "node"
    shutil.copy(source / "package.json", tmp_path / "package.json")
    shutil.copy(source / "package-lock.json", tmp_path / "package-lock.json")
    manifest = json.loads((tmp_path / "package.json").read_text())
    manifest["dependencies"]["ts-morph"] = "^28.0.0"
    manifest["dependencies"]["left-pad"] = "^1.3.0"
    (tmp_path / "package.json").write_text(json.dumps(manifest, indent=2))

    assert verdicts(check_lock_drift(tmp_path)) == [
        ("declared-not-locked", "left-pad@^1.3.0"),
        ("spec-drift", "ts-morph@^28.0.0"),
    ]


def test_pnpm_lock_drift(tmp_path):
    shutil.copytree(FIXTURES / "ts-only", tmp_path / "repo")
    repo = tmp_path / "repo"
    assert check_lock_drift(repo).findings == []  # the fixture is in sync

    manifest = json.loads((repo / "package.json").read_text())
    del manifest["devDependencies"]["vitest"]
    (repo / "package.json").write_text(json.dumps(manifest, indent=2))

    assert verdicts(check_lock_drift(repo)) == [("locked-not-declared", "vitest@^1.6.0")]


def test_a_v1_package_lock_is_not_judged(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"a": "^1"}}')
    (tmp_path / "package-lock.json").write_text('{"name": "x", "lockfileVersion": 1, "dependencies": {}}')
    result = check_lock_drift(tmp_path)

    assert result.skipped is True
    assert any("lockfileVersion 1" in note for note in result.notes)


@pytest.mark.parametrize("lock", ["poetry.lock"])
def test_formats_without_recorded_specs_say_so(tmp_path, lock):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\nrequests = "^2"\n')
    (tmp_path / lock).write_text("")
    result = check_lock_drift(tmp_path)

    assert result.findings == []
