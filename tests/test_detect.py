"""Detection tests run against real fixture directories under tests/fixtures/."""

from pathlib import Path

import pytest

from trustlayer.detect import Dependency, Language, Project, RepoProfile, profile_repository


FIXTURES = Path(__file__).parent / "fixtures"


def profile(name: str) -> RepoProfile:
    return profile_repository(FIXTURES / name)


def project_at(repo: RepoProfile, path: str, language: Language) -> Project:
    return next(p for p in repo.projects if p.path == path and p.language == language)


def dependency(project: Project, name: str) -> Dependency:
    return next(d for d in project.dependencies if d.name == name)


def findings_of(repo: RepoProfile, kind: str) -> list[str]:
    return [f.detail for f in repo.findings if f.kind == kind]


def test_python_only_repo_detects_language_and_pytest_from_config():
    repo = profile("python-only")

    assert repo.languages == [Language.PYTHON]
    assert len(repo.projects) == 1

    billing = project_at(repo, ".", Language.PYTHON)
    assert billing.manifests == ["pyproject.toml"]
    assert [(r.name, r.evidence) for r in billing.runners] == [
        ("pytest", "pyproject.toml [tool.pytest.ini_options]")
    ]


def test_lockfile_versions_win_over_manifest_specifiers():
    billing = project_at(profile("python-only"), ".", Language.PYTHON)

    assert billing.lockfile == "uv.lock"
    # Declared as ">=2.6" but the lock resolves it, so it counts as pinned.
    assert dependency(billing, "pydantic") == Dependency(
        name="pydantic",
        version="2.7.1",
        pinned=True,
        declared_spec=">=2.6",
        source="uv.lock",
    )
    assert dependency(billing, "httpx").version == "0.27.0"
    assert billing.pinned_count == len(billing.dependencies) == 3


def test_lockfile_transitives_are_not_reported_as_direct_dependencies():
    billing = project_at(profile("python-only"), ".", Language.PYTHON)

    # anyio is in uv.lock but not declared in pyproject.toml.
    assert "anyio" not in {d.name for d in billing.dependencies}


def test_ts_only_repo_detects_vitest_config_and_strips_pnpm_peer_suffix():
    repo = profile("ts-only")

    assert repo.languages == [Language.JAVASCRIPT]
    storefront = project_at(repo, ".", Language.JAVASCRIPT)

    assert storefront.lockfile == "pnpm-lock.yaml"
    assert [(r.name, r.evidence) for r in storefront.runners] == [("vitest", "vitest.config.ts")]
    # pnpm records "1.6.0(@types/node@20.12.7)"; the peer suffix is not part of the version.
    assert dependency(storefront, "vitest").version == "1.6.0"
    assert dependency(storefront, "react").version == "18.2.0"
    assert dependency(storefront, "react").declared_spec == "^18.2.0"


def test_monorepo_finds_both_projects():
    repo = profile("monorepo")

    assert sorted((p.path, p.language) for p in repo.projects) == [
        ("apps/api", Language.PYTHON),
        ("apps/web", Language.JAVASCRIPT),
    ]
    assert repo.languages == [Language.PYTHON, Language.JAVASCRIPT]


def test_monorepo_python_app_follows_requirements_includes():
    api = project_at(profile("monorepo"), "apps/api", Language.PYTHON)

    assert api.lockfile is None
    assert [(r.name, r.evidence) for r in api.runners] == [("pytest", "pytest.ini")]
    assert dependency(api, "fastapi").version == "0.111.0"
    # pytest is only reachable by following "-r requirements-dev.txt".
    assert dependency(api, "pytest") == Dependency(
        name="pytest",
        version="8.2.0",
        pinned=True,
        declared_spec="==8.2.0",
        source="requirements-dev.txt",
    )


def test_unpinned_dependencies_and_missing_lockfile_are_findings():
    repo = profile("monorepo")
    api = project_at(repo, "apps/api", Language.PYTHON)

    assert dependency(api, "uvicorn").pinned is False
    assert dependency(api, "uvicorn").version is None
    assert dependency(api, "ruff").declared_spec is None

    unpinned = findings_of(repo, "unpinned-dependency")
    assert "uvicorn (>=0.29) is not pinned" in unpinned
    assert "ruff (no version constraint) is not pinned" in unpinned
    assert "no lockfile; versions resolved from manifests only" in findings_of(repo, "no-lockfile")


def test_monorepo_web_app_resolves_package_lock_and_skips_nested_installs():
    web = project_at(profile("monorepo"), "apps/web", Language.JAVASCRIPT)

    assert web.lockfile == "package-lock.json"
    assert [(r.name, r.evidence) for r in web.runners] == [("jest", 'package.json "jest" key')]
    assert dependency(web, "next").version == "14.2.3"
    # "^29.7.0" in the manifest, resolved by the lock.
    assert dependency(web, "jest") == Dependency(
        name="jest",
        version="29.7.0",
        pinned=True,
        declared_spec="^29.7.0",
        source="package-lock.json",
    )
    # chalk is only at node_modules/jest/node_modules/chalk, so it is not a direct dep.
    assert {d.name for d in web.dependencies} == {"next", "jest"}


def test_setup_py_is_parsed_without_execution_and_unittest_is_detected():
    repo = profile("python-unittest")
    calc = project_at(repo, ".", Language.PYTHON)

    assert calc.manifests == ["setup.py"]
    assert dependency(calc, "requests").version == "2.31.0"
    assert dependency(calc, "urllib3").pinned is False

    assert [r.name for r in calc.runners] == ["unittest"]
    assert calc.runners[0].evidence == "tests/test_calc.py subclasses unittest.TestCase"


def test_unittest_is_not_reported_just_because_a_tests_directory_exists():
    billing = project_at(profile("python-only"), ".", Language.PYTHON)

    assert "unittest" not in {r.name for r in billing.runners}


def test_nested_project_tests_do_not_leak_into_the_parent_runner_detection():
    """tests/fixtures/python-unittest is a project root; its runner is not TrustLayer's."""
    repo = profile_repository(FIXTURES.parents[1])
    root = project_at(repo, ".", Language.PYTHON)

    assert [r.name for r in root.runners] == ["pytest"]
    assert "tests/fixtures/python-unittest" in {p.path for p in repo.projects}


def test_profile_repository_rejects_a_file_path():
    with pytest.raises(NotADirectoryError):
        profile_repository(FIXTURES / "python-only" / "pyproject.toml")
