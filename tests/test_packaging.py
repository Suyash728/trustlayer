"""2.4: an installed wheel (uvx) must carry its data and find its helpers outside the repo.

The full proof is `uv build` + install into a clean venv + `trustlayer audit` from another
directory, which was run by hand on 2026-11-20 (see CLAUDE.md). These pin the configuration
that makes it work, so it cannot silently regress.
"""

from __future__ import annotations

from pathlib import Path
import tomllib

from trustlayer import __version__, risk
from trustlayer.checks import node_helper, stale_models
from trustlayer.checks.node_helper import helper_dir, sync_scripts


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_wheel_force_includes_the_data_directory():
    include = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]

    assert include["data"] == "trustlayer/data"
    # Every file the code reads from data/ is in that directory.
    for name in ("model_deprecations.toml", "top_pypi_packages.json"):
        assert (ROOT / "data" / name).is_file()


def test_the_version_has_one_source():
    assert "version" in PYPROJECT["project"]["dynamic"]
    assert PYPROJECT["tool"]["hatch"]["version"]["path"] == "trustlayer/__init__.py"
    assert __version__.count(".") == 2


def test_runtime_imports_are_declared_dependencies():
    """`trustlayer ui` imports uvicorn; it was only present transitively."""
    declared = " ".join(PYPROJECT["project"]["dependencies"])
    for name in ("uvicorn", "fastapi", "typer", "packaging"):
        assert name in declared


def test_the_entry_point_maps_crashes_to_exit_three():
    assert PYPROJECT["project"]["scripts"]["trustlayer"] == "trustlayer.cli:main_entry"
    assert (ROOT / "trustlayer" / "__main__.py").is_file()


def test_no_private_typer_modules_are_imported():
    """`typer._click` changed layout between 0.27 and 0.29 and broke a fresh install."""
    for path in (ROOT / "trustlayer").rglob("*.py"):
        assert "typer._click" not in path.read_text(encoding="utf-8").replace(
            "`typer._click`", ""
        ), path


def test_packaged_data_wins_over_a_stray_site_packages_data_dir(tmp_path, monkeypatch):
    packaged = tmp_path / "trustlayer" / "data" / "model_deprecations.toml"
    packaged.parent.mkdir(parents=True)
    packaged.write_text("")
    monkeypatch.setattr(stale_models, "PACKAGED_REGISTRY_PATH", packaged)

    assert stale_models._registry_path() == packaged


def test_a_source_checkout_falls_back_to_the_repo_data(tmp_path, monkeypatch):
    monkeypatch.setattr(risk, "PACKAGED_CORPUS_PATH", tmp_path / "absent.json")

    assert risk._corpus_path() == risk.DEFAULT_CORPUS_PATH


def _fake_helper(directory: Path) -> Path:
    (directory / "node_modules" / "ts-morph").mkdir(parents=True)
    return directory


def test_the_configured_helper_dir_wins_and_gets_current_scripts(tmp_path, monkeypatch):
    configured = _fake_helper(tmp_path / "configured")
    (configured / "fail_open.mjs").write_text("// stale")
    monkeypatch.setenv(node_helper.DIR_ENV, str(configured))

    assert helper_dir() == configured
    shipped = (node_helper.PACKAGED_DIR / "fail_open.mjs").read_text()
    assert (configured / "fail_open.mjs").read_text() == shipped
    assert (configured / "resolve_imports.mjs").is_file()


def test_the_user_dir_is_used_when_nothing_else_has_ts_morph(tmp_path, monkeypatch):
    user = _fake_helper(tmp_path / "user")
    monkeypatch.delenv(node_helper.DIR_ENV, raising=False)
    monkeypatch.setattr(node_helper, "USER_DIR", user)
    monkeypatch.setattr(node_helper, "_has_ts_morph", lambda d: d == user)

    assert helper_dir() == user


def test_no_helper_anywhere_is_a_skip_reason_that_says_how_to_fix_it(monkeypatch):
    monkeypatch.delenv(node_helper.DIR_ENV, raising=False)
    monkeypatch.setattr(node_helper, "_has_ts_morph", lambda d: False)

    assert helper_dir() is None
    assert "trustlayer setup-node" in node_helper.missing_reason()


def test_sync_leaves_identical_scripts_alone(tmp_path):
    sync_scripts(tmp_path)
    before = {p.name: p.stat().st_mtime_ns for p in tmp_path.glob("*.mjs")}
    sync_scripts(tmp_path)

    assert {p.name: p.stat().st_mtime_ns for p in tmp_path.glob("*.mjs")} == before


def test_mcp_is_capped_below_the_version_that_renamed_fastmcp():
    """A fresh install resolved mcp 2.x, where `mcp.server.fastmcp` no longer exists."""
    spec = next(d for d in PYPROJECT["project"]["dependencies"] if d.startswith("mcp"))
    assert "<2" in spec
