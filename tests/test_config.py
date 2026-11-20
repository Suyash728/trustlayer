"""F1: exclude globs and inline ignores. Suppression hides; it never changes a verdict."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from trustlayer.checks.base import CheckResult, Finding, Severity
from trustlayer.checks.runner import run_checks, suppress
from trustlayer.config import Config, ConfigError, load_config
from trustlayer.detect import profile_repository
from trustlayer.report import Report, render_text, to_dict
from trustlayer.suite import inspect_suite


def _finding(file: str, line: int = 1, check: str = "stale-models") -> Finding:
    return Finding(Severity.HIGH, check, file, line, "claim", "verdict", ["evidence"])


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("tests/fixtures", "tests/fixtures/a/b.py", True),
        ("tests/fixtures/**", "tests/fixtures/a/b.py", True),
        ("tests/fixtures", "tests/fixtures_other/b.py", False),
        ("tests/fixtures", "tests/test_fixtures.py", False),
        ("*.generated.py", "api.generated.py", True),
        ("demo-*", "demo-repos/x/requirements.txt", True),
        ("src", "lib/src/x.py", False),  # anchored at the root, not anywhere in the path
    ],
)
def test_exclude_patterns_match_paths_and_whole_directories(pattern, path, expected):
    assert Config(exclude=(pattern,)).is_excluded(path) is expected


def test_config_reads_tool_trustlayer_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.trustlayer]\nexclude = ["tests/fixtures/", "demo"]\n', encoding="utf-8"
    )
    config = load_config(tmp_path)

    assert config.exclude == ("tests/fixtures", "demo")
    assert config.source == "pyproject.toml"


def test_a_standalone_trustlayer_toml_works_for_non_python_repos(tmp_path):
    (tmp_path / ".trustlayer.toml").write_text('exclude = ["vendor"]\n', encoding="utf-8")

    assert load_config(tmp_path).exclude == ("vendor",)


def test_no_config_means_nothing_is_excluded(tmp_path):
    assert load_config(tmp_path) == Config()


def test_a_misspelled_setting_is_an_error_not_a_silent_no_op(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.trustlayer]\nexcludes = ["tests"]\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="excludes"):
        load_config(tmp_path)


def test_exclude_must_be_a_list_of_strings(tmp_path):
    (tmp_path / ".trustlayer.toml").write_text('exclude = "tests"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_inline_ignore_matches_named_checks_and_check_families(tmp_path):
    (tmp_path / "a.py").write_text(
        'x = "m"  # trustlayer: ignore[stale-models]\n'
        'y = "m"  # trustlayer: ignore[fail-open]\n'
        'z = "m"  # trustlayer: ignore\n'
        "import q  # trustlayer: ignore[api-resolution]\n"
        "w = 1\n",
        encoding="utf-8",
    )
    config = Config()

    assert config.ignored_inline(tmp_path, "a.py", 1, "stale-models")
    assert not config.ignored_inline(tmp_path, "a.py", 2, "stale-models")
    assert config.ignored_inline(tmp_path, "a.py", 3, "anything")
    assert config.ignored_inline(tmp_path, "a.py", 4, "api-resolution:python")
    assert not config.ignored_inline(tmp_path, "a.py", 5, "stale-models")
    assert not config.ignored_inline(tmp_path, "a.py", 99, "stale-models")
    assert not config.ignored_inline(tmp_path, "missing.py", 1, "stale-models")


def test_a_js_style_comment_also_suppresses(tmp_path):
    (tmp_path / "a.ts").write_text('const m = "x"; // trustlayer: ignore[stale-models]\n')

    assert Config().ignored_inline(tmp_path, "a.ts", 1, "stale-models")


def test_suppression_counts_what_it_hides(tmp_path):
    result = CheckResult(
        "stale-models",
        findings=[_finding("tests/fixtures/a.py"), _finding("src/a.py")],
    )
    filtered = suppress(tmp_path, result, Config(exclude=("tests/fixtures",)))

    assert [f.file for f in filtered.findings] == ["src/a.py"]
    assert filtered.suppressed == 1


def test_a_suppressed_run_says_so_in_text_and_json(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n[tool.trustlayer]\nexclude = ["fixtures"]\n', encoding="utf-8"
    )
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "client.py").write_text('MODEL = "llama-3.3-70b-versatile"\n')  # trustlayer: ignore[stale-models]

    profile = profile_repository(tmp_path)
    results = run_checks(tmp_path, ["stale-models"], None, profile)
    report = Report(root=tmp_path, profile=profile, results=results, suite=inspect_suite(tmp_path))

    assert report.findings == []
    assert report.exit_code == 0
    assert to_dict(report)["summary"]["suppressed"] == 1

    console = Console(record=True, width=120)
    render_text(report, console)
    assert "suppressed  1 finding(s)" in console.export_text()


def test_the_repository_config_excludes_its_own_fixtures():
    """TrustLayer's own pyproject must keep the intentional fixtures out of a self-audit."""
    config = load_config(Path(__file__).resolve().parents[1])

    assert config.is_excluded("tests/fixtures/models-dirty/client.py")
    assert config.is_excluded("demo-repos/slopsquat-demo/requirements.txt")
    assert not config.is_excluded("trustlayer/cli.py")


def test_a_note_about_an_excluded_project_is_dropped(tmp_path):
    result = CheckResult(
        "api-resolution:python",
        notes=["demo-repos/x: not importable: requests", "PyPI unreachable: foo"],
    )
    filtered = suppress(tmp_path, result, Config(exclude=("demo-repos",)))

    assert filtered.notes == ["PyPI unreachable: foo"]


def test_excluded_manifests_are_never_fetched(tmp_path):
    """`deps` must not spend a request - or fail a run - on a fixture it was told to skip."""
    from trustlayer.checks.slopsquat import scan
    from trustlayer.risk import load_corpus

    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "requirements.txt").write_text("totally-fake-pkg-xyz==1.0\n")
    fetched = []

    def fetcher(name, **kwargs):
        fetched.append(name)
        raise AssertionError("an excluded manifest was fetched")

    result = scan(
        tmp_path, fetcher=fetcher, corpus=load_corpus(), config=Config(exclude=("fixtures",))
    )

    assert fetched == []
    assert [item.name for item in result.scored] == ["requests"]
    assert any("1 declaration(s) not scored" in note for note in result.notes)
