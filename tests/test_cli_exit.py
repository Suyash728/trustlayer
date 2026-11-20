"""Exit codes are the hook contract: 0 clean, 1 medium, 2 high, 3 operational error.

These run the real console entry point, because Typer's own error handling (exit 1 on a
crash, exit 2 on a usage error) is exactly what would break that contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from killscore import cli


FIXTURES = Path(__file__).parent / "fixtures"


def _run(monkeypatch, *args: str) -> int:
    monkeypatch.setattr("sys.argv", ["killscore", *args])
    return cli.main_entry()


def test_a_clean_audit_exits_zero(monkeypatch):
    assert _run(monkeypatch, "audit", str(FIXTURES / "models-clean"), "--no-save") == 0


def test_a_high_finding_exits_two(monkeypatch):
    assert _run(monkeypatch, "audit", str(FIXTURES / "failopen-dirty"), "--no-save") == 2


def test_a_missing_path_is_operational(monkeypatch):
    assert _run(monkeypatch, "audit", "/definitely/not/here", "--no-save") == 3


def test_a_usage_error_is_operational_not_high(monkeypatch):
    """Click exits 2 on a bad option, and 2 means "high findings" to a hook."""
    assert _run(monkeypatch, "audit", "--no-such-option") == 3


def test_a_crash_inside_a_check_is_operational_not_medium(monkeypatch):
    """Typer exits 1 on an uncaught exception, and 1 means "medium findings"."""

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "run_checks", explode)
    assert _run(monkeypatch, "audit", str(FIXTURES / "models-clean"), "--no-save") == 3


def test_a_bad_config_is_operational(monkeypatch, tmp_path):
    (tmp_path / ".killscore.toml").write_text("exclude = 3\n")
    assert _run(monkeypatch, "audit", str(tmp_path), "--no-save") == 3


@pytest.mark.parametrize("command", ["history", "diff", "tui", "ui"])
def test_every_command_is_registered_before_the_entry_point_runs(command):
    """The `__main__` guard used to sit above these definitions."""
    names = {c.name or c.callback.__name__ for c in cli.app.registered_commands}
    assert command in names


def test_audit_help_keeps_its_square_brackets_and_lists_every_opt_in_check(capsys, monkeypatch):
    """Rich read `[tool.killscore]` and `[check]` as style tags and silently dropped them."""
    from killscore.checks.runner import OPT_IN_CHECKS

    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr("sys.argv", ["killscore", "audit", "--help"])
    assert cli.main_entry() in (0, None)

    text = " ".join(capsys.readouterr().out.split())
    assert "[tool.killscore] exclude = [...]" in text
    assert "killscore: ignore[check]" in text
    assert "\\[" not in text
    for check in OPT_IN_CHECKS:
        assert f"`{check}`" in text or check in text.split("opt-in")[0], check
