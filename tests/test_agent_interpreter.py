"""B9: the agent's own pytest runs must use the ORIGINAL repo's interpreter.

The workspace copy has no .venv, so a bare `pytest` resolves from $PATH - wrong or absent -
and the model reads ImportErrors as feedback on its tests.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

from trustlayer.agent import runtime
from trustlayer.agent.localtools import execute, repo_test_runner
from trustlayer.agent.runtime import venv_bin_for, venv_environment


def test_a_bare_pytest_is_pointed_at_the_repo_venv(tmp_path):
    bin_dir = tmp_path / "bin"
    assert repo_test_runner(["pytest", "-q", "tests/"], bin_dir) == [
        str(bin_dir / "python"), "-m", "pytest", "-q", "tests/",
    ]


def test_python_dash_m_pytest_keeps_its_arguments(tmp_path):
    bin_dir = tmp_path / "bin"
    assert repo_test_runner(["python3", "-m", "pytest", "-x"], bin_dir) == [
        str(bin_dir / "python"), "-m", "pytest", "-x",
    ]


def test_without_a_venv_the_command_is_unchanged():
    assert repo_test_runner(["pytest", "-q"], None) == ["pytest", "-q"]


def test_venv_bin_is_found_without_resolving_the_symlink(tmp_path):
    bin_dir = tmp_path / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python").symlink_to(sys.executable)

    found = venv_bin_for(tmp_path)
    assert found == bin_dir.absolute()
    assert venv_bin_for(tmp_path / "nothing-here") is None
    assert venv_bin_for(None) is None


def test_the_claude_backend_gets_the_venv_first_on_path(tmp_path):
    env = venv_environment(tmp_path / ".venv" / "bin")

    assert env["PATH"].split(os.pathsep)[0] == str(tmp_path / ".venv" / "bin")
    assert env["VIRTUAL_ENV"] == str(tmp_path / ".venv")
    assert venv_environment(None) == {}


def test_run_agent_passes_the_environment_to_the_sdk(tmp_path, monkeypatch):
    seen = {}

    def fake_run(*args):
        seen["env"] = args[-1]
        return runtime.AgentResult(ok=True)

    monkeypatch.setattr(runtime.anyio, "run", lambda fn, *args: fake_run(*args))
    runtime.run_agent("x", cwd=tmp_path, backend="claude", venv_bin=tmp_path / "bin")

    assert seen["env"]["VIRTUAL_ENV"] == str(tmp_path)


def test_the_local_bash_tool_really_runs_the_repo_interpreter(tmp_path):
    """End to end: a workspace with no venv still runs pytest from the original one."""
    workspace = tmp_path / "workspace"
    (workspace / "tests").mkdir(parents=True)
    (workspace / "tests" / "test_ok.py").write_text("def test_ok():\n    assert 1\n")
    venv_bin = Path(sys.executable).parent  # this environment has pytest installed

    output = execute(
        "Bash", {"command": "pytest -q -p no:cacheprovider tests"}, workspace, venv_bin=venv_bin
    )

    assert output.startswith("exit code 0"), output
    assert "1 passed" in output
