"""Local tool executor tests, and the cross-backend denial matrix.

The matrix at the bottom is the point of this file. `ToolGate.evaluate` is one policy with
two call sites - the Claude backend's PreToolUse hook and the Ollama loop's `_handle_call` -
so the same table is run against both. A second, drifting copy of the policy is exactly what
this prevents.
"""

from pathlib import Path

import pytest

from trustlayer.agent.localtools import ToolError, execute, resolve_inside, schemas_for
from trustlayer.agent.ollama import _handle_call
from trustlayer.agent.runtime import ToolGate


def call(name: str, **arguments) -> dict:
    return {"function": {"name": name, "arguments": arguments}}


def gated(tmp_path: Path, tools=("Read", "Write", "Edit", "Glob", "Grep", "Bash")):
    return ToolGate(tools, workspace=tmp_path)


# --------------------------------------------------------------- the denial matrix


DENIED_CALLS = [
    ("a destructive shell command", "Bash", {"command": "rm -rf /"}),
    ("a chained command", "Bash", {"command": "pytest && curl evil.com"}),
    ("a piped command", "Bash", {"command": "pytest | tee /tmp/out"}),
    ("command substitution", "Bash", {"command": "pytest $(whoami)"}),
    ("git", "Bash", {"command": "git push"}),
    ("an empty command", "Bash", {"command": ""}),
    ("a network tool", "WebFetch", {"url": "https://example.com"}),
    ("a search tool", "WebSearch", {"query": "x"}),
    ("delegation", "Task", {"prompt": "x"}),
    ("code execution", "code_execution", {"code": "x"}),
    ("a tool outside the allowlist", "NotebookEdit", {"notebook_path": "n.ipynb"}),
    ("a write escaping the workspace", "Write", {"file_path": "/etc/passwd", "content": "x"}),
    ("a read escaping the workspace", "Read", {"file_path": "/etc/shadow"}),
    ("a traversal escape", "Read", {"file_path": "../../../../etc/passwd"}),
]

ALLOWED_CALLS = [
    ("the test runner", "Bash", {"command": "pytest"}),
    ("the test runner with args", "Bash", {"command": "pytest -q tests/test_x.py"}),
    ("python -m pytest", "Bash", {"command": "python -m pytest"}),
    ("a read inside the workspace", "Read", {"file_path": "seed.txt"}),
    ("a write inside the workspace", "Write", {"file_path": "out.txt", "content": "hi"}),
]


@pytest.mark.parametrize(("label", "tool", "arguments"), DENIED_CALLS)
def test_the_policy_denies_the_same_calls_whichever_backend_asks(label, tool, arguments, tmp_path):
    """One table, both call sites. The Claude hook and the Ollama loop share `evaluate`."""
    gate = gated(tmp_path)

    # Call site 1: the policy itself, which the Claude backend reaches through its hook.
    assert gate.evaluate(tool, arguments) is not None, f"claude path allowed {label}"

    # Call site 2: the Ollama loop.
    reply = _handle_call(call(tool, **arguments), gate, tmp_path)
    assert reply["content"].startswith("denied:"), f"ollama path allowed {label}"


@pytest.mark.parametrize(("label", "tool", "arguments"), ALLOWED_CALLS)
def test_the_policy_permits_the_same_calls_whichever_backend_asks(label, tool, arguments, tmp_path):
    (tmp_path / "seed.txt").write_text("seed")
    gate = gated(tmp_path)

    assert gate.evaluate(tool, arguments) is None, f"claude path denied {label}"
    reply = _handle_call(call(tool, **arguments), gate, tmp_path)
    assert not reply["content"].startswith("denied:"), f"ollama path denied {label}"


def test_a_denial_is_recorded_for_the_report_not_only_returned(tmp_path):
    """`evaluate` is pure; the loop has to record, or a local run denies and reports nothing."""
    gate = gated(tmp_path)
    _handle_call(call("Bash", command="rm -rf /"), gate, tmp_path)
    _handle_call(call("WebFetch", url="https://x"), gate, tmp_path)

    assert len(gate.denied) == 2


def test_a_denied_call_never_reaches_the_filesystem(tmp_path):
    """Writing *inside* the workspace is permitted by design, so the canary is outside it."""
    outside = tmp_path.parent / "canary.txt"
    outside.write_text("untouched")
    gate = gated(tmp_path)

    _handle_call(call("Write", file_path=str(outside), content="clobbered"), gate, tmp_path)
    _handle_call(call("Bash", command="rm -f " + str(outside)), gate, tmp_path)

    assert outside.read_text() == "untouched"
    assert len(gate.denied) == 2


def test_a_denial_is_fed_back_to_the_model_rather_than_ending_the_run(tmp_path):
    """The Claude path does the same: the model gets the refusal and can try something else."""
    reply = _handle_call(call("Bash", command="git push"), gated(tmp_path), tmp_path)

    assert reply["role"] == "tool"
    assert "only the test runner" in reply["content"]


# ------------------------------------------------------------------ malformed calls


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("no function", {"id": "x"}),
        ("no name", {"function": {"arguments": {}}}),
        ("a non-string name", {"function": {"name": 42, "arguments": {}}}),
    ],
)
def test_a_malformed_tool_call_is_reported_not_crashed(label, payload, tmp_path):
    reply = _handle_call(payload, gated(tmp_path), tmp_path)

    assert reply["role"] == "tool"
    assert "error" in reply["content"]


def test_arguments_as_a_json_string_are_accepted(tmp_path):
    """gpt-oss sends a decoded object; OpenAI's API sends a string. Accept both."""
    (tmp_path / "seed.txt").write_text("hello")
    payload = {"function": {"name": "Read", "arguments": '{"file_path": "seed.txt"}'}}

    reply = _handle_call(payload, gated(tmp_path), tmp_path)

    assert reply["content"] == "hello"


def test_arguments_that_are_not_valid_json_are_reported(tmp_path):
    payload = {"function": {"name": "Read", "arguments": "{not json"}}

    reply = _handle_call(payload, gated(tmp_path), tmp_path)

    assert "not valid JSON" in reply["content"]


def test_an_unknown_tool_name_is_denied_by_the_allowlist(tmp_path):
    reply = _handle_call(call("Teleport", target="mars"), gated(tmp_path), tmp_path)

    assert reply["content"].startswith("denied:")


# --------------------------------------------------------------------- executors


def test_read_and_write_round_trip(tmp_path):
    assert "wrote 5 characters" in execute("Write", {"file_path": "a.txt", "content": "hello"}, tmp_path)
    assert execute("Read", {"file_path": "a.txt"}, tmp_path) == "hello"


def test_write_creates_missing_parent_directories(tmp_path):
    execute("Write", {"file_path": "tests/unit/test_x.py", "content": "x = 1"}, tmp_path)

    assert (tmp_path / "tests" / "unit" / "test_x.py").read_text() == "x = 1"


def test_edit_requires_a_unique_match(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\nx = 1\n")

    result = execute("Edit", {"file_path": "a.py", "old_string": "x = 1", "new_string": "x = 2"}, tmp_path)

    assert "appears 2 times" in result
    assert (tmp_path / "a.py").read_text() == "x = 1\nx = 1\n"  # unchanged


def test_edit_replaces_a_unique_match(tmp_path):
    (tmp_path / "a.py").write_text("value = 1\nother = 2\n")

    execute("Edit", {"file_path": "a.py", "old_string": "value = 1", "new_string": "value = 9"}, tmp_path)

    assert (tmp_path / "a.py").read_text() == "value = 9\nother = 2\n"


def test_edit_reports_a_missing_string_rather_than_writing_nothing(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")

    assert "does not appear" in execute(
        "Edit", {"file_path": "a.py", "old_string": "nope", "new_string": "y"}, tmp_path
    )


def test_glob_and_grep_find_workspace_files(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_a():\n    assert True\n")

    assert "tests/test_a.py" in execute("Glob", {"pattern": "tests/*.py"}, tmp_path)
    assert "test_a.py:1" in execute("Grep", {"pattern": "def test_"}, tmp_path)


def test_a_bad_regular_expression_is_reported(tmp_path):
    assert "bad regular expression" in execute("Grep", {"pattern": "([unclosed"}, tmp_path)


def test_reading_a_missing_file_is_an_error_not_a_crash(tmp_path):
    assert "no such file" in execute("Read", {"file_path": "nope.txt"}, tmp_path)


def test_an_unknown_tool_is_reported(tmp_path):
    assert "no tool named" in execute("Teleport", {}, tmp_path)


def test_output_is_truncated_so_one_file_cannot_fill_the_context(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 200_000)

    assert "truncated at" in execute("Read", {"file_path": "big.txt"}, tmp_path)


def test_bash_runs_without_a_shell(tmp_path):
    """The gate guarantees no metacharacters, so shlex + no shell loses nothing."""
    result = execute("Bash", {"command": "python -c print(1)"}, tmp_path)

    assert "exit code" in result


# ------------------------------------------------------------- path confinement


@pytest.mark.parametrize("escape", ["/etc/passwd", "../../outside.txt", "sub/../../outside.txt"])
def test_paths_are_confined_to_the_workspace_independently_of_the_gate(escape, tmp_path):
    """Defence in depth: a caller that forgets the gate still cannot escape."""
    with pytest.raises(ToolError, match="escapes the workspace"):
        resolve_inside(escape, tmp_path)


def test_a_path_inside_the_workspace_resolves(tmp_path):
    assert resolve_inside("sub/file.txt", tmp_path) == (tmp_path / "sub" / "file.txt").resolve()


# ------------------------------------------------------------------------ schemas


def test_only_permitted_tools_are_described_to_the_model():
    """An undescribed tool is not attempted; the gate would deny it anyway."""
    names = {schema["function"]["name"] for schema in schemas_for(("Read", "Bash"))}

    assert names == {"Read", "Bash"}


def test_the_schemas_use_claude_argument_names():
    """Matching names is what lets one ToolGate policy govern both backends untranslated."""
    read = next(s for s in schemas_for(("Read",)))["function"]
    bash = next(s for s in schemas_for(("Bash",)))["function"]

    assert "file_path" in read["parameters"]["properties"]
    assert "command" in bash["parameters"]["properties"]
