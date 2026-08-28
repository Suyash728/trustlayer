"""Tool schemas and executors for a local model.

The Claude backend gets its tools from the `claude` CLI. A local model has none, so they are
implemented here - and the names and argument keys deliberately match Claude's exactly
(`Read(file_path)`, `Write(file_path, content)`, `Bash(command)`). That is not cosmetic:
`ToolGate.evaluate` keys its policy on those names and on `PATH_ARGUMENT_KEYS`, so matching
them means one policy governs both backends with no translation layer to drift.

Nothing here decides whether a call is allowed. The gate does that, before any function in
this module is reached. These are the hands, not the judgement.

Two safety properties are enforced here anyway, because defence in depth costs little:
every path is resolved against the workspace and rejected if it escapes, and `Bash` is split
with `shlex` and run without a shell - the gate has already established the command contains
no shell metacharacters, so there is nothing a shell would add except risk.
"""

from __future__ import annotations

from pathlib import Path
import re
import shlex

from trustlayer.checks.base import run_tool


BASH_TIMEOUT_SECONDS = 600
MAX_OUTPUT_CHARS = 60_000
MAX_MATCHES = 200

# Shapes match Claude's tools so ToolGate needs no translation. Descriptions are terse on
# purpose: a local model pays for every schema token out of its context budget.
TOOL_SCHEMAS = {
    "Read": {
        "name": "Read",
        "description": "Read a file from the workspace.",
        "parameters": {
            "type": "object",
            "properties": {"file_path": {"type": "string", "description": "Path to the file"}},
            "required": ["file_path"],
        },
    },
    "Write": {
        "name": "Write",
        "description": "Write a file, replacing it if it exists.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
                "content": {"type": "string", "description": "Full contents to write"},
            },
            "required": ["file_path", "content"],
        },
    },
    "Edit": {
        "name": "Edit",
        "description": "Replace an exact string in a file. The old string must appear exactly once.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
            },
            "required": ["file_path", "old_string", "new_string"],
        },
    },
    "Glob": {
        "name": "Glob",
        "description": "List workspace files matching a glob pattern, e.g. 'tests/*.py'.",
        "parameters": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
            "required": ["pattern"],
        },
    },
    "Grep": {
        "name": "Grep",
        "description": "Search workspace files for a regular expression.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "path": {"type": "string", "description": "Optional subdirectory to search"},
            },
            "required": ["pattern"],
        },
    },
    "Bash": {
        "name": "Bash",
        "description": "Run the test runner. Only pytest may be invoked.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
}


def schemas_for(allowed_tools) -> list[dict]:
    """Ollama's `tools` payload for the tools this run permits.

    Anything the caller did not allow is never described to the model, so it has no reason to
    reach for it - the gate would deny it anyway, but an undescribed tool is not attempted.
    """
    return [
        {"type": "function", "function": TOOL_SCHEMAS[name]}
        for name in allowed_tools
        if name in TOOL_SCHEMAS
    ]


class ToolError(Exception):
    """A tool could not do what was asked. Reported to the model, never raised at the caller."""


def execute(name: str, arguments: dict, workspace: Path) -> str:
    """Run one already-permitted tool call and return what the model should see."""
    handler = _HANDLERS.get(name)
    if handler is None:
        return f"error: no tool named {name!r}"
    try:
        return _truncate(handler(arguments, workspace))
    except ToolError as error:
        return f"error: {error}"
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return f"error: {type(error).__name__}: {error}"


def resolve_inside(raw: object, workspace: Path) -> Path:
    """Resolve a path against the workspace, refusing anything that escapes it.

    The gate already checks this. Doing it again here means a future caller that forgets the
    gate still cannot write outside the temp copy.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ToolError("a path is required")
    candidate = Path(raw)
    root = workspace.resolve()
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise ToolError(f"path escapes the workspace: {resolved}")
    return resolved


def _read(arguments: dict, workspace: Path) -> str:
    path = resolve_inside(arguments.get("file_path"), workspace)
    if not path.is_file():
        raise ToolError(f"no such file: {_relative(path, workspace)}")
    return path.read_text(encoding="utf-8")


def _write(arguments: dict, workspace: Path) -> str:
    path = resolve_inside(arguments.get("file_path"), workspace)
    content = arguments.get("content")
    if not isinstance(content, str):
        raise ToolError("content must be a string")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} characters to {_relative(path, workspace)}"


def _edit(arguments: dict, workspace: Path) -> str:
    path = resolve_inside(arguments.get("file_path"), workspace)
    old, new = arguments.get("old_string"), arguments.get("new_string")
    if not isinstance(old, str) or not isinstance(new, str):
        raise ToolError("old_string and new_string must both be strings")
    if not path.is_file():
        raise ToolError(f"no such file: {_relative(path, workspace)}")

    source = path.read_text(encoding="utf-8")
    occurrences = source.count(old)
    if occurrences == 0:
        raise ToolError("old_string does not appear in the file")
    if occurrences > 1:
        raise ToolError(f"old_string appears {occurrences} times; it must be unique")

    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    return f"edited {_relative(path, workspace)}"


def _glob(arguments: dict, workspace: Path) -> str:
    pattern = arguments.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        raise ToolError("a pattern is required")
    root = workspace.resolve()
    matches = sorted(
        _relative(path, workspace)
        for path in root.glob(pattern)
        if path.is_file() and (root in path.resolve().parents or path.resolve() == root)
    )
    return "\n".join(matches[:MAX_MATCHES]) or "no files matched"


def _grep(arguments: dict, workspace: Path) -> str:
    pattern = arguments.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ToolError("a pattern is required")
    try:
        expression = re.compile(pattern)
    except re.error as error:
        raise ToolError(f"bad regular expression: {error}") from error

    base = resolve_inside(arguments.get("path") or ".", workspace)
    hits: list[str] = []
    for path in sorted(base.rglob("*") if base.is_dir() else [base]):
        if not path.is_file() or ".venv" in path.parts or ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if expression.search(line):
                hits.append(f"{_relative(path, workspace)}:{number}:{line.strip()}")
                if len(hits) >= MAX_MATCHES:
                    return "\n".join(hits)
    return "\n".join(hits) or "no matches"


def _bash(arguments: dict, workspace: Path) -> str:
    command = arguments.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ToolError("a command is required")

    # The gate has already established there are no shell metacharacters, so splitting and
    # running without a shell loses nothing and removes an entire class of surprise.
    try:
        argv = shlex.split(command)
    except ValueError as error:
        raise ToolError(f"could not parse command: {error}") from error
    if not argv:
        raise ToolError("empty command")

    outcome = run_tool(argv, cwd=workspace, timeout=BASH_TIMEOUT_SECONDS)
    if outcome.error:
        return f"error: {outcome.error}"
    body = (outcome.stdout + outcome.stderr).strip() or "(no output)"
    return f"exit code {outcome.returncode}\n{body}"


def _relative(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return str(path)


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + f"\n... truncated at {MAX_OUTPUT_CHARS} characters"


_HANDLERS = {
    "Read": _read,
    "Write": _write,
    "Edit": _edit,
    "Glob": _glob,
    "Grep": _grep,
    "Bash": _bash,
}
