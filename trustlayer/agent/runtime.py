"""Agent runtime, built on claude-agent-sdk 0.2.128.

Verified against the installed SDK rather than remembered signatures:

- `query()` is an async generator (`inspect.isasyncgenfunction` is True) with
  keyword-only arguments. You iterate it; awaiting it yields nothing.
- `ClaudeAgentOptions` has no timeout field (`load_timeout_ms` covers loading only), so
  the `timeout` argument here is a cancel scope this module owns.
- `allowed_tools` is joined with commas and forwarded to the `claude` CLI as
  `--allowedTools`; the SDK itself enforces nothing.
- `can_use_tool` is NOT sufficient on its own. The SDK skips it entirely when an
  `allowed_tools` entry allows a whole tool, because that auto-approves the call first
  (CanUseToolShadowedWarning). Verified against a live agent. The enforcement point is
  therefore a **PreToolUse hook**, which is consulted for every call; both share
  `ToolGate.evaluate`, so there is one policy with two entry points.
- `can_use_tool` requires streaming mode: a plain string prompt raises
  "can_use_tool callback requires streaming mode", so the prompt is wrapped in an
  AsyncIterable.

The agent's job is to write tests. It has no business making network calls or touching
git, so the gate is a positive allowlist, not a blocklist.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shlex
import time
import warnings

import anyio
from claude_agent_sdk import (
    AssistantMessage,
    CanUseToolShadowedWarning,
    ClaudeAgentOptions,
    CLINotFoundError,
    HookMatcher,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    TextBlock,
    ToolPermissionContext,
    query,
)


DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_MAX_TURNS = 12
DEFAULT_MAX_BUDGET_USD = 2.0
DEFAULT_MODEL = "claude-opus-5"

# Backends. "claude" stays the default; the local path is opt-in, per invocation or via
# the environment, and never becomes the default by accident.
CLAUDE_BACKEND = "claude"
OLLAMA_BACKEND = "ollama"
BACKENDS = (CLAUDE_BACKEND, OLLAMA_BACKEND)
BACKEND_ENV = "TRUSTLAYER_BACKEND"

# File tools the agent needs to read code and write tests, plus Bash for the test runner.
FILE_TOOLS = ("Read", "Write", "Edit", "Glob", "Grep")
DEFAULT_ALLOWED_TOOLS = (*FILE_TOOLS, "Bash")

# Never permitted, whatever the caller passes. These are the network reach.
ALWAYS_DENIED = frozenset(
    {
        "WebSearch",
        "WebFetch",
        "web_search",
        "web_fetch",
        "advisor",
        "code_execution",
        "bash_code_execution",
        "text_editor_code_execution",
        "tool_search_tool_regex",
        "tool_search_tool_bm25",
        "NotebookEdit",
        "Task",
    }
)

# A second command can be chained with any of these, so a command containing one is not a
# bare test-runner invocation no matter what it starts with.
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", "${", ">", "<", "\n", "\r", "&")

# Positive match: optional interpreter prefix, optional path prefix, then pytest.
TEST_RUNNER_RE = re.compile(
    r"^\s*(?:(?:[\w./+-]*/)?python[\d.]*\s+-m\s+)?(?:[\w./+-]*/)?pytest(?:\s|$)"
)

PATH_ARGUMENT_KEYS = ("file_path", "path", "notebook_path")

# pytest options a test-writing agent needs, and nothing that writes a file, loads code, or
# reaches the network. Everything else is denied: `--pastebin` uploads output to a paste
# service, `--junitxml`/`--basetemp`/`--debug`/`--log-file`/`-o cache_dir=` write wherever
# they are pointed, `-p <plugin>`/`-W <category>`/`-c`/`--rootdir` load or relocate code.
PYTEST_FLAGS = frozenset(
    {
        "-q", "-qq", "-v", "-vv", "-vvv", "-x", "-s", "-l",
        "--quiet", "--verbose", "--exitfirst", "--showlocals", "--no-header", "--no-summary",
        "--lf", "--last-failed", "--ff", "--failed-first", "--sw", "--stepwise",
        "--co", "--collect-only", "--strict-markers", "--disable-warnings", "--runxfail",
    }
)
PYTEST_VALUE_OPTIONS = {
    "-k": None,  # any expression; it selects tests, it cannot load or write anything
    "-m": None,
    "--tb": {"auto", "long", "short", "line", "native", "no"},
    "--capture": {"fd", "sys", "no", "tee-sys"},
    "--color": {"yes", "no", "auto"},
    "--maxfail": "int",
    "--durations": "int",
    "-n": "int",  # pytest-xdist worker count
    "-p": "no:",  # only disabling a plugin, never loading one
    "-r": "chars",
}
COMBINABLE_SHORT_FLAGS = set("qvxsl")

# The SDK warns that can_use_tool is shadowed by whole-tool allowlist entries. That is
# true and intended here: the PreToolUse hook is the enforcement point and is consulted
# for every call. Leaving the warning visible would imply the gate is off, which it isn't.
warnings.filterwarnings("ignore", category=CanUseToolShadowedWarning)


@dataclass(frozen=True)
class Denial:
    tool: str
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.tool}: {self.reason}" + (f" ({self.detail})" if self.detail else "")


@dataclass
class AgentResult:
    ok: bool
    text: str = ""
    session_id: str | None = None
    num_turns: int = 0
    cost_usd: float | None = None
    duration_ms: int = 0
    stop_reason: str | None = None
    denied: list[Denial] = field(default_factory=list)
    error: str | None = None
    # A local run costs nothing, so cost_usd stops being a usable comparison signal.
    # Tokens and duration are what a local backend reports in its place.
    backend: str = "claude"
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    # Local backend only: calls a model wrote as text and the loop recovered unambiguously.
    # Reported so a run that leaned on recovery is distinguishable from a clean one.
    recovered_text_calls: int = 0


class ToolGate:
    """In-process permission gate. This is the enforced boundary, not `allowed_tools`."""

    def __init__(self, allowed_tools: tuple[str, ...] | list[str], workspace: Path | None = None):
        self.allowed = {name.split("(", 1)[0] for name in allowed_tools}
        self.workspace = workspace.resolve() if workspace else None
        self.denied: list[Denial] = []

    async def __call__(
        self, tool_name: str, tool_input: dict, context: ToolPermissionContext
    ) -> PermissionResultAllow | PermissionResultDeny:
        denial = self.evaluate(tool_name, tool_input)
        if denial is None:
            return PermissionResultAllow()
        self.denied.append(denial)
        return PermissionResultDeny(message=str(denial))

    async def hook(self, input_data: dict, tool_use_id: str | None, context: object) -> dict:
        """PreToolUse hook - the actual enforcement point.

        `can_use_tool` alone is not enough: the SDK raises CanUseToolShadowedWarning and
        skips the callback entirely when an `allowed_tools` entry allows a whole tool,
        which auto-approves it first. A PreToolUse hook is consulted for every call, so
        this is what genuinely stops the agent, and it shares `evaluate()` with the
        callback so both paths enforce one policy.
        """
        denial = self.evaluate(
            str(input_data.get("tool_name", "")), input_data.get("tool_input") or {}
        )
        if denial is None:
            return {}
        self.denied.append(denial)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": str(denial),
            }
        }

    def evaluate(self, tool_name: str, tool_input: dict) -> Denial | None:
        """Synchronous core, so the policy is testable without an event loop."""
        if tool_name in ALWAYS_DENIED:
            return Denial(tool_name, "network and delegation tools are never permitted")

        if tool_name not in self.allowed:
            return Denial(tool_name, "not in the allowed tool list")

        if tool_name == "Bash":
            return self._evaluate_bash(tool_input)

        return self._evaluate_path(tool_name, tool_input)

    def _evaluate_bash(self, tool_input: dict) -> Denial | None:
        command = str(tool_input.get("command", "")).strip()
        if not command:
            return Denial("Bash", "empty command")

        found = [token for token in SHELL_METACHARACTERS if token in command]
        if found:
            return Denial(
                "Bash",
                "shell metacharacters could chain a second command",
                f"found {found[0]!r} in {command!r}",
            )

        if not TEST_RUNNER_RE.match(command):
            return Denial("Bash", "only the test runner may be invoked", f"got {command!r}")

        try:
            tokens = shlex.split(command)
        except ValueError as error:
            return Denial("Bash", "command could not be parsed", str(error))
        # TEST_RUNNER_RE has established the shape: `pytest ...` or `python -m pytest ...`.
        arguments = tokens[3:] if tokens and tokens[0].rsplit("/", 1)[-1].startswith("python") else tokens[1:]
        problem = _pytest_argument_problem(arguments, self.workspace)
        if problem is not None:
            return Denial("Bash", "pytest argument not permitted", problem)
        return None

    def _evaluate_path(self, tool_name: str, tool_input: dict) -> Denial | None:
        if tool_name == "Glob":
            # A glob pattern is a path too: `/etc/*` or `../../**/*.env` lists files outside.
            pattern = str(tool_input.get("pattern", ""))
            parts = Path(pattern).parts
            if pattern.startswith(("/", "~")) or Path(pattern).is_absolute() or ".." in parts:
                return Denial(tool_name, "glob pattern escapes the workspace", pattern)

        if self.workspace is None:
            return None

        for key in PATH_ARGUMENT_KEYS:
            raw = tool_input.get(key)
            if not raw:
                continue
            try:
                target = Path(str(raw))
                resolved = (target if target.is_absolute() else self.workspace / target).resolve()
            except (OSError, RuntimeError):
                return Denial(tool_name, "unreadable path", str(raw))
            if resolved != self.workspace and self.workspace not in resolved.parents:
                return Denial(tool_name, "path escapes the workspace", str(resolved))
        return None


def _pytest_argument_problem(arguments: list[str], workspace: Path | None) -> str | None:
    """Why a pytest argument list is not allowed, or None when every argument is safe."""
    index = 0
    while index < len(arguments):
        token = arguments[index]
        index += 1
        if not token.startswith("-") or token == "-":
            problem = _test_path_problem(token, workspace)
            if problem is not None:
                return problem
            continue
        if token in PYTEST_FLAGS:
            continue

        name, has_inline, inline = token.partition("=")
        if name.startswith("-") and not name.startswith("--") and len(name) > 2 and not has_inline:
            # `-ra`, `-k expr` glued as `-kexpr`, or combined flags like `-qx`.
            head, rest = name[:2], name[2:]
            if head in PYTEST_VALUE_OPTIONS:
                name, has_inline, inline = head, "=", rest
            elif all(char in COMBINABLE_SHORT_FLAGS for char in name[1:]):
                continue
        if name not in PYTEST_VALUE_OPTIONS:
            return f"option {token!r} is not on the allowlist"
        if has_inline:
            value = inline
        else:
            if index >= len(arguments):
                return f"option {name!r} needs a value"
            value = arguments[index]
            index += 1
        problem = _option_value_problem(name, value)
        if problem is not None:
            return problem
    return None


def _option_value_problem(name: str, value: str) -> str | None:
    rule = PYTEST_VALUE_OPTIONS[name]
    if rule is None:
        return None
    if rule == "int":
        return None if value.isdigit() else f"{name} takes a number, got {value!r}"
    if rule == "no:":
        return None if value.startswith("no:") else f"{name} may only disable a plugin (no:...)"
    if rule == "chars":
        return None if value.isalpha() else f"{name} takes report characters, got {value!r}"
    return None if value in rule else f"{name} does not accept {value!r}"


def _test_path_problem(token: str, workspace: Path | None) -> str | None:
    """A positional argument is a test path, optionally with a `::node` id. Keep it inside."""
    path_part = token.split("::", 1)[0]
    if not path_part:
        return f"empty test path in {token!r}"
    if path_part.startswith("~") or "$" in path_part:
        return f"test path {token!r} expands outside the workspace"
    candidate = Path(path_part)
    if workspace is None:
        if candidate.is_absolute() or ".." in candidate.parts:
            return f"test path {token!r} is not relative to the workspace"
        return None
    try:
        resolved = (candidate if candidate.is_absolute() else workspace / candidate).resolve()
    except (OSError, RuntimeError):
        return f"unreadable test path {token!r}"
    if resolved != workspace and workspace not in resolved.parents:
        return f"test path {token!r} escapes the workspace"
    return None


def resolve_backend(backend: str | None = None) -> str:
    """Explicit argument wins, then TRUSTLAYER_BACKEND, then Claude.

    An unrecognised name falls back to Claude rather than failing: a typo in an environment
    variable must not silently route work to a different model.
    """
    chosen = (backend or os.environ.get(BACKEND_ENV) or CLAUDE_BACKEND).strip().lower()
    return chosen if chosen in BACKENDS else CLAUDE_BACKEND


def run_agent(
    prompt: str,
    cwd: Path | str,
    allowed_tools: tuple[str, ...] | list[str] = DEFAULT_ALLOWED_TOOLS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    model: str | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float = DEFAULT_MAX_BUDGET_USD,
    system_prompt: str | None = None,
    backend: str | None = None,
    venv_bin: Path | None = None,
) -> AgentResult:
    """Run one agent turn-set and return a normalized result.

    `venv_bin` is the ORIGINAL repository's `.venv/bin`. The workspace copy has no venv, so
    without it the agent's own `pytest` runs resolve from $PATH - the wrong interpreter, or
    none - and the model is fed ImportErrors as if they were feedback on its tests.

    Never raises for agent-side failures: a timeout, a missing CLI, or a crash all come
    back as `ok=False` with `error` set, because the callers are loops that must keep
    their own accounting.

    The backend changes which model runs, never what it is allowed to do: `ToolGate` is the
    policy for both, so the denial matrix in `tests/test_agent.py` covers each of them.
    """
    if resolve_backend(backend) == OLLAMA_BACKEND:
        # Imported here so runtime.py stays importable without the local path, and so the
        # two modules do not form a cycle - ollama.py imports AgentResult from here.
        from trustlayer.agent.ollama import run_ollama

        return run_ollama(
            prompt,
            model=model,
            timeout=timeout,
            system_prompt=system_prompt,
            allowed_tools=allowed_tools,
            workspace=Path(cwd),
            max_turns=max_turns,
            venv_bin=venv_bin,
        )

    gate = ToolGate(allowed_tools, workspace=Path(cwd))
    return anyio.run(
        _run,
        prompt,
        Path(cwd),
        list(allowed_tools),
        timeout,
        model or DEFAULT_MODEL,
        max_turns,
        max_budget_usd,
        system_prompt,
        gate,
        venv_environment(venv_bin),
    )


def venv_bin_for(repository: Path | None) -> Path | None:
    """The original repository's venv `bin/`. absolute(), never resolve(): resolving the
    python symlink drops the venv's site-packages."""
    if repository is None:
        return None
    for candidate in (Path(repository) / ".venv" / "bin", Path(repository) / "venv" / "bin"):
        if (candidate / "python").is_file():
            return candidate.absolute()
    return None


def venv_environment(venv_bin: Path | None) -> dict[str, str]:
    """Environment overrides that make `pytest` in the agent's shell mean the repo's own."""
    if venv_bin is None:
        return {}
    return {
        "PATH": f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        "VIRTUAL_ENV": str(venv_bin.parent),
    }


async def _stream(prompt: str) -> AsyncIterator[dict]:
    """One user message, in the shape query() documents for streaming mode."""
    yield {
        "type": "user",
        "message": {"role": "user", "content": prompt},
        "parent_tool_use_id": None,
        "session_id": "default",
    }


async def _run(
    prompt: str,
    cwd: Path,
    allowed_tools: list[str],
    timeout: float,
    model: str,
    max_turns: int,
    max_budget_usd: float,
    system_prompt: str | None,
    gate: ToolGate,
    env: dict[str, str] | None = None,
) -> AgentResult:
    options = ClaudeAgentOptions(
        cwd=str(cwd),
        env=env or {},
        allowed_tools=allowed_tools,
        disallowed_tools=sorted(ALWAYS_DENIED),
        can_use_tool=gate,
        # The hook is the real boundary; can_use_tool is skipped whenever an
        # allowed_tools entry allows a whole tool (CanUseToolShadowedWarning).
        hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[gate.hook])]},
        permission_mode="default",
        model=model,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        system_prompt=system_prompt,
        setting_sources=None,  # ignore the user's own settings; this run is self-contained
    )

    result = AgentResult(ok=False, backend=CLAUDE_BACKEND, model=model)
    chunks: list[str] = []
    started = time.monotonic()

    try:
        with anyio.fail_after(timeout):
            # can_use_tool requires streaming mode: passing a plain string raises
            # "can_use_tool callback requires streaming mode". The gate is the enforced
            # security boundary, so the prompt is wrapped rather than the gate dropped.
            async for message in query(prompt=_stream(prompt), options=options):
                if isinstance(message, AssistantMessage):
                    chunks.extend(
                        block.text for block in message.content if isinstance(block, TextBlock)
                    )
                elif isinstance(message, ResultMessage):
                    result.ok = not message.is_error
                    result.session_id = message.session_id
                    result.num_turns = message.num_turns
                    result.cost_usd = message.total_cost_usd
                    result.duration_ms = message.duration_ms
                    result.stop_reason = message.stop_reason
                    if message.errors:
                        result.error = "; ".join(message.errors)
    except TimeoutError:
        result.error = f"agent timed out after {timeout}s"
    except CLINotFoundError as error:
        result.error = f"claude CLI not found: {error}"
    except Exception as error:  # noqa: BLE001 - a loop must not die on one bad turn
        result.error = f"{type(error).__name__}: {error}"

    result.text = "\n".join(chunks)
    result.denied = gate.denied
    if not result.duration_ms:
        result.duration_ms = int((time.monotonic() - started) * 1000)
    return result
