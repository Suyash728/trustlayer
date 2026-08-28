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

        return None

    def _evaluate_path(self, tool_name: str, tool_input: dict) -> Denial | None:
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
) -> AgentResult:
    """Run one agent turn-set and return a normalized result.

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
    )


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
) -> AgentResult:
    options = ClaudeAgentOptions(
        cwd=str(cwd),
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
