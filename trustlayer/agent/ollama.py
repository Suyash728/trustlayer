"""Ollama backend. Local models, same result shape, same gate.

Written against shapes probed from the running server on 2026-08-28, not remembered ones -
see the "Ollama API" section of CLAUDE.md. Two facts from that probe drive this module:

- **`message.thinking` is reasoning, not answer text.** gpt-oss returns hundreds of
  characters of it on every turn. Concatenating it into the result would put the model's
  scratchpad into a user-facing explanation, so only `message.content` is ever read.
- **Tool-call shape differs by model family.** gpt-oss returns a structured
  `message.tool_calls`; qwen2.5-coder returns `tool_calls: None` and emits the call as raw
  JSON text in `message.content`, sometimes inside a fenced block. That is a reliability
  problem rather than a security one - `ToolGate` still evaluates whatever is parsed, so a
  mangled call is denied, not executed - but a client that misses or misreads a call
  silently is not something to build a loop on. The tool path is therefore gpt-oss-only.

  This is not a quirk of one probe: the same failure was found independently by a
  controlled A/B test in ~/AI/OPENCODE.md, which traces it to the model's own `<tool_call>`
  tag-wrapping at Q4 quantization and notes it is unaffected by context length.

A local run costs nothing, which makes `cost_usd` useless as a comparison signal. Token
counts and wall-clock duration are reported in its place.
"""

from __future__ import annotations

from http.client import HTTPException
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

from trustlayer.agent.localtools import execute, schemas_for
from trustlayer.agent.runtime import AgentResult, ToolGate


DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "gpt-oss-agent-64k:latest"
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_TURNS = 12

HOST_ENV = "TRUSTLAYER_OLLAMA_HOST"
MODEL_ENV = "TRUSTLAYER_OLLAMA_MODEL"


# Only this family returns a structured `message.tool_calls`. Everything else emits the
# call as text, which a loop cannot depend on. Verified twice: by probe here, and by the
# A/B test recorded in ~/AI/OPENCODE.md.
TOOL_CAPABLE_PREFIXES = ("gpt-oss",)


def default_model() -> str:
    """The agent-tuned gpt-oss build: structured tool calls and num_ctx raised to 65536.

    The server caps context at 4096 whatever the model was trained for, so the `-agent-*`
    variants exist precisely to raise it in their own Modelfile. 64k is this machine's
    established default for agent work.
    """
    return os.environ.get(MODEL_ENV) or DEFAULT_MODEL


def supports_tools(model: str) -> bool:
    """Whether this model returns tool calls a loop can rely on.

    Decided by family rather than by trying it: a model that emits its call as prose looks
    exactly like a model that chose not to call anything, so a runtime probe cannot tell
    "no tool needed" from "tool call lost".
    """
    bare = model.split("/")[-1]
    return bare.startswith(TOOL_CAPABLE_PREFIXES)


def host() -> str:
    return (os.environ.get(HOST_ENV) or DEFAULT_HOST).rstrip("/")


def run_ollama(
    prompt: str,
    *,
    model: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    system_prompt: str | None = None,
    allowed_tools: tuple[str, ...] | list[str] = (),
    workspace: Path | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
) -> AgentResult:
    """One local turn-set. Never raises: every failure comes back as `ok=False` with a reason."""
    chosen = model or default_model()

    if allowed_tools and not supports_tools(chosen):
        return AgentResult(
            ok=False,
            backend="ollama",
            model=chosen,
            error=(
                f"{chosen} does not return structured tool calls - it emits them as text, "
                f"which a tool loop cannot depend on. Use a {TOOL_CAPABLE_PREFIXES[0]} model "
                f"(default: {DEFAULT_MODEL})"
            ),
        )

    if allowed_tools:
        return _run_tool_loop(
            prompt,
            model=chosen,
            timeout=timeout,
            system_prompt=system_prompt,
            allowed_tools=allowed_tools,
            workspace=Path(workspace) if workspace else Path.cwd(),
            max_turns=max_turns,
        )

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    started = time.monotonic()
    payload, error = _chat(chosen, messages, timeout)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    if payload is None:
        return AgentResult(ok=False, backend="ollama", model=chosen, error=error, duration_ms=elapsed_ms)

    message = payload.get("message") or {}
    # Only `content`. `thinking` is the model's scratchpad and must never reach the caller.
    text = message.get("content")
    if not isinstance(text, str) or not text.strip():
        return AgentResult(
            ok=False,
            backend="ollama",
            model=chosen,
            error="the model returned no content",
            duration_ms=elapsed_ms,
        )

    return AgentResult(
        ok=True,
        text=text.strip(),
        backend="ollama",
        model=chosen,
        num_turns=1,
        cost_usd=0.0,  # honest: a local run costs nothing
        input_tokens=_as_int(payload.get("prompt_eval_count")),
        output_tokens=_as_int(payload.get("eval_count")),
        duration_ms=_duration_ms(payload, elapsed_ms),
        stop_reason=payload.get("done_reason"),
    )


def _chat(
    model: str, messages: list[dict], timeout: float, tools: list[dict] | None = None
) -> tuple[dict | None, str | None]:
    """POST /api/chat. Returns (payload, error); exactly one is ever set."""
    request_body = {"model": model, "messages": messages, "stream": False}
    if tools:
        request_body["tools"] = tools
    body = json.dumps(request_body).encode()
    request = urllib.request.Request(
        f"{host()}/api/chat", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        return None, _http_error(error)
    except TimeoutError:
        return None, f"ollama did not respond within {timeout}s"
    except urllib.error.URLError as error:
        return None, f"ollama unreachable at {host()}: {error.reason} (is `ollama serve` running?)"
    except (HTTPException, OSError, ValueError) as error:
        return None, f"ollama request failed: {error}"

    if not isinstance(payload, dict):
        return None, "ollama returned a non-object payload"
    return payload, None


def _http_error(error: urllib.error.HTTPError) -> str:
    """Ollama reports a missing model or an unsupported capability as a JSON error body."""
    try:
        detail = json.loads(error.read()).get("error")
    except (ValueError, OSError, AttributeError):
        detail = None
    return f"ollama returned HTTP {error.code}" + (f": {detail}" if detail else "")


def _duration_ms(payload: dict, measured: int) -> int:
    """`total_duration` is nanoseconds; fall back to what we timed ourselves."""
    total = payload.get("total_duration")
    return int(total / 1_000_000) if isinstance(total, int | float) and total else measured


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _run_tool_loop(
    prompt: str,
    *,
    model: str,
    timeout: float,
    system_prompt: str | None,
    allowed_tools: tuple[str, ...] | list[str],
    workspace: Path,
    max_turns: int,
) -> AgentResult:
    """Read / write / run pytest, with `ToolGate` consulted before every execution.

    The gate is `ToolGate.evaluate` - the same synchronous policy the Claude backend enforces
    through its PreToolUse hook, called here directly. There is one policy and two call
    sites, which is why `tests/test_agent.py` covers both backends from one matrix.

    A denial is not an error: it is fed back to the model as the tool's result, exactly as
    the Claude path does, so the model can try something permitted instead. Denials are
    recorded on the result either way.
    """
    gate = ToolGate(allowed_tools, workspace=workspace)
    tools = schemas_for(allowed_tools)
    deadline = time.monotonic() + timeout

    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    input_tokens = output_tokens = turns = 0
    text = ""

    for _ in range(max_turns):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _timed_out(model, gate, timeout, turns, input_tokens, output_tokens, text)

        payload, error = _chat(model, messages, remaining, tools=tools)
        if payload is None:
            return AgentResult(
                ok=False, backend="ollama", model=model, error=error,
                num_turns=turns, denied=gate.denied,
                input_tokens=input_tokens, output_tokens=output_tokens,
            )

        turns += 1
        input_tokens += _as_int(payload.get("prompt_eval_count"))
        output_tokens += _as_int(payload.get("eval_count"))
        message = payload.get("message") or {}

        content = message.get("content")
        if isinstance(content, str) and content.strip():
            text = content.strip()  # `thinking` is never read; only content

        calls = message.get("tool_calls")
        if not calls:
            return AgentResult(
                ok=True, text=text, backend="ollama", model=model, num_turns=turns,
                cost_usd=0.0, denied=gate.denied, stop_reason=payload.get("done_reason"),
                input_tokens=input_tokens, output_tokens=output_tokens,
                duration_ms=int((time.monotonic() - (deadline - timeout)) * 1000),
            )

        messages.append(message)  # the assistant turn must be echoed back verbatim
        for call in calls if isinstance(calls, list) else []:
            messages.append(_handle_call(call, gate, workspace))

    return AgentResult(
        ok=False, backend="ollama", model=model, num_turns=turns, text=text,
        error=f"reached the {max_turns}-turn limit without finishing",
        denied=gate.denied, input_tokens=input_tokens, output_tokens=output_tokens,
    )


def _handle_call(call: object, gate: ToolGate, workspace: Path) -> dict:
    """Gate one tool call, run it if permitted, and shape the reply the model expects."""
    function = call.get("function") if isinstance(call, dict) else None
    name = (function or {}).get("name") if isinstance(function, dict) else None
    if not isinstance(name, str):
        return _tool_message("unknown", "error: the tool call had no name")

    # gpt-oss returns `arguments` already decoded. OpenAI's API returns a JSON string there,
    # so accept both rather than trusting one shape.
    raw = (function or {}).get("arguments")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return _tool_message(name, "error: arguments were not valid JSON")
    arguments = raw if isinstance(raw, dict) else {}

    denial = gate.evaluate(name, arguments)
    if denial is not None:
        # `evaluate` is the pure policy function and records nothing - the Claude path
        # appends in its callback and its hook. This is the equivalent call site, so it has
        # to record too, or a local run would deny correctly and report nothing.
        gate.denied.append(denial)
        # Denials are reported to the model, not raised: it can then try something allowed.
        return _tool_message(name, f"denied: {denial}")

    return _tool_message(name, execute(name, arguments, workspace))


def _tool_message(name: str, content: str) -> dict:
    return {"role": "tool", "content": content, "tool_name": name}


def _timed_out(model, gate, timeout, turns, input_tokens, output_tokens, text) -> AgentResult:
    return AgentResult(
        ok=False, backend="ollama", model=model, num_turns=turns, text=text,
        error=f"the local agent ran out of time after {timeout}s",
        denied=gate.denied, input_tokens=input_tokens, output_tokens=output_tokens,
    )
