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
import time
import urllib.error
import urllib.request

from trustlayer.agent.runtime import AgentResult


DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "gpt-oss-agent-64k:latest"
DEFAULT_TIMEOUT_SECONDS = 300

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
) -> AgentResult:
    """One local turn. Never raises: every failure comes back as `ok=False` with a reason."""
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
        # Staged deliberately. The gate must be enforced identically for a local model, and
        # that is the tool-loop stage - not something to half-do here.
        return AgentResult(
            ok=False,
            backend="ollama",
            model=chosen,
            error=(
                "the ollama backend has no tool loop yet; it currently serves the no-tool "
                "path only (`deps --explain`)"
            ),
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


def _chat(model: str, messages: list[dict], timeout: float) -> tuple[dict | None, str | None]:
    """POST /api/chat. Returns (payload, error); exactly one is ever set."""
    body = json.dumps({"model": model, "messages": messages, "stream": False}).encode()
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
