"""Ollama backend. Local models, same result shape, same gate.

Written against shapes probed from the running server on 2026-08-28, not remembered ones -
see the "Ollama API" section of CLAUDE.md. Two facts from that probe drive this module:

- **`message.thinking` is reasoning, not answer text.** gpt-oss returns hundreds of
  characters of it on every turn. Concatenating it into the result would put the model's
  scratchpad into a user-facing explanation, so only `message.content` is ever read.
- **Tool-call shape differs by model family.** gpt-oss returns a structured
  `message.tool_calls`; qwen2.5-coder returns `tool_calls: None` and emits the call as raw
  JSON text in `message.content`. Recovering a call from free text means parsing prose to
  decide what to execute, which is a poor way to feed a security gate - so the tool-using
  path is gpt-oss-only and is not implemented in this stage.

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
DEFAULT_MODEL = "gpt-oss-agent-32k:latest"
DEFAULT_TIMEOUT_SECONDS = 300

HOST_ENV = "TRUSTLAYER_OLLAMA_HOST"
MODEL_ENV = "TRUSTLAYER_OLLAMA_MODEL"


def default_model() -> str:
    """The agent-tuned gpt-oss build: structured tool calls and num_ctx raised to 32768.

    The stock tags train at a longer context than the server's 4096 default allows, so the
    `-agent-*` variants exist precisely to raise it in their own Modelfile.
    """
    return os.environ.get(MODEL_ENV) or DEFAULT_MODEL


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
