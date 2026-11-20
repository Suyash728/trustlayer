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
  silently is not something to build a loop on.

  **Updated 2026-11-20** (probed on Ollama 0.40.16): the tool path is no longer gated on a
  model-name prefix. `POST /api/show` reports `capabilities` (contains `"tools"` when the
  model's template supports them) and `model_info["<arch>.context_length"]`; that is the
  gate now. qwen3.5 returns structured `tool_calls` in the gpt-oss shape. But "tools" is a
  template claim, not a behaviour guarantee - glm-4-9b advertises it and still writes
  `Read\n{"file_path": ...}` as prose, then invents the file's contents. So a text-emitted
  call is recovered only when the whole reply is exactly one call (see `recover_text_call`),
  and anything that merely *looks* like a call ends the run with an explicit error rather
  than reading as a normal finish.

  This is not a quirk of one probe: the same failure was found independently by a
  controlled A/B test in ~/AI/OPENCODE.md, which traces it to the model's own `<tool_call>`
  tag-wrapping at Q4 quantization and notes it is unaffected by context length.

A local run costs nothing, which makes `cost_usd` useless as a comparison signal. Token
counts and wall-clock duration are reported in its place.
"""

from __future__ import annotations

from dataclasses import dataclass
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

from trustlayer.agent.localtools import execute, schemas_for
from trustlayer.agent.runtime import AgentResult, ToolGate


DEFAULT_HOST = "http://localhost:11434"
# The stock upstream tag, so the default means the same thing on every machine
# (`ollama pull gpt-oss:20b`). The context-raised `-agent-*` builds the default used to name
# are unnecessary now that `num_ctx` is sent explicitly on every request. gpt-oss is a family
# verified to return structured `tool_calls`; any model whose /api/show lists `tools` can be
# chosen with TRUSTLAYER_OLLAMA_MODEL.
DEFAULT_MODEL = "gpt-oss:20b"
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_TURNS = 12

HOST_ENV = "TRUSTLAYER_OLLAMA_HOST"
MODEL_ENV = "TRUSTLAYER_OLLAMA_MODEL"


NUM_CTX_ENV = "TRUSTLAYER_OLLAMA_NUM_CTX"
DEFAULT_NUM_CTX = 32768
# The server default. At this size the tool loop demonstrably fails (CLAUDE.md, 2026-08-28).
MIN_TOOL_NUM_CTX = 4096
SHOW_TIMEOUT_SECONDS = 15

TOOL_CALL_TAG_RE = re.compile(r"^<tool_call>\s*(?P<body>\{.*\})\s*</tool_call>$", re.DOTALL)


@dataclass(frozen=True)
class ModelInfo:
    """What the server says about a model, from `POST /api/show`."""

    tools: bool = False
    context_length: int | None = None  # what the model was trained for
    modelfile_num_ctx: int | None = None  # what its Modelfile asks the server for
    error: str | None = None


def default_model() -> str:
    """TRUSTLAYER_OLLAMA_MODEL, else the stock gpt-oss tag."""
    return os.environ.get(MODEL_ENV) or DEFAULT_MODEL


def installed_tool_models() -> list[str]:
    """Installed models whose /api/show lists `tools`, for an error message - never a choice.

    Nothing is picked automatically: `tools` is a template claim, and glm-4-9b advertises it
    while writing its calls as prose. The user decides; this only shows what there is.
    """
    payload, _ = _get("/api/tags", SHOW_TIMEOUT_SECONDS)
    names = [
        entry.get("name")
        for entry in (payload or {}).get("models") or []
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    ]
    return sorted(name for name in names if fetch_model_info(name).tools)


def _missing_model_hint(model: str, error: str) -> str:
    """Turn the server's 404 into what to do about it."""
    if "404" not in error and "not found" not in error:
        return error
    available = installed_tool_models()
    choice = (
        f"installed models that report tool support: {', '.join(available)}"
        if available
        else "no installed model reports tool support"
    )
    return (
        f"{error}. `ollama pull {model}`, or set {MODEL_ENV} to another model - {choice}"
    )


_INFO_CACHE: dict[tuple[str, str], ModelInfo] = {}


def model_info(model: str) -> ModelInfo:
    """Capabilities for a model, cached per host for the life of the process."""
    key = (host(), model)
    if key not in _INFO_CACHE:
        info = fetch_model_info(model)
        if info.error is not None:
            return info  # an unreachable server is not a fact about the model; never cache it
        _INFO_CACHE[key] = info
    return _INFO_CACHE[key]


def fetch_model_info(model: str) -> ModelInfo:
    payload, error = _post("/api/show", {"model": model}, SHOW_TIMEOUT_SECONDS)
    if payload is None:
        return ModelInfo(error=error)

    capabilities = payload.get("capabilities")
    details = payload.get("model_info") if isinstance(payload.get("model_info"), dict) else {}
    context = next(
        (
            value
            for key, value in details.items()
            if key.endswith(".context_length") and ".rope." not in key and isinstance(value, int)
        ),
        None,
    )
    return ModelInfo(
        tools=isinstance(capabilities, list) and "tools" in capabilities,
        context_length=context,
        modelfile_num_ctx=_modelfile_num_ctx(payload.get("parameters")),
    )


def _modelfile_num_ctx(parameters: object) -> int | None:
    """`parameters` is Modelfile text: one `name value` pair per line."""
    if not isinstance(parameters, str):
        return None
    for line in parameters.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "num_ctx" and parts[1].isdigit():
            return int(parts[1])
    return None


def effective_num_ctx(info: ModelInfo) -> int:
    """The context TrustLayer requests explicitly, so a run never depends on a server default.

    Order: TRUSTLAYER_OLLAMA_NUM_CTX, then the model's own Modelfile value (someone tuned it
    for this machine's VRAM), then 32768. Never more than the model was trained for.
    """
    raw = os.environ.get(NUM_CTX_ENV, "").strip()
    chosen = int(raw) if raw.isdigit() else (info.modelfile_num_ctx or DEFAULT_NUM_CTX)
    if info.context_length:
        chosen = min(chosen, info.context_length)
    return chosen


def tool_loop_refusal(model: str, info: ModelInfo) -> str | None:
    """Why this model cannot run a tool loop, or None. Decided before any chat call."""
    if info.error is not None:
        return info.error
    if not info.tools:
        return (
            f"{model} does not support tools: the server's /api/show lists no 'tools' "
            "capability. Pick a model whose capabilities include tools (`ollama show <model>`)"
        )
    num_ctx = effective_num_ctx(info)
    if num_ctx <= MIN_TOOL_NUM_CTX:
        return (
            f"{model} would run with num_ctx={num_ctx}; a tool loop fails at "
            f"{MIN_TOOL_NUM_CTX} or less. Set {NUM_CTX_ENV} higher (the model was trained for "
            f"{info.context_length or 'an unknown length'})"
        )
    return None


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
    venv_bin: Path | None = None,
) -> AgentResult:
    """One local turn-set. Never raises: every failure comes back as `ok=False` with a reason."""
    chosen = model or default_model()

    if allowed_tools:
        info = model_info(chosen)
        if info.error is not None:
            info = ModelInfo(error=_missing_model_hint(chosen, info.error))
        refusal = tool_loop_refusal(chosen, info)
        if refusal is not None:
            return AgentResult(ok=False, backend="ollama", model=chosen, error=refusal)
        return _run_tool_loop(
            prompt,
            model=chosen,
            timeout=timeout,
            system_prompt=system_prompt,
            allowed_tools=allowed_tools,
            workspace=Path(workspace) if workspace else Path.cwd(),
            max_turns=max_turns,
            venv_bin=venv_bin,
            num_ctx=effective_num_ctx(info),
        )

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    started = time.monotonic()
    payload, error = _chat(chosen, messages, timeout)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    if payload is None:
        return AgentResult(
            ok=False, backend="ollama", model=chosen,
            error=_missing_model_hint(chosen, error or ""), duration_ms=elapsed_ms,
        )

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
    model: str,
    messages: list[dict],
    timeout: float,
    tools: list[dict] | None = None,
    num_ctx: int | None = None,
) -> tuple[dict | None, str | None]:
    """POST /api/chat. Returns (payload, error); exactly one is ever set."""
    request_body: dict = {"model": model, "messages": messages, "stream": False}
    if tools:
        request_body["tools"] = tools
    if num_ctx:
        # Sent explicitly so the run never inherits the server's 4096 default.
        request_body["options"] = {"num_ctx": num_ctx}
    return _post("/api/chat", request_body, timeout)


def _post(path: str, request_body: dict, timeout: float) -> tuple[dict | None, str | None]:
    body = json.dumps(request_body).encode()
    request = urllib.request.Request(
        f"{host()}{path}", data=body, headers={"Content-Type": "application/json"}
    )
    return _send(request, timeout)


def _get(path: str, timeout: float) -> tuple[dict | None, str | None]:
    return _send(urllib.request.Request(f"{host()}{path}"), timeout)


def _send(request: urllib.request.Request, timeout: float) -> tuple[dict | None, str | None]:
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
    venv_bin: Path | None = None,
    num_ctx: int | None = None,
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

    input_tokens = output_tokens = turns = recovered_calls = 0
    text = ""

    for _ in range(max_turns):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _timed_out(model, gate, timeout, turns, input_tokens, output_tokens, text)

        payload, error = _chat(model, messages, remaining, tools=tools, num_ctx=num_ctx)
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
            offered = {tool["function"]["name"] for tool in tools}
            recovered = recover_text_call(content, offered)
            if recovered is not None:
                # Same gate, same executor: recovery changes how a call is read, never
                # whether it is allowed.
                recovered_calls += 1
                calls = [recovered]
            elif looks_like_text_call(content, offered):
                return AgentResult(
                    ok=False, backend="ollama", model=model, num_turns=turns, text=text,
                    error=(
                        f"{model} wrote a tool call as text that is not exactly one call, so "
                        "it was not executed; a loop cannot tell a lost call from a finished "
                        "task. Use a model that returns structured tool_calls"
                    ),
                    denied=gate.denied, input_tokens=input_tokens, output_tokens=output_tokens,
                    recovered_text_calls=recovered_calls,
                )
            else:
                return AgentResult(
                    ok=True, text=text, backend="ollama", model=model, num_turns=turns,
                    cost_usd=0.0, denied=gate.denied, stop_reason=payload.get("done_reason"),
                    input_tokens=input_tokens, output_tokens=output_tokens,
                    duration_ms=int((time.monotonic() - (deadline - timeout)) * 1000),
                    recovered_text_calls=recovered_calls,
                )

        messages.append(message)  # the assistant turn must be echoed back verbatim
        for call in calls if isinstance(calls, list) else []:
            messages.append(_handle_call(call, gate, workspace, venv_bin))

    return AgentResult(
        ok=False, backend="ollama", model=model, num_turns=turns, text=text,
        error=f"reached the {max_turns}-turn limit without finishing",
        denied=gate.denied, input_tokens=input_tokens, output_tokens=output_tokens,
        recovered_text_calls=recovered_calls,
    )


def _handle_call(
    call: object, gate: ToolGate, workspace: Path, venv_bin: Path | None = None
) -> dict:
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

    return _tool_message(name, execute(name, arguments, workspace, venv_bin=venv_bin))


def recover_text_call(content: object, offered: set[str]) -> dict | None:
    """A tool call the model wrote as text, recovered only when there is no ambiguity.

    Accepted: the entire reply is exactly one JSON object `{"name": ..., "arguments": {...}}`
    (optionally inside one ```json fence or one <tool_call>...</tool_call> tag), naming a tool
    this run offered. Anything else - prose around it, two calls, an unknown name, arguments
    that are not an object - is not a call. The result is shaped like a structured call so it
    reaches `ToolGate` through exactly the same path.
    """
    if not isinstance(content, str):
        return None
    body = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", body, re.DOTALL)
    tagged = TOOL_CALL_TAG_RE.fullmatch(body)
    if fenced:
        body = fenced.group(1)
    elif tagged:
        body = tagged.group("body")
    if not (body.startswith("{") and body.endswith("}")):
        return None
    try:
        decoded = json.loads(body)
    except ValueError:
        return None
    if not isinstance(decoded, dict) or set(decoded) - {"name", "arguments"}:
        return None
    name, arguments = decoded.get("name"), decoded.get("arguments")
    if not isinstance(name, str) or name not in offered or not isinstance(arguments, dict):
        return None
    return {"function": {"name": name, "arguments": arguments}}


def looks_like_text_call(content: object, offered: set[str]) -> bool:
    """A reply that mentions a call it did not make cleanly. Never executed; it ends the run.

    Deliberately broad, because the cost of a false alarm here is a failed run that says
    why, while the cost of a miss is a silent loop that "finishes" without doing anything.
    """
    if not isinstance(content, str) or not content.strip():
        return False
    if "<tool_call>" in content or ('"name"' in content and '"arguments"' in content):
        return True
    return any(re.search(rf"(?m)^\s*{re.escape(name)}\s*\n?\s*\{{", content) for name in offered)


def _tool_message(name: str, content: str) -> dict:
    return {"role": "tool", "content": content, "tool_name": name}


def _timed_out(model, gate, timeout, turns, input_tokens, output_tokens, text) -> AgentResult:
    return AgentResult(
        ok=False, backend="ollama", model=model, num_turns=turns, text=text,
        error=f"the local agent ran out of time after {timeout}s",
        denied=gate.denied, input_tokens=input_tokens, output_tokens=output_tokens,
    )
