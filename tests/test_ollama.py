"""Ollama backend tests.

The transport is stubbed so these run with no server. One opt-in test talks to a real
local model and skips when nothing is listening, matching the PyPI precedent elsewhere.

The shapes asserted here were probed from a running server, not remembered - see the
"Ollama API" section of CLAUDE.md. The one that matters most is `message.thinking`:
gpt-oss returns hundreds of characters of reasoning on every turn, and letting it reach
the caller would put the model's scratchpad into a user-facing explanation.
"""

import io
import json
import urllib.error

import pytest

from trustlayer.agent import ollama
from trustlayer.agent.runtime import (
    CLAUDE_BACKEND,
    OLLAMA_BACKEND,
    AgentResult,
    resolve_backend,
)


def respond_with(payload: dict, monkeypatch):
    """Stub /api/chat with a fixed JSON body."""

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(payload).encode()

    monkeypatch.setattr(ollama.urllib.request, "urlopen", lambda *a, **k: _Response())


def fail_with(error: Exception, monkeypatch):
    def explode(*args, **kwargs):
        raise error

    monkeypatch.setattr(ollama.urllib.request, "urlopen", explode)


def turn(content="ok", **extra):
    message = {"role": "assistant", "content": content}
    message.update(extra.pop("message", {}))
    return {"message": message, "done_reason": "stop", **extra}


# ---------------------------------------------------------------- backend selection


def test_claude_is_the_default_and_a_typo_never_reroutes(monkeypatch):
    """A mistyped environment variable must not silently send work to another model."""
    monkeypatch.delenv("TRUSTLAYER_BACKEND", raising=False)

    assert resolve_backend() == CLAUDE_BACKEND
    assert resolve_backend("olama") == CLAUDE_BACKEND
    assert resolve_backend("OLLAMA") == OLLAMA_BACKEND


def test_an_explicit_backend_beats_the_environment(monkeypatch):
    monkeypatch.setenv("TRUSTLAYER_BACKEND", "ollama")

    assert resolve_backend() == OLLAMA_BACKEND
    assert resolve_backend("claude") == CLAUDE_BACKEND


def test_the_model_and_host_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.setenv(ollama.MODEL_ENV, "qwen2.5-coder-agent-32k:latest")
    monkeypatch.setenv(ollama.HOST_ENV, "http://box:9999/")

    assert ollama.default_model() == "qwen2.5-coder-agent-32k:latest"
    assert ollama.host() == "http://box:9999"  # trailing slash trimmed


def test_the_default_model_is_a_tool_capable_agent_variant():
    """The -agent-* builds raise num_ctx in their Modelfile; the server caps it at 4096."""
    assert "agent" in ollama.DEFAULT_MODEL
    assert ollama.supports_tools(ollama.DEFAULT_MODEL)


@pytest.mark.parametrize(
    ("model", "capable"),
    [
        ("gpt-oss-agent-64k:latest", True),
        ("gpt-oss:20b", True),
        ("qwen2.5-coder-agent-32k:latest", False),
        ("qwen2.5-coder:14b-instruct-q4_K_M", False),
        ("gemma3:12b", False),
    ],
)
def test_only_the_gpt_oss_family_is_treated_as_tool_capable(model, capable):
    """qwen emits its call as text. That is a model bug, verified twice - see CLAUDE.md."""
    assert ollama.supports_tools(model) is capable


def test_a_model_that_emits_tool_calls_as_text_is_refused_before_spending_a_call():
    result = ollama.run_ollama(
        "go", model="qwen2.5-coder-agent-32k:latest", allowed_tools=("Read",)
    )

    assert result.ok is False
    assert "does not return structured tool calls" in result.error


# --------------------------------------------------------------------- happy path


def test_content_is_returned_with_tokens_and_duration(monkeypatch):
    respond_with(
        turn("HELLO.", prompt_eval_count=76, eval_count=124, total_duration=1_422_807_537),
        monkeypatch,
    )
    result = ollama.run_ollama("say hello")

    assert result.ok is True
    assert result.text == "HELLO."
    assert result.backend == "ollama"
    assert result.input_tokens == 76
    assert result.output_tokens == 124
    assert result.duration_ms == 1422  # nanoseconds converted, not passed through
    assert result.cost_usd == 0.0  # honest: a local run costs nothing


def test_thinking_is_never_treated_as_answer_text(monkeypatch):
    """gpt-oss returns reasoning alongside the answer. It is not the answer."""
    respond_with(
        turn("The answer is four.", message={"thinking": "Let me reason about this at length..."}),
        monkeypatch,
    )
    result = ollama.run_ollama("what is 2+2")

    assert result.text == "The answer is four."
    assert "reason about this" not in result.text


def test_a_system_prompt_is_sent_as_its_own_message(monkeypatch):
    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(turn("ok")).encode()

    def capture(request, *args, **kwargs):
        captured["body"] = json.loads(request.data)
        return _Response()

    monkeypatch.setattr(ollama.urllib.request, "urlopen", capture)
    ollama.run_ollama("do the thing", system_prompt="you are terse")

    assert captured["body"]["messages"][0] == {"role": "system", "content": "you are terse"}
    assert captured["body"]["messages"][1]["content"] == "do the thing"
    assert captured["body"]["stream"] is False


# ------------------------------------------------------------------ failure paths


def scripted(turns, monkeypatch):
    """Serve a fixed sequence of /api/chat responses, one per turn."""
    remaining = list(turns)
    sent = []

    class _Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    def serve(request, *args, **kwargs):
        sent.append(json.loads(request.data))
        return _Response(remaining.pop(0))

    monkeypatch.setattr(ollama.urllib.request, "urlopen", serve)
    return sent


def tool_turn(name, arguments):
    return {
        "message": {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "function": {"index": 0, "name": name, "arguments": arguments}}
        ]},
        "prompt_eval_count": 10,
        "eval_count": 5,
    }


def test_the_tool_loop_runs_a_permitted_call_and_returns_the_final_answer(tmp_path, monkeypatch):
    (tmp_path / "seed.txt").write_text("the contents")
    sent = scripted(
        [tool_turn("Read", {"file_path": "seed.txt"}), turn("I read it.")], monkeypatch
    )

    result = ollama.run_ollama(
        "read seed.txt", allowed_tools=("Read",), workspace=tmp_path, model="gpt-oss-agent-64k"
    )

    assert result.ok is True
    assert result.text == "I read it."
    assert result.num_turns == 2
    # The tool result was fed back as a tool-role message on the second request.
    roles = [m["role"] for m in sent[1]["messages"]]
    assert roles[-1] == "tool"
    assert sent[1]["messages"][-1]["content"] == "the contents"


def test_the_loop_offers_only_the_permitted_tools(tmp_path, monkeypatch):
    sent = scripted([turn("done")], monkeypatch)

    ollama.run_ollama("go", allowed_tools=("Read", "Bash"), workspace=tmp_path,
                      model="gpt-oss-agent-64k")

    offered = {t["function"]["name"] for t in sent[0]["tools"]}
    assert offered == {"Read", "Bash"}


def test_a_denied_call_is_fed_back_and_the_loop_continues(tmp_path, monkeypatch):
    scripted(
        [tool_turn("Bash", {"command": "git push"}), turn("understood, I will not.")], monkeypatch
    )

    result = ollama.run_ollama(
        "push the code", allowed_tools=("Bash",), workspace=tmp_path, model="gpt-oss-agent-64k"
    )

    assert result.ok is True
    assert len(result.denied) == 1
    assert "only the test runner" in str(result.denied[0])


def test_the_loop_stops_at_the_turn_limit_rather_than_spinning(tmp_path, monkeypatch):
    (tmp_path / "seed.txt").write_text("x")
    scripted([tool_turn("Read", {"file_path": "seed.txt"})] * 4, monkeypatch)

    result = ollama.run_ollama(
        "loop forever", allowed_tools=("Read",), workspace=tmp_path,
        model="gpt-oss-agent-64k", max_turns=3,
    )

    assert result.ok is False
    assert "3-turn limit" in result.error


def test_tokens_accumulate_across_turns(tmp_path, monkeypatch):
    (tmp_path / "seed.txt").write_text("x")
    scripted(
        [
            tool_turn("Read", {"file_path": "seed.txt"}),
            {"message": {"role": "assistant", "content": "done"}, "prompt_eval_count": 40,
             "eval_count": 7},
        ],
        monkeypatch,
    )

    result = ollama.run_ollama(
        "go", allowed_tools=("Read",), workspace=tmp_path, model="gpt-oss-agent-64k"
    )

    assert result.input_tokens == 50  # 10 + 40
    assert result.output_tokens == 12  # 5 + 7


def test_a_model_without_tool_support_reports_what_the_server_said(monkeypatch):
    body = json.dumps({"error": "registry.ollama.ai/library/gemma3:12b does not support tools"})
    fail_with(
        urllib.error.HTTPError("u", 400, "Bad Request", {}, io.BytesIO(body.encode())), monkeypatch
    )
    result = ollama.run_ollama("go")

    assert result.ok is False
    assert "400" in result.error
    assert "does not support tools" in result.error


def test_an_unreachable_server_says_how_to_fix_it(monkeypatch):
    fail_with(urllib.error.URLError("[Errno 111] Connection refused"), monkeypatch)
    result = ollama.run_ollama("go")

    assert result.ok is False
    assert "ollama serve" in result.error


def test_a_timeout_names_the_limit(monkeypatch):
    fail_with(TimeoutError("timed out"), monkeypatch)
    result = ollama.run_ollama("go", timeout=45)

    assert result.ok is False
    assert "45" in result.error


def test_empty_content_is_a_failure_not_an_empty_explanation(monkeypatch):
    respond_with(turn("   "), monkeypatch)
    result = ollama.run_ollama("go")

    assert result.ok is False
    assert "no content" in result.error


def test_a_non_object_payload_is_rejected(monkeypatch):
    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'["not", "an", "object"]'

    monkeypatch.setattr(ollama.urllib.request, "urlopen", lambda *a, **k: _Response())
    result = ollama.run_ollama("go")

    assert result.ok is False
    assert "non-object" in result.error


def test_a_missing_duration_falls_back_to_what_we_timed(monkeypatch):
    respond_with(turn("ok"), monkeypatch)
    result = ollama.run_ollama("go")

    assert result.ok is True
    assert result.duration_ms >= 0


# ------------------------------------------------------------------- integration


def test_run_agent_routes_to_ollama_without_touching_the_claude_path(monkeypatch):
    from trustlayer.agent import runtime

    monkeypatch.setattr(
        ollama, "run_ollama", lambda *a, **k: AgentResult(ok=True, text="local", backend="ollama")
    )

    def explode(*args, **kwargs):
        raise AssertionError("the claude path must not run when the ollama backend is selected")

    monkeypatch.setattr(runtime.anyio, "run", explode)
    result = runtime.run_agent("go", cwd=".", allowed_tools=(), backend="ollama")

    assert result.backend == "ollama"
    assert result.text == "local"


def test_the_explanation_carries_its_attribution():
    from trustlayer.explain import Explanation

    local = Explanation("prose", "ollama", "gpt-oss-agent-32k:latest", 646, 466, 17300)
    remote = Explanation("prose", "claude", "claude-opus-5")

    assert "646->466 tokens" in local.attribution
    assert "17.3s" in local.attribution
    assert "changed no score" in local.attribution and "changed no score" in remote.attribution
    assert "claude-opus-5" in remote.attribution


@pytest.mark.parametrize("model", [ollama.DEFAULT_MODEL])
def test_a_real_local_model_answers(model):
    """Opt-in: skips when nothing is listening on the Ollama port."""
    result = ollama.run_ollama(
        "Reply with exactly the word READY and nothing else.", model=model, timeout=180
    )
    if not result.ok and "unreachable" in (result.error or ""):
        pytest.skip("ollama not running")

    assert result.ok is True, result.error
    assert result.output_tokens > 0
    assert result.model == model
