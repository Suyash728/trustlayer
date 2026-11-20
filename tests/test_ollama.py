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

from killscore.agent import ollama
from killscore.agent.runtime import (
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
    monkeypatch.delenv("KILLSCORE_BACKEND", raising=False)

    assert resolve_backend() == CLAUDE_BACKEND
    assert resolve_backend("olama") == CLAUDE_BACKEND
    assert resolve_backend("OLLAMA") == OLLAMA_BACKEND


def test_an_explicit_backend_beats_the_environment(monkeypatch):
    monkeypatch.setenv("KILLSCORE_BACKEND", "ollama")

    assert resolve_backend() == OLLAMA_BACKEND
    assert resolve_backend("claude") == CLAUDE_BACKEND


def test_the_model_and_host_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.setenv(ollama.MODEL_ENV, "qwen2.5-coder-agent-32k:latest")
    monkeypatch.setenv(ollama.HOST_ENV, "http://box:9999/")

    assert ollama.default_model() == "qwen2.5-coder-agent-32k:latest"
    assert ollama.host() == "http://box:9999"  # trailing slash trimmed


@pytest.fixture(autouse=True)
def capable_model(monkeypatch):
    """Every test sees a tool-capable model unless it says otherwise.

    `/api/show` is probed before any tool loop; stubbing it here keeps the scripted
    `/api/chat` queues below one-response-per-turn.
    """
    info = ollama.ModelInfo(tools=True, context_length=131072, modelfile_num_ctx=16384)
    monkeypatch.setattr(ollama, "model_info", lambda model: info)
    monkeypatch.delenv(ollama.NUM_CTX_ENV, raising=False)
    return info


def show_payload(capabilities, context=131072, num_ctx=None, arch="gpt-oss"):
    """The /api/show shape, as probed from Ollama 0.40.16 on 2026-11-20."""
    payload = {
        "capabilities": capabilities,
        "model_info": {
            f"{arch}.context_length": context,
            f"{arch}.rope.scaling.original_context_length": 4096,
        },
        "parameters": "stop                           \"<|end|>\"",
    }
    if num_ctx is not None:
        payload["parameters"] += f"\nnum_ctx                        {num_ctx}"
    return payload


def test_capabilities_and_context_are_read_from_api_show(monkeypatch):
    respond_with(show_payload(["completion", "tools", "thinking"], num_ctx=16384), monkeypatch)

    info = ollama.fetch_model_info("gpt-oss-20b-16k:latest")

    assert info == ollama.ModelInfo(tools=True, context_length=131072, modelfile_num_ctx=16384)


def test_rope_scaling_is_not_mistaken_for_the_context_length(monkeypatch):
    respond_with(show_payload(["tools"], context=131072), monkeypatch)

    assert ollama.fetch_model_info("m").context_length == 131072


def test_a_model_without_the_tools_capability_is_refused_before_any_chat():
    info = ollama.ModelInfo(tools=False, context_length=2048)

    refusal = ollama.tool_loop_refusal("nomic-embed-text", info)
    assert "does not support tools" in refusal


def test_a_missing_model_reports_the_server_error(monkeypatch):
    body = json.dumps({"error": "model 'nope:latest' not found"})
    fail_with(urllib.error.HTTPError("u", 404, "Not Found", {}, io.BytesIO(body.encode())), monkeypatch)

    info = ollama.fetch_model_info("nope:latest")
    assert "404" in info.error and "not found" in info.error


@pytest.mark.parametrize(
    ("env", "modelfile", "trained", "expected"),
    [
        (None, None, 131072, 32768),  # no opinion anywhere: the agent default
        (None, 16384, 131072, 16384),  # the Modelfile was tuned for this machine
        ("65536", 16384, 131072, 65536),  # the environment wins
        ("65536", None, 32768, 32768),  # never beyond what the model was trained for
    ],
)
def test_num_ctx_is_chosen_explicitly(monkeypatch, env, modelfile, trained, expected):
    if env:
        monkeypatch.setenv(ollama.NUM_CTX_ENV, env)
    info = ollama.ModelInfo(tools=True, context_length=trained, modelfile_num_ctx=modelfile)

    assert ollama.effective_num_ctx(info) == expected


def test_a_tool_loop_is_refused_at_the_server_default_context(monkeypatch):
    monkeypatch.setenv(ollama.NUM_CTX_ENV, "4096")
    info = ollama.ModelInfo(tools=True, context_length=131072)

    refusal = ollama.tool_loop_refusal("m", info)
    assert "num_ctx=4096" in refusal


def test_a_refused_model_never_reaches_the_chat_endpoint(monkeypatch, tmp_path):
    monkeypatch.setattr(ollama, "model_info", lambda m: ollama.ModelInfo(tools=False))
    fail_with(AssertionError("chat must not be called"), monkeypatch)

    result = ollama.run_ollama("go", model="gemma3:12b", allowed_tools=("Read",), workspace=tmp_path)

    assert result.ok is False
    assert "does not support tools" in result.error


def test_the_chosen_context_is_sent_on_every_chat(tmp_path, monkeypatch):
    sent = scripted([turn("done")], monkeypatch)

    ollama.run_ollama("go", allowed_tools=("Read",), workspace=tmp_path, model="m")

    assert sent[0]["options"] == {"num_ctx": 16384}


def test_an_unreachable_server_is_not_cached_as_a_fact(monkeypatch):
    monkeypatch.undo()  # use the real model_info for this one
    ollama._INFO_CACHE.clear()
    fail_with(urllib.error.URLError("refused"), monkeypatch)
    assert ollama.model_info("m").error is not None
    assert ollama._INFO_CACHE == {}


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
    from killscore.agent import runtime

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
    from killscore.explain import Explanation

    local = Explanation("prose", "ollama", "gpt-oss-agent-32k:latest", 646, 466, 17300)
    remote = Explanation("prose", "claude", "claude-opus-5")

    assert "646->466 tokens" in local.attribution
    assert "17.3s" in local.attribution
    assert "changed no score" in local.attribution and "changed no score" in remote.attribution
    assert "claude-opus-5" in remote.attribution


@pytest.mark.parametrize("model", [ollama.default_model()])
def test_a_real_local_model_answers(model):
    """Opt-in: skips when nothing is listening on the Ollama port.

    Runs against KILLSCORE_OLLAMA_MODEL when set, else the stock default.
    """
    result = ollama.run_ollama(
        "Reply with exactly the word READY and nothing else.", model=model, timeout=180
    )
    if not result.ok and "unreachable" in (result.error or ""):
        pytest.skip("ollama not running")
    if not result.ok and "not found" in (result.error or ""):
        pytest.skip(f"{model} is not installed on this server")

    assert result.ok is True, result.error
    assert result.output_tokens > 0
    assert result.model == model


# ------------------------------------------------------- text-emitted tool calls


OFFERED = {"Read", "Bash"}


@pytest.mark.parametrize(
    "content",
    [
        '{"name": "Read", "arguments": {"file_path": "a.py"}}',
        '  {"name": "Read", "arguments": {"file_path": "a.py"}}\n',
        '```json\n{"name": "Read", "arguments": {"file_path": "a.py"}}\n```',
        '<tool_call>\n{"name": "Read", "arguments": {"file_path": "a.py"}}\n</tool_call>',
    ],
)
def test_exactly_one_call_is_recovered(content):
    assert ollama.recover_text_call(content, OFFERED) == {
        "function": {"name": "Read", "arguments": {"file_path": "a.py"}}
    }


@pytest.mark.parametrize(
    ("label", "content"),
    [
        ("prose around it", 'Sure! {"name": "Read", "arguments": {"file_path": "a.py"}}'),
        ("two calls", '{"name": "Read", "arguments": {}}\n{"name": "Read", "arguments": {}}'),
        ("a tool not offered", '{"name": "Write", "arguments": {"file_path": "a"}}'),
        ("arguments as a string", '{"name": "Read", "arguments": "a.py"}'),
        ("extra keys", '{"name": "Read", "arguments": {}, "then": "rm -rf /"}'),
        # glm-4-9b on Ollama 0.40.16, verbatim shape: a name line, JSON, then invented output.
        ("glm-4 style", 'Read\n{"file_path": "config.yaml"}\nThe content of the file is: ...'),
        ("plain prose", "I have finished writing the tests."),
    ],
)
def test_anything_ambiguous_is_not_recovered(label, content):
    assert ollama.recover_text_call(content, OFFERED) is None, label


@pytest.mark.parametrize(
    "content",
    [
        'Read\n{"file_path": "config.yaml"}\nThe content of the file is: ...',
        'Sure! {"name": "Read", "arguments": {"file_path": "a.py"}}',
        "<tool_call>broken",
    ],
)
def test_a_garbled_call_is_detected(content):
    assert ollama.looks_like_text_call(content, OFFERED)


@pytest.mark.parametrize(
    "content",
    [
        "I have finished writing the tests.",
        "Read the docstring: it says the function returns a dict.",
        "",
    ],
)
def test_ordinary_prose_is_not_mistaken_for_a_call(content):
    assert not ollama.looks_like_text_call(content, OFFERED)


def test_a_recovered_call_goes_through_the_same_gate(tmp_path, monkeypatch):
    (tmp_path / "seed.txt").write_text("the contents")
    sent = scripted(
        [turn('{"name": "Read", "arguments": {"file_path": "seed.txt"}}'), turn("Read it.")],
        monkeypatch,
    )

    result = ollama.run_ollama("go", allowed_tools=("Read",), workspace=tmp_path, model="m")

    assert result.ok is True
    assert result.recovered_text_calls == 1
    assert sent[1]["messages"][-1] == {
        "role": "tool", "content": "the contents", "tool_name": "Read",
    }


def test_a_recovered_call_can_still_be_denied(tmp_path, monkeypatch):
    scripted(
        [turn('{"name": "Bash", "arguments": {"command": "git push"}}'), turn("ok")],
        monkeypatch,
    )

    result = ollama.run_ollama("go", allowed_tools=("Bash",), workspace=tmp_path, model="m")

    assert result.recovered_text_calls == 1
    assert len(result.denied) == 1


def test_a_garbled_call_ends_the_run_instead_of_reading_as_finished(tmp_path, monkeypatch):
    scripted([turn('Read\n{"file_path": "seed.txt"}\nThe file says hello.')], monkeypatch)

    result = ollama.run_ollama("go", allowed_tools=("Read",), workspace=tmp_path, model="m")

    assert result.ok is False
    assert "not exactly one call" in result.error


@pytest.mark.parametrize("model", [ollama.default_model()])
def test_a_real_local_tool_loop_reads_a_file_through_the_gate(model, tmp_path, monkeypatch):
    """Opt-in, live: one real Read call, through ToolGate, against a real model."""
    monkeypatch.setattr(ollama, "model_info", ollama.fetch_model_info)  # undo the autouse stub
    (tmp_path / "config.py").write_text("secret_value = 4217\n")
    result = ollama.run_ollama(
        "Use the Read tool to read config.py, then reply with only the value of secret_value.",
        model=model, allowed_tools=("Read",), workspace=tmp_path, timeout=300,
    )
    if not result.ok and "unreachable" in (result.error or ""):
        pytest.skip("ollama not running")
    if not result.ok and "not found" in (result.error or ""):
        pytest.skip(f"{model} is not installed on this server")

    assert result.ok is True, result.error
    assert result.num_turns >= 2  # a tool turn, then the answer
    assert "4217" in result.text


def test_a_missing_model_names_what_is_installed(monkeypatch):
    responses = {
        "/api/tags": {"models": [{"name": "qwen3.5-9b:latest"}, {"name": "nomic-embed-text:latest"}]},
    }
    monkeypatch.setattr(ollama, "_get", lambda path, timeout: (responses[path], None))
    monkeypatch.setattr(
        ollama, "fetch_model_info",
        lambda name: ollama.ModelInfo(tools=name.startswith("qwen")),
    )

    hint = ollama._missing_model_hint("gpt-oss:20b", "ollama returned HTTP 404: model 'gpt-oss:20b' not found")

    assert "ollama pull gpt-oss:20b" in hint
    assert ollama.MODEL_ENV in hint
    assert "qwen3.5-9b:latest" in hint and "nomic" not in hint


def test_other_errors_are_passed_through_unchanged():
    assert ollama._missing_model_hint("m", "ollama did not respond within 5s") == (
        "ollama did not respond within 5s"
    )
