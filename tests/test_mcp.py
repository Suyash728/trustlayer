"""`trustlayer mcp`: the checks over stdio JSON-RPC, with stdout reserved for the protocol."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import textwrap
import time

import pytest

from trustlayer import __version__, mcp_server
from trustlayer.checks.runner import DEFAULT_CHECKS


FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ the handlers


def test_audit_returns_findings_with_the_exit_code_and_its_meaning():
    payload = mcp_server.audit_payload(str(FIXTURES / "failopen-dirty"))

    assert payload["exit_code"] == 2
    assert payload["exit_meaning"].startswith("high")
    assert payload["findings"] and all("evidence" in f for f in payload["findings"])
    assert payload["checks_run"] == list(DEFAULT_CHECKS)


def test_audit_can_select_checks_and_threshold():
    payload = mcp_server.audit_payload(
        str(FIXTURES / "models-dirty"), checks=["stale-models"], fail_on="high"
    )

    assert payload["checks_run"] == ["stale-models"]
    assert {f["check"] for f in payload["findings"]} == {"stale-models"}
    assert payload["exit_code"] == 2


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"path": "/definitely/not/here"}, "not a directory"),
        ({"path": str(FIXTURES / "models-clean"), "checks": ["nope"]}, "unknown check"),
        ({"path": str(FIXTURES / "models-clean"), "fail_on": "critical"}, "--fail-on"),
        ({"path": str(FIXTURES / "models-clean"), "warn_expiring_within": "soon"}, "duration"),
    ],
)
def test_a_bad_request_is_exit_three_never_clean(kwargs, message):
    payload = mcp_server.audit_payload(**kwargs)

    assert payload["exit_code"] == 3
    assert message in payload["error"]


def test_a_crashing_check_is_exit_three(monkeypatch):
    from trustlayer.checks import runner

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(runner, "run_checks", explode)
    payload = mcp_server.audit_payload(str(FIXTURES / "models-clean"))

    assert payload["exit_code"] == 3
    assert "boom" in payload["error"]


def test_audit_does_not_record_unless_asked(monkeypatch):
    from trustlayer import store

    monkeypatch.setattr(store, "save_run", lambda *a, **k: pytest.fail("recorded a run"))
    mcp_server.audit_payload(str(FIXTURES / "models-clean"))


def test_deps_is_offline_by_default():
    payload = mcp_server.deps_payload(str(FIXTURES / "slopsquat-clean"))

    assert payload["offline"] is True
    assert payload["exit_code"] == 0


def test_deps_without_manifests_is_exit_three(tmp_path):
    assert mcp_server.deps_payload(str(tmp_path))["exit_code"] == 3


def test_models_lists_sourced_rows():
    payload = mcp_server.models_payload()

    assert payload["models"]
    assert all(row["verified"] and row["source_url"] for row in payload["models"])


@pytest.mark.anyio
async def test_the_tools_are_registered_with_schemas():
    tools = {tool.name: tool for tool in await mcp_server.build_server().list_tools()}

    assert set(tools) == {"trustlayer_audit", "trustlayer_deps", "trustlayer_models"}
    assert tools["trustlayer_audit"].inputSchema["required"] == ["path"]
    assert tools["trustlayer_audit"].annotations.readOnlyHint is True


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------- the real stdio server

# Runs the server with a handler that misbehaves the two ways that break real servers: a
# print() in-process, and a child process writing to the fd 1 it inherited.
NOISY_SERVER = textwrap.dedent(
    """
    import subprocess, sys
    from trustlayer import __version__, mcp_server

    real = mcp_server.audit_payload

    def noisy(*args, **kwargs):
        print("NOISE-FROM-PRINT")
        subprocess.run([sys.executable, "-c", "print('NOISE-FROM-CHILD')"], timeout=30)
        return real(*args, **kwargs)

    mcp_server.audit_payload = noisy
    mcp_server.serve()
    """
)


class _Server:
    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", NOISY_SERVER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        self.lines: list[str] = []
        self._next_id = 0

    def send(self, method: str, params: dict | None = None, *, notify: bool = False) -> int | None:
        message: dict = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self._next_id += 1
            message["id"] = self._next_id
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()
        return message.get("id")

    def response(self, request_id: int, timeout: float = 60) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.process.stdout], [], [], 0.5)
            if not ready:
                continue
            raw = self.process.stdout.readline()
            if not raw:
                break
            line = raw.decode()
            self.lines.append(line)
            frame = json.loads(line)  # a non-JSON line here is exactly the bug under test
            if frame.get("id") == request_id:
                return frame
        raise AssertionError(f"no response to request {request_id}; stdout so far: {self.lines}")

    def close(self) -> str:
        """End the session (stdin EOF) and keep any trailing stdout for the frame check."""
        try:
            stdout, stderr = self.process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            stdout, stderr = self.process.communicate(timeout=5)
        self.lines.extend(line + "\n" for line in stdout.decode().splitlines() if line)
        return stderr.decode()


@pytest.mark.skipif(sys.platform == "win32", reason="select() on pipes is POSIX-only")
def test_stdout_carries_only_json_rpc_even_when_a_tool_prints():
    server = _Server()
    try:
        init = server.response(
            server.send(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "0"},
                },
            )
        )
        assert init["result"]["serverInfo"]["name"] == "trustlayer"
        assert init["result"]["serverInfo"]["version"] == __version__
        server.send("notifications/initialized", notify=True)

        listed = server.response(server.send("tools/list"))
        assert {t["name"] for t in listed["result"]["tools"]} == {
            "trustlayer_audit", "trustlayer_deps", "trustlayer_models",
        }

        called = server.response(
            server.send(
                "tools/call",
                {"name": "trustlayer_audit", "arguments": {"path": str(FIXTURES / "failopen-dirty")}},
            )
        )
        result = called["result"]
        assert result["isError"] is False
        assert result["structuredContent"]["exit_code"] == 2
    finally:
        stderr = server.close()

    assert all(json.loads(line)["jsonrpc"] == "2.0" for line in server.lines)
    assert "NOISE-FROM-PRINT" in stderr
    assert "NOISE-FROM-CHILD" in stderr
