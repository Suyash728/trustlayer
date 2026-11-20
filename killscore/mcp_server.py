"""`killscore mcp`: the deterministic checks over a local stdio Model Context Protocol server.

Built on the `mcp` SDK's FastMCP (verified against mcp 1.29.0). A coding agent calls these
tools to check its own work before it says it is done. The agent gets the same evidence and
the same exit-code meaning a hook would; it never gets a say in either. No model runs here.

**stdout belongs to JSON-RPC and nothing else.** One stray `print` - from killscore, from a
library, from a child process that inherited fd 1 - corrupts the stream and the client
drops the connection. So before serving, the real stdout is duplicated to a private fd for
the transport, and fd 1 itself is pointed at stderr. Anything that writes to "stdout" after
that lands in the client's log instead of the protocol.

Tools are deliberately narrow: `killscore_audit`, `killscore_deps`, `killscore_models`.
There is no agent tool (`baseline`/`harden`) - an agent asking killscore to run another
agent is exactly the multi-agent orchestration CLAUDE.md says not to build.
"""

from __future__ import annotations

from io import TextIOWrapper
import os
from pathlib import Path
import sys
import time
from typing import Any

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.server.stdio import stdio_server
from mcp.types import ToolAnnotations

from killscore import __version__


EXIT_MEANINGS = {
    0: "clean: no finding at or above the --fail-on threshold",
    1: "medium (or low under --fail-on low) findings",
    2: "high findings",
    3: "operational error: the check could not run, which says nothing about the code",
}

INSTRUCTIONS = (
    "killscore runs mechanical checks on a repository: retired model IDs, swallowed "
    "exceptions, import-time side effects, hallucinated APIs and call signatures, "
    "slopsquatted dependencies, yanked pins, test tautologies. Every finding carries "
    "evidence a human can re-derive (a registry 404, a resolved version, a source line). "
    "Run killscore_audit on code you wrote before finishing; treat exit_code 2 as must-fix. "
    "exit_code 3 means the check could not run - read `error`, do not treat it as clean."
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)


def _error(message: str) -> dict:
    return {"exit_code": 3, "exit_meaning": EXIT_MEANINGS[3], "error": message}


def _with_meaning(payload: dict, code: int) -> dict:
    payload["exit_code"] = code
    payload["exit_meaning"] = EXIT_MEANINGS[code]
    return payload


def audit_payload(
    path: str,
    checks: list[str] | None = None,
    all_checks: bool = False,
    warn_expiring_within: str | None = None,
    fail_on: str = "medium",
    save: bool = False,
) -> dict:
    """The `killscore audit --format json` document plus the exit code and its meaning.

    Never raises: an unusable request is `exit_code: 3` with an `error`, exactly as the CLI
    would exit 3, so an agent can never read a failure as a clean result.
    """
    from killscore.checks.runner import ALL_CHECKS, DEFAULT_CHECKS, run_checks
    from killscore.cli import _check_fail_on, _parse_duration
    from killscore.config import load_config
    from killscore.detect import profile_repository
    from killscore.report import Report, to_dict
    from killscore.store import save_run
    from killscore.suite import inspect_suite

    root = Path(path).expanduser()
    if not root.is_dir():
        return _error(f"{path} is not a directory")
    try:
        if all_checks:
            selected = list(ALL_CHECKS)
        elif checks:
            unknown = [name for name in checks if name not in ALL_CHECKS]
            if unknown:
                raise ValueError(f"unknown check(s) {unknown}; choose from {list(ALL_CHECKS)}")
            selected = list(dict.fromkeys(checks))
        else:
            selected = list(DEFAULT_CHECKS)
        warn_days = _parse_duration(warn_expiring_within)
        _check_fail_on(fail_on)
        config = load_config(root)
    except ValueError as error:
        return _error(str(error))

    started = time.monotonic()
    try:
        profile = profile_repository(root)
        results = run_checks(root, selected, warn_days, profile, config)
        suite = inspect_suite(root)
    except Exception as error:  # noqa: BLE001 - a crash is exit 3, never a verdict
        return _error(f"audit crashed: {type(error).__name__}: {error}")

    report = Report(
        root=root.resolve(), profile=profile, results=results, suite=suite, fail_on=fail_on
    )
    payload = to_dict(report)
    payload["checks_run"] = selected
    if save:
        try:
            save_run(report, time.monotonic() - started)
        except Exception as error:  # noqa: BLE001 - recording is a convenience, as in the CLI
            payload["warning"] = f"could not record run: {error}"
    return _with_meaning(payload, report.exit_code)


def deps_payload(path: str, offline: bool = True, fail_on: str = "medium") -> dict:
    """The `killscore deps --format json` document plus the exit code and its meaning."""
    from killscore.checks.slopsquat import scan
    from killscore.cli import _check_fail_on
    from killscore.config import load_config
    from killscore.report import deps_exit_code, deps_to_dict

    root = Path(path).expanduser()
    if not root.is_dir():
        return _error(f"{path} is not a directory")
    try:
        _check_fail_on(fail_on)
        config = load_config(root)
    except ValueError as error:
        return _error(str(error))
    try:
        result = scan(root, offline=offline, config=config)
    except Exception as error:  # noqa: BLE001
        return _error(f"deps crashed: {type(error).__name__}: {error}")
    if result.skip_reason:
        return _error(result.skip_reason)
    payload = deps_to_dict(result, root.resolve(), None)
    payload["offline"] = offline
    return _with_meaning(payload, deps_exit_code(result, fail_on))


def models_payload() -> dict:
    """The deprecation registry, with each row's status today and whether it is sourced."""
    from datetime import UTC, datetime

    from killscore.checks.stale_models import load_registry

    today = datetime.now(tz=UTC).date()
    try:
        registry = load_registry()
    except OSError as error:
        return _error(f"could not read the registry: {error}")
    return {
        "today": today.isoformat(),
        "models": [
            {
                "model_id": model.model_id,
                "provider": model.provider,
                "deprecated_on": model.deprecated_on.isoformat() if model.deprecated_on else None,
                "status": model.status(today),
                "successor": model.successor or None,
                "source_url": model.source_url or None,
                "verified": model.verified and bool(model.source_url),
            }
            for model in registry
        ],
    }


def build_server() -> FastMCP:
    # Tool return types are `dict[str, Any]`, not `dict`: FastMCP 1.29 only derives an
    # output schema (and sends `structuredContent`) for a parameterised dict.
    # Request logs at INFO would flood the client's stderr pane with one line per call.
    server = FastMCP("killscore", instructions=INSTRUCTIONS, log_level="WARNING")
    # FastMCP does not take a version, so the handshake would report the SDK's own (1.29.0).
    # The low-level server reads `version` when it builds the initialization options.
    server._mcp_server.version = __version__

    @server.tool(
        name="killscore_audit",
        title="Audit a repository",
        description=(
            "Run killscore's mechanical checks on a local directory and return every finding "
            "with its evidence, plus exit_code (0 clean, 1 medium, 2 high, 3 could not run). "
            "Default checks are offline: stale-models, fail-open, import-effects. `checks` "
            "picks specific ones; `all_checks` adds the opt-in checks, some of which contact "
            "PyPI/npm/GitHub (slopsquat, pinned-version, gha-refs) or import code from the "
            "repo's own virtualenv (api-resolution)."
        ),
        annotations=READ_ONLY,
    )
    async def killscore_audit(
        path: str,
        checks: list[str] | None = None,
        all_checks: bool = False,
        warn_expiring_within: str | None = None,
        fail_on: str = "medium",
        save: bool = False,
    ) -> dict[str, Any]:
        return await anyio.to_thread.run_sync(
            lambda: audit_payload(path, checks, all_checks, warn_expiring_within, fail_on, save)
        )

    @server.tool(
        name="killscore_deps",
        title="Score dependencies for slopsquatting",
        description=(
            "Score every dependency declared in requirements*.txt / pyproject.toml / setup.* / "
            "package.json: a definitive registry 404 scores 100; otherwise age, release count, "
            "maintainers, downloads and typo-distance to popular packages add up. Offline by "
            "default (bundled corpus + local cache); set offline=false to query registries."
        ),
        annotations=READ_ONLY,
    )
    async def killscore_deps(
        path: str, offline: bool = True, fail_on: str = "medium"
    ) -> dict[str, Any]:
        return await anyio.to_thread.run_sync(lambda: deps_payload(path, offline, fail_on))

    @server.tool(
        name="killscore_models",
        title="List retired and retiring model IDs",
        description=(
            "The model deprecation registry: each ID's retirement date, status today, "
            "successor, and the vendor page it was verified against."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
    )
    async def killscore_models() -> dict[str, Any]:
        return models_payload()

    return server


def serve() -> None:
    """Serve on stdio with fd 1 protected. Blocks until the client disconnects."""
    protocol_fd = os.dup(1)
    os.dup2(2, 1)  # every later write to fd 1 - ours, a library's, a child's - goes to stderr
    sys.stdout = sys.stderr
    protocol = TextIOWrapper(os.fdopen(protocol_fd, "wb"), encoding="utf-8", write_through=True)
    print(f"killscore {__version__} MCP server on stdio", file=sys.stderr)

    server = build_server()

    async def run() -> None:
        async with stdio_server(stdout=anyio.wrap_file(protocol)) as (read_stream, write_stream):
            # `_mcp_server` is FastMCP's own low-level server; `run_stdio_async` does exactly
            # this but always wraps sys.stdout, which is now stderr. Verified on mcp 1.29.0.
            low_level = server._mcp_server
            await low_level.run(read_stream, write_stream, low_level.create_initialization_options())

    anyio.run(run)
