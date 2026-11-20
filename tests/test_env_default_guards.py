"""Silence tests for `env-default-degrades-url`: a guarded empty default is not a defect.

Every silent case below is a shape found in a real repository (graphify's `llm.py`) that the
check reported as HIGH before the guard rule existed. An empty default that is tested before
use cannot reach a request, so reporting it is a false accusation at the severity that
always fails a pre-commit hook. The firing cases pin that the guard rule is not a blanket
exemption: an unrelated `if` or a test on a *different* name must not silence anything.
"""

from __future__ import annotations

from pathlib import Path
import textwrap

import pytest

from killscore.checks.fail_open import check_python_fail_open, check_typescript_fail_open


def _python(tmp_path: Path, source: str) -> list[str]:
    (tmp_path / "app.py").write_text(textwrap.dedent(source))
    result = check_python_fail_open(tmp_path)
    return [f.verdict for f in result.findings if f.verdict == "env-default-degrades-url"]


def _typescript(tmp_path: Path, source: str) -> list[str]:
    (tmp_path / "app.ts").write_text(textwrap.dedent(source))
    result = check_typescript_fail_open(tmp_path)
    if result.skipped:
        pytest.skip(result.skip_reason or "TypeScript checks unavailable")
    return [f.verdict for f in result.findings if f.verdict == "env-default-degrades-url"]


# ----------------------------------------------------------------------------- Python silence


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            """
            import os
            def base(default):
                url = os.environ.get("OLLAMA_BASE_URL")
                if url is not None:
                    return url
                return default
            """,
            id="is-not-None-guard",
        ),
        pytest.param(
            """
            import os
            def endpoint():
                endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
                if not endpoint:
                    raise ValueError("AZURE_OPENAI_ENDPOINT must be set")
                return endpoint
            """,
            id="falsy-raise-guard",
        ),
        pytest.param(
            """
            import os
            def detect():
                if os.environ.get("AZURE_OPENAI_ENDPOINT"):
                    return "azure"
                return None
            """,
            id="getter-is-the-if-test",
        ),
        pytest.param(
            """
            import os
            def detect():
                return "azure" if os.getenv("AZURE_OPENAI_ENDPOINT") else None
            """,
            id="getter-is-a-ternary-test",
        ),
        pytest.param(
            """
            import os
            API_URL = os.getenv("API_URL")
            assert API_URL, "API_URL must be set"
            """,
            id="assert-guard",
        ),
        pytest.param(
            """
            import os
            API_URL = os.getenv("API_URL") or "https://api.example.com"
            """,
            id="or-fallback",
        ),
    ],
)
def test_guarded_python_env_default_is_silent(tmp_path, source):
    assert _python(tmp_path, source) == []


# ------------------------------------------------------------------------------ Python fires


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            """
            import os
            API_URL = os.getenv("API_URL", "")
            """,
            id="unguarded",
        ),
        pytest.param(
            """
            import os
            def call(debug):
                url = os.getenv("API_URL", "")
                if debug:
                    print("calling")
                return url
            """,
            id="unrelated-if-does-not-guard",
        ),
        pytest.param(
            """
            import os
            def call(other):
                url = os.getenv("API_URL", "")
                if other is None:
                    return None
                return url
            """,
            id="guard-on-another-name-does-not-guard",
        ),
        pytest.param(
            """
            import os
            def call():
                if True:
                    pass
                url = os.getenv("API_URL", "")
                return url
            """,
            id="if-before-the-assignment-does-not-guard",
        ),
        pytest.param(
            """
            import os
            API_URL = os.getenv("API_URL") or ""
            """,
            id="or-with-empty-fallback-is-still-empty",
        ),
    ],
)
def test_unguarded_python_env_default_still_fires(tmp_path, source):
    assert _python(tmp_path, source) == ["env-default-degrades-url"]


# ------------------------------------------------------------------------------- TypeScript


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            """
            export function base(): string {
              const url = process.env.API_URL || "";
              if (!url) throw new Error("API_URL must be set");
              return url;
            }
            """,
            id="falsy-throw-guard",
        ),
        pytest.param(
            """
            export const provider = (process.env.API_URL ?? "") ? "remote" : "local";
            """,
            id="ternary-test",
        ),
        pytest.param(
            """
            export function detect(): boolean {
              if (process.env.API_URL || "") return true;
              return false;
            }
            """,
            id="getter-is-the-if-test",
        ),
    ],
)
def test_guarded_typescript_env_default_is_silent(tmp_path, source):
    assert _typescript(tmp_path, source) == []


@pytest.mark.parametrize(
    "source",
    [
        pytest.param('export const apiUrl = process.env.API_URL || "";\n', id="unguarded"),
        pytest.param(
            """
            export function call(debug: boolean): string {
              const url = process.env.API_URL || "";
              if (debug) console.log("calling");
              return url;
            }
            """,
            id="unrelated-if-does-not-guard",
        ),
    ],
)
def test_unguarded_typescript_env_default_still_fires(tmp_path, source):
    assert _typescript(tmp_path, source) == ["env-default-degrades-url"]
