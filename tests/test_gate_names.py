"""`gate-fails-open` only judges functions whose name reads as a yes/no access question.

Found on anthropic-sdk-python: `resolve_auth_mode()` returns True to mean "use SigV4", not
"grant access". It matched only because its name contains "auth". A function that picks a
mode or reads a setting is not a gate, and calling its fall-through a fail-open is false.
"""

from __future__ import annotations

from pathlib import Path
import textwrap

import pytest

from killscore.checks.fail_open import check_python_fail_open, check_typescript_fail_open


def _gates(tmp_path: Path, name: str, source: str, check) -> list[str]:
    (tmp_path / name).write_text(textwrap.dedent(source))
    result = check(tmp_path)
    if result.skipped:
        pytest.skip(result.skip_reason or "checks unavailable")
    return [f.claim for f in result.findings if f.verdict == "gate-fails-open"]


PYTHON_GATE = """
def {name}(user):
    if user.banned:
        return False
    return True
"""


@pytest.mark.parametrize("name", ["resolve_auth_mode", "auth_backend_for", "access_log_enabled", "tier_label"])
def test_a_function_that_is_not_a_question_is_not_a_gate(tmp_path, name):
    assert _gates(tmp_path, "app.py", PYTHON_GATE.format(name=name), check_python_fail_open) == []


@pytest.mark.parametrize(
    "name", ["check_access", "is_allowed", "has_permission", "can_access", "_authorize", "allow_request"]
)
def test_a_question_shaped_gate_still_fires(tmp_path, name):
    assert _gates(tmp_path, "app.py", PYTHON_GATE.format(name=name), check_python_fail_open) == [
        f"{name}() falls through to True"
    ]


TS_GATE = """
export function {name}(user: any): boolean {{
  if (user.banned) {{
    return false;
  }}
  return true;
}}
"""


def test_typescript_mode_resolver_is_not_a_gate(tmp_path):
    assert _gates(tmp_path, "app.ts", TS_GATE.format(name="resolveAuthMode"), check_typescript_fail_open) == []


def test_typescript_question_shaped_gate_still_fires(tmp_path):
    claims = _gates(tmp_path, "app.ts", TS_GATE.format(name="canAccess"), check_typescript_fail_open)
    assert len(claims) == 1 and claims[0].startswith("canAccess()")
