"""Assertions that cannot fail, in test files.

AI-written tests pass for the wrong reason surprisingly often, and the commonest way is an
assertion that is true by construction. Each pattern below is decided from the AST alone,
and each is reported only in its unambiguous form:

- **mock-auto-attribute** (HIGH): `assert m.called_once_with(x)`. `called_once_with` is not a
  Mock method - Mock invents the attribute, calling it returns another Mock, and a Mock is
  truthy. The real method is `m.assert_called_once_with(x)`. Verified 2026-11-20: Python
  3.10/3.11 pass this silently; 3.12 added a deny-list (`called_once_with`, `called_with`,
  `called_once`, `has_calls`, `any_call`, `not_called`) that raises AttributeError instead.
  The `awaited_*` look-alikes are on no deny-list and pass silently on every version. Either
  way the line is wrong, and the evidence says which failure mode applies.
- **uncalled-assertion** (HIGH): `m.assert_called_once_with` with no parentheses - as a bare
  statement it does nothing; inside `assert` it is a bound method, which is truthy.
- **unused-raises** (HIGH): `pytest.raises(ValueError)` as a bare statement creates a context
  manager and discards it. Nothing is checked. (The legacy call form
  `pytest.raises(E, func, arg)` does run `func`, so a call with more than one positional
  argument is left alone.)
- **constant-assertion** (HIGH): `assert True`, `assert "message"`, `assert (x, "message")` -
  a truthy constant, or a tuple, which is truthy whenever it is non-empty. `assert False`
  is a deliberate failure and is never reported.
- **self-comparison** (MEDIUM): `assert x == x`, `assertEqual(x, x)`, `assert x is x` on plain
  names and attributes. MEDIUM, not HIGH, because `x == x` is False for NaN and a test can
  mean that; `x != x` (the NaN idiom) is never reported.
- **always-true-comparison** (HIGH): `assert len(x) >= 0` - a length is never negative.

Only files a test runner would collect are read (`test_*.py`, `*_test.py`); helpers and
conftest are not, because a fixture factory may legitimately build any of these shapes.
"""

from __future__ import annotations

import ast
from pathlib import Path

from trustlayer.checks.base import (
    PYTHON_SUFFIXES,
    CheckResult,
    Finding,
    Severity,
    iter_files,
    read_source,
    relative_to,
    sort_findings,
)


CHECK_NAME = "test-tautology"

# Python 3.12+ raises AttributeError for these instead of inventing them (mock._ATTRIB_DENY_LIST).
DENY_LISTED_SINCE_312 = frozenset(
    {"called_once_with", "called_with", "called_once", "has_calls", "any_call", "not_called"}
)

# Attributes Mock invents on access. Each has a real `assert_*` counterpart.
MOCK_LOOKALIKES = {
    "called_once_with": "assert_called_once_with",
    "called_with": "assert_called_with",
    "called_once": "assert_called_once",
    "has_calls": "assert_has_calls",
    "any_call": "assert_any_call",
    "not_called": "assert_not_called",
    "awaited_once_with": "assert_awaited_once_with",
    "awaited_with": "assert_awaited_with",
    "awaited_once": "assert_awaited_once",
}
MOCK_ASSERTIONS = frozenset(
    {
        "assert_called", "assert_called_once", "assert_called_with", "assert_called_once_with",
        "assert_any_call", "assert_has_calls", "assert_not_called", "assert_awaited",
        "assert_awaited_once", "assert_awaited_with", "assert_awaited_once_with",
        "assert_any_await", "assert_has_awaits", "assert_not_awaited",
    }
)
SELF_COMPARING_METHODS = frozenset({"assertEqual", "assertEquals", "assertIs", "assertCountEqual"})


def is_test_file(path: Path) -> bool:
    name = path.name
    return path.suffix in PYTHON_SUFFIXES and (
        (name.startswith("test_") and name != "test_.py") or name.endswith("_test.py")
    )


def check_test_tautology(root: Path) -> CheckResult:
    files = list(iter_files(root, is_test_file))
    if not files:
        return CheckResult(CHECK_NAME, skipped=True, skip_reason="no Python test files found")

    findings: list[Finding] = []
    for path in files:
        source = read_source(path)
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        findings.extend(_scan(tree, relative_to(path, root), source))
    return CheckResult(CHECK_NAME, sort_findings(findings))


def _scan(tree: ast.AST, file: str, source: str) -> list[Finding]:
    found: list[Finding] = []

    def report(node: ast.AST, severity: Severity, verdict: str, *evidence: str) -> None:
        text = ast.get_source_segment(source, node) or ast.unparse(node)
        found.append(
            Finding(
                severity=severity,
                check=CHECK_NAME,
                file=file,
                line=node.lineno,
                claim=" ".join(text.split())[:120],
                verdict=verdict,
                evidence=list(evidence),
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            _check_assert(node, report)
        elif isinstance(node, ast.Expr):
            _check_statement(node, report)
    return found


def _check_assert(node: ast.Assert, report) -> None:
    test = node.test

    if isinstance(test, ast.Tuple) and test.elts:
        report(
            node, Severity.HIGH, "constant-assertion",
            "the asserted expression is a non-empty tuple, which is always truthy",
            "to attach a message, write `assert condition, \"message\"` without parentheses",
        )
        return
    if isinstance(test, ast.Constant) and test.value:
        report(
            node, Severity.HIGH, "constant-assertion",
            f"asserts the constant {test.value!r}, which is always truthy - nothing is tested",
        )
        return

    if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute):
        real = MOCK_LOOKALIKES.get(test.func.attr)
        if real is not None:
            behaviour = (
                "on Python 3.11 and older this passes whatever was called; 3.12+ raises "
                "AttributeError for this name, so there the test errors instead"
                if test.func.attr in DENY_LISTED_SINCE_312
                else "no Python version guards this name, so it passes whatever was awaited"
            )
            report(
                node, Severity.HIGH, "mock-auto-attribute",
                f"`{test.func.attr}` is not a Mock method: Mock creates it on access and calling "
                "it returns a truthy Mock",
                behaviour,
                f"the real check is `{ast.unparse(test.func.value)}.{real}(...)`, not inside `assert`",
            )
            return

    if isinstance(test, ast.Attribute) and test.attr in MOCK_ASSERTIONS:
        report(
            node, Severity.HIGH, "uncalled-assertion",
            f"`{test.attr}` is referenced but not called; a bound method is always truthy",
            f"call it: `{ast.unparse(test)}(...)`, as a statement rather than inside `assert`",
        )
        return

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        _check_comparison(node, test, report)


def _check_comparison(node: ast.Assert, test: ast.Compare, report) -> None:
    left, op, right = test.left, test.ops[0], test.comparators[0]

    if isinstance(op, ast.Eq | ast.Is | ast.GtE | ast.LtE) and _plain(left) and _same(left, right):
        report(
            node, Severity.MEDIUM, "self-comparison",
            f"both sides are `{ast.unparse(left)}`, so this holds for any value",
            "the only exception is NaN for `==`; if that is the intent, `math.isnan` says so",
        )
        return

    if _is_len_call(left) and isinstance(right, ast.Constant) and isinstance(right.value, int):
        always = (isinstance(op, ast.GtE) and right.value <= 0) or (isinstance(op, ast.Gt) and right.value < 0)
        if always:
            report(
                node, Severity.HIGH, "always-true-comparison",
                f"`{ast.unparse(test)}` - a length is never negative, so this cannot fail",
            )


def _check_statement(node: ast.Expr, report) -> None:
    value = node.value

    if isinstance(value, ast.Attribute) and value.attr in MOCK_ASSERTIONS:
        report(
            node, Severity.HIGH, "uncalled-assertion",
            f"`{ast.unparse(value)}` is a bare attribute reference: without `()` the "
            "assertion never runs",
        )
        return

    if isinstance(value, ast.Call):
        if _is_pytest_raises(value.func) and len(value.args) <= 1 and not _has_star(value):
            report(
                node, Severity.HIGH, "unused-raises",
                "`pytest.raises(...)` was called but its context manager was discarded; "
                "nothing is checked",
                "use `with pytest.raises(...):` around the code that should raise",
            )
            return
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr in SELF_COMPARING_METHODS
            and len(value.args) >= 2
            and _plain(value.args[0])
            and _same(value.args[0], value.args[1])
        ):
            report(
                node, Severity.MEDIUM, "self-comparison",
                f"`{value.func.attr}` compares `{ast.unparse(value.args[0])}` with itself",
            )
            return
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr == "assertTrue"
            and value.args
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value
        ):
            report(
                node, Severity.HIGH, "constant-assertion",
                f"`assertTrue({value.args[0].value!r})` is always true",
            )


def _plain(node: ast.AST) -> bool:
    """A name or an attribute chain on a name - evaluating it twice gives the same object."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)


def _same(left: ast.AST, right: ast.AST) -> bool:
    return ast.dump(left, annotate_fields=False) == ast.dump(right, annotate_fields=False)


def _is_len_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
        and len(node.args) == 1
        and not node.keywords
    )


def _is_pytest_raises(func: ast.AST) -> bool:
    """Only the qualified `pytest.raises`: a bare `raises` could be anyone's function."""
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "raises"
        and isinstance(func.value, ast.Name)
        and func.value.id == "pytest"
    )


def _has_star(call: ast.Call) -> bool:
    return any(isinstance(arg, ast.Starred) for arg in call.args)
