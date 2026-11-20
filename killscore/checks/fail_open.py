"""Config-safety checks: code that silently degrades instead of failing loudly.

Every detector requires two independent signals before it reports. A false positive here
costs more than silence, because it trains people to ignore the output.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re

from killscore.checks import node_helper
from killscore.checks.base import (
    PYTHON_SUFFIXES,
    TYPESCRIPT_SUFFIXES,
    CheckResult,
    Finding,
    Severity,
    iter_source_files,
    read_source,
    relative_to,
    run_tool,
    sort_findings,
)


CHECK_NAME = "fail-open"
NODE_TIMEOUT_SECONDS = 120

URLISH_RE = re.compile(r"url|uri|endpoint|host|dsn|conn|base|webhook|origin", re.IGNORECASE)
# A name that holds a credential is not a URL, however it is prefixed: WEBHOOK_SECRET and
# WEBHOOK_SIGNING_KEY matched "webhook" and were reported as URLs on two real SDKs.
CREDENTIAL_PARTS = frozenset(
    {"secret", "key", "token", "password", "passwd", "signing", "signature", "credential", "credentials"}
)
GATE_NAME_RE = re.compile(r"auth|tier|gate|permission|access|allow", re.IGNORECASE)
# A gate answers a yes/no question about a caller, so its name starts with one. Found on
# anthropic-sdk-python: `resolve_auth_mode()` returns True to mean "use SigV4", not "allow".
QUESTION_WORDS = frozenset(
    {"is", "has", "can", "check", "may", "should", "verify", "validate", "authorize",
     "authorise", "allow", "allowed", "permit", "require", "ensure"}
)
ENV_GETTERS = ("getenv", "environ.get")

FAILURE_MODES = {
    "env-default-degrades-url": (
        "An unset variable yields an empty base URL, so requests resolve against a relative "
        "path and silently hit the wrong host instead of raising."
    ),
    "gate-fails-open": (
        "When no branch matches, the function returns permissive, so an unrecognised caller "
        "is granted access instead of being denied."
    ),
    "swallowed-exception": (
        "The error is discarded, so a failing dependency looks identical to a working one and "
        "the failure surfaces later somewhere unrelated."
    ),
    "cors-wildcard-with-credentials": (
        "Wildcard origins combined with credentials lets any site issue authenticated "
        "cross-origin requests using the visitor's cookies."
    ),
}


@dataclass(frozen=True)
class _Detection:
    severity: Severity
    line: int
    claim: str
    verdict: str


def check_fail_open(root: Path) -> list[CheckResult]:
    return [check_python_fail_open(root), check_typescript_fail_open(root)]


def check_python_fail_open(root: Path) -> CheckResult:
    check = f"{CHECK_NAME}:python"
    sources = list(iter_source_files(root, PYTHON_SUFFIXES))
    if not sources:
        return CheckResult(check, skipped=True, skip_reason="no Python sources found")

    findings: list[Finding] = []
    for path in sources:
        source = read_source(path)
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        lines = source.splitlines()
        relative = relative_to(path, root)
        detections = [
            *_env_default_detections(tree),
            *_fail_open_gate_detections(tree),
            *_swallowed_exception_detections(tree),
            *_cors_detections(tree),
        ]
        for detection in detections:
            findings.append(
                Finding(
                    severity=detection.severity,
                    check=check,
                    file=relative,
                    line=detection.line,
                    claim=detection.claim,
                    verdict=detection.verdict,
                    evidence=[
                        _source_line(lines, detection.line),
                        FAILURE_MODES[detection.verdict],
                    ],
                )
            )
    return CheckResult(check, sort_findings(findings))


def _source_line(lines: list[str], line: int) -> str:
    if 1 <= line <= len(lines):
        return f"{line}: {lines[line - 1].strip()}"
    return f"{line}: <source unavailable>"


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


# 1. Empty env default flowing into a URL - HIGH


def _env_default_detections(tree: ast.AST) -> list[_Detection]:
    parents = _parents(tree)
    detections = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_env_getter(node.func):
            continue
        default = _degrading_default(node)
        if default is None:
            continue
        if default == "none" and _falls_back_to_empty(node, parents):
            default = "empty"  # `getenv("URL") or ""` is an empty default spelled differently

        variable = _first_string_arg(node)
        targets = _enclosing_assignment_names(node, parents)
        in_url_fstring = _inside_url_fstring(node, parents)

        if default == "none" and not in_url_fstring:
            # None is Python's "not set": a library substitutes its default or raises. It only
            # degrades a URL once it is formatted into one (f"https://{None}/v1").
            continue
        signals = [name for name in ([variable] + targets) if name and _names_a_url(name)]
        if not signals and not in_url_fstring:
            continue  # only one signal: not enough to call it a defect
        if _is_guarded(node, targets, parents, tree):
            continue  # an empty value that is tested before use cannot reach a request

        detections.append(
            _Detection(
                severity=Severity.HIGH,
                line=node.lineno,
                claim=f"{_call_name(node.func)}({variable!r}, <empty default>)"
                if variable
                else f"{_call_name(node.func)}(<empty default>)",
                verdict="env-default-degrades-url",
            )
        )
    return detections


def _is_env_getter(func: ast.expr) -> bool:
    return _call_name(func) in ENV_GETTERS


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Attribute):
            return f"{func.value.attr}.{func.attr}"
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}" if func.value.id != "os" else func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _degrading_default(call: ast.Call) -> str | None:
    """`"empty"` for an explicit `""` fallback, `"none"` for None (explicit or implicit)."""
    default: ast.expr | None = None
    if len(call.args) >= 2:
        default = call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "default":
            default = keyword.value

    if default is None:
        return "none"
    if isinstance(default, ast.Constant) and default.value == "":
        return "empty"
    if isinstance(default, ast.Constant) and default.value is None:
        return "none"
    return None


def _falls_back_to_empty(call: ast.Call, parents: dict[int, ast.AST]) -> bool:
    parent = parents.get(id(call))
    if not (isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.Or)):
        return False
    later = parent.values[parent.values.index(call) + 1 :]
    return bool(later) and all(_is_empty_constant(value) for value in later)


def _names_a_url(name: str) -> bool:
    """URL-ish, and not a credential: `WEBHOOK_URL` is a URL, `WEBHOOK_SECRET` is not."""
    if not URLISH_RE.search(name):
        return False
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    return not any(part in CREDENTIAL_PARTS for part in re.split(r"[^a-z0-9]+", snake))


def _first_string_arg(call: ast.Call) -> str | None:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


def _enclosing_assignment_names(node: ast.AST, parents: dict[int, ast.AST]) -> list[str]:
    current: ast.AST | None = node
    while current is not None:
        parent = parents.get(id(current))
        if isinstance(parent, ast.Assign):
            return [t.id for t in parent.targets if isinstance(t, ast.Name)]
        if isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
            return [parent.target.id]
        current = parent
    return []


_TEST_OWNERS = (ast.If, ast.While, ast.IfExp, ast.Assert)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)


def _is_guarded(
    call: ast.Call, targets: list[str], parents: dict[int, ast.AST], tree: ast.AST
) -> bool:
    """True when the empty value is tested before anything can use it.

    Three shapes, all found reporting HIGH in a real repository:
    the getter *is* a condition (`if os.environ.get(...)`), it has a non-empty `or`
    fallback, or the name it is bound to is tested later in the same scope
    (`if not endpoint: raise`, `if url is not None`). The test must mention the bound name
    and come after the assignment; an unrelated `if` guards nothing.
    """
    current: ast.AST = call
    while (parent := parents.get(id(current))) is not None and not isinstance(parent, ast.stmt):
        if isinstance(parent, ast.IfExp) and parent.test is current:
            return True
        if isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.Or):
            later = parent.values[parent.values.index(current) + 1 :]
            if any(not _is_empty_constant(value) for value in later):
                return True
        current = parent
    if isinstance(parent, (ast.If, ast.While, ast.Assert)) and parent.test is current:
        return True

    if not targets:
        return False
    statement = parent if parent is not None else call
    scope: ast.AST = tree
    walker: ast.AST | None = statement
    while (walker := parents.get(id(walker))) is not None:
        if isinstance(walker, _SCOPES):
            scope = walker
            break
    assigned_at = getattr(statement, "end_lineno", None) or call.lineno
    names = set(targets)
    for node in ast.walk(scope):
        if getattr(node, "lineno", 0) < assigned_at:
            continue
        if isinstance(node, _TEST_OWNERS):
            if {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)} & names:
                return True
        elif _tests_name(node, names):
            return True
    return False


def _tests_name(node: ast.AST, names: set[str]) -> bool:
    """A test of the value outside an `if`: `url is None or not url.strip()`, `url != ""`.

    Found on two real SDKs, where the check was a `return` expression or an assignment.
    """
    def is_target(expr: ast.expr) -> bool:
        return isinstance(expr, ast.Name) and expr.id in names

    if isinstance(node, ast.Compare):
        operands = [node.left, *node.comparators]
        return any(is_target(o) for o in operands) and any(_is_empty_constant(o) for o in operands)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return is_target(node.operand)
    if isinstance(node, ast.BoolOp):
        return any(is_target(value) for value in node.values[:-1])
    return False


def _is_empty_constant(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value in ("", None)


def _inside_url_fstring(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    current: ast.AST | None = node
    while current is not None:
        parent = parents.get(id(current))
        if isinstance(parent, ast.JoinedStr):
            literal = "".join(
                part.value
                for part in parent.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if "://" in literal:
                return True
        current = parent
    return False


# 2. Gate that falls through to permissive - HIGH


def _fail_open_gate_detections(tree: ast.AST) -> list[_Detection]:
    detections = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not GATE_NAME_RE.search(node.name) or not _reads_as_question(node.name):
            continue
        # Requires real branching: a function that always returns True is not "failing open".
        if not any(isinstance(statement, ast.If) for statement in node.body):
            continue

        last = node.body[-1]
        if isinstance(last, ast.Return) and _is_permissive(last.value):
            detections.append(
                _Detection(
                    severity=Severity.HIGH,
                    line=last.lineno,
                    claim=f"{node.name}() falls through to {ast.unparse(last.value)}",
                    verdict="gate-fails-open",
                )
            )
    return detections


def _reads_as_question(name: str) -> bool:
    words = re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower())
    first = next((word for word in words if word), "")
    return first in QUESTION_WORDS


def _is_permissive(value: ast.expr | None) -> bool:
    if not isinstance(value, ast.Constant):
        return False
    return value.value is True or (isinstance(value.value, str) and value.value.lower() == "allow")


# 3. Swallowed errors - MEDIUM


def _swallowed_exception_detections(tree: ast.AST) -> list[_Detection]:
    detections = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        bare = node.type is None
        silent = len(node.body) == 1 and _is_noop(node.body[0])
        if not bare and not silent:
            continue

        if bare and silent:
            claim = "bare `except:` with an empty body"
        elif bare:
            claim = "bare `except:` catches SystemExit and KeyboardInterrupt"
        else:
            caught = ast.unparse(node.type) if node.type else "Exception"
            claim = f"`except {caught}:` with an empty body"

        detections.append(
            _Detection(Severity.MEDIUM, node.lineno, claim, "swallowed-exception")
        )
    return detections


def _is_noop(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Pass):
        return True
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    )


# 4. Wildcard CORS with credentials - MEDIUM


def _cors_detections(tree: ast.AST) -> list[_Detection]:
    detections = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        origins = keywords.get("allow_origins")
        credentials = keywords.get("allow_credentials")
        if origins is None or credentials is None:
            continue
        if not (isinstance(credentials, ast.Constant) and credentials.value is True):
            continue
        if not _contains_wildcard(origins):
            continue

        detections.append(
            _Detection(
                Severity.MEDIUM,
                node.lineno,
                'allow_origins=["*"] with allow_credentials=True',
                "cors-wildcard-with-credentials",
            )
        )
    return detections


def _contains_wildcard(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            isinstance(element, ast.Constant) and element.value == "*" for element in node.elts
        )
    return isinstance(node, ast.Constant) and node.value == "*"


# TypeScript path


def check_typescript_fail_open(root: Path) -> CheckResult:
    check = f"{CHECK_NAME}:typescript"
    if not list(iter_source_files(root, TYPESCRIPT_SUFFIXES)):
        return CheckResult(check, skipped=True, skip_reason="no TypeScript or JavaScript sources found")

    helper_dir = node_helper.helper_dir()
    if helper_dir is None:
        return CheckResult(check, skipped=True, skip_reason=node_helper.missing_reason())

    # cwd is the helper dir so node resolves ts-morph, so the repo path must be absolute.
    helper = run_tool(
        ["node", str(helper_dir / "fail_open.mjs"), str(root.resolve())],
        cwd=helper_dir,
        timeout=NODE_TIMEOUT_SECONDS,
    )
    if not helper.ok:
        reason = helper.error or (helper.stderr.strip().splitlines() or ["helper failed"])[-1]
        return CheckResult(check, skipped=True, skip_reason=f"ts-morph helper failed: {reason}")

    try:
        payload = json.loads(helper.stdout)
    except json.JSONDecodeError as error:
        return CheckResult(check, skipped=True, skip_reason=f"helper returned invalid JSON: {error}")

    if payload.get("error"):
        return CheckResult(check, skipped=True, skip_reason=f"ts-morph helper: {payload['error']}")

    findings = [
        Finding(
            severity=Severity(item["severity"]),
            check=check,
            file=item["file"],
            line=item["line"],
            claim=item["claim"],
            verdict=item["verdict"],
            evidence=[item["source_line"], FAILURE_MODES[item["verdict"]]],
        )
        for item in payload.get("findings") or []
    ]
    return CheckResult(check, sort_findings(findings))
