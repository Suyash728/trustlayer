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

from trustlayer.checks.base import (
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
NODE_HELPER_DIR = Path(__file__).parent / "node"
NODE_HELPER = NODE_HELPER_DIR / "fail_open.mjs"
NODE_TIMEOUT_SECONDS = 120

URLISH_RE = re.compile(r"url|uri|endpoint|host|dsn|conn|base|webhook|origin", re.IGNORECASE)
GATE_NAME_RE = re.compile(r"auth|tier|gate|permission|access|allow", re.IGNORECASE)
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
        if not _has_degrading_default(node):
            continue

        variable = _first_string_arg(node)
        targets = _enclosing_assignment_names(node, parents)
        in_url_fstring = _inside_url_fstring(node, parents)

        signals = [name for name in ([variable] + targets) if name and URLISH_RE.search(name)]
        if not signals and not in_url_fstring:
            continue  # only one signal: not enough to call it a defect

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


def _has_degrading_default(call: ast.Call) -> bool:
    """True when the fallback is an empty string or None, explicit or implicit."""
    default: ast.expr | None = None
    if len(call.args) >= 2:
        default = call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "default":
            default = keyword.value

    if default is None:
        return True  # implicit None
    return isinstance(default, ast.Constant) and default.value in ("", None)


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
        if not GATE_NAME_RE.search(node.name):
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

    if not (NODE_HELPER_DIR / "node_modules" / "ts-morph").is_dir():
        return CheckResult(
            check,
            skipped=True,
            skip_reason=f"ts-morph helper not installed; run `npm install --prefix {NODE_HELPER_DIR}`",
        )

    # cwd is the helper dir so node resolves ts-morph, so the repo path must be absolute.
    helper = run_tool(
        ["node", str(NODE_HELPER), str(root.resolve())],
        cwd=NODE_HELPER_DIR,
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
