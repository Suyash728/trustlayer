"""Import-time side effects: network, subprocess, and destructive I/O at module scope.

Importing a module executes its top-level code. When that code opens a connection, shells
out, or deletes a file, every importer inherits the effect - including the test collector,
which is why a suite can hang or mutate a machine before a single test runs. AI-generated
modules do this routinely, because a model writing "set up the client" has no notion that
module scope is not a function body.

The whole check is its silence. Two rules keep it quiet:

**Nesting means silence.** Only unconditional top-level statements are candidates. A call
inside `if`, `try`, `with`, a loop, a function, or a class is skipped outright - the AST
cannot see that a `subprocess` call sits behind a feature flag or under `if TYPE_CHECKING`,
so it does not guess.

**Reads are not effects.** `open(path)`, `Path.read_text()`, and friends never report.
Reading a version file or a template at import is ordinary, and flagging it would produce
exactly the noise that trains people to ignore a tool.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from trustlayer.checks.base import (
    PYTHON_SUFFIXES,
    CheckResult,
    Finding,
    Severity,
    iter_source_files,
    read_source,
    relative_to,
    sort_findings,
)


CHECK_NAME = "import-effects"

# Statements that introduce a scope or a condition. A call inside one of these is not
# unconditionally executed at import, so it is never a candidate.
NESTING_STATEMENTS = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.If,
    ast.Try,
    ast.With,
    ast.AsyncWith,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Match,
)

# Fully-qualified callables, resolved through import aliases before lookup.
#
# Deliberately absent: `requests.Session()` and `httpx.Client()` construct an object without
# touching the network, and bare `socket.socket()` allocates a descriptor without connecting.
# Flagging them would make the evidence line untrue.
NETWORK_CALLS = frozenset(
    {
        f"{module}.{verb}"
        for module in ("requests", "httpx")
        for verb in ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")
    }
    | {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "socket.create_connection",
    }
)
SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "os.system",
        "os.popen",
    }
)
DESTRUCTIVE_CALLS = frozenset({"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"})

WRITE_MODE_CHARACTERS = frozenset("wax+")

EFFECTS = {
    "import-time-network": (
        Severity.MEDIUM,
        (
            "This runs on `import`, so every importer performs the request - including the "
            "test collector, before any test is selected. A slow or unreachable host becomes "
            "an import hang rather than a test failure."
        ),
    ),
    "import-time-subprocess": (
        Severity.MEDIUM,
        (
            "This runs on `import`, so merely importing the module spawns a process. Import "
            "order then decides when it happens, which makes the behaviour depend on "
            "something no caller controls."
        ),
    ),
    "import-time-destructive": (
        Severity.HIGH,
        (
            "This deletes from the filesystem on `import`. Importing a module - to read its "
            "docstring, to collect its tests, to generate documentation - destroys data."
        ),
    ),
    "import-time-write": (
        Severity.MEDIUM,
        (
            "This opens a file for writing on `import`, so importing the module truncates or "
            "creates it as a side effect."
        ),
    ),
}


@dataclass(frozen=True)
class _Effect:
    verdict: str
    claim: str
    line: int


def check_import_effects(root: Path) -> CheckResult:
    """Scan Python sources for unconditional I/O at module scope."""
    sources = list(iter_source_files(root, PYTHON_SUFFIXES))
    if not sources:
        return CheckResult(CHECK_NAME, skipped=True, skip_reason="no Python sources found")

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
        for effect in _effects_in_module(tree):
            severity, why = EFFECTS[effect.verdict]
            evidence = [why]
            if 0 < effect.line <= len(lines):
                evidence.insert(0, lines[effect.line - 1].strip())
            findings.append(
                Finding(
                    severity=severity,
                    check=CHECK_NAME,
                    file=relative,
                    line=effect.line,
                    claim=effect.claim,
                    verdict=effect.verdict,
                    evidence=evidence,
                )
            )

    return CheckResult(CHECK_NAME, sort_findings(findings))


def _effects_in_module(tree: ast.Module) -> list[_Effect]:
    aliases = _import_aliases(tree)
    effects: list[_Effect] = []

    for statement in tree.body:
        if isinstance(statement, NESTING_STATEMENTS):
            continue  # conditional or scoped: never a candidate
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                effect = _classify(node, aliases)
                if effect is not None:
                    effects.append(effect)
    return effects


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> fully qualified name, from top-level imports only."""
    aliases: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(statement, ast.ImportFrom) and statement.module and not statement.level:
            for alias in statement.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
    return aliases


def _classify(node: ast.Call, aliases: dict[str, str]) -> _Effect | None:
    name = _qualified_name(node.func, aliases)
    if name is None:
        return None

    if name in NETWORK_CALLS:
        return _Effect("import-time-network", f"{name}() at module scope", node.lineno)
    if name in SUBPROCESS_CALLS:
        return _Effect("import-time-subprocess", f"{name}() at module scope", node.lineno)
    if name in DESTRUCTIVE_CALLS:
        return _Effect("import-time-destructive", f"{name}() at module scope", node.lineno)
    if name == "open" and _opens_for_writing(node):
        return _Effect("import-time-write", "open() for writing at module scope", node.lineno)
    return None


def _qualified_name(func: ast.expr, aliases: dict[str, str]) -> str | None:
    """Resolve a call target to a dotted name, or None when the receiver is not a plain name.

    `foo().bar()` and `d["k"].bar()` resolve to None on purpose: the object is unknown, so
    any claim about what `.bar` does would be a guess.
    """
    parts: list[str] = []
    current: ast.expr = func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None

    parts.append(aliases.get(current.id, current.id))
    return ".".join(reversed(parts))


def _opens_for_writing(node: ast.Call) -> bool:
    """True only when the mode is a literal containing a write character.

    A non-literal mode is unknowable, so it is treated as a read and stays silent.
    """
    mode: ast.expr | None = None
    if len(node.args) >= 2:
        mode = node.args[1]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value

    if mode is None:
        return False  # defaults to "r"
    if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str):
        return False  # computed mode: unknowable, so silent
    return bool(WRITE_MODE_CHARACTERS & set(mode.value))
