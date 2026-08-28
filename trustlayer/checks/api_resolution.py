"""Hallucinated-API detector.

Collects what the source *claims* exists, then resolves each claim against the environment
the audited repository actually installed. Every verdict is mechanical: a resolved version,
a real exported-name list, or a definitive registry 404.

The guards matter more than the check. A package is only called a slopsquat when PyPI
returns a definitive 404 - never when the network merely failed, and never for stdlib,
relative, or first-party imports.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import difflib
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

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


CHECK_NAME = "api-resolution"
PROBE_PATH = Path(__file__).parent / "_probe.py"
NODE_HELPER_DIR = Path(__file__).parent / "node"
NODE_HELPER = NODE_HELPER_DIR / "resolve_imports.mjs"

PROBE_TIMEOUT_SECONDS = 60
NODE_TIMEOUT_SECONDS = 120
PYPI_TIMEOUT_SECONDS = 8
MAX_RANKED_NAMES = 5

INTERPRETER_CANDIDATES = (
    Path(".venv") / "bin" / "python",
    Path("venv") / "bin" / "python",
    Path(".venv") / "Scripts" / "python.exe",
    Path("venv") / "Scripts" / "python.exe",
)


@dataclass(frozen=True)
class ModuleClaim:
    module: str
    file: str
    line: int


@dataclass(frozen=True)
class CallClaim:
    """A call site, with only what can be counted statically."""

    module: str
    attribute: str
    file: str
    line: int
    positional: int
    keywords: tuple[str, ...]
    star_args: bool  # *a at the call site: the real count is unknowable
    star_kwargs: bool  # **kw at the call site: any keyword may be present


@dataclass(frozen=True)
class AttributeClaim:
    module: str
    attribute: str
    file: str
    line: int
    called: bool


def check_api_resolution(root: Path, *, pypi_lookup=None) -> list[CheckResult]:
    """Run both language paths. Each returns its own result so one can skip independently."""
    return [
        check_python_apis(root, pypi_lookup=pypi_lookup),
        check_typescript_apis(root),
    ]


# --------------------------------------------------------------------------- Python path


def check_python_apis(root: Path, *, pypi_lookup=None, interpreter: Path | None = None) -> CheckResult:
    """Resolve Python import claims.

    `interpreter` overrides discovery of the repo's own venv; production callers leave it
    None so resolution always happens against the audited repo's environment.
    """
    check = f"{CHECK_NAME}:python"
    lookup = pypi_lookup if pypi_lookup is not None else pypi_package_exists

    sources = list(iter_source_files(root, PYTHON_SUFFIXES))
    if not sources:
        return CheckResult(check, skipped=True, skip_reason="no Python sources found")

    if interpreter is not None:
        origin = "caller-supplied interpreter"
    else:
        interpreter, origin = find_interpreter(root)
    if interpreter is None:
        return CheckResult(
            check,
            skipped=True,
            skip_reason=(
                "no virtualenv found at .venv/ or venv/ and no poetry env; "
                "install one (e.g. `uv venv && uv pip install -e .`) so imports can be resolved"
            ),
        )

    module_claims, attribute_claims, call_claims = collect_python_claims(root, sources)
    external = {
        claim.module
        for claim in module_claims
        if not is_first_party(root, claim.module)
    }
    if not external:
        return CheckResult(check)

    wanted: dict[str, list[str]] = {module: [] for module in external}
    for claim in (*attribute_claims, *call_claims):
        if claim.module in wanted and claim.attribute not in wanted[claim.module]:
            wanted[claim.module].append(claim.attribute)

    resolved, probe_error = run_probe(interpreter, wanted)
    if probe_error is not None:
        return CheckResult(check, skipped=True, skip_reason=probe_error)

    findings = _module_findings(module_claims, resolved, root, interpreter, origin, lookup)
    findings += _attribute_findings(attribute_claims, resolved, external)
    findings += _signature_findings(call_claims, resolved, external)
    return CheckResult(check, sort_findings(findings))


def _module_findings(
    module_claims: list[ModuleClaim],
    resolved: dict[str, dict],
    root: Path,
    interpreter: Path,
    origin: str,
    lookup,
) -> list[Finding]:
    findings: list[Finding] = []
    verdict_cache: dict[str, tuple[Severity, str, list[str]]] = {}

    for claim in module_claims:
        if is_first_party(root, claim.module):
            continue
        info = resolved.get(claim.module)
        if info is None or info.get("found"):
            continue

        top_level = claim.module.split(".")[0]
        if top_level not in verdict_cache:
            verdict_cache[top_level] = _unresolved_verdict(top_level, interpreter, origin, lookup)
        severity, verdict, evidence = verdict_cache[top_level]

        detail = list(evidence)
        if info.get("import_error"):
            detail.append(f"import error: {info['import_error']}")
        findings.append(
            Finding(
                severity=severity,
                check=f"{CHECK_NAME}:python",
                file=claim.file,
                line=claim.line,
                claim=f"import {claim.module}",
                verdict=verdict,
                evidence=detail,
            )
        )
    return findings


def _unresolved_verdict(
    top_level: str, interpreter: Path, origin: str, lookup
) -> tuple[Severity, str, list[str]]:
    base = [
        f"not importable by {interpreter} ({origin})",
        "note: import name and distribution name can differ (e.g. `yaml` ships as `PyYAML`)",
    ]
    on_pypi = lookup(top_level)

    if on_pypi is False:
        return (
            Severity.HIGH,
            "possible-slopsquat",
            [*base, f"https://pypi.org/pypi/{top_level}/json returned 404 - no such project"],
        )
    if on_pypi is True:
        return (
            Severity.MEDIUM,
            "not-installed",
            [*base, f"exists on PyPI: https://pypi.org/project/{top_level}/ - not installed here"],
        )
    return (
        Severity.LOW,
        "unresolvable",
        [*base, "PyPI unreachable, so a missing install cannot be told apart from a fake package"],
    )


def _attribute_findings(
    attribute_claims: list[AttributeClaim], resolved: dict[str, dict], external: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for claim in attribute_claims:
        if claim.module not in external:
            continue
        info = resolved.get(claim.module)
        if not info or not info.get("found") or claim.attribute not in (info.get("missing") or []):
            continue

        exports = info.get("exports") or []
        package = info.get("distribution") or claim.module
        version = info.get("version") or "unknown version"
        location = info.get("location") or "unknown location"

        evidence = [
            f"{package} {version} ({location})",
            f"'{claim.attribute}' not in dir({claim.module}) - {len(exports)} public names exported",
        ]
        ranked = rank_similar_names(claim.attribute, exports)
        if ranked:
            evidence.append("closest real names: " + ", ".join(f"{n} ({s:.2f})" for n, s in ranked))
        else:
            evidence.append("no similarly named export exists")

        findings.append(
            Finding(
                severity=Severity.HIGH,
                check=f"{CHECK_NAME}:python",
                file=claim.file,
                line=claim.line,
                claim=f"{claim.module}.{claim.attribute}" + ("()" if claim.called else ""),
                verdict="missing-attribute",
                evidence=evidence,
            )
        )
    return findings


POSITIONAL_KINDS = ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")
NAMEABLE_KINDS = ("POSITIONAL_OR_KEYWORD", "KEYWORD_ONLY")


def _signature_findings(
    call_claims: list[CallClaim], resolved: dict[str, dict], external: set[str]
) -> list[Finding]:
    """Check call sites against the real signature, and stay silent whenever unsure.

    The guards are the check. Everything below is a reason to say nothing:

    - the callable is absent from `signatures` - the probe already refused it, because it is
      not a plain Python function, has no introspectable signature, or is @overload-ed
    - `*args` in the signature, or `*a` at the call site: arity is unbounded or uncountable
    - `**kwargs` in the signature, or `**kw` at the call site: any keyword may be legitimate

    Arity is only judged on a call with **no keywords at all**. A mixed call like
    `get(url, timeout=5)` is sound to check for an unknown *keyword* - the name is either in
    the signature or it is not, and the positional arguments cannot change that - but working
    out whether the positional count satisfies the required parameters once keywords are also
    filling slots is where an off-by-one becomes a false accusation. That is a v1 limitation,
    not a permanent one.
    """
    findings: list[Finding] = []

    for claim in call_claims:
        if claim.module not in external:
            continue
        info = resolved.get(claim.module)
        if not info or not info.get("found"):
            continue
        described = (info.get("signatures") or {}).get(claim.attribute)
        if not described:
            continue  # the probe declined to describe it, so nothing is claimed

        parameters = described.get("parameters") or []
        kinds = {parameter.get("kind") for parameter in parameters}
        text = described.get("text") or claim.attribute
        location = f"{info.get('distribution') or claim.module} {info.get('version') or ''}".strip()

        if not claim.star_kwargs and "VAR_KEYWORD" not in kinds:
            unknown = [
                keyword
                for keyword in claim.keywords
                if keyword not in {p["name"] for p in parameters if p.get("kind") in NAMEABLE_KINDS}
            ]
            if unknown:
                findings.append(
                    _signature_finding(
                        claim,
                        "unknown-keyword",
                        f"{claim.module}.{claim.attribute}({', '.join(f'{k}=' for k in unknown)})",
                        [
                            f"real signature: {text}",
                            f"resolved from {location}" if location else "",
                            f"no parameter named {', '.join(repr(k) for k in unknown)}",
                        ],
                    )
                )

        arity = _arity_finding(claim, parameters, kinds, text, location)
        if arity is not None:
            findings.append(arity)

    return findings


def _arity_finding(claim, parameters, kinds, text, location) -> Finding | None:
    if claim.star_args or claim.keywords or claim.star_kwargs:
        return None  # only a purely positional call is counted in v1
    if "VAR_POSITIONAL" in kinds:
        return None  # unbounded arity

    slots = [p for p in parameters if p.get("kind") in POSITIONAL_KINDS]
    required = [p for p in slots if not p.get("has_default")]
    required += [
        p for p in parameters if p.get("kind") == "KEYWORD_ONLY" and not p.get("has_default")
    ]

    if claim.positional > len(slots):
        detail = f"takes at most {len(slots)} positional argument(s), called with {claim.positional}"
    elif claim.positional < len(required):
        missing = [p["name"] for p in required[claim.positional :]]
        detail = f"requires {', '.join(missing)}, called with {claim.positional} argument(s)"
    else:
        return None

    return _signature_finding(
        claim,
        "wrong-arity",
        f"{claim.module}.{claim.attribute}() with {claim.positional} positional argument(s)",
        [f"real signature: {text}", f"resolved from {location}" if location else "", detail],
    )


def _signature_finding(claim: CallClaim, verdict: str, summary: str, evidence: list[str]) -> Finding:
    return Finding(
        severity=Severity.HIGH,
        check=f"{CHECK_NAME}:python",
        file=claim.file,
        line=claim.line,
        claim=summary,
        verdict=verdict,
        evidence=[line for line in evidence if line],
    )


def collect_python_claims(
    root: Path, sources: list[Path]
) -> tuple[list[ModuleClaim], list[AttributeClaim], list[CallClaim]]:
    modules: list[ModuleClaim] = []
    attributes: list[AttributeClaim] = []
    calls: list[CallClaim] = []

    for path in sources:
        source = read_source(path)
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        collector = _ClaimCollector(relative_to(path, root))
        collector.visit(tree)
        modules.extend(collector.modules)
        attributes.extend(collector.attributes)
        calls.extend(collector.calls)

    return modules, attributes, calls


class _ClaimCollector(ast.NodeVisitor):
    """Collects imports, module aliases, attribute access, and calls on those attributes."""

    def __init__(self, file: str) -> None:
        self.file = file
        self.modules: list[ModuleClaim] = []
        self.attributes: list[AttributeClaim] = []
        self.calls: list[CallClaim] = []
        self.aliases: dict[str, str] = {}  # local name -> module it refers to
        self.imported: dict[str, tuple[str, str]] = {}  # local name -> (module, attribute)
        self._called_attribute_ids: set[int] = set()

    def visit(self, node: ast.AST) -> None:
        # Imports bind names, so record every one before resolving any attribute access.
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                self._visit_import(child)
            elif isinstance(child, ast.ImportFrom):
                self._visit_import_from(child)
            elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                self._called_attribute_ids.add(id(child.func))

        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                self._visit_attribute(child)
            elif isinstance(child, ast.Call):
                self._visit_call(child)

    def _visit_import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.modules.append(ModuleClaim(alias.name, self.file, node.lineno))
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]

    def _visit_import_from(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return  # relative import: resolved inside the repo, not against the environment
        self.modules.append(ModuleClaim(node.module, self.file, node.lineno))
        for alias in node.names:
            if alias.name == "*":
                continue
            self.imported[alias.asname or alias.name] = (node.module, alias.name)
            self.attributes.append(
                AttributeClaim(node.module, alias.name, self.file, node.lineno, called=False)
            )

    def _visit_call(self, node: ast.Call) -> None:
        """Record `mod.func(...)` and `from mod import func; func(...)`.

        A receiver that is not a plain name - `factory().go()`, `table["k"].go()` - is not
        recorded at all: the object is unknown, so nothing about its parameters is knowable.
        """
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = self.aliases.get(node.func.value.id)
            target = (module, node.func.attr) if module else None
        elif isinstance(node.func, ast.Name):
            target = self.imported.get(node.func.id)
        else:
            target = None

        if target is None:
            return

        module, attribute = target
        self.calls.append(
            CallClaim(
                module=module,
                attribute=attribute,
                file=self.file,
                line=node.lineno,
                positional=sum(1 for arg in node.args if not isinstance(arg, ast.Starred)),
                keywords=tuple(kw.arg for kw in node.keywords if kw.arg is not None),
                star_args=any(isinstance(arg, ast.Starred) for arg in node.args),
                star_kwargs=any(kw.arg is None for kw in node.keywords),
            )
        )

    def _visit_attribute(self, node: ast.Attribute) -> None:
        if not isinstance(node.value, ast.Name):
            return
        module = self.aliases.get(node.value.id)
        if module is None:
            return
        self.attributes.append(
            AttributeClaim(
                module=module,
                attribute=node.attr,
                file=self.file,
                line=node.lineno,
                called=id(node) in self._called_attribute_ids,
            )
        )


def find_interpreter(root: Path) -> tuple[Path | None, str]:
    """Locate the audited repo's own interpreter. Never falls back to ours."""
    for relative in INTERPRETER_CANDIDATES:
        candidate = root / relative
        if candidate.is_file():
            return candidate, relative.as_posix()

    poetry = run_tool(["poetry", "env", "info", "--path"], cwd=root, timeout=15)
    if poetry.ok and poetry.stdout.strip():
        for suffix in (Path("bin") / "python", Path("Scripts") / "python.exe"):
            candidate = Path(poetry.stdout.strip()) / suffix
            if candidate.is_file():
                return candidate, "poetry env"
    return None, ""


def run_probe(interpreter: Path, wanted: dict[str, list[str]]) -> tuple[dict[str, dict], str | None]:
    request = json.dumps({"modules": wanted})
    probe = run_tool(
        [str(interpreter), str(PROBE_PATH)],
        timeout=PROBE_TIMEOUT_SECONDS,
        stdin=request,
    )
    if not probe.ok:
        reason = probe.error or (probe.stderr.strip().splitlines() or ["probe failed"])[-1]
        return {}, f"could not resolve imports with {interpreter}: {reason}"

    try:
        payload = json.loads(probe.stdout)
    except json.JSONDecodeError as error:
        return {}, f"probe returned invalid JSON: {error}"

    return payload.get("modules") or {}, None


def is_first_party(root: Path, module: str) -> bool:
    """True when the module is defined in this repository rather than installed."""
    top_level = module.split(".")[0]
    for base in (root, root / "src"):
        if (base / f"{top_level}.py").is_file() or (base / top_level / "__init__.py").is_file():
            return True
    return False


def rank_similar_names(wanted: str, exports: list[str]) -> list[tuple[str, float]]:
    scored = [
        (name, difflib.SequenceMatcher(None, wanted.lower(), name.lower()).ratio())
        for name in exports
    ]
    scored.sort(key=lambda pair: (-pair[1], pair[0]))
    return [pair for pair in scored[:MAX_RANKED_NAMES] if pair[1] > 0.4]


def pypi_package_exists(name: str, timeout: float = PYPI_TIMEOUT_SECONDS) -> bool | None:
    """True if on PyPI, False on a definitive 404, None when the network could not answer."""
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "trustlayer-audit"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as error:
        return False if error.code == 404 else None
    except (urllib.error.URLError, OSError, ValueError):
        return None


# ----------------------------------------------------------------------- TypeScript path


def check_typescript_apis(root: Path) -> CheckResult:
    check = f"{CHECK_NAME}:typescript"

    sources = list(iter_source_files(root, TYPESCRIPT_SUFFIXES))
    if not sources:
        return CheckResult(check, skipped=True, skip_reason="no TypeScript or JavaScript sources found")

    if not (NODE_HELPER_DIR / "node_modules" / "ts-morph").is_dir():
        return CheckResult(
            check,
            skipped=True,
            skip_reason=(
                "ts-morph helper not installed; run "
                f"`npm install --prefix {NODE_HELPER_DIR}`"
            ),
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

    if payload.get("unresolvable"):
        return CheckResult(
            check,
            findings=[
                Finding(
                    severity=Severity.LOW,
                    check=check,
                    file=payload.get("file", "package.json"),
                    line=payload.get("line", 1),
                    claim="TypeScript import resolution",
                    verdict="unresolvable",
                    evidence=[payload["unresolvable"]],
                )
            ],
        )

    findings = [
        Finding(
            severity=Severity(item["severity"]),
            check=check,
            file=item["file"],
            line=item["line"],
            claim=item["claim"],
            verdict=item["verdict"],
            evidence=item.get("evidence") or [],
        )
        for item in payload.get("findings") or []
    ]
    return CheckResult(check, sort_findings(findings))
