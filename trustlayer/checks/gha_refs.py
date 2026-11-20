"""GitHub Actions `uses:` references that cannot resolve, and inputs the action does not take.

Opt-in: it contacts github.com. Model-written workflows invent action versions as readily as
they invent package names - `astral-sh/setup-uv@v10` looks right, but setup-uv publishes only
exact `v10.x.y` tags past v7, so that line fails at runtime.

What is claimed, and on what evidence:

- **nonexistent-ref** (HIGH): `git ls-remote https://github.com/<owner>/<repo>` succeeds, so the
  repository is public, and lists no branch or tag with the referenced name. A 40-character
  commit SHA is not judged here (ls-remote only lists ref tips).
- **no-action-metadata** (HIGH): the ref exists, but neither `action.yml` nor `action.yaml` is
  at the referenced path on raw.githubusercontent.com - the runner needs one of them.
- **missing-local-action** (HIGH, offline): `uses: ./path` with no metadata file at that path.
- **unknown-input** (MEDIUM): a `with:` key the action's metadata does not declare. GitHub
  only warns ("Unexpected input"), so the step still runs - with the input ignored.

What is never claimed: a repository `ls-remote` cannot read. A private or internal action is
indistinguishable from a nonexistent one without credentials, so that is a note, not a
finding. Docker references, expressions and reusable-workflow calls are not judged.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

import yaml

from trustlayer.checks.base import CheckResult, Finding, Severity, run_tool, sort_findings


CHECK_NAME = "gha-refs"
LS_REMOTE_TIMEOUT_SECONDS = 30
RAW_TIMEOUT_SECONDS = 15
RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
REMOTE_URL = "https://github.com/{owner}/{repo}"
USES_RE = re.compile(r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)(?P<path>(?:/[^@]+)?)@(?P<ref>.+)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
METADATA_NAMES = ("action.yml", "action.yaml")


@dataclass(frozen=True)
class Remote:
    """What `git ls-remote` said. `refs` is None when the repository could not be read."""

    refs: frozenset[str] | None
    error: str | None = None


@dataclass(frozen=True)
class UsesSite:
    file: str
    line: int
    uses: str
    inputs: tuple[str, ...]


def ls_remote(owner: str, repo: str) -> Remote:
    """Branch and tag names of a public repository. No credentials are ever offered."""
    run = _run_git(["git", "ls-remote", "--heads", "--tags", REMOTE_URL.format(owner=owner, repo=repo)])
    if not run.ok:
        reason = run.error or (run.stderr.strip().splitlines() or ["git ls-remote failed"])[-1]
        return Remote(None, reason)
    names: set[str] = set()
    for line in run.stdout.splitlines():
        _, _, ref = line.partition("\t")
        ref = ref.removesuffix("^{}")
        for prefix in ("refs/heads/", "refs/tags/"):
            if ref.startswith(prefix):
                names.add(ref[len(prefix):])
    return Remote(frozenset(names))


def _run_git(command: list[str]):
    # A private repository must fail, never prompt for a password or reach for a keychain.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": "",
           "GCM_INTERACTIVE": "never"}
    return run_tool(command, timeout=LS_REMOTE_TIMEOUT_SECONDS, env=env)


def fetch_metadata(owner: str, repo: str, ref: str, path: str) -> tuple[dict | None, bool | None]:
    """(metadata, found). found is False on a definitive 404 for both names, None if unknown."""
    for name in METADATA_NAMES:
        url = RAW_URL.format(owner=owner, repo=repo, ref=ref, path=f"{path}/{name}".lstrip("/"))
        request = urllib.request.Request(url, headers={"User-Agent": "trustlayer-audit"})
        try:
            with urllib.request.urlopen(request, timeout=RAW_TIMEOUT_SECONDS) as response:
                return _parse_metadata(response.read().decode("utf-8", errors="replace")), True
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            return None, None
        except (urllib.error.URLError, OSError, ValueError):
            return None, None
    return None, False


def _parse_metadata(text: str) -> dict | None:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def check_gha_refs(
    root: Path,
    *,
    remote: Callable[[str, str], Remote] = ls_remote,
    metadata: Callable[[str, str, str, str], tuple[dict | None, bool | None]] = fetch_metadata,
) -> CheckResult:
    files = _workflow_files(root)
    if not files:
        return CheckResult(CHECK_NAME, skipped=True, skip_reason="no GitHub Actions workflows or action.yml found")

    findings: list[Finding] = []
    notes: list[str] = []
    remotes: dict[tuple[str, str], Remote] = {}
    metadata_cache: dict[tuple[str, str, str, str], tuple[dict | None, bool | None]] = {}

    for path in files:
        relative = path.relative_to(root).as_posix()
        for site in _uses_sites(path, relative):
            if site.uses.startswith("./"):
                findings.extend(_local(root, site))
                continue
            match = USES_RE.match(site.uses)
            if match is None or "${{" in site.uses:
                continue  # docker://, expressions, or a shape this check does not judge
            owner, repo, sub, ref = match["owner"], match["repo"], match["path"].strip("/"), match["ref"]
            if sub.endswith((".yml", ".yaml")):
                continue  # a reusable workflow call, not an action

            key = (owner.lower(), repo.lower())
            if key not in remotes:
                remotes[key] = remote(owner, repo)
            listed = remotes[key]
            if listed.refs is None:
                notes.append(
                    f"{owner}/{repo}: not judged - could not read the repository "
                    f"(private, renamed, or nonexistent: {listed.error})"
                )
                continue
            if not SHA_RE.match(ref) and ref not in listed.refs:
                findings.append(_nonexistent_ref(site, owner, repo, ref, listed.refs))
                continue

            meta_key = (owner, repo, ref, sub)
            if meta_key not in metadata_cache:
                metadata_cache[meta_key] = metadata(owner, repo, ref, sub)
            data, found = metadata_cache[meta_key]
            if found is False:
                findings.append(
                    _finding(
                        Severity.HIGH, site, "no-action-metadata",
                        f"{owner}/{repo}@{ref} exists, but there is no action.yml or action.yaml "
                        f"at '{sub or '/'}' (both returned 404 from raw.githubusercontent.com)",
                        "the runner cannot load an action without its metadata file",
                    )
                )
            elif data is not None:
                findings.extend(_inputs(site, data, f"{owner}/{repo}@{ref}"))

    return CheckResult(CHECK_NAME, sort_findings(findings), notes=sorted(set(notes)))


def _workflow_files(root: Path) -> list[Path]:
    found = sorted((root / ".github" / "workflows").glob("*.y*ml")) if (root / ".github").is_dir() else []
    found += [root / name for name in METADATA_NAMES if (root / name).is_file()]
    return [path for path in found if path.suffix in (".yml", ".yaml")]


def _uses_sites(path: Path, relative: str) -> list[UsesSite]:
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return []
    lines = text.splitlines()
    steps: list[dict] = []
    if isinstance(data, dict):
        for job in (data.get("jobs") or {}).values():
            if isinstance(job, dict):
                steps.extend(step for step in job.get("steps") or [] if isinstance(step, dict))
        runs = data.get("runs")
        if isinstance(runs, dict):
            steps.extend(step for step in runs.get("steps") or [] if isinstance(step, dict))

    sites = []
    for step in steps:
        uses = step.get("uses")
        if not isinstance(uses, str) or not uses.strip():
            continue
        with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
        sites.append(
            UsesSite(relative, _line_of(lines, uses.strip()), uses.strip(), tuple(str(k) for k in with_block))
        )
    return sites


def _local(root: Path, site: UsesSite) -> list[Finding]:
    directory = (root / site.uses).resolve()
    if root.resolve() not in (directory, *directory.parents):
        return []
    for name in METADATA_NAMES:
        candidate = directory / name
        if candidate.is_file():
            data = _parse_metadata(candidate.read_text(encoding="utf-8", errors="replace"))
            return _inputs(site, data, site.uses) if data else []
    return [
        _finding(
            Severity.HIGH, site, "missing-local-action",
            f"no action.yml or action.yaml in {site.uses} (checked on disk)",
        )
    ]


def _inputs(site: UsesSite, data: dict, label: str) -> list[Finding]:
    declared = data.get("inputs")
    if not isinstance(declared, dict):
        if site.inputs:
            declared = {}
        else:
            return []
    # Inputs reach the action as INPUT_<NAME>, upper-cased, so names compare case-insensitively.
    known = {str(name).lower() for name in declared}
    unknown = [name for name in site.inputs if name.lower() not in known]
    if not unknown:
        return []
    return [
        _finding(
            Severity.MEDIUM, site, "unknown-input",
            f"{label} declares inputs: {', '.join(sorted(known)) or 'none'}",
            f"not among them: {', '.join(unknown)} - GitHub warns 'Unexpected input' and ignores it",
        )
    ]


def _nonexistent_ref(site: UsesSite, owner: str, repo: str, ref: str, refs: frozenset[str]) -> Finding:
    nearby = sorted((name for name in refs if name.startswith(ref)), key=_natural)[-5:]
    evidence = [
        (
            f"git ls-remote {REMOTE_URL.format(owner=owner, repo=repo)} lists {len(refs)} branches "
            f"and tags, and no branch or tag named '{ref}'"
        ),
    ]
    if nearby:
        evidence.append(f"refs that do exist with that prefix: {', '.join(nearby)}")
    return _finding(Severity.HIGH, site, "nonexistent-ref", *evidence)


def _natural(name: str) -> list:
    """`v10.3.3` after `v10.2.0` after `v9.9.9`: compare digit runs as numbers."""
    return [(0, int(part)) if part.isdigit() else (1, part) for part in re.split(r"(\d+)", name)]


def _finding(severity: Severity, site: UsesSite, verdict: str, *evidence: str) -> Finding:
    return Finding(severity, CHECK_NAME, site.file, site.line, site.uses, verdict, list(evidence))


def _line_of(lines: list[str], uses: str) -> int:
    return next(
        (number for number, line in enumerate(lines, start=1) if "uses:" in line and uses in line), 1
    )
