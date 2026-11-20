"""gha-refs: action references that cannot resolve. Offline - git and HTTP are stubbed.

The live behaviour (setup-uv@v10 -> nonexistent-ref naming v10.3.3; checkout input typo ->
unknown-input) was run by hand on 2026-11-20 against github.com.
"""

from __future__ import annotations

from pathlib import Path
import textwrap

from trustlayer.checks.base import Severity
from trustlayer.checks.gha_refs import Remote, _natural, check_gha_refs


ROOT = Path(__file__).resolve().parents[1]

REMOTES = {
    ("actions", "checkout"): Remote(frozenset({"main", "v4", "v4.2.2", "v7", "v7.0.1"})),
    ("astral-sh", "setup-uv"): Remote(frozenset({"main", "v7", "v10.2.0", "v10.3.3", "v9.0.0"})),
    ("acme", "multi"): Remote(frozenset({"v1"})),
}
CHECKOUT_META = {"name": "Checkout", "inputs": {"fetch-depth": {}, "ref": {}, "Token": {}}}


def remote(owner, repo):
    return REMOTES.get((owner, repo), Remote(None, "repository not found"))


def metadata(owner, repo, ref, path):
    if (owner, repo) == ("actions", "checkout"):
        return CHECKOUT_META, True
    if (owner, repo, path) == ("acme", "multi", "lint"):
        return {"inputs": {"strict": {}}}, True
    if (owner, repo, path) == ("acme", "multi", "missing"):
        return None, False
    return {"inputs": {}}, True


def workflow(tmp_path: Path, steps: str, name: str = "ci.yml") -> Path:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        + textwrap.indent(textwrap.dedent(steps), "      ")
    )
    return tmp_path


def run(root: Path):
    return check_gha_refs(root, remote=remote, metadata=metadata)


def verdicts(result):
    return sorted((f.verdict, f.claim) for f in result.findings)


def test_real_refs_and_declared_inputs_are_silent(tmp_path):
    root = workflow(tmp_path, """
        - uses: actions/checkout@v7
          with:
            fetch-depth: 0
            token: x
        - uses: astral-sh/setup-uv@v10.3.3
        - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        - uses: docker://alpine:3.20
        - run: echo no uses here
    """)
    result = run(root)

    assert result.skipped is False
    assert result.findings == []


def test_a_floating_tag_that_was_never_published(tmp_path):
    result = run(workflow(tmp_path, "- uses: astral-sh/setup-uv@v10\n"))
    finding = result.findings[0]

    assert (finding.verdict, finding.severity) == ("nonexistent-ref", Severity.HIGH)
    assert "no branch or tag named 'v10'" in finding.evidence[0]
    assert finding.evidence[1].endswith("v10.2.0, v10.3.3")
    assert finding.line == 7


def test_an_unknown_input_is_medium_because_github_only_warns(tmp_path):
    result = run(workflow(tmp_path, """
        - uses: actions/checkout@v7
          with:
            fetch-tags-too: true
    """))
    finding = result.findings[0]

    assert (finding.verdict, finding.severity) == ("unknown-input", Severity.MEDIUM)
    assert "fetch-tags-too" in finding.evidence[1]


def test_a_private_or_missing_repo_is_a_note_never_a_finding(tmp_path):
    result = run(workflow(tmp_path, "- uses: my-org/internal-action@v1\n"))

    assert result.findings == []
    assert any("my-org/internal-action: not judged" in note for note in result.notes)


def test_subdirectory_actions_and_missing_metadata(tmp_path):
    result = run(workflow(tmp_path, """
        - uses: acme/multi/lint@v1
          with:
            strict: true
            fix: true
        - uses: acme/multi/missing@v1
    """))

    assert verdicts(result) == [
        ("no-action-metadata", "acme/multi/missing@v1"),
        ("unknown-input", "acme/multi/lint@v1"),
    ]


def test_local_actions_are_checked_on_disk(tmp_path):
    root = workflow(tmp_path, """
        - uses: ./.github/actions/setup
          with:
            python: "3.12"
        - uses: ./.github/actions/absent
    """)
    action = root / ".github" / "actions" / "setup"
    action.mkdir(parents=True)
    (action / "action.yml").write_text("name: setup\ninputs:\n  python-version: {}\nruns:\n  using: composite\n  steps: []\n")

    assert verdicts(run(root)) == [
        ("missing-local-action", "./.github/actions/absent"),
        ("unknown-input", "./.github/actions/setup"),
    ]


def test_reusable_workflow_calls_and_expressions_are_not_judged(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "call.yml").write_text(
        "on: [push]\njobs:\n  call:\n    uses: acme/multi/.github/workflows/x.yml@v9\n"
    )
    workflow(tmp_path, "- uses: acme/multi@${{ inputs.ref }}\n")

    assert run(tmp_path).findings == []


def test_composite_action_steps_at_the_root_are_checked(tmp_path):
    (tmp_path / "action.yml").write_text(
        "name: x\nruns:\n  using: composite\n  steps:\n    - uses: astral-sh/setup-uv@v10\n"
    )
    assert verdicts(run(tmp_path)) == [("nonexistent-ref", "astral-sh/setup-uv@v10")]


def test_input_names_compare_case_insensitively(tmp_path):
    root = workflow(tmp_path, "- uses: actions/checkout@v7\n  with:\n    TOKEN: x\n")

    assert run(root).findings == []


def test_no_workflows_is_a_skip(tmp_path):
    assert check_gha_refs(tmp_path, remote=remote, metadata=metadata).skipped is True


def test_each_repository_is_listed_once(tmp_path):
    calls = []

    def counting(owner, repo):
        calls.append((owner, repo))
        return remote(owner, repo)

    root = workflow(tmp_path, "- uses: actions/checkout@v7\n- uses: actions/checkout@v4\n")
    check_gha_refs(root, remote=counting, metadata=metadata)

    assert calls == [("actions", "checkout")]


def test_versions_sort_naturally():
    assert sorted(["v10.3.3", "v9.0.0", "v10.2.0", "v10.10.0"], key=_natural) == [
        "v9.0.0", "v10.2.0", "v10.3.3", "v10.10.0",
    ]


def test_the_repositorys_own_workflows_reference_real_tags():
    """The refs in action.yml and .github/workflows were checked by hand; pin the shapes."""
    result = check_gha_refs(
        ROOT,
        remote=lambda owner, repo: Remote(frozenset({"v7", "v10.3.3", "v4"})),
        metadata=lambda *a: ({"inputs": {
            "python-version": {}, "sarif_file": {}, "category": {}, "fetch-depth": {},
            "command": {}, "sarif-category": {}, "fail-on": {}, "token": {}, "args": {},
        }}, True),
    )
    assert result.findings == [], result.findings
