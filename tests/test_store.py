"""Persistence tests.

Every test uses an injected db_path. Nothing here may touch ~/.trustlayer, which is a
real user directory - one test asserts that explicitly.
"""

import json
from pathlib import Path

import pytest

from trustlayer.checks.base import Finding, Severity, run_tool
from trustlayer.checks.fail_open import check_python_fail_open
from trustlayer.detect import profile_repository
from trustlayer.report import Report
from trustlayer.store import (
    DEFAULT_DB_PATH,
    connect,
    diff_runs,
    get_run,
    git_info,
    latest_run_per_repo,
    list_runs,
    previous_run,
    run_findings,
    save_run,
)
from trustlayer.suite import SuiteState


FIXTURES = Path(__file__).parent / "fixtures"


def report_for(root: Path, findings=None) -> Report:
    from trustlayer.checks.base import CheckResult

    results = [CheckResult("fail-open:python", findings)] if findings is not None else [
        check_python_fail_open(root)
    ]
    return Report(root.resolve(), profile_repository(root), results, SuiteState())


def finding(check="fail-open:python", severity=Severity.HIGH, file="app.py", line=11,
            claim="getenv(...)", verdict="env-default-degrades-url", evidence=None):
    return Finding(
        severity=severity, check=check, file=file, line=line, claim=claim,
        verdict=verdict, evidence=evidence if evidence is not None else ["line", "why"],
    )


# ------------------------------------------------------------------ schema + round-trip


def test_the_reserved_word_column_round_trips(tmp_path):
    """`check` is a SQL reserved word: an unquoted CREATE TABLE is a syntax error.

    If the quoting regressed anywhere, this fails rather than silently storing nothing.
    """
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-dirty"

    run_id = save_run(report_for(root), 1.5, db_path=db)
    rows = run_findings(run_id, db_path=db)

    assert rows, "no findings persisted"
    assert all(row.check for row in rows)
    assert {row.check for row in rows} == {"fail-open:python"}


def test_a_run_round_trips_with_its_findings(tmp_path):
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-dirty"
    report = report_for(root)

    run_id = save_run(report, 2.25, db_path=db)
    stored = get_run(run_id, db_path=db)
    rows = run_findings(run_id, db_path=db)

    assert stored is not None
    assert stored.repo_name == "failopen-dirty"
    assert stored.duration_s == 2.25
    assert stored.counts == {
        "high": 3, "medium": 3, "low": 0, "total": 6,
    }
    assert len(rows) == len(report.findings)
    assert rows[0].evidence  # evidence survives the JSON round-trip


def test_evidence_survives_as_a_list(tmp_path):
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-clean"
    run_id = save_run(report_for(root, [finding(evidence=["a", "b", "c"])]), 0.1, db_path=db)

    assert run_findings(run_id, db_path=db)[0].evidence == ["a", "b", "c"]


def test_deleting_a_run_cascades_to_its_findings(tmp_path):
    db = tmp_path / "runs.db"
    run_id = save_run(report_for(FIXTURES / "failopen-clean", [finding()]), 0.1, db_path=db)

    with connect(db) as connection:
        connection.execute("DELETE FROM runs WHERE id = ?", (run_id,))

    assert run_findings(run_id, db_path=db) == []


# ------------------------------------------------------------------------ git honesty


def _git_repo(tmp_path: Path, *, dirty: bool) -> Path:
    """A real git repository with a known state.

    The previous version of these tests asserted against TrustLayer's own checkout and only
    passed while it happened to have uncommitted work - so committing made the suite fail.
    A test about dirtiness has to own the tree whose dirtiness it asserts.
    """
    root = tmp_path / ("dirty" if dirty else "clean")
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("x = 1\n")

    def git(*args):
        run_tool(["git", *args], cwd=root, timeout=30)

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Test")
    git("config", "commit.gpgsign", "false")
    git("add", "-A")
    git("commit", "-q", "-m", "initial")
    if dirty:
        (root / "src" / "app.py").write_text("x = 2  # uncommitted\n")
    return root


def test_a_dirty_tree_is_recorded_as_dirty(tmp_path):
    """A run against uncommitted work must never look like a run against a commit."""
    db = tmp_path / "runs.db"
    root = _git_repo(tmp_path, dirty=True)

    run_id = save_run(report_for(root, [finding()]), 0.1, db_path=db)

    stored = get_run(run_id, db_path=db)
    assert stored.dirty is True
    assert stored.git_sha  # a dirty tree still has a HEAD
    assert stored.summary["git_root"]
    assert stored.summary["path_is_repo_root"] is True


def test_a_clean_tree_is_not_recorded_as_dirty(tmp_path):
    """The other half of the same contract, which nothing pinned before."""
    db = tmp_path / "runs.db"
    root = _git_repo(tmp_path, dirty=False)

    run_id = save_run(report_for(root, [finding()]), 0.1, db_path=db)

    assert get_run(run_id, db_path=db).dirty is False


def test_auditing_a_subdirectory_records_the_parent_repo(tmp_path):
    """Auditing a subdirectory records the *parent* repo's SHA, so the flag has to say so."""
    db = tmp_path / "runs.db"
    root = _git_repo(tmp_path, dirty=False)

    run_id = save_run(report_for(root / "src", [finding()]), 0.1, db_path=db)

    stored = get_run(run_id, db_path=db)
    assert stored.summary["path_is_repo_root"] is False
    assert stored.summary["git_root"] == str(root.resolve())


def test_a_directory_outside_git_records_no_sha(tmp_path):
    db = tmp_path / "runs.db"
    outside = tmp_path / "loose"
    (outside / "src").mkdir(parents=True)
    (outside / "src" / "a.py").write_text("x = 1\n")

    info = git_info(outside)
    run_id = save_run(report_for(outside, [finding()]), 0.1, db_path=db)

    assert info.sha is None and info.root is None
    assert get_run(run_id, db_path=db).git_sha is None
    assert get_run(run_id, db_path=db).short_sha == "no-git"


# ------------------------------------------------------------------------ diff semantics


def test_a_finding_that_only_moved_lines_is_unchanged(tmp_path):
    """Adding an import above a finding must not read as fixed-and-reintroduced."""
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-clean"

    before = save_run(report_for(root, [finding(line=11)]), 0.1, db_path=db)
    after = save_run(report_for(root, [finding(line=24)]), 0.1, db_path=db)

    appeared, disappeared = diff_runs(before, after, db_path=db)

    assert appeared == []
    assert disappeared == []


def test_a_genuinely_new_finding_appears(tmp_path):
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-clean"

    before = save_run(report_for(root, [finding()]), 0.1, db_path=db)
    after = save_run(
        report_for(root, [finding(), finding(claim="other()", verdict="gate-fails-open")]),
        0.1, db_path=db,
    )

    appeared, disappeared = diff_runs(before, after, db_path=db)

    assert [f.claim for f in appeared] == ["other()"]
    assert disappeared == []


def test_a_fixed_finding_disappears(tmp_path):
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-clean"

    before = save_run(report_for(root, [finding(), finding(claim="gone()")]), 0.1, db_path=db)
    after = save_run(report_for(root, [finding()]), 0.1, db_path=db)

    appeared, disappeared = diff_runs(before, after, db_path=db)

    assert appeared == []
    assert [f.claim for f in disappeared] == ["gone()"]


# ----------------------------------------------------------------------------- queries


def test_runs_are_listed_newest_first_and_scoped_to_one_repo(tmp_path):
    db = tmp_path / "runs.db"
    a, b = FIXTURES / "failopen-clean", FIXTURES / "failopen-dirty"

    first = save_run(report_for(a, [finding()]), 0.1, db_path=db)
    second = save_run(report_for(a, [finding()]), 0.1, db_path=db)
    save_run(report_for(b, [finding()]), 0.1, db_path=db)

    runs = list_runs(a, limit=10, db_path=db)

    assert [run.id for run in runs] == [second, first]
    assert all(run.repo_name == "failopen-clean" for run in runs)


def test_latest_run_per_repo_returns_one_row_each(tmp_path):
    db = tmp_path / "runs.db"
    a, b = FIXTURES / "failopen-clean", FIXTURES / "failopen-dirty"
    save_run(report_for(a, [finding()]), 0.1, db_path=db)
    save_run(report_for(a, [finding()]), 0.1, db_path=db)
    save_run(report_for(b, [finding()]), 0.1, db_path=db)

    rows = latest_run_per_repo(db_path=db)

    assert sorted(row.repo_name for row in rows) == ["failopen-clean", "failopen-dirty"]


def test_previous_run_walks_back_one(tmp_path):
    db = tmp_path / "runs.db"
    root = FIXTURES / "failopen-clean"
    first = save_run(report_for(root, [finding()]), 0.1, db_path=db)
    second = save_run(report_for(root, [finding()]), 0.1, db_path=db)

    latest = get_run(second, db_path=db)

    assert previous_run(latest, db_path=db).id == first
    assert previous_run(get_run(first, db_path=db), db_path=db) is None


def test_summary_json_is_valid_json_with_the_git_context(tmp_path):
    db = tmp_path / "runs.db"
    run_id = save_run(report_for(FIXTURES / "failopen-clean", [finding()]), 0.1, db_path=db)

    with connect(db) as connection:
        raw = connection.execute(
            "SELECT summary_json FROM runs WHERE id = ?", (run_id,)
        ).fetchone()[0]

    payload = json.loads(raw)
    assert {"summary", "exit_code", "git_root", "git_dirty", "path_is_repo_root"} <= set(payload)


@pytest.mark.parametrize("_", [0])
def test_tests_never_write_to_the_real_home_database(_, tmp_path):
    """The default path is a real user directory; every test must inject its own."""
    existed = DEFAULT_DB_PATH.exists()
    before = DEFAULT_DB_PATH.stat().st_mtime_ns if existed else None

    save_run(report_for(FIXTURES / "failopen-clean", [finding()]), 0.1, db_path=tmp_path / "x.db")

    if existed:
        assert DEFAULT_DB_PATH.stat().st_mtime_ns == before
    else:
        assert not DEFAULT_DB_PATH.exists()
