"""UI route tests.

The UI is read-only over the run database: it can render runs and nothing else. These
drive it through a real ASGI client against an injected database.
"""

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from trustlayer.checks.base import CheckResult, Finding, Severity
from trustlayer.detect import profile_repository
from trustlayer.report import Report
from trustlayer.store import save_run
from trustlayer.suite import SuiteState
from trustlayer.ui import create_app


FIXTURES = Path(__file__).parent / "fixtures"
ROOT = FIXTURES / "failopen-clean"


def finding(claim="getenv(...)", severity=Severity.HIGH, line=11, verdict="env-default-degrades-url"):
    return Finding(
        severity=severity, check="fail-open:python", file="app.py", line=line,
        claim=claim, verdict=verdict, evidence=["11: os.getenv('X', '')", "why it matters"],
    )


def report_with(findings):
    return Report(ROOT.resolve(), profile_repository(ROOT), [CheckResult("fail-open:python", findings)], SuiteState())


@pytest.fixture
def seeded(tmp_path):
    db = tmp_path / "runs.db"
    first = save_run(report_with([finding(), finding(claim="gone()")]), 0.5, db_path=db)
    second = save_run(report_with([finding(), finding(claim="new()", severity=Severity.MEDIUM)]), 0.6, db_path=db)
    return db, first, second


@pytest.fixture
def client(seeded):
    db, _, _ = seeded
    return TestClient(create_app(db))


def test_project_list_renders_the_repo_and_its_counts(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "failopen-clean" in response.text
    assert "high" in response.text and "medium" in response.text


def test_project_list_is_empty_but_valid_with_no_runs(tmp_path):
    response = TestClient(create_app(tmp_path / "empty.db")).get("/")

    assert response.status_code == 200
    assert "No runs recorded yet" in response.text


def test_run_detail_groups_findings_by_check(client, seeded):
    _, _, second = seeded

    response = client.get(f"/runs/{second}")

    assert response.status_code == 200
    assert "fail-open:python" in response.text
    assert "app.py:11" in response.text


def test_run_detail_404s_for_an_unknown_run(client):
    assert client.get("/runs/9999").status_code == 404


def test_evidence_is_served_as_an_htmx_fragment(client, seeded):
    _, _, second = seeded
    detail = client.get(f"/runs/{second}")
    # Evidence is not inlined; it loads on expand.
    assert "why it matters" not in detail.text

    finding_id = 3  # first finding of the second run
    fragment = client.get(f"/runs/{second}/finding/{finding_id}")

    assert fragment.status_code == 200
    assert "<html" not in fragment.text.lower()  # a fragment, not a page
    assert "why it matters" in fragment.text


def test_compare_shows_appeared_and_disappeared(client, seeded):
    _, first, second = seeded

    response = client.get(f"/compare?a={first}&b={second}")

    assert response.status_code == 200
    assert "new()" in response.text  # appeared in the second run
    assert "gone()" in response.text  # disappeared after the first


def test_compare_rejects_runs_from_different_repositories(tmp_path):
    db = tmp_path / "runs.db"
    a = save_run(report_with([finding()]), 0.1, db_path=db)
    other = Report(
        (FIXTURES / "failopen-dirty").resolve(),
        profile_repository(FIXTURES / "failopen-dirty"),
        [CheckResult("fail-open:python", [finding()])],
        SuiteState(),
    )
    b = save_run(other, 0.1, db_path=db)

    response = TestClient(create_app(db)).get(f"/compare?a={a}&b={b}")

    assert response.status_code == 400


def test_severity_is_never_colour_alone(client, seeded):
    """A status colour must ship with its label, so the word appears beside the mark."""
    _, _, second = seeded

    text = client.get(f"/runs/{second}").text

    assert "mark-high" in text  # the colored mark
    assert "high" in text  # and the word, always
