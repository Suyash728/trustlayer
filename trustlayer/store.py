"""Run persistence, so "is this repo getting better or worse" has an answer.

SQLite at ~/.trustlayer/runs.db. Runs are keyed to the git SHA, which makes a run
comparable to a commit - but only when the tree was clean, so `git_dirty` is recorded
alongside it and the UI and CLI both surface it. A run against uncommitted work must
never be silently mistaken for a run against a commit.

`check` is a reserved word in SQL: `CREATE TABLE t (check TEXT)` is a syntax error. It is
quoted as "check" in every statement here. Unquoting it anywhere fails loudly at table
creation, which is why the round-trip test is load-bearing rather than decorative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3

from trustlayer.checks.base import run_tool
from trustlayer.report import Report, to_dict


DEFAULT_DB_PATH = Path.home() / ".trustlayer" / "runs.db"
GIT_TIMEOUT_SECONDS = 15

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_path    TEXT NOT NULL,
    repo_name    TEXT NOT NULL,
    git_sha      TEXT,
    started_at   TEXT NOT NULL,
    duration_s   REAL NOT NULL,
    summary_json TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    "check"  TEXT NOT NULL,
    severity TEXT NOT NULL,
    file     TEXT NOT NULL,
    line     INTEGER NOT NULL,
    claim    TEXT NOT NULL,
    verdict  TEXT NOT NULL,
    evidence TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS registry_cache (
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name)
) STRICT;

CREATE INDEX IF NOT EXISTS runs_by_repo ON runs (repo_path, started_at DESC);
CREATE INDEX IF NOT EXISTS findings_by_run ON findings (run_id);
"""

REGISTRY_CACHE_TTL_HOURS = 24
SQLITE_PARAMETER_CHUNK = 500


@dataclass(frozen=True)
class GitInfo:
    sha: str | None = None
    root: str | None = None
    dirty: bool = False
    path_is_repo_root: bool = False

    @property
    def short_sha(self) -> str:
        return self.sha[:7] if self.sha else "no-git"


@dataclass(frozen=True)
class RunRow:
    id: int
    repo_path: str
    repo_name: str
    git_sha: str | None
    started_at: str
    duration_s: float
    summary: dict = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return self.summary.get("summary") or {"high": 0, "medium": 0, "low": 0, "total": 0}

    @property
    def short_sha(self) -> str:
        return self.git_sha[:7] if self.git_sha else "no-git"

    @property
    def dirty(self) -> bool:
        return bool(self.summary.get("git_dirty"))

    @property
    def exit_code(self) -> int:
        return int(self.summary.get("exit_code", 0))


@dataclass(frozen=True)
class FindingRow:
    id: int
    run_id: int
    check: str
    severity: str
    file: str
    line: int
    claim: str
    verdict: str
    evidence: list[str] = field(default_factory=list)

    @property
    def identity(self) -> tuple[str, str, str, str]:
        """What makes two findings "the same" across runs.

        Line is deliberately excluded: a finding that moved because someone added an
        import above it is the same finding, and including the line would turn one
        unrelated edit into a screenful of false churn.
        """
        return (self.check, self.file, self.claim, self.verdict)


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open (and create) the run database. Callers own closing it."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA)
    return connection


def git_info(path: Path | str) -> GitInfo:
    """Read git context. Not a git repo is a fact, not an error."""
    target = Path(path).resolve()

    root = run_tool(["git", "rev-parse", "--show-toplevel"], cwd=target, timeout=GIT_TIMEOUT_SECONDS)
    if not root.ok or not root.stdout.strip():
        return GitInfo()

    repo_root = root.stdout.strip()
    sha = run_tool(["git", "rev-parse", "HEAD"], cwd=target, timeout=GIT_TIMEOUT_SECONDS)
    status = run_tool(["git", "status", "--porcelain"], cwd=target, timeout=GIT_TIMEOUT_SECONDS)

    return GitInfo(
        sha=sha.stdout.strip() or None if sha.ok else None,
        root=repo_root,
        dirty=bool(status.stdout.strip()) if status.ok else False,
        path_is_repo_root=str(target) == repo_root,
    )


def save_run(
    report: Report,
    duration_s: float,
    db_path: Path | str | None = None,
    started_at: datetime | None = None,
) -> int:
    """Persist one audit. Returns the new run id."""
    payload = to_dict(report)
    root = Path(report.root)
    git = git_info(root)

    # The schema has no columns for git context beyond the SHA, so it rides in
    # summary_json. Without git_dirty a run on 20 uncommitted files is indistinguishable
    # from a run on a clean commit.
    summary = {
        "summary": payload["summary"],
        "exit_code": payload["exit_code"],
        "suite": payload["suite"],
        "languages": payload["profile"]["languages"],
        "checks": [
            {"check": c["check"], "skipped": c["skipped"], "findings": c["findings"]}
            for c in payload["checks"]
        ],
        "git_root": git.root,
        "git_dirty": git.dirty,
        "path_is_repo_root": git.path_is_repo_root,
    }

    moment = (started_at or datetime.now(tz=UTC)).isoformat()

    with connect(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO runs (repo_path, repo_name, git_sha, started_at, duration_s, summary_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (str(root), root.name, git.sha, moment, float(duration_s), json.dumps(summary)),
        )
        run_id = int(cursor.lastrowid)
        connection.executemany(
            'INSERT INTO findings (run_id, "check", severity, file, line, claim, verdict, evidence)'
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    finding.check,
                    str(finding.severity),
                    finding.file,
                    finding.line,
                    finding.claim,
                    finding.verdict,
                    json.dumps(list(finding.evidence)),
                )
                for finding in report.findings
            ],
        )
    return run_id


def list_runs(
    repo_path: Path | str | None = None, limit: int = 10, db_path: Path | str | None = None
) -> list[RunRow]:
    """Runs newest first, optionally for one repository."""
    query = "SELECT * FROM runs"
    params: list = []
    if repo_path is not None:
        query += " WHERE repo_path = ?"
        params.append(str(Path(repo_path).resolve()))
    query += " ORDER BY started_at DESC, id DESC LIMIT ?"
    params.append(int(limit))

    with connect(db_path) as connection:
        return [_run_row(row) for row in connection.execute(query, params)]


def latest_run_per_repo(db_path: Path | str | None = None) -> list[RunRow]:
    """One row per repository - the newest run. Powers the UI project list."""
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM runs WHERE id IN"
            " (SELECT id FROM runs GROUP BY repo_path HAVING MAX(started_at))"
            " ORDER BY repo_name"
        )
        return [_run_row(row) for row in rows]


def get_run(run_id: int, db_path: Path | str | None = None) -> RunRow | None:
    with connect(db_path) as connection:
        row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    return _run_row(row) if row else None


def run_findings(run_id: int, db_path: Path | str | None = None) -> list[FindingRow]:
    with connect(db_path) as connection:
        rows = connection.execute(
            'SELECT * FROM findings WHERE run_id = ? ORDER BY "check", file, line', (run_id,)
        )
        return [_finding_row(row) for row in rows]


def previous_run(run: RunRow, db_path: Path | str | None = None) -> RunRow | None:
    """The run immediately before this one for the same repository."""
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM runs WHERE repo_path = ? AND (started_at < ? OR (started_at = ? AND id < ?))"
            " ORDER BY started_at DESC, id DESC LIMIT 1",
            (run.repo_path, run.started_at, run.started_at, run.id),
        ).fetchone()
    return _run_row(row) if row else None


def diff_runs(
    before_id: int, after_id: int, db_path: Path | str | None = None
) -> tuple[list[FindingRow], list[FindingRow]]:
    """(appeared, disappeared) between two runs, matched ignoring line number."""
    before = run_findings(before_id, db_path)
    after = run_findings(after_id, db_path)

    before_ids = {finding.identity for finding in before}
    after_ids = {finding.identity for finding in after}

    appeared = [finding for finding in after if finding.identity not in before_ids]
    disappeared = [finding for finding in before if finding.identity not in after_ids]
    return appeared, disappeared


def read_registry_cache(
    ecosystem: str,
    names: list[str],
    db_path: Path | str | None = None,
    ignore_ttl: bool = False,
) -> dict[str, str]:
    """Cached registry payloads by name, dropping anything older than the TTL.

    `ignore_ttl` is what makes `--no-network` reproduce an online run: offline there is no
    fresher answer available, so a stale record beats refusing to answer. Online the TTL
    applies, because a package's risk profile genuinely changes.
    """
    if not names:
        return {}

    cutoff = (datetime.now(tz=UTC) - timedelta(hours=REGISTRY_CACHE_TTL_HOURS)).isoformat()
    found: dict[str, str] = {}

    with connect(db_path) as connection:
        for start in range(0, len(names), SQLITE_PARAMETER_CHUNK):
            chunk = names[start : start + SQLITE_PARAMETER_CHUNK]
            placeholders = ",".join("?" * len(chunk))
            query = (
                f"SELECT name, payload FROM registry_cache WHERE ecosystem = ? AND name IN ({placeholders})"
            )
            params: list = [ecosystem, *chunk]
            if not ignore_ttl:
                query += " AND fetched_at >= ?"
                params.append(cutoff)
            for row in connection.execute(query, params):
                found[row["name"]] = row["payload"]

    return found


def write_registry_cache(
    ecosystem: str, entries: list[tuple[str, str]], db_path: Path | str | None = None
) -> None:
    """Upsert cached payloads. Callers pass only successful lookups; failures are not cached."""
    if not entries:
        return
    moment = datetime.now(tz=UTC).isoformat()
    with connect(db_path) as connection:
        connection.executemany(
            "INSERT INTO registry_cache (ecosystem, name, fetched_at, payload) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(ecosystem, name) DO UPDATE SET fetched_at = excluded.fetched_at,"
            " payload = excluded.payload",
            [(ecosystem, name, moment, payload) for name, payload in entries],
        )


def _run_row(row: sqlite3.Row) -> RunRow:
    try:
        summary = json.loads(row["summary_json"])
    except (ValueError, TypeError):
        summary = {}
    return RunRow(
        id=row["id"],
        repo_path=row["repo_path"],
        repo_name=row["repo_name"],
        git_sha=row["git_sha"],
        started_at=row["started_at"],
        duration_s=row["duration_s"],
        summary=summary if isinstance(summary, dict) else {},
    )


def _finding_row(row: sqlite3.Row) -> FindingRow:
    try:
        evidence = json.loads(row["evidence"])
    except (ValueError, TypeError):
        evidence = []
    return FindingRow(
        id=row["id"],
        run_id=row["run_id"],
        check=row["check"],
        severity=row["severity"],
        file=row["file"],
        line=row["line"],
        claim=row["claim"],
        verdict=row["verdict"],
        evidence=evidence if isinstance(evidence, list) else [],
    )
