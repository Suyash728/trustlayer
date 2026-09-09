"""Local read-only UI over the run database.

One process, no build step, no node_modules: FastAPI + Jinja, with Tailwind and HTMX
from CDN. The UI can read runs and nothing else - it cannot trigger a run or write to a
repository.

Design notes, from the dataviz method:
- Severity is a *status* palette (fixed, never themed), not a categorical series, so it
  uses the reserved status steps and never doubles as "series 4".
- Counts and paths are text, so they wear ink tokens; a small colored mark beside them
  carries severity identity. A status colour never carries meaning alone.
- Three runs are a delta, not a plot, so the trend is an arrow and a number - no chart.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from trustlayer.presentation import rank as _rank
from trustlayer.presentation import trend as _trend
from trustlayer.store import (
    diff_runs,
    get_run,
    latest_run_per_repo,
    list_runs,
    previous_run,
    run_findings,
)


TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def create_app(db_path: Path | str | None = None) -> FastAPI:
    app = FastAPI(title="TrustLayer", docs_url=None, redoc_url=None)

    def render(request: Request, template: str, **context) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(request, template, context)

    @app.get("/", response_class=HTMLResponse)
    def projects(request: Request):
        rows = []
        for run in latest_run_per_repo(db_path):
            prior = previous_run(run, db_path)
            rows.append({"run": run, "trend": _trend(run, prior), "prior": prior})
        return render(request, "projects.html", rows=rows, active="projects")

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: int):
        run = get_run(run_id, db_path)
        if run is None:
            return PlainTextResponse(f"run {run_id} not found", status_code=404)

        findings = run_findings(run_id, db_path)
        groups: dict[str, list] = {}
        for finding in findings:
            groups.setdefault(finding.check, []).append(finding)
        ordered = sorted(
            groups.items(), key=lambda kv: (_rank(kv[1][0].severity), kv[0])
        )
        return render(
            request,
            "run.html",
            run=run,
            groups=ordered,
            history=list_runs(run.repo_path, limit=20, db_path=db_path),
            active="run",
        )

    @app.get("/runs/{run_id}/finding/{finding_id}", response_class=HTMLResponse)
    def finding_evidence(request: Request, run_id: int, finding_id: int):
        """HTMX fragment: the expanded evidence for one finding."""
        finding = next((f for f in run_findings(run_id, db_path) if f.id == finding_id), None)
        if finding is None:
            return PlainTextResponse("not found", status_code=404)
        return render(request, "_evidence.html", finding=finding)

    @app.get("/compare", response_class=HTMLResponse)
    def compare(request: Request, a: int, b: int):
        before, after = get_run(a, db_path), get_run(b, db_path)
        if before is None or after is None:
            return PlainTextResponse("run not found", status_code=404)
        if before.repo_path != after.repo_path:
            return PlainTextResponse("runs are from different repositories", status_code=400)

        appeared, disappeared = diff_runs(before.id, after.id, db_path)
        return render(
            request,
            "compare.html",
            before=before,
            after=after,
            appeared=appeared,
            disappeared=disappeared,
            history=list_runs(after.repo_path, limit=20, db_path=db_path),
            active="compare",
        )

    return app
