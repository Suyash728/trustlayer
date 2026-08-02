"""Rich rendering. Consumes RepoProfile and CheckResult only; never re-reads manifests."""

from __future__ import annotations

from datetime import date

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trustlayer.checks.base import CheckResult, Severity
from trustlayer.checks.stale_models import DeprecatedModel
from trustlayer.detect import Project, RepoProfile


SEVERITY_STYLES = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan"}

FINDING_STYLES = {
    "unpinned-dependency": "yellow",
    "no-lockfile": "yellow",
    "multiple-lockfiles": "yellow",
    "no-test-runner": "red",
    "unparsed-manifest": "red",
}


def render_profile(profile: RepoProfile, console: Console) -> None:
    """Print the audit summary panel, project table, and findings."""
    console.print(_summary_panel(profile))

    if not profile.projects:
        console.print(
            Panel(
                "No Python or JavaScript project detected.",
                title="nothing to audit",
                border_style="red",
            )
        )
        return

    console.print(_projects_table(profile))
    if profile.findings:
        console.print(_findings_table(profile))


def _summary_panel(profile: RepoProfile) -> Panel:
    languages = ", ".join(language.value for language in profile.languages) or "none detected"
    pinned = sum(project.pinned_count for project in profile.projects)
    total = sum(len(project.dependencies) for project in profile.projects)

    body = Text()
    body.append(f"{profile.root}\n", style="bold")
    body.append("languages    ", style="dim")
    body.append(f"{languages}\n")
    body.append("projects     ", style="dim")
    body.append(f"{len(profile.projects)}\n")
    body.append("dependencies ", style="dim")
    body.append(f"{pinned}/{total} pinned\n")
    body.append("findings     ", style="dim")
    body.append(str(len(profile.findings)), style="yellow" if profile.findings else "green")

    return Panel(body, title="TrustLayer audit", border_style="cyan", expand=False)


def _projects_table(profile: RepoProfile) -> Table:
    table = Table(title="Projects", title_justify="left", header_style="bold")
    table.add_column("Path")
    table.add_column("Language")
    table.add_column("Manifests")
    table.add_column("Lockfile")
    table.add_column("Test runners")
    table.add_column("Dependencies", justify="right")

    for project in profile.projects:
        table.add_row(
            project.path,
            project.language.value,
            ", ".join(project.manifests),
            project.lockfile or Text("none", style="yellow"),
            _runner_cell(project),
            _dependency_cell(project),
        )
    return table


def _runner_cell(project: Project) -> Text:
    if not project.runners:
        return Text("none detected", style="red")
    return Text("\n".join(f"{r.name}  ({r.evidence})" for r in project.runners))


def _dependency_cell(project: Project) -> Text:
    total = len(project.dependencies)
    if total == 0:
        return Text("0", style="dim")
    pinned = project.pinned_count
    style = "green" if pinned == total else "yellow"
    return Text(f"{pinned}/{total} pinned", style=style)


def _findings_table(profile: RepoProfile) -> Table:
    table = Table(title="Findings", title_justify="left", header_style="bold")
    table.add_column("Kind")
    table.add_column("Project")
    table.add_column("Detail")

    for finding in profile.findings:
        table.add_row(
            Text(finding.kind, style=FINDING_STYLES.get(finding.kind, "white")),
            finding.project,
            finding.detail,
        )
    return table


def render_check_results(results: list[CheckResult], console: Console) -> None:
    """Print the per-check status table, then every finding with its evidence."""
    console.print(_checks_table(results))

    findings = [finding for result in results for finding in result.findings]
    if not findings:
        return

    console.print()
    console.print(Text("Findings", style="bold"))
    for finding in findings:
        style = SEVERITY_STYLES[finding.severity]
        header = Text()
        header.append(f"{finding.severity.value.upper():<6} ", style=style)
        header.append(f"{finding.file}:{finding.line}", style="bold")
        header.append(f"  [{finding.check}]", style="dim")
        console.print(header)
        console.print(Text(f"       claim    {finding.claim}"))
        console.print(Text(f"       verdict  {finding.verdict}", style=style))
        for line in finding.evidence:
            if line:
                console.print(Text(f"       - {line}", style="dim"))
        console.print()


def _checks_table(results: list[CheckResult]) -> Table:
    table = Table(title="Checks", title_justify="left", header_style="bold")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("High", justify="right")
    table.add_column("Medium", justify="right")
    table.add_column("Low", justify="right")
    table.add_column("Note")

    for result in results:
        counts = result.counts
        if result.skipped:
            status = Text("skipped", style="dim")
            note = Text(result.skip_reason or "", style="dim")
            cells = [Text("-", style="dim")] * 3
        else:
            status = Text("ran", style="green")
            note = Text("; ".join(result.notes), style="dim")
            cells = [
                Text(str(counts[Severity.HIGH]), style="bold red" if counts[Severity.HIGH] else "dim"),
                Text(str(counts[Severity.MEDIUM]), style="yellow" if counts[Severity.MEDIUM] else "dim"),
                Text(str(counts[Severity.LOW]), style="cyan" if counts[Severity.LOW] else "dim"),
            ]
        table.add_row(result.check, status, *cells, note)
    return table


def render_registry(registry: list[DeprecatedModel], console: Console, today: date) -> None:
    """Print the model deprecation registry, marking anything never verified."""
    table = Table(title="Model deprecation registry", title_justify="left", header_style="bold")
    table.add_column("Model ID")
    table.add_column("Provider")
    table.add_column("Date")
    table.add_column("Status")
    table.add_column("Successor")
    table.add_column("Source")

    for model in registry:
        status = model.status(today)
        table.add_row(
            model.model_id,
            model.provider,
            str(model.deprecated_on) if model.deprecated_on else Text("not recorded", style="dim"),
            Text(status, style="red" if status == "retired" else "yellow"),
            model.successor or Text("none recorded", style="dim"),
            Text(model.source_url, style="green")
            if (model.verified and model.source_url)
            else Text("UNVERIFIED", style="bold yellow"),
        )

    console.print(table)
    unverified = sum(1 for model in registry if not (model.verified and model.source_url))
    if unverified:
        console.print(
            Text(
                f"\n{unverified} of {len(registry)} entries are UNVERIFIED: seeded from a maintainer "
                "note, not confirmed against a vendor deprecation page.",
                style="yellow",
            )
        )
    console.print(
        Text(
            "This registry is hand-maintained and goes stale. See README.md.",
            style="dim",
        )
    )
