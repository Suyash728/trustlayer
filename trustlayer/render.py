"""Rich rendering of a RepoProfile. Consumes RepoProfile only; never re-reads manifests."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trustlayer.detect import Project, RepoProfile


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
