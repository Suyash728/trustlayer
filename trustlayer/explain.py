"""Prose for a dependency scan. The model writes sentences and decides nothing.

This is the one place in TrustLayer where a model touches the dependency path, and the
boundary is structural rather than a promise in a prompt:

- Every score, severity, and verdict is computed by `risk.py` *before* this module is
  called, and this module returns a string. There is no code path from the returned text
  back into a `RiskScore`, a `Severity`, or an exit code.
- The agent runs with `allowed_tools=()`, so `ToolGate` denies every tool call. It cannot
  read the repository, reach a registry, or check the maths - it only sees the factor list
  it is handed.
- A failure here is a warning on stderr and an empty string, never a changed verdict.

If the explanation is wrong, it is wrong the way a bad comment is wrong: annoying and
harmless. That is the only kind of wrong an LLM is allowed to be in this codebase.
"""

from __future__ import annotations

from pathlib import Path

from trustlayer.agent.runtime import run_agent
from trustlayer.checks.slopsquat import ScanResult


EXPLAIN_TIMEOUT_SECONDS = 120
EXPLAIN_MAX_TURNS = 2
EXPLAIN_BUDGET_USD = 0.25
MAX_PACKAGES_IN_PROMPT = 25

SYSTEM_PROMPT = (
    "You explain dependency risk scores that have already been computed. You have no tools "
    "and no way to look anything up. Describe only what the supplied factors say. Never "
    "invent a fact, never restate a score as a different number, and never suggest a "
    "package is malicious - the scores measure unfamiliarity and typo-adjacency, not intent."
)

INSTRUCTIONS = (
    "Write at most three short paragraphs of plain prose for a developer reviewing this "
    "dependency list. Say what was flagged and why those specific facts matter. Do not use "
    "markdown, headings, bullet points, or emoji. Do not repeat the table. Do not recommend "
    "running any command. If a package merely sits near a popular name, say plainly that "
    "this alone is not evidence of anything."
)


def explain_scan(result: ScanResult, root: Path) -> tuple[str, str | None]:
    """Return (prose, error). Either may be empty; the caller treats a failure as cosmetic."""
    reportable = result.reportable
    if not reportable:
        return "", None

    outcome = run_agent(
        _build_prompt(result, root),
        cwd=root,
        allowed_tools=(),  # ToolGate denies every call; the model gets facts and nothing else
        timeout=EXPLAIN_TIMEOUT_SECONDS,
        max_turns=EXPLAIN_MAX_TURNS,
        max_budget_usd=EXPLAIN_BUDGET_USD,
        system_prompt=SYSTEM_PROMPT,
    )
    if not outcome.ok:
        return "", outcome.error or "the agent returned no result"
    if not outcome.text.strip():
        return "", "the agent returned no text"
    return outcome.text.strip(), None


def _build_prompt(result: ScanResult, root: Path) -> str:
    lines = [
        f"Repository: {root}",
        "",
        (
            "These dependency risk scores were computed mechanically. They are final: your "
            "job is to describe them, not to re-evaluate them."
        ),
        "",
    ]
    for item in result.reportable[:MAX_PACKAGES_IN_PROMPT]:
        severity = item.risk.severity.value if item.risk.severity else "none"
        lines.append(
            f"{item.name}{item.declared_spec or ''} - score {item.risk.score}/100, "
            f"severity {severity}, verdict {item.risk.verdict}, declared at "
            f"{item.file}:{item.line}"
        )
        for factor in item.risk.factors:
            lines.append(f"    [{factor.points:+d}] {factor.name}: {factor.detail}")
        lines.append("")

    cleared = [item for item in result.scored if not item.risk.reportable and item.risk.score is not None]
    if cleared:
        lines.append(f"Cleared with no finding: {', '.join(item.name for item in cleared)}")
        lines.append("")

    lines.append(INSTRUCTIONS)
    return "\n".join(lines)
