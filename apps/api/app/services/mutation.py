"""Mutation-testing command helpers and mutmut output parsing.

The implementation lives in `killscore.mutation`; this module re-exports it so the
architecture rule in CLAUDE.md still holds ("all mutation-tool invocations go through
app/services/mutation.py") while the dependency points from the API app into the
`killscore` package rather than the other way around.

Patching note: the real `subprocess.run` call happens in `killscore.mutation`, so tests
must patch `killscore.mutation.subprocess.run`, not this module's namespace.
"""

from __future__ import annotations

from killscore.mutation import (
    DEFAULT_TIMEOUT_SECONDS,
    FUNCTION_NAME_RE,
    MUTATION_TIMEOUT_SECONDS,
    RESULT_LINE_RE,
    MutationRun,
    Survivor,
    get_mutation_run,
    get_survivors,
    run_mutation,
)


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "FUNCTION_NAME_RE",
    "MUTATION_TIMEOUT_SECONDS",
    "RESULT_LINE_RE",
    "MutationRun",
    "Survivor",
    "get_mutation_run",
    "get_survivors",
    "run_mutation",
]
