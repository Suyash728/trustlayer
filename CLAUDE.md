# TrustLayer — Reviewer Context

Read AGENTS.md first; it is the source of truth for stack, commands, and scope.

## Working style
- Plan before building anything over ~30 lines. Show the plan, wait.
- Never write against a remembered API. Check the installed version's actual
  surface first and tell me what you found.
- Every subprocess call gets an explicit timeout.
- No LLM call in any verdict path. Checks are mechanical or they don't ship.
- A check with a false positive is worse than no check.

## mutmut 3.6.0 output format (VERIFIED — do not rediscover)
- `mutmut results --all true` → `<module>.x_<funcname>__mutmut_<N>: <status>`.
  Text before `: ` is the exact ID for `mutmut show`.
- `mutmut show <id>` diffs the FUNCTION in isolation — @@ hunk offsets are
  relative to the function body, NOT the file. Never derive file line numbers
  from the hunk; locate the removed line's text in the real source instead.
- `mutmut result-ids` does NOT exist in 3.6.0.