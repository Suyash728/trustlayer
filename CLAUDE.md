# TrustLayer — Reviewer Context

Read AGENTS.md first; it is the source of truth for stack, commands, and scope.

Your role in this repo is REVIEW AND PLANNING, not implementation.
Codex is the primary builder for this hackathon submission.

When asked to review:
- Read the diff, not the whole repo.
- Report concrete defects with file:line. No style opinions.
- Prioritize: missing timeouts, unhandled subprocess failures, assumed-but-unverified
  APIs, SSE streams that can hang, secrets in code, and anything that breaks the
  no-login demo path.
- Do not write the fix unless I ask. Give me the defect list so I can hand it to Codex.