"""No deprecated model IDs. Includes near-misses that must not match."""

# gemini-2.5-flash-lite and llama-3.3-70b are different IDs from the registered ones,
# and the boundary rules must keep them from matching.
CURRENT_MODEL = "claude-opus-4-5"
GEMINI_MODEL = "gemini-3.5-flash"
EMBEDDING_MODEL = "gemini-embedding-001"


def build_request(prompt):
    return {"model": CURRENT_MODEL, "prompt": prompt}
