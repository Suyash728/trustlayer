"""Deprecated model IDs in literals, plus one that is only scheduled to retire."""

import os


GROQ_MODEL = "llama-3.3-70b-versatile"
GEMINI_MODEL = "gemini-2.0-flash-001"
EMBEDDING_MODEL = "text-embedding-004"
SCHEDULED_MODEL = "gemini-2.5-flash"

# A comment naming llama-3.1-8b-instant must not match: Python is read via AST.
CURRENT_MODEL = "claude-opus-4-5"


def build_request(prompt):
    return {"model": os.getenv("MODEL_ID", GROQ_MODEL), "prompt": prompt}
