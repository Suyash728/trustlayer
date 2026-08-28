"""Article summarizer service.

A deliberately unremarkable FastAPI app. The interesting part is requirements.txt: three of
its six dependencies are wrong, in three different ways, and none of them are wrong in a way
that reading the code would reveal.
"""

import os

from fastapi import FastAPI
import requests


app = FastAPI()

USER_AGENT = "article-summarizer/1.0"
TIMEOUT_SECONDS = 10


@app.get("/summarize")
def summarize(url: str) -> dict:
    response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return {
        "url": url,
        "length": len(response.text),
        "model": os.environ.get("SUMMARY_MODEL", "claude-opus-5"),
    }
