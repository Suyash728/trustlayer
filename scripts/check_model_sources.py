"""Tripwire for data/model_deprecations.toml: does every verified row's page still name it?

Vendor pages are prose and tables, so this deliberately does NOT parse dates out of them -
that would be guessing at someone else's layout. It checks the one thing that is mechanical:
each verified model ID still appears, as a whole ID, in the text of its `source_url`. A page
that moved, 404s, or dropped an ID fails the run, and a human re-verifies the row.

    python scripts/check_model_sources.py        # exit 0 all found, 1 something missing
"""

from __future__ import annotations

from collections import defaultdict
import html
from pathlib import Path
import re
import sys
import tomllib
import urllib.error
import urllib.request


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "model_deprecations.toml"
TIMEOUT_SECONDS = 30
# Some vendor pages refuse non-browser agents outright, which would read as "page gone".
USER_AGENT = "Mozilla/5.0 (compatible; trustlayer-source-check)"
ID_BOUNDARY = r"[A-Za-z0-9._\-]"


def page_text(raw: str) -> str:
    """Visible-ish text: tags removed, entities decoded, whitespace collapsed."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw)))


def missing_ids(text: str, model_ids: list[str]) -> list[str]:
    """IDs that do not appear as a whole ID: `x-001` must not be found inside `vendor-x-001`."""
    return [
        model_id
        for model_id in model_ids
        if not re.search(rf"(?<!{ID_BOUNDARY}){re.escape(model_id)}(?!{ID_BOUNDARY})", text)
    ]


def verified_rows(registry: dict) -> dict[str, list[str]]:
    by_url: dict[str, list[str]] = defaultdict(list)
    for model_id, entry in (registry.get("models") or {}).items():
        if entry.get("verified") and entry.get("source_url"):
            by_url[entry["source_url"]].append(model_id)
    return dict(by_url)


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


def main() -> int:
    registry = tomllib.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    failures = 0
    for url, model_ids in sorted(verified_rows(registry).items()):
        try:
            text = page_text(fetch(url))
        except (urllib.error.URLError, OSError, ValueError) as error:
            print(f"FAIL {url}: could not fetch ({error})")
            failures += 1
            continue
        gone = missing_ids(text, model_ids)
        if gone:
            print(f"FAIL {url}: no longer names {', '.join(gone)}")
            failures += 1
        else:
            print(f"ok   {url}: {len(model_ids)} id(s) present")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
