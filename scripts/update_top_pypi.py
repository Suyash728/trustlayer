"""Refresh data/top_pypi_packages.json from hugovk/top-pypi-packages.

Deterministic: the same upstream snapshot always produces byte-identical output. Rows are
ordered by download count (desc) then name, the top N are kept, and the provenance keys
(`_comment`, `source`, `upstream_url`, `upstream_last_update`, `vendored_on`, `count`) are
preserved. `vendored_on` moves only when the package list itself changed, so a scheduled run
against an unchanged upstream produces no diff and no pull request.

    python scripts/update_top_pypi.py            # rewrite the file in place
    python scripts/update_top_pypi.py --check    # exit 1 if the vendored file is behind
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import sys
import urllib.request


UPSTREAM_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "top_pypi_packages.json"
DEFAULT_COUNT = 2000
TIMEOUT_SECONDS = 60
USER_AGENT = "killscore-corpus-refresh"


def build_corpus(upstream: dict, existing: dict, today: str, count: int = DEFAULT_COUNT) -> dict:
    """The new corpus document. Pure: no I/O, so it is testable and reproducible."""
    rows = upstream.get("rows")
    if not isinstance(rows, list) or len(rows) < count:
        raise ValueError(f"upstream has {len(rows) if isinstance(rows, list) else 0} rows, need {count}")

    packages = []
    for row in rows:
        name, downloads = row.get("project"), row.get("download_count")
        if not isinstance(name, str) or not isinstance(downloads, int):
            raise ValueError(f"malformed upstream row: {row!r}")  # noqa: TRY004 - bad data, not a bad call
        packages.append({"name": name, "downloads": downloads})
    packages.sort(key=lambda item: (-item["downloads"], item["name"]))
    packages = packages[:count]

    unchanged = existing.get("packages") == packages
    return {
        "_comment": existing.get("_comment", ""),
        "source": upstream.get("source", existing.get("source", "")),
        "upstream_url": UPSTREAM_URL,
        "upstream_last_update": upstream.get("last_update", ""),
        "vendored_on": existing.get("vendored_on", today) if unchanged else today,
        "count": count,
        "packages": packages,
    }


def render(corpus: dict) -> str:
    return json.dumps(corpus, indent=1, ensure_ascii=False) + "\n"


def fetch_upstream() -> dict:
    request = urllib.request.Request(UPSTREAM_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the vendored file is behind")
    parser.add_argument("--path", type=Path, default=CORPUS_PATH)
    args = parser.parse_args(argv)

    existing = json.loads(args.path.read_text(encoding="utf-8"))
    today = datetime.now(tz=UTC).date().isoformat()
    corpus = build_corpus(fetch_upstream(), existing, today, existing.get("count", DEFAULT_COUNT))
    text = render(corpus)
    current = args.path.read_text(encoding="utf-8")

    if args.check:
        if text != current:
            print(f"{args.path} is behind upstream ({corpus['upstream_last_update']})", file=sys.stderr)
            return 1
        print(f"{args.path} is current ({corpus['upstream_last_update']})")
        return 0

    if text == current:
        print("no change")
        return 0
    args.path.write_text(text, encoding="utf-8")
    print(f"updated {args.path}: upstream {corpus['upstream_last_update']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
