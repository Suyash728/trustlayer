"""Build data/top_npm_packages.json: the npm typo-adjacency corpus.

Sources, both verified 2026-11-20:

- **Names**: `lib/top-download.js` from the `npm-high-impact` package (MIT, wooorm), read
  straight out of its registry tarball - every package with >= 1M downloads a week, most
  downloaded first. npm has no first-party popularity ranking, so this is the source.
- **Counts**: `api.npmjs.org/downloads/point/last-month/<names>` - first-party. Unscoped
  names go up to 128 per request; the bulk form does not accept scoped names, so those are
  fetched one at a time.

Daily download counts move every day, so a run is anchored to the upstream list *version*:
if `npm-high-impact` has not published a new version since the last snapshot, nothing is
rewritten. That keeps the scheduled workflow from proposing a pull request every week.

    python scripts/update_top_npm.py            # rewrite when upstream moved
    python scripts/update_top_npm.py --force    # rebuild regardless
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request


UPSTREAM_PACKAGE = "npm-high-impact"
UPSTREAM_META_URL = f"https://registry.npmjs.org/{UPSTREAM_PACKAGE}"
LIST_MEMBER = "package/lib/top-download.js"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-month/{names}"
CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "top_npm_packages.json"
DEFAULT_COUNT = 2000
BULK_LIMIT = 128
WORKERS = 6
# One request per scoped name. Measured 2026-11-20: ~600 of them in a burst, even two at a
# time or 0.3 s apart, gets HTTP 429 from api.npmjs.org. One a second stays under the limit.
SCOPED_PAUSE_SECONDS = 1.0
MAX_ATTEMPTS = 8
MAX_BACKOFF_SECONDS = 120
TIMEOUT_SECONDS = 60
USER_AGENT = "killscore-corpus-refresh"

COMMENT = (
    "THIS FILE GOES STALE. Snapshot of the most-downloaded npm packages, used as the npm "
    "typo-adjacency corpus and offline popularity baseline. Names from npm-high-impact "
    "(lib/top-download.js), counts from api.npmjs.org last-month. Regenerate with "
    "scripts/update_top_npm.py; see README.md, 'Maintaining the top-packages corpus'."
)

ENTRY_RE = re.compile(r"'((?:[^'\\]|\\.)*)'")


def parse_top_download(source: str) -> list[str]:
    """Names from `export const topDownload = ['a', 'b', ...]`, in order, without duplicates."""
    if "topDownload" not in source:
        raise ValueError("top-download.js no longer exports `topDownload`; the format changed")
    body = source[source.index("[") : source.rindex("]") + 1]
    names = [match.group(1) for match in ENTRY_RE.finditer(body)]
    if not names:
        raise ValueError("top-download.js contained no package names")
    return list(dict.fromkeys(names))


def build_corpus(
    names: list[str],
    downloads: dict[str, int],
    *,
    upstream_version: str,
    upstream_last_update: str,
    today: str,
    count: int = DEFAULT_COUNT,
) -> dict:
    """Pure. Packages without a download figure are dropped rather than recorded as zero."""
    chosen = [name for name in names[:count] if isinstance(downloads.get(name), int)]
    packages = [{"name": name, "downloads": downloads[name]} for name in chosen]
    packages.sort(key=lambda item: (-item["downloads"], item["name"]))
    return {
        "_comment": COMMENT,
        "source": f"{UPSTREAM_PACKAGE} {upstream_version} + api.npmjs.org last-month",
        "upstream_url": f"https://www.npmjs.com/package/{UPSTREAM_PACKAGE}",
        "upstream_version": upstream_version,
        "upstream_last_update": upstream_last_update,
        "vendored_on": today,
        "count": len(packages),
        "packages": packages,
    }


def render(corpus: dict) -> str:
    return json.dumps(corpus, indent=1, ensure_ascii=False) + "\n"


def _get(url: str) -> bytes:
    """GET with backoff on 429 and 5xx. Any other failure, or running out of attempts, raises."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(MAX_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code != 429 and error.code < 500 or attempt == MAX_ATTEMPTS - 1:
                raise
            retry_after = error.headers.get("Retry-After", "")
            wait = int(retry_after) if retry_after.isdigit() else 5 * 2**attempt
            time.sleep(min(max(wait, 1), MAX_BACKOFF_SECONDS))
    raise AssertionError("unreachable")


def fetch_upstream() -> tuple[str, str, list[str]]:
    meta = json.loads(_get(UPSTREAM_META_URL))
    version = meta["dist-tags"]["latest"]
    published = meta.get("time", {}).get(version, "")
    tarball = _get(meta["versions"][version]["dist"]["tarball"])
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        member = archive.extractfile(LIST_MEMBER)
        if member is None:
            raise ValueError(f"{LIST_MEMBER} missing from {UPSTREAM_PACKAGE} {version}")
        source = member.read().decode("utf-8")
    return version, published, parse_top_download(source)


def fetch_downloads(names: list[str]) -> dict[str, int]:
    unscoped = [name for name in names if not name.startswith("@")]
    scoped = [name for name in names if name.startswith("@")]
    batches = [unscoped[i : i + BULK_LIMIT] for i in range(0, len(unscoped), BULK_LIMIT)]

    def bulk(batch: list[str]) -> dict[str, int]:
        if len(batch) == 1:
            return single(batch[0])
        payload = json.loads(_get(DOWNLOADS_URL.format(names=",".join(batch))))
        return {
            name: entry["downloads"]
            for name, entry in payload.items()
            if isinstance(entry, dict) and isinstance(entry.get("downloads"), int)
        }

    def single(name: str) -> dict[str, int]:
        # Errors propagate: a corpus quietly missing popular names is worse than no update.
        payload = json.loads(_get(DOWNLOADS_URL.format(names=urllib.parse.quote(name, safe="@"))))
        count = payload.get("downloads")
        return {name: count} if isinstance(count, int) else {}

    found: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for part in pool.map(bulk, batches):
            found.update(part)
    for index, name in enumerate(scoped, start=1):
        found.update(single(name))
        if index % 100 == 0:
            print(f"  {index}/{len(scoped)} scoped packages counted", file=sys.stderr)
        time.sleep(SCOPED_PAUSE_SECONDS)
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="rebuild even if upstream is unchanged")
    parser.add_argument("--path", type=Path, default=CORPUS_PATH)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    args = parser.parse_args(argv)

    existing = json.loads(args.path.read_text(encoding="utf-8")) if args.path.is_file() else {}
    version, published, names = fetch_upstream()
    if not args.force and existing.get("upstream_version") == version:
        print(f"no change: {UPSTREAM_PACKAGE} is still {version}")
        return 0

    candidates = names[: args.count]
    downloads = fetch_downloads(candidates)
    corpus = build_corpus(
        candidates,
        downloads,
        upstream_version=version,
        upstream_last_update=published,
        today=datetime.now(tz=UTC).date().isoformat(),
        count=args.count,
    )
    missing = [name for name in candidates if name not in downloads]
    if missing:
        print(
            f"refusing to write: {len(missing)} name(s) returned no download figure, "
            f"e.g. {', '.join(missing[:5])}",
            file=sys.stderr,
        )
        return 1
    args.path.write_text(render(corpus), encoding="utf-8")
    print(f"wrote {corpus['count']} packages from {UPSTREAM_PACKAGE} {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
