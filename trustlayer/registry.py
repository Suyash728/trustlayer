"""Package metadata fetched from real registries, normalized to one shape.

Verified against the live APIs rather than remembered (2026-08-16):

- `pypi.org/pypi/<name>/json` returns `info`, `releases`, `urls`, `last_serial`,
  `vulnerabilities`, and `ownership`. `ownership.roles` is a list of `{role, user}` - that
  is the maintainer signal, and it is official.
- **`info.downloads` is dead.** It returns `{last_day: -1, last_week: -1, last_month: -1}`
  for every project. Never read it. Download counts come from pypistats.org, which is a
  third party, so a failure there degrades to "unavailable" and scores nothing.
- `releases` maps a version to a list of files, each carrying `upload_time_iso_8601`. A
  version can have an empty file list, so the age of a project is the earliest upload across
  all files, not the timestamp of the first key.
- npm (probed 2026-11-20): `registry.npmjs.org/<name>` - scoped names with the slash as
  `%2F` - carries `time.created`, `versions`, `maintainers`, `dist-tags.latest`, and a
  per-version `deprecated` message. A missing name is HTTP 404 `{"error":"Not found"}`. An
  *unpublished* package is HTTP **200** with only `{_id, name, time}` and
  `time.unpublished = {time, versions}`. A package npm took over after removing malware has
  `latest` like `0.0.1-security` (also seen: `1.0.0-security`) and the description
  "security holding package". Downloads are first-party at
  `api.npmjs.org/downloads/point/last-month/<name>` -> `{downloads, start, end, package}`.

The three-state contract from `pypi_package_exists` is preserved everywhere: True means the
registry answered, False means a definitive 404, and None means the network could not answer.
A network failure must never read as evidence about a package.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, date, datetime
from http.client import HTTPException
import json
import urllib.error
import urllib.parse
import urllib.request

from trustlayer.deps import canonicalize_python_name
from trustlayer.store import read_registry_cache, write_registry_cache


PYPI_TIMEOUT_SECONDS = 8
PYPISTATS_TIMEOUT_SECONDS = 8
MAX_WORKERS = 8
USER_AGENT = "trustlayer-audit"

# Bump when the normalized shape changes so stale rows are ignored rather than misread.
CACHE_FORMAT_VERSION = 2

PYPI_URL = "https://pypi.org/pypi/{name}/json"
PYPISTATS_URL = "https://pypistats.org/api/packages/{name}/recent"
NPM_URL = "https://registry.npmjs.org/{name}"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-month/{name}"
NPM_TIMEOUT_SECONDS = 8
SECURITY_HOLDING_DESCRIPTION = "security holding package"


@dataclass(frozen=True)
class PackageFacts:
    """What a registry says about one package. Every optional field means "not measured"."""

    name: str
    ecosystem: str = "pypi"
    url: str = ""
    exists: bool | None = None
    unreachable: bool = False
    error: str | None = None
    first_release: date | None = None
    last_release: date | None = None
    release_count: int | None = None
    maintainer_count: int | None = None
    downloads_last_month: int | None = None
    downloads_note: str | None = None
    yanked: bool = False
    vulnerability_count: int = 0
    # Every version the index lists, and the fully-yanked ones mapped to their reason.
    # Both default to empty so a row missing them can never crash a run.
    versions: list[str] = field(default_factory=list)
    yanked_versions: dict[str, str] = field(default_factory=dict)
    # npm states that are as definitive as a 404. Defaulted, so older cache rows still load.
    unpublished: bool = False
    security_holding: bool = False
    deprecated_note: str | None = None  # the latest version's deprecation message
    from_cache: bool = False

    def to_json(self) -> str:
        payload = asdict(self)
        payload["version"] = CACHE_FORMAT_VERSION
        payload["first_release"] = self.first_release.isoformat() if self.first_release else None
        payload["last_release"] = self.last_release.isoformat() if self.last_release else None
        payload.pop("from_cache", None)
        return json.dumps(payload)

    @classmethod
    def from_json(cls, text: str) -> PackageFacts | None:
        """Returns None for anything this version cannot read, so a bad row is just a miss."""
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict) or payload.get("version") != CACHE_FORMAT_VERSION:
            return None

        payload.pop("version", None)
        try:
            for key in ("first_release", "last_release"):
                raw = payload.get(key)
                payload[key] = date.fromisoformat(raw) if isinstance(raw, str) else None
            return cls(**payload, from_cache=True)
        except (TypeError, ValueError):
            # A corrupt row is a cache miss, never a crash: the caller just refetches.
            return None


@dataclass(frozen=True)
class _Response:
    data: dict | None = None
    not_found: bool = False
    error: str | None = None


def _get_json(url: str, timeout: float) -> _Response:
    """Fetch JSON. A 404 is data; every other failure is an error, never a verdict."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return _Response(not_found=True)
        return _Response(error=f"HTTP {error.code}")
    # HTTPException covers a truncated body (IncompleteRead), which is NOT an OSError and
    # would otherwise escape as an unhandled traceback mid-scan.
    except (urllib.error.URLError, HTTPException, OSError, ValueError) as error:
        return _Response(error=str(error) or type(error).__name__)

    if not isinstance(payload, dict):
        return _Response(error="registry returned a non-object payload")
    return _Response(data=payload)


def fetch_pypi(name: str, *, timeout: float = PYPI_TIMEOUT_SECONDS, downloads: bool = True) -> PackageFacts:
    """Resolve one PyPI project. Never raises; a failure comes back as `unreachable`."""
    canonical = canonicalize_python_name(name)
    url = PYPI_URL.format(name=urllib.parse.quote(canonical, safe=""))
    response = _get_json(url, timeout)

    if response.not_found:
        return PackageFacts(name=name, url=url, exists=False)
    if response.data is None:
        return PackageFacts(name=name, url=url, exists=None, unreachable=True, error=response.error)

    payload = response.data
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    releases = payload.get("releases") if isinstance(payload.get("releases"), dict) else {}

    first, last = _release_window(releases)
    vulnerabilities = payload.get("vulnerabilities")
    facts = PackageFacts(
        name=name,
        url=url,
        exists=True,
        first_release=first,
        last_release=last,
        release_count=len(releases) or None,
        versions=sorted(releases),
        yanked_versions=_yanked_versions(releases),
        maintainer_count=_maintainer_count(payload),
        yanked=bool(info.get("yanked")),
        vulnerability_count=len(vulnerabilities) if isinstance(vulnerabilities, list) else 0,
    )

    if not downloads:
        return replace(facts, downloads_note="download lookup disabled")
    count, note = _pypistats_downloads(canonical)
    return replace(facts, downloads_last_month=count, downloads_note=note)


def npm_url_name(name: str) -> str:
    """`@scope/pkg` -> `@scope%2Fpkg`, the form the registry documents for scoped names."""
    return urllib.parse.quote(name.strip(), safe="@")


def fetch_npm(name: str, *, timeout: float = NPM_TIMEOUT_SECONDS, downloads: bool = True) -> PackageFacts:
    """Resolve one npm package. Never raises; a failure comes back as `unreachable`."""
    url = NPM_URL.format(name=npm_url_name(name))
    response = _get_json(url, timeout)

    if response.not_found:
        return PackageFacts(name=name, ecosystem="npm", url=url, exists=False)
    if response.data is None:
        return PackageFacts(
            name=name, ecosystem="npm", url=url, exists=None, unreachable=True, error=response.error
        )

    payload = response.data
    times = payload.get("time") if isinstance(payload.get("time"), dict) else {}
    if isinstance(times.get("unpublished"), dict):
        return PackageFacts(
            name=name, ecosystem="npm", url=url, exists=True, unpublished=True,
            first_release=_parse_timestamp(times.get("created")),
        )

    versions = payload.get("versions") if isinstance(payload.get("versions"), dict) else {}
    tags = payload.get("dist-tags") if isinstance(payload.get("dist-tags"), dict) else {}
    latest = tags.get("latest") if isinstance(tags.get("latest"), str) else None
    latest_meta = versions.get(latest) if latest and isinstance(versions.get(latest), dict) else {}
    description = str(payload.get("description") or latest_meta.get("description") or "")
    maintainers = payload.get("maintainers")
    deprecated = latest_meta.get("deprecated")

    stamps = [_parse_timestamp(times.get(version)) for version in versions]
    published = [stamp for stamp in stamps if stamp is not None]
    facts = PackageFacts(
        name=name,
        ecosystem="npm",
        url=url,
        exists=True,
        first_release=_parse_timestamp(times.get("created")) or (min(published) if published else None),
        last_release=max(published) if published else None,
        release_count=len(versions) or None,
        versions=sorted(versions),
        maintainer_count=len(maintainers) if isinstance(maintainers, list) else None,
        security_holding=bool(latest and latest.endswith("-security"))
        and SECURITY_HOLDING_DESCRIPTION in description.lower(),
        # npm un-deprecates by setting the message to "", so only a non-empty one counts.
        deprecated_note=(deprecated.strip() or None) if isinstance(deprecated, str) else None,
    )

    if not downloads:
        return replace(facts, downloads_note="download lookup disabled")
    count, note = _npm_downloads(name)
    return replace(facts, downloads_last_month=count, downloads_note=note)


def _npm_downloads(name: str) -> tuple[int | None, str | None]:
    """First-party on npm, but still optional: a failure is 'unavailable', never a signal."""
    response = _get_json(NPM_DOWNLOADS_URL.format(name=npm_url_name(name)), NPM_TIMEOUT_SECONDS)
    if response.not_found:
        return None, "npm has no download record for this package"
    if response.data is None:
        return None, f"npm downloads API unreachable: {response.error}"
    count = response.data.get("downloads")
    if not isinstance(count, int):
        return None, "npm downloads API returned no figure"
    return count, None


def _release_window(releases: dict) -> tuple[date | None, date | None]:
    """Earliest and latest upload across every file of every version.

    A version key with no files was never published as an artifact, so keying off the first
    version rather than the first *upload* would date the project wrong.
    """
    stamps: list[date] = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for entry in files:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("upload_time_iso_8601") or entry.get("upload_time")
            parsed = _parse_timestamp(raw)
            if parsed is not None:
                stamps.append(parsed)
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def _yanked_versions(releases: dict) -> dict[str, str]:
    """Fully-yanked versions mapped to the reason the index recorded.

    Yanking is per-file under PEP 592 but conventionally applied to a whole release, so a
    version counts as yanked only when every one of its files is. A partially-yanked release
    still has something installable, and claiming otherwise would be false.

    `yanked_reason` is frequently null even on a genuine yank, which is why the value is
    allowed to be an empty string rather than dropped.
    """
    yanked: dict[str, str] = {}
    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue
        if all(isinstance(f, dict) and f.get("yanked") for f in files):
            reason = files[0].get("yanked_reason")
            yanked[version] = reason if isinstance(reason, str) else ""
    return yanked


def _parse_timestamp(raw: object) -> date | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw).astimezone(UTC).date()
    except ValueError:
        return None


def _maintainer_count(payload: dict) -> int | None:
    """From `ownership.roles`. Absent on mirrors and older indexes, which is 'unavailable'."""
    ownership = payload.get("ownership")
    if not isinstance(ownership, dict):
        return None
    roles = ownership.get("roles")
    if not isinstance(roles, list):
        return None
    return len({entry.get("user") for entry in roles if isinstance(entry, dict) and entry.get("user")})


def _pypistats_downloads(canonical: str) -> tuple[int | None, str | None]:
    """Third-party enrichment. Any failure is 'unavailable', never a risk signal."""
    url = PYPISTATS_URL.format(name=urllib.parse.quote(canonical, safe=""))
    response = _get_json(url, PYPISTATS_TIMEOUT_SECONDS)
    if response.not_found:
        return None, "pypistats has no record for this project"
    if response.data is None:
        return None, f"pypistats unreachable: {response.error}"

    data = response.data.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("last_month"), int):
        return None, "pypistats returned no last_month figure"
    return data["last_month"], None


def fetch_many(
    names: list[str],
    *,
    fetcher=None,
    db_path=None,
    offline: bool = False,
    use_cache: bool = True,
    max_workers: int = MAX_WORKERS,
    ecosystem: str = "pypi",
) -> dict[str, PackageFacts]:
    """Resolve many packages, reading and writing the cache on this thread only.

    sqlite3 connections are not shareable across threads, so the pool does network work and
    nothing else: cache lookups happen before it starts and writes happen after it drains.
    In `offline` mode the cache is consulted without a TTL and nothing is ever fetched - a
    warm cache then reproduces an online run exactly, which is the point of `--no-network`.
    """
    lookup = fetcher or (fetch_npm if ecosystem == "npm" else fetch_pypi)
    if fetcher is not None:
        # The cache holds real registry answers. A caller supplying its own fetcher is a
        # test or a simulation, and writing that into ~/.trustlayer would poison every later
        # run with data no registry ever returned.
        use_cache = False
    unique = list(dict.fromkeys(names))
    results: dict[str, PackageFacts] = {}
    pending: list[str] = []

    cached = _read_cache(unique, db_path, ignore_ttl=offline, ecosystem=ecosystem) if use_cache else {}
    for name in unique:
        hit = cached.get(_cache_key(name, ecosystem))
        if hit is not None:
            results[name] = replace(hit, name=name)
        elif offline:
            results[name] = PackageFacts(
                name=name,
                unreachable=True,
                error="offline mode and no cached record for this package",
            )
        else:
            pending.append(name)

    if pending:
        workers = max(1, min(max_workers, len(pending)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for name, facts in zip(pending, pool.map(lookup, pending), strict=True):
                results[name] = facts
        if use_cache:
            _write_cache([results[name] for name in pending], db_path, ecosystem)

    return results


def _cache_key(name: str, ecosystem: str) -> str:
    """PyPI folds names (PEP 503); npm does not, so its key is the name as written."""
    return canonicalize_python_name(name) if ecosystem == "pypi" else name.strip()


def _read_cache(names: list[str], db_path, ignore_ttl: bool, ecosystem: str = "pypi") -> dict[str, PackageFacts]:
    try:
        rows = read_registry_cache(
            ecosystem, [_cache_key(name, ecosystem) for name in names], db_path=db_path, ignore_ttl=ignore_ttl
        )
    except OSError:
        return {}

    facts = {}
    for key, payload in rows.items():
        parsed = PackageFacts.from_json(payload)
        if parsed is not None:
            facts[key] = parsed
    return facts


def _write_cache(entries: list[PackageFacts], db_path, ecosystem: str = "pypi") -> None:
    # Never cache a failure: the next run must retry rather than inherit an outage.
    fresh = [facts for facts in entries if not facts.unreachable]
    if not fresh:
        return
    try:
        write_registry_cache(
            ecosystem,
            [(_cache_key(facts.name, ecosystem), facts.to_json()) for facts in fresh],
            db_path=db_path,
        )
    except OSError:
        return  # a cache that cannot be written is a slow run, not a failed one
