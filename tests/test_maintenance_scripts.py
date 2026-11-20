"""The corpus scripts: deterministic, provenance-preserving, and quiet when nothing changed."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tomllib

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


update = _load("update_top_pypi")
sources = _load("check_model_sources")


def upstream(rows):
    return {
        "last_update": "2026-11-01 06:41:05",
        "source": "ClickHouse",
        "rows": [{"project": name, "download_count": count} for name, count in rows],
    }


EXISTING = {"_comment": "THIS FILE GOES STALE.", "source": "ClickHouse", "vendored_on": "2026-08-16"}


def test_the_corpus_is_ordered_and_truncated_deterministically():
    data = upstream([("b", 5), ("a", 5), ("c", 9), ("d", 1)])

    corpus = update.build_corpus(data, EXISTING, "2026-11-20", count=3)

    assert [p["name"] for p in corpus["packages"]] == ["c", "a", "b"]  # ties broken by name
    assert update.render(corpus) == update.render(
        update.build_corpus(data, EXISTING, "2026-11-20", count=3)
    )


def test_provenance_keys_are_preserved():
    corpus = update.build_corpus(upstream([("a", 2), ("b", 1)]), EXISTING, "2026-11-20", count=2)

    assert corpus["_comment"] == "THIS FILE GOES STALE."
    assert corpus["upstream_url"] == update.UPSTREAM_URL
    assert corpus["upstream_last_update"] == "2026-11-01 06:41:05"
    assert corpus["vendored_on"] == "2026-11-20"
    assert corpus["count"] == 2


def test_vendored_on_does_not_move_when_nothing_changed():
    """Otherwise every scheduled run would open a pull request that changes one date."""
    data = upstream([("a", 2), ("b", 1)])
    first = update.build_corpus(data, EXISTING, "2026-11-20", count=2)

    again = update.build_corpus(data, first, "2026-11-27", count=2)
    assert again["vendored_on"] == "2026-11-20"


def test_a_short_or_malformed_upstream_is_refused():
    with pytest.raises(ValueError, match="need 3"):
        update.build_corpus(upstream([("a", 1)]), EXISTING, "2026-11-20", count=3)
    with pytest.raises(ValueError, match="malformed"):
        update.build_corpus({"rows": [{"project": 3, "download_count": "x"}]}, {}, "d", count=1)


def test_the_vendored_corpus_is_in_canonical_form():
    """The checked-in file is exactly what the script would write from its own content."""
    path = update.CORPUS_PATH
    import json

    current = json.loads(path.read_text(encoding="utf-8"))
    assert update.render(current) == path.read_text(encoding="utf-8")
    names = [p["name"] for p in current["packages"]]
    assert len(names) == current["count"] == len(set(names))


@pytest.mark.parametrize(
    ("text", "model_id", "found"),
    [
        ("`embedding-001` * April 9, 2024", "embedding-001", True),  # trustlayer: ignore[stale-models]
        ("`gemini-embedding-001` * July 14, 2025", "embedding-001", False),  # trustlayer: ignore[stale-models]
        ("gemini-2.0-flash-001 * June 1", "gemini-2.0-flash", False),  # trustlayer: ignore[stale-models]
        ("llama-3.1-8b-instant 08/16/26", "llama-3.1-8b-instant", True),  # trustlayer: ignore[stale-models]
    ],
)
def test_ids_must_appear_as_whole_ids(text, model_id, found):
    assert (sources.missing_ids(text, [model_id]) == []) is found


def test_html_is_reduced_to_text():
    assert sources.page_text("<td><code>a&amp;b</code></td>\n<td>x</td>") == " a&b x "


def test_only_verified_rows_with_a_source_are_checked():
    registry = {
        "models": {
            "a": {"verified": True, "source_url": "https://x"},
            "b": {"verified": True, "source_url": "https://x"},
            "c": {"verified": False, "source_url": "https://x"},
            "d": {"verified": True, "source_url": ""},
        }
    }
    assert sources.verified_rows(registry) == {"https://x": ["a", "b"]}


def test_every_shipped_row_is_checkable():
    registry = tomllib.loads(sources.REGISTRY_PATH.read_text(encoding="utf-8"))
    checked = sum(len(ids) for ids in sources.verified_rows(registry).values())

    assert checked == len(registry["models"])


npm = _load("update_top_npm")


def test_the_npm_list_is_read_from_the_upstream_array():
    source = "export const topDownload = [\n  'semver',\n  '@types/node',\n  'semver',\n  'it\\'s'\n]\n"

    assert npm.parse_top_download(source) == ["semver", "@types/node", "it\\'s"]


def test_a_changed_upstream_format_is_refused():
    with pytest.raises(ValueError):
        npm.parse_top_download("export const somethingElse = ['a']")


def test_the_npm_corpus_keeps_only_counted_names_in_a_stable_order():
    corpus = npm.build_corpus(
        ["a", "b", "c", "d"],
        {"a": 5, "b": 9, "c": 5},
        upstream_version="1.13.0",
        upstream_last_update="2026-06-08T16:53:09.411Z",
        today="2026-11-20",
        count=3,
    )

    assert [p["name"] for p in corpus["packages"]] == ["b", "a", "c"]
    assert corpus["upstream_version"] == "1.13.0"
    assert corpus["count"] == 3
