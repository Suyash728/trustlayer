"""Silence tests for TS `unresolved-import` on non-code files (found HIGH on a Next.js app).

TypeScript's resolver only answers for modules it can type, so `import "./globals.css"`
never resolves to a source file even when the stylesheet is right there. A bundler owns
those imports; the honest question is whether the file exists on disk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from killscore.checks.api_resolution import check_typescript_apis


def _project(tmp_path: Path, layout: str) -> Path:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "package.json").write_text('{"name": "app"}')
    app = tmp_path / "src" / "app"
    app.mkdir(parents=True)
    (app / "layout.tsx").write_text(layout)
    return app


def _unresolved(tmp_path: Path) -> list[str]:
    result = check_typescript_apis(tmp_path)
    if result.skipped:
        pytest.skip(result.skip_reason or "TypeScript checks unavailable")
    return [f.claim for f in result.findings if f.verdict == "unresolved-import"]


def test_an_existing_stylesheet_import_is_silent(tmp_path):
    app = _project(tmp_path, 'import "./globals.css";\nimport logo from "../logo.svg";\n')
    (app / "globals.css").write_text("body {}\n")
    (tmp_path / "src" / "logo.svg").write_text("<svg/>\n")

    assert _unresolved(tmp_path) == []


def test_a_missing_stylesheet_import_is_still_reported(tmp_path):
    _project(tmp_path, 'import "./missing.css";\n')

    assert _unresolved(tmp_path) == ['import from "./missing.css"']


def test_a_missing_source_import_is_still_reported(tmp_path):
    _project(tmp_path, 'import { x } from "./nowhere";\nexport const y = x;\n')

    assert _unresolved(tmp_path) == ['import from "./nowhere"']
