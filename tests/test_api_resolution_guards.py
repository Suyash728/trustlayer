"""Silence tests for api-resolution false positives found by auditing TrustLayer itself.

Each test is a shape of real, correct code that used to be reported as HIGH or MEDIUM.
"""

from __future__ import annotations

from pathlib import Path
import sys
import textwrap

from trustlayer.checks.api_resolution import (
    check_python_apis,
    collect_python_claims,
    is_first_party,
)


INTERPRETER = Path(sys.executable)


def ON_PYPI(name):
    return True


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _run(root: Path):
    return check_python_apis(root, pypi_lookup=ON_PYPI, interpreter=INTERPRETER)


def test_a_submodule_imported_from_its_package_is_not_missing(tmp_path):
    """`ElementTree` is not in dir(xml.etree) until imported - it is still real."""
    _write(
        tmp_path,
        "app.py",
        """
        from xml.etree import ElementTree
        from concurrent import futures
        from email import policy

        ElementTree.parse
        """,
    )
    result = _run(tmp_path)

    assert result.findings == []


def test_a_dotted_import_used_by_its_full_path_is_not_missing(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        import xml.etree.ElementTree

        xml.etree.ElementTree.parse("x.xml")
        """,
    )
    result = _run(tmp_path)

    assert result.findings == []


def test_a_genuinely_missing_name_in_a_package_is_still_reported(tmp_path):
    """The submodule guard must not swallow a real hallucination on a package."""
    _write(tmp_path, "app.py", "from xml.etree import ElementTreeX\n")
    result = _run(tmp_path)

    assert [f.claim for f in result.findings] == ["xml.etree.ElementTreeX"]


def test_a_module_alias_rebound_elsewhere_in_the_file_is_not_judged(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        import json

        def handler(response):
            json = response.json()
            return json.get("key")
        """,
    )
    result = _run(tmp_path)

    assert result.findings == []


def test_rebinding_by_parameter_loop_or_except_is_also_respected(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        import re
        import os
        from json import loads

        def f(re):
            return re.not_a_real_thing

        for os in []:
            os.not_real

        try:
            pass
        except ValueError as loads:
            loads.not_real
        """,
    )
    _, attributes, calls = collect_python_claims(tmp_path, [tmp_path / "app.py"])

    assert {(a.module, a.attribute) for a in attributes} == {("json", "loads")}
    assert calls == []


def test_an_import_resolved_from_a_nested_directory_is_first_party(tmp_path):
    test_file = _write(tmp_path, "apps/api/tests/test_x.py", "import app.services\n")
    _write(tmp_path, "apps/api/app/__init__.py", "")

    assert is_first_party(tmp_path, "app.services", test_file)
    assert not is_first_party(tmp_path, "app.services")


def test_a_nested_src_layout_is_first_party(tmp_path):
    test_file = _write(tmp_path, "demo/pricing/tests/test_p.py", "import pricing\n")
    _write(tmp_path, "demo/pricing/src/pricing.py", "")

    assert is_first_party(tmp_path, "pricing", test_file)


def test_a_nested_project_without_a_venv_does_not_report_not_installed(tmp_path):
    """The root venv was never meant to hold a nested project's dependencies."""
    _write(tmp_path, "pyproject.toml", "[project]\nname='root'\n")
    _write(tmp_path, "root_app.py", "import json\n")
    _write(tmp_path, "nested/requirements.txt", "definitely-not-installed-pkg\n")
    _write(tmp_path, "nested/app.py", "import definitely_not_installed_pkg\n")
    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(INTERPRETER)

    result = check_python_apis(tmp_path, pypi_lookup=ON_PYPI)

    assert result.skipped is False
    assert result.findings == []
    assert any("definitely_not_installed_pkg" in note for note in result.notes)


def test_a_definitive_404_still_stands_under_a_borrowed_environment(tmp_path):
    _write(tmp_path, "pyproject.toml", "[project]\nname='root'\n")
    _write(tmp_path, "nested/requirements.txt", "x\n")
    _write(tmp_path, "nested/app.py", "import definitely_not_installed_pkg\n")
    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(INTERPRETER)

    result = check_python_apis(tmp_path, pypi_lookup=lambda name: False)

    assert [f.verdict for f in result.findings] == ["possible-slopsquat"]


# --- import names that are not distribution names (cv2 found reporting HIGH in a real repo) ---


def test_a_known_import_alias_is_not_a_slopsquat(tmp_path):
    """`cv2` 404s on PyPI because OpenCV publishes as `opencv-python`. Not a fake package."""
    _write(tmp_path, "app.py", "import cv2\n")
    asked: list[str] = []

    def lookup(name):
        asked.append(name)
        return name != "cv2"

    result = check_python_apis(tmp_path, pypi_lookup=lookup, interpreter=INTERPRETER)

    [finding] = result.findings
    assert finding.verdict == "not-installed"
    assert finding.severity.value == "medium"
    assert any("opencv-python" in line for line in finding.evidence)
    assert "cv2" not in asked  # the import name is never looked up: its 404 means nothing


def test_an_alias_with_several_distributions_names_them_all(tmp_path):
    _write(tmp_path, "app.py", "import psycopg2\n")
    result = check_python_apis(tmp_path, pypi_lookup=ON_PYPI, interpreter=INTERPRETER)

    [finding] = result.findings
    evidence = " ".join(finding.evidence)
    assert "psycopg2-binary" in evidence and "psycopg2" in evidence


def test_an_alias_whose_distributions_all_404_is_still_reported(tmp_path):
    """The table changes which name is asked, not whether a 404 counts."""
    _write(tmp_path, "app.py", "import cv2\n")
    result = check_python_apis(tmp_path, pypi_lookup=lambda name: False, interpreter=INTERPRETER)

    assert [f.verdict for f in result.findings] == ["possible-slopsquat"]


def test_an_unknown_404_import_is_still_a_possible_slopsquat(tmp_path):
    _write(tmp_path, "app.py", "import definitely_not_a_real_pkg_xyz\n")
    result = check_python_apis(tmp_path, pypi_lookup=lambda name: False, interpreter=INTERPRETER)

    assert [f.verdict for f in result.findings] == ["possible-slopsquat"]


def test_the_alias_table_covers_the_common_traps():
    from trustlayer.checks.api_resolution import IMPORT_DISTRIBUTIONS

    expected = {
        "cv2": "opencv-python", "PIL": "Pillow", "yaml": "PyYAML", "sklearn": "scikit-learn",
        "bs4": "beautifulsoup4", "dotenv": "python-dotenv", "jwt": "PyJWT",
        "docx": "python-docx", "dateutil": "python-dateutil", "skimage": "scikit-image",
        "fitz": "PyMuPDF", "serial": "pyserial", "Crypto": "pycryptodome",
        "OpenSSL": "pyOpenSSL", "gi": "PyGObject", "magic": "python-magic",
        "MySQLdb": "mysqlclient", "rest_framework": "djangorestframework",
        "googleapiclient": "google-api-python-client",
    }
    for module, distribution in expected.items():
        assert distribution in IMPORT_DISTRIBUTIONS[module], module
    assert set(IMPORT_DISTRIBUTIONS["psycopg2"]) == {"psycopg2-binary", "psycopg2"}
