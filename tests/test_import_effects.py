"""Import-time side-effect tests.

The silence tests are the point of this file. A call that is nested, conditional, or a read
must never report, because a false positive here trains people to ignore the whole tool.
The `-clean` fixture deliberately contains network calls, a subprocess call, an rmtree and
an os.remove - every one of them guarded - and must produce nothing at all.
"""

from pathlib import Path

import pytest

from trustlayer.checks.base import Severity
from trustlayer.checks.import_effects import CHECK_NAME, check_import_effects


FIXTURES = Path(__file__).parent / "fixtures"


def findings_for(name: str):
    return check_import_effects(FIXTURES / name).findings


def verdicts(name: str):
    return sorted(finding.verdict for finding in findings_for(name))


# ------------------------------------------------------------------------- silence


def test_a_module_of_guarded_calls_reports_nothing():
    """The clean fixture is full of dangerous calls. Every one is nested or a read."""
    assert findings_for("import-effects-clean") == []


@pytest.mark.parametrize(
    ("guard", "source"),
    [
        ("function body", "import requests\n\n\ndef go():\n    requests.get('https://x')\n"),
        ("class body", "import requests\n\n\nclass C:\n    def go(self):\n        requests.get('https://x')\n"),
        ("if", "import requests\n\nif FLAG:\n    requests.get('https://x')\n"),
        ("if TYPE_CHECKING", "import requests\nfrom typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    requests.get('https://x')\n"),
        ("try", "import requests\n\ntry:\n    requests.get('https://x')\nexcept OSError:\n    pass\n"),
        ("with", "import requests\n\nwith ctx():\n    requests.get('https://x')\n"),
        ("for", "import requests\n\nfor u in urls:\n    requests.get(u)\n"),
        ("while", "import requests\n\nwhile True:\n    requests.get('https://x')\n"),
        ("__main__ guard", "import requests\n\nif __name__ == '__main__':\n    requests.get('https://x')\n"),
    ],
)
def test_nesting_of_any_kind_means_silence(tmp_path, guard, source):
    """AST cannot see that a call sits behind a feature flag, so it never guesses."""
    (tmp_path / "m.py").write_text(source)

    assert check_import_effects(tmp_path).findings == [], f"reported inside a {guard}"


@pytest.mark.parametrize(
    "source",
    [
        "open('/tmp/x')\n",
        "open('/tmp/x', 'r')\n",
        "open('/tmp/x', mode='r')\n",
        "open('/tmp/x', 'rb')\n",
        "from pathlib import Path\nPath('/tmp/x').read_text()\n",
        "import json\nDATA = json.load(open('/tmp/x.json'))\n",
    ],
)
def test_reads_are_not_effects(tmp_path, source):
    (tmp_path / "m.py").write_text(source)

    assert check_import_effects(tmp_path).findings == []


def test_a_computed_mode_is_unknowable_so_it_stays_silent(tmp_path):
    (tmp_path / "m.py").write_text("import os\nMODE = os.environ.get('M', 'r')\nH = open('/tmp/x', MODE)\n")

    assert check_import_effects(tmp_path).findings == []


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nS = requests.Session()\n",  # constructs, touches no network
        "import httpx\nC = httpx.Client()\n",
        "import socket\nS = socket.socket()\n",  # allocates a descriptor, does not connect
    ],
)
def test_constructors_that_perform_no_io_are_not_flagged(tmp_path, source):
    """Flagging these would make the evidence line untrue."""
    (tmp_path / "m.py").write_text(source)

    assert check_import_effects(tmp_path).findings == []


def test_an_unresolvable_receiver_is_never_guessed_about(tmp_path):
    """`get_client().get(...)` says nothing about what `.get` does."""
    (tmp_path / "m.py").write_text("R = get_client().get('https://x')\nQ = registry['a'].remove('/tmp/y')\n")

    assert check_import_effects(tmp_path).findings == []


def test_a_syntactically_broken_module_is_skipped_not_crashed(tmp_path):
    (tmp_path / "m.py").write_text("import requests\nrequests.get(\n")

    assert check_import_effects(tmp_path).findings == []


# ------------------------------------------------------------------------ findings


def test_every_effect_category_is_caught():
    assert verdicts("import-effects-dirty") == [
        "import-time-destructive",
        "import-time-destructive",
        "import-time-network",
        "import-time-network",
        "import-time-subprocess",
        "import-time-write",
    ]


def test_destructive_calls_outrank_the_rest():
    """Deleting data on import is worse than being slow on import."""
    by_verdict = {f.verdict: f for f in findings_for("import-effects-dirty")}

    assert by_verdict["import-time-destructive"].severity is Severity.HIGH
    assert by_verdict["import-time-network"].severity is Severity.MEDIUM
    assert by_verdict["import-time-subprocess"].severity is Severity.MEDIUM
    assert by_verdict["import-time-write"].severity is Severity.MEDIUM


def test_the_finding_quotes_the_line_it_is_about():
    """Evidence has to be re-derivable by hand, so the source line comes first."""
    finding = next(f for f in findings_for("import-effects-dirty") if f.verdict == "import-time-network")
    source = (FIXTURES / "import-effects-dirty" / "service.py").read_text().splitlines()

    assert finding.evidence[0] == source[finding.line - 1].strip()
    assert finding.check == CHECK_NAME


@pytest.mark.parametrize(
    ("source", "verdict"),
    [
        ("import requests\nR = requests.post('https://x')\n", "import-time-network"),
        ("import httpx\nR = httpx.get('https://x')\n", "import-time-network"),
        ("import urllib.request\nR = urllib.request.urlopen('https://x')\n", "import-time-network"),
        ("import socket\nC = socket.create_connection(('h', 80))\n", "import-time-network"),
        ("import subprocess\nR = subprocess.run(['ls'])\n", "import-time-subprocess"),
        ("import os\nos.system('ls')\n", "import-time-subprocess"),
        ("import shutil\nshutil.rmtree('/tmp/x')\n", "import-time-destructive"),
        ("open('/tmp/x', 'w')\n", "import-time-write"),
        ("open('/tmp/x', mode='a')\n", "import-time-write"),
    ],
)
def test_each_flagged_call_is_recognised(tmp_path, source, verdict):
    (tmp_path / "m.py").write_text(source)
    findings = check_import_effects(tmp_path).findings

    assert [f.verdict for f in findings] == [verdict]


@pytest.mark.parametrize(
    "source",
    [
        "import requests as rq\nR = rq.get('https://x')\n",
        "from subprocess import run\nR = run(['ls'])\n",
        "from shutil import rmtree\nrmtree('/tmp/x')\n",
    ],
)
def test_import_aliases_are_resolved(tmp_path, source):
    (tmp_path / "m.py").write_text(source)

    assert len(check_import_effects(tmp_path).findings) == 1


def test_a_repo_without_python_skips_with_a_reason(tmp_path):
    (tmp_path / "notes.md").write_text("# nothing to parse\n")
    result = check_import_effects(tmp_path)

    assert result.skipped is True
    assert result.skip_reason == "no Python sources found"


def test_the_check_runs_by_default():
    """It touches nothing but the AST, so it is not opt-in."""
    from trustlayer.checks.runner import DEFAULT_CHECKS

    assert "import-effects" in DEFAULT_CHECKS
