"""Call-signature tests. The silence tests come first because they are the check.

`api-resolution` answers "does this attribute exist". This answers "can it be called the way
the code calls it", which is the next thing a model gets wrong once it has the name right.
It is also the easiest check in this repo to turn into a false-positive generator, so every
condition it cannot be certain about has a test asserting it reports nothing.

Signatures are resolved against this interpreter's own stdlib, so the expected shapes are
stable without a fixture environment.
"""

from pathlib import Path
import sys

import pytest

from trustlayer.checks.api_resolution import (
    CallClaim,
    check_python_apis,
    collect_python_claims,
)
from trustlayer.checks.base import Severity


FIXTURES = Path(__file__).parent / "fixtures"
INTERPRETER = Path(sys.executable)


def ON_PYPI(name):
    return True


def run(fixture: str):
    return check_python_apis(FIXTURES / fixture, pypi_lookup=ON_PYPI, interpreter=INTERPRETER)


def signature_findings(fixture: str):
    return [f for f in run(fixture).findings if f.verdict in {"wrong-arity", "unknown-keyword"}]


def calls_in(tmp_path: Path, source: str) -> list[CallClaim]:
    (tmp_path / "m.py").write_text(source)
    _, _, calls = collect_python_claims(tmp_path, [tmp_path / "m.py"])
    return calls


# -------------------------------------------------------------------------- silence


def test_correct_calls_and_every_guard_case_report_nothing():
    """The clean fixture holds one instance of each guard condition."""
    assert signature_findings("signature-clean") == []


@pytest.mark.parametrize(
    ("guard", "source"),
    [
        (
            "**kwargs in the signature",
            "import textwrap\nX = textwrap.shorten('b', 20, totally_made_up=1)\n",
        ),
        (
            "*a at the call site",
            "import textwrap\nA = ('b', ' ')\nX = textwrap.indent(*A)\n",
        ),
        (
            "**kw at the call site",
            "import textwrap\nO = {}\nX = textwrap.indent('b', ' ', **O)\n",
        ),
        (
            "a C builtin",
            "import math\nX = math.sqrt(1, 2, 3, 4)\n",
        ),
        (
            "a class rather than a function",
            "import json\nX = json.JSONEncoder(1, 2, 3, 4, 5, 6, 7, 8, 9)\n",
        ),
        (
            "*args in the signature",
            "import os.path\nX = os.path.join('a', 'b', 'c', 'd', 'e', 'f')\n",
        ),
    ],
)
def test_each_guard_condition_produces_no_finding(tmp_path, guard, source):
    (tmp_path / "app.py").write_text(source)
    result = check_python_apis(tmp_path, pypi_lookup=ON_PYPI, interpreter=INTERPRETER)
    findings = [f for f in result.findings if f.verdict in {"wrong-arity", "unknown-keyword"}]

    assert findings == [], f"reported despite {guard}"


def test_arity_is_not_judged_on_a_call_that_mixes_positional_and_keyword(tmp_path):
    """A v1 limitation, deliberately: working out which slots the keywords fill is where an
    off-by-one becomes a false accusation. The keyword name is still checked."""
    (tmp_path / "app.py").write_text("import textwrap\nX = textwrap.indent('b', predicate=None)\n")
    result = check_python_apis(tmp_path, pypi_lookup=ON_PYPI, interpreter=INTERPRETER)

    assert [f for f in result.findings if f.verdict == "wrong-arity"] == []


def test_an_unresolvable_receiver_is_never_recorded(tmp_path):
    """`factory().go()` and `table['k'].go()` say nothing about what `go` is."""
    calls = calls_in(tmp_path, "import json\nA = factory().dumps(1,2,3)\nB = t['k'].dumps(1,2,3)\n")

    assert calls == []


def test_a_local_name_that_shadows_nothing_is_not_a_call_claim(tmp_path):
    """A bare call to something never imported cannot be attributed to a module."""
    calls = calls_in(tmp_path, "X = helper(1, 2, 3)\n")

    assert calls == []


# ------------------------------------------------------------------------- findings


def test_all_four_defect_shapes_are_caught():
    assert sorted(f.verdict for f in signature_findings("signature-dirty")) == [
        "unknown-keyword",
        "unknown-keyword",
        "wrong-arity",
        "wrong-arity",
    ]


def test_too_many_positional_arguments_is_reported_with_the_real_signature():
    finding = next(
        f for f in signature_findings("signature-dirty") if "indent() with 4" in f.claim
    )

    assert finding.severity is Severity.HIGH
    assert finding.verdict == "wrong-arity"
    assert "indent(text, prefix, predicate=None)" in " ".join(finding.evidence)
    assert "at most 3" in " ".join(finding.evidence)


def test_too_few_positional_arguments_names_what_is_missing():
    finding = next(f for f in signature_findings("signature-dirty") if "b64encode" in f.claim)

    assert "requires s" in " ".join(finding.evidence)


def test_a_misspelled_keyword_is_reported_against_the_real_parameter_list():
    finding = next(
        f for f in signature_findings("signature-dirty") if f.verdict == "unknown-keyword"
        and "indent" in f.claim
    )

    assert "'predicat'" in " ".join(finding.evidence)
    assert "predicate=None" in " ".join(finding.evidence)


def test_a_from_import_call_is_attributed_to_its_module():
    """`from shutil import which; which(...)` is a call on shutil, not on a local name."""
    finding = next(f for f in signature_findings("signature-dirty") if "shutil.which" in f.claim)

    assert finding.verdict == "unknown-keyword"
    assert "'pathh'" in " ".join(finding.evidence)


# --------------------------------------------------------------------- call capture


def test_star_unpacking_is_recorded_so_the_checker_can_refuse(tmp_path):
    calls = calls_in(tmp_path, "import textwrap\nX = textwrap.indent(*a, **k)\n")

    assert len(calls) == 1
    assert calls[0].star_args is True
    assert calls[0].star_kwargs is True
    assert calls[0].positional == 0


def test_positional_and_keyword_arguments_are_counted_separately(tmp_path):
    calls = calls_in(tmp_path, "import textwrap\nX = textwrap.indent('a', 'b', predicate=None)\n")

    assert calls[0].positional == 2
    assert calls[0].keywords == ("predicate",)


def test_an_aliased_import_resolves_to_the_real_module(tmp_path):
    calls = calls_in(tmp_path, "import textwrap as tw\nX = tw.indent('a', 'b')\n")

    assert calls[0].module == "textwrap"
    assert calls[0].attribute == "indent"


# ------------------------------------------------------------------- probe contract


@pytest.mark.parametrize(
    ("module", "name", "described"),
    [
        ("textwrap", "indent", True),  # plain function
        ("json", "JSONEncoder", False),  # class
        ("math", "sqrt", False),  # C builtin
    ],
)
def test_the_probe_only_describes_what_it_can_be_sure_about(module, name, described):
    import json as json_module
    import subprocess

    from trustlayer.checks.api_resolution import PROBE_PATH

    completed = subprocess.run(
        [sys.executable, str(PROBE_PATH)],
        input=json_module.dumps({"modules": {module: [name]}}),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    signatures = json_module.loads(completed.stdout)["modules"][module]["signatures"]

    assert (name in signatures) is described
