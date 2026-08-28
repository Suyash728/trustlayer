"""mutmut's cached state must not be allowed to answer for a suite it has never seen.

`mutants/` is not scratch space: it holds a copy of the project including a copy of
`tests/`, plus `mutmut-stats.json` mapping each mutated function to the tests that cover
it. mutmut runs the tests from that copy and consults that map, and refreshes neither when
the real `tests/` changes.

That made `harden` unable to observe its own work. A generated test that genuinely killed
mutants was never copied in, never entered the map, never ran - so every iteration reported
the same score, every run reported +0.0%, and the plateau detector stopped the loop on the
strength of a number that could not move. Measured on the demo repo: a test that takes the
score from 61.7% to 63.6% read as 61.7% with the cache intact.

Per CLAUDE.md, subprocess is patched at `trustlayer.mutation.subprocess.run` - patching the
`app.services.mutation` re-export namespace intercepts nothing.
"""

from pathlib import Path
import subprocess
from unittest.mock import patch

from trustlayer.mutation import clear_mutmut_state, run_mutation


RESULTS = "pricing.x_f__mutmut_1: killed\npricing.x_g__mutmut_1: survived\n"


def fake_mutmut(command, **kwargs):
    """`run` produces nothing on stdout; `results` lists mutants; `show` renders a diff."""
    if "results" in command:
        return subprocess.CompletedProcess(command, 0, stdout=RESULTS)
    if "show" in command:
        # The real shape: header, unprefixed paths, a hunk, and a removed line.
        diff = (
            "# pricing.x_g__mutmut_1: survived\n"
            "--- src/pricing.py\n"
            "+++ src/pricing.py\n"
            "@@ -1,3 +1,3 @@\n"
            " def g(x):\n"
            "-    return x >= 1\n"
            "+    return x > 1\n"
        )
        return subprocess.CompletedProcess(command, 0, stdout=diff)
    return subprocess.CompletedProcess(command, 0, stdout="")


def seeded(tmp_path: Path) -> Path:
    """A repo carrying the state a previous mutmut run would have left."""
    mutants = tmp_path / "mutants"
    (mutants / "tests").mkdir(parents=True)
    (mutants / "tests" / "test_x.py").write_text("# a stale copy of the suite\n")
    (mutants / "mutmut-stats.json").write_text('{"tests_by_mangled_function_name": {}}')
    (tmp_path / ".mutmut-cache").write_text("stale")
    return tmp_path


def test_stale_state_is_cleared_before_a_run(tmp_path):
    repo = seeded(tmp_path)

    with patch("trustlayer.mutation.subprocess.run", side_effect=fake_mutmut):
        run_mutation(repo)

    assert not (repo / "mutants").exists()
    assert not (repo / ".mutmut-cache").exists()


def test_clearing_is_the_default_because_a_stale_score_is_worse_than_a_slow_one(tmp_path):
    repo = seeded(tmp_path)

    with patch("trustlayer.mutation.subprocess.run", side_effect=fake_mutmut):
        run_mutation(repo)  # no `fresh` argument passed

    assert not (repo / "mutants").exists()


def test_the_opt_out_keeps_the_cache(tmp_path):
    repo = seeded(tmp_path)

    with patch("trustlayer.mutation.subprocess.run", side_effect=fake_mutmut):
        run_mutation(repo, fresh=False)

    assert (repo / "mutants" / "tests" / "test_x.py").is_file()
    assert (repo / ".mutmut-cache").is_file()


def test_clearing_a_repo_that_never_ran_mutmut_is_not_an_error(tmp_path):
    clear_mutmut_state(tmp_path)  # no mutants/, no cache file

    assert tmp_path.is_dir()


def test_the_score_is_still_read_after_clearing(tmp_path):
    """Clearing must not disturb the parsing contract the rest of the tool depends on."""
    repo = seeded(tmp_path)

    with patch("trustlayer.mutation.subprocess.run", side_effect=fake_mutmut):
        result = run_mutation(repo)

    assert result.killed == 1
    assert result.survived == 1
    assert result.score == 50.0
