"""The cumulative cost ceiling.

`--budget` caps a single agent turn-set. `harden` makes up to
MAX_SURVIVORS_PER_ITERATION of them per iteration, for up to max_iterations
iterations - so before this ceiling existed, `--budget 2` could spend many times
two dollars while the flag said otherwise. The ceiling is checked after every
agent call and reported the same way a plateau is.
"""

from pathlib import Path

import pytest

from trustlayer.agent import harden as harden_module
from trustlayer.agent.harden import DEFAULT_MAX_TOTAL_COST_USD, harden
from trustlayer.agent.runtime import AgentResult
from trustlayer.mutation import MutationRun, Survivor


def survivors(count: int) -> list[Survivor]:
    """`function` is derived from the mutmut id, so the id has to carry the real shape."""
    return [
        Survivor(id=f"src.m.x_f{i}__mutmut_1", file="src/m.py", line=i + 1, diff="")
        for i in range(count)
    ]


@pytest.fixture
def stub_repo(tmp_path, monkeypatch):
    """A repo whose mutation score never moves, so only a stop condition ends the loop."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.py").write_text("def f0():\n    return 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_m.py").write_text("def test_f0():\n    assert True\n")

    monkeypatch.setattr(harden_module, "_mutmut_executable", lambda source: Path("mutmut"))
    monkeypatch.setattr(harden_module, "tooling_interpreter", lambda source: Path("python"))
    monkeypatch.setattr(
        harden_module,
        "run_mutation",
        lambda root, executable=None: MutationRun(
            score=50.0, killed=1, survived=3, total=4, survivors=survivors(3)
        ),
    )
    monkeypatch.setattr(harden_module, "prune_to_passing", lambda *a, **k: ([], []))
    monkeypatch.setattr(harden_module, "count_tests", lambda path: 0)
    return tmp_path


def test_the_ceiling_stops_the_run_and_says_so(stub_repo, monkeypatch):
    calls = []

    def spend(*args, **kwargs):
        calls.append(1)
        return AgentResult(ok=True, text="done", cost_usd=1.0)

    monkeypatch.setattr(harden_module, "run_agent", spend)
    result = harden(stub_repo, target_score=100.0, max_iterations=5, max_total_cost_usd=2.0)

    assert "total cost ceiling" in result.stopped_because
    assert result.total_cost_usd == pytest.approx(2.0)
    # Without the ceiling this would have been 5 iterations x 3 survivors = 15 calls.
    assert len(calls) == 2


def test_a_run_under_the_ceiling_is_not_cut_short(stub_repo, monkeypatch):
    monkeypatch.setattr(
        harden_module, "run_agent", lambda *a, **k: AgentResult(ok=True, text="d", cost_usd=0.01)
    )
    result = harden(stub_repo, target_score=100.0, max_iterations=2, max_total_cost_usd=10.0)

    assert "total cost ceiling" not in result.stopped_because
    assert result.total_cost_usd == pytest.approx(0.06)  # 2 iterations x 3 survivors


def test_work_already_done_is_still_measured_when_the_ceiling_hits(stub_repo, monkeypatch):
    """Stopping must not throw away the iteration that was in progress."""
    monkeypatch.setattr(
        harden_module, "run_agent", lambda *a, **k: AgentResult(ok=True, text="d", cost_usd=5.0)
    )
    result = harden(stub_repo, target_score=100.0, max_iterations=5, max_total_cost_usd=1.0)

    assert len(result.iterations) == 1
    assert result.final_score == 50.0


def test_a_local_run_reports_tokens_because_its_cost_is_always_zero(stub_repo, monkeypatch):
    monkeypatch.setattr(
        harden_module,
        "run_agent",
        lambda *a, **k: AgentResult(
            ok=True, text="d", cost_usd=0.0, backend="ollama", input_tokens=100, output_tokens=20
        ),
    )
    result = harden(stub_repo, target_score=100.0, max_iterations=1, backend="ollama")

    assert result.backend == "ollama"
    assert result.total_input_tokens == 300  # 3 survivors
    assert result.total_output_tokens == 60
    assert result.total_cost_usd == 0.0


def test_the_default_ceiling_exists_and_is_finite():
    assert 0 < DEFAULT_MAX_TOTAL_COST_USD < float("inf")
