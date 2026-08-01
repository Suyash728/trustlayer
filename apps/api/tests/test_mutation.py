from pathlib import Path
import re
import subprocess
from unittest.mock import patch

from app.services.mutation import DEFAULT_TIMEOUT_SECONDS, Survivor, get_survivors


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_OUTPUT_PATH = REPOSITORY_ROOT / "docs" / "codex-runs" / "mutmut-sample-output.txt"
PRICING_SOURCE_PATH = REPOSITORY_ROOT / "demo-repos" / "pricing-py" / "src" / "pricing.py"


def _load_real_mutmut_output() -> tuple[str, str]:
    """Return the recorded `mutmut results` and `mutmut show` output.

    These are the first two text blocks in the transcript. Later blocks are narrative
    from the same run, so this selects what it needs rather than pinning the file's
    total block count.
    """
    sample = SAMPLE_OUTPUT_PATH.read_text()
    blocks = re.findall(r"```text\n(.*?)\n```", sample, flags=re.DOTALL)
    assert len(blocks) >= 2
    return blocks[0], blocks[1]


def test_get_survivors_parses_the_recorded_mutmut_3_6_output():
    results_output, show_output = _load_real_mutmut_output()
    expected_diff = show_output[show_output.index("--- ") :]
    expected_line = next(
        line_number
        for line_number, source_line in enumerate(PRICING_SOURCE_PATH.read_text().splitlines(), start=1)
        if source_line.strip().startswith("rate = 0.15 if quantity >= 50")
    )

    def run_mutmut(command, **kwargs):
        assert kwargs["timeout"] == DEFAULT_TIMEOUT_SECONDS
        if command[1:] == ["results", "--all", "true"]:
            return subprocess.CompletedProcess(command, 0, stdout=results_output)
        assert command[1] == "show"
        return subprocess.CompletedProcess(command, 0, stdout=show_output)

    with patch("app.services.mutation.subprocess.run", side_effect=run_mutmut) as run:
        survivors = get_survivors(PRICING_SOURCE_PATH.parents[1])

    assert len(survivors) == 41
    assert survivors[0] == Survivor(
        id="pricing.x_apply_volume_discount__mutmut_3",
        file="src/pricing.py",
        line=expected_line,
        diff=expected_diff,
    )
    assert run.call_count == 42
    assert all(call.kwargs["timeout"] == DEFAULT_TIMEOUT_SECONDS for call in run.call_args_list)
