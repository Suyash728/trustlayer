"""Session-wide guards for the test suite.

`~/.trustlayer/runs.db` is a real user database. `audit` records to it by default, so a
single CLI test that forgets `--no-save` writes fixture runs into someone's actual history,
where they surface in `trustlayer history` and the local UI. That happened: 116 of the 119
runs in this machine's database were fixture rows left by earlier test runs.

Passing `--no-save` in each test fixes today's leak but relies on every future test
remembering. Redirecting the default path for the whole session makes it structural: a test
that forgets the flag writes to a temporary file instead of the user's history.
"""

import pytest

from trustlayer import store


@pytest.fixture(autouse=True, scope="session")
def _never_touch_the_real_database(tmp_path_factory):
    """Point the default database at a throwaway file for the whole run."""
    redirected = tmp_path_factory.mktemp("trustlayer-home") / "runs.db"
    original = store.DEFAULT_DB_PATH
    store.DEFAULT_DB_PATH = redirected
    try:
        yield redirected
    finally:
        store.DEFAULT_DB_PATH = original
