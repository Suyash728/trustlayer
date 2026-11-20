"""Terminal UI over the run database and the checks.

`create_app` mirrors `killscore.ui.create_app`, so both surfaces are constructed the same
way and both take an optional `db_path` for tests.
"""

from killscore.tui.app import KillscoreApp, create_app


__all__ = ["KillscoreApp", "create_app"]
