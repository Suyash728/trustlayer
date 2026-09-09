"""Terminal UI over the run database and the checks.

`create_app` mirrors `trustlayer.ui.create_app`, so both surfaces are constructed the same
way and both take an optional `db_path` for tests.
"""

from trustlayer.tui.app import TrustLayerApp, create_app


__all__ = ["TrustLayerApp", "create_app"]
