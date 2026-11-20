"""Where the ts-morph helpers run from.

The `.mjs` helpers ship inside the package, but their `node_modules` cannot: it is ~30 MB and
platform-neutral JavaScript that npm installs. Node resolves an ESM import relative to the
*script's own directory*, not the cwd and not NODE_PATH, so the scripts must sit next to the
`node_modules` that holds ts-morph.

Search order, first one with ts-morph installed wins:

1. `$TRUSTLAYER_NODE_DIR`
2. the package's own `checks/node/` (a source checkout after `npm install --prefix ...`)
3. `~/.trustlayer/node/` (what `trustlayer setup-node` creates - the path for wheel/uvx installs)

For (1) and (3) the packaged scripts are copied in before each run when they differ, so an
upgraded TrustLayer never runs a stale helper against a newer Python side.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil

from trustlayer.checks.base import ToolRun, run_tool


PACKAGED_DIR = Path(__file__).parent / "node"
USER_DIR = Path.home() / ".trustlayer" / "node"
DIR_ENV = "TRUSTLAYER_NODE_DIR"
NPM_TIMEOUT_SECONDS = 600
SHIPPED_FILES = ("package.json", "package-lock.json")


def _candidates() -> list[Path]:
    configured = os.environ.get(DIR_ENV, "").strip()
    found = [Path(configured).expanduser()] if configured else []
    return [*found, PACKAGED_DIR, USER_DIR]


def _has_ts_morph(directory: Path) -> bool:
    return (directory / "node_modules" / "ts-morph").is_dir()


def helper_dir() -> Path | None:
    """The directory to run helpers from, with its scripts current, or None."""
    for directory in _candidates():
        if _has_ts_morph(directory):
            if directory != PACKAGED_DIR:
                sync_scripts(directory)
            return directory
    return None


def sync_scripts(directory: Path) -> None:
    """Copy the packaged `.mjs` helpers into `directory` when they differ."""
    for script in sorted(PACKAGED_DIR.glob("*.mjs")):
        target = directory / script.name
        try:
            if target.is_file() and target.read_bytes() == script.read_bytes():
                continue
            shutil.copyfile(script, target)
        except OSError:
            continue  # a read-only helper dir keeps whatever scripts it already has


def missing_reason() -> str:
    return "ts-morph helper not installed; run `trustlayer setup-node` (needs node and npm)"


def setup(directory: Path | None = None) -> tuple[Path, ToolRun]:
    """Create a helper dir: copy the manifest, lockfile and scripts, then `npm ci`."""
    target = (directory or Path(os.environ.get(DIR_ENV, "") or USER_DIR)).expanduser()
    target.mkdir(parents=True, exist_ok=True)
    for name in SHIPPED_FILES:
        source = PACKAGED_DIR / name
        if source.is_file():
            shutil.copyfile(source, target / name)
    sync_scripts(target)
    command = ["npm", "ci", "--no-audit", "--no-fund"]
    if not (target / "package-lock.json").is_file():
        command = ["npm", "install", "--no-audit", "--no-fund"]
    return target, run_tool(command, cwd=target, timeout=NPM_TIMEOUT_SECONDS)
