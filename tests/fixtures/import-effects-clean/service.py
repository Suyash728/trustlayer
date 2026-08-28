"""Every call here is either nested, conditional, or a read. None of it should report."""

from pathlib import Path
import json
import os
import shutil
import subprocess
from typing import TYPE_CHECKING
import urllib.request

import requests


# Reads at import are ordinary and never reported.
VERSION = Path(__file__).with_name("VERSION").read_text().strip()
DEFAULTS = json.load(open(Path(__file__).with_name("defaults.json")))
TEMPLATE = open(Path(__file__).with_name("template.txt")).read()
NOTES = open(Path(__file__).with_name("notes.txt"), "r").read()

# A computed mode is unknowable, so it stays silent rather than guessing.
MODE = os.environ.get("LOG_MODE", "r")
HANDLE = open("/tmp/maybe.log", MODE)

if TYPE_CHECKING:
    REVISION = subprocess.check_output(["git", "rev-parse", "HEAD"])

if os.environ.get("PREFETCH"):
    SETTINGS = requests.get("https://config.internal/settings.json", timeout=5).json()

try:
    LICENCE = urllib.request.urlopen("https://example.invalid/licence.txt")
except OSError:
    LICENCE = None

for stale in ("/tmp/a", "/tmp/b"):
    shutil.rmtree(stale, ignore_errors=True)

with open("/tmp/report.txt") as handle:
    FIRST_LINE = handle.readline()


def refresh():
    """Nested in a function: runs only when called."""
    requests.post("https://config.internal/refresh", timeout=5)
    subprocess.run(["systemctl", "reload", "service"], timeout=30, check=False)
    os.remove("/tmp/service.lock")


class Client:
    SESSION = requests.Session()  # constructing a Session touches no network

    def fetch(self, url):
        return requests.get(url, timeout=5)


if __name__ == "__main__":
    refresh()
