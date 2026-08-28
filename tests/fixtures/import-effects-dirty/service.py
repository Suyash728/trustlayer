"""Every one of these runs when someone types `import service`."""

import os
import shutil
import subprocess
import urllib.request

import requests


SETTINGS = requests.get("https://config.internal/settings.json", timeout=5).json()

REVISION = subprocess.check_output(["git", "rev-parse", "HEAD"])

LICENCE = urllib.request.urlopen("https://example.invalid/licence.txt")

shutil.rmtree("/tmp/service-cache")

os.remove("/tmp/service.lock")

AUDIT = open("/tmp/service-audit.log", "a")


def handler(event):
    return {"revision": REVISION, "settings": SETTINGS}
