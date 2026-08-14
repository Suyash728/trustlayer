"""Every import and attribute here is real. The check must stay silent."""

import json
from pathlib import Path

from rich.console import Console
import yaml


def load(text):
    return yaml.safe_load(text)


def render(payload):
    console = Console()
    console.print(json.dumps(payload))
    return Path.cwd()
