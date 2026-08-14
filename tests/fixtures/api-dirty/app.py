"""Every import here is wrong in a different way."""

import totally_not_a_real_package_xyz123
from rich.console import ConsoleeX
import yaml


def load(text):
    return yaml.safe_loadd(text)


def render():
    return ConsoleeX()


def fetch():
    return totally_not_a_real_package_xyz123.get("/")
