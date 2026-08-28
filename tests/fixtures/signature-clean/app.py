"""Correct calls, plus one instance of every condition the check must stay silent on."""

import base64
import json
import math
from shutil import which
import textwrap


OPTIONS = {"predicate": None}
ARGS = ("body", "    ")

# Correct calls.
GOOD_A = textwrap.indent("body", "    ")
GOOD_B = textwrap.indent("body", "    ", None)
GOOD_C = base64.b64encode(b"data")
GOOD_D = base64.b64encode(b"data", b"-_")
GOOD_E = which("ls")
GOOD_F = which("ls", 1, "/usr/bin")

# **kwargs in the signature: any keyword may be legitimate.
KWARGS_SIGNATURE = textwrap.shorten("body", 20, placeholder="...", not_a_real_option=1)

# *a at the call site: the positional count is not knowable.
STAR_ARGS = textwrap.indent(*ARGS)

# **kw at the call site: any keyword may be present.
STAR_KWARGS = textwrap.indent("body", "    ", **OPTIONS)

# A C builtin has no reliable introspectable signature.
BUILTIN = math.sqrt(4)

# A class drags in __new__ and metaclasses; the probe declines to describe it.
CLASS_CALL = json.JSONEncoder(1, 2, 3, 4, 5, 6, 7, 8, 9)

# The receiver is not a plain name, so the object is unknown.
UNKNOWN_RECEIVER = (json or textwrap).indent(1, 2, 3, 4, 5)
