"""Four call sites, each wrong in a way only the real signature reveals."""

import base64
from shutil import which
import textwrap


# textwrap.indent(text, prefix, predicate=None) takes at most 3.
TOO_MANY = textwrap.indent("body", "    ", None, "surplus")

# base64.b64encode(s, altchars=None) requires s.
TOO_FEW = base64.b64encode()

# 'predicat' is a misspelling of 'predicate'. The call is otherwise fine.
BAD_KEYWORD = textwrap.indent("body", "    ", predicat=None)

# Same defect reached through `from shutil import which`.
BAD_KEYWORD_FROM_IMPORT = which("ls", pathh="/usr/bin")
