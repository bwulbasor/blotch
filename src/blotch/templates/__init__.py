"""HTML templates for the web UI and the interactive review page.

They are plain files (open them in a browser, lint the JS) rather than Python
strings with every brace doubled. Slots are ``@@NAME@@`` markers, filled in a
single pass by :func:`fill` so a value can never inject another slot.
"""

from __future__ import annotations

import re
from importlib.resources import files

_SLOT = re.compile(r"@@([A-Z][A-Z_]*)@@")


def load(name: str) -> str:
    """Return the text of the packaged template ``name`` (e.g. ``"review.html"``)."""
    return files(__name__).joinpath(name).read_text(encoding="utf-8")


def fill(template: str, values: dict[str, str]) -> str:
    """Replace each ``@@NAME@@`` slot with ``values[NAME]`` in ONE pass.

    Sequential ``str.replace`` would be unsafe: a document containing the text
    "@@AUTO_JSON@@" would be substituted into ORIGINAL_JSON first, then that
    copy would be rewritten by the next replace. A single regex pass never
    re-scans inserted values. Unknown or missing slots raise, so a template and
    its caller can't silently drift apart.
    """
    missing = {m.group(1) for m in _SLOT.finditer(template)} - set(values)
    if missing:
        raise KeyError(f"template slots with no value: {sorted(missing)}")
    return _SLOT.sub(lambda m: values[m.group(1)], template)
