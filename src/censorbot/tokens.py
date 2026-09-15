"""Opaque, reversible placeholder tokens.

Design decisions (see README "Token format"):

* **Plain ASCII** ``[[TYPE_NNN]]``. Unicode brackets (``⟦⟧``) get normalised or
  stripped by some model tokenizers; double square brackets survive round-trips
  through every major LLM and through DOCX/PDF/JSON/email far more reliably.
* **Readable type + sequential index.** The type aids the human review UI and
  keeps relationship structure legible; the sequential index makes "the model
  invented ``[[PERSON_842]]`` that we never issued" trivial to detect.
* **Guessability is not a leak.** The token→value mapping lives only in the local
  vault, and *only tokens the vault issued* are ever rehydrated. Guessing a token
  reveals nothing, so a random suffix would buy no real security while hurting
  readability and round-trip validation.
"""

from __future__ import annotations

import re

from .spans import EntityType

# Matches [[PERSON_001]], [[PATIENT_ID_017]], etc. The type is greedy up to the
# final underscore so multi-word types (PATIENT_ID) resolve correctly.
TOKEN_RE = re.compile(r"\[\[([A-Z][A-Z_]*)_(\d{3,})\]\]")


def make_token(entity_type: EntityType | str, index: int) -> str:
    """Build a token string for ``entity_type`` with a 1-based ``index``."""

    type_str = entity_type.value if isinstance(entity_type, EntityType) else str(entity_type)
    if not re.fullmatch(r"[A-Z][A-Z_]*", type_str):
        raise ValueError(f"invalid token type: {type_str!r}")
    if index < 1:
        raise ValueError("token index must be >= 1")
    return f"[[{type_str}_{index:03d}]]"


def parse_token(token: str) -> tuple[str, int] | None:
    """Return ``(type, index)`` for a full token string, or ``None``."""

    m = TOKEN_RE.fullmatch(token)
    if not m:
        return None
    return m.group(1), int(m.group(2))


class TokenRegistry:
    """Assigns stable tokens by (type, value) across many documents.

    Per document, tokens come from the resolver's per-document index. For a set of
    *related* documents that should share pseudonyms (the same person → the same
    token everywhere), pass one registry to every ``sanitize`` call: it maps a
    normalised (type, value) to a token created once, with a per-type counter.

    This is opt-in. The default (no registry) keeps tokens session/document-scoped
    so unrelated documents can't be correlated through a shared mapping.
    """

    def __init__(self) -> None:
        self._map: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def token_for(self, entity_type, value: str) -> str:
        type_str = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
        key = (type_str, " ".join(value.strip().lower().split()))
        tok = self._map.get(key)
        if tok is None:
            self._counters[type_str] = self._counters.get(type_str, 0) + 1
            tok = make_token(type_str, self._counters[type_str])
            self._map[key] = tok
        return tok


def find_tokens(text: str) -> list[tuple[str, str, int, int, int]]:
    """Find every token in ``text``.

    Returns a list of ``(token, type, index, start, end)`` tuples.
    """

    out = []
    for m in TOKEN_RE.finditer(text):
        out.append((m.group(0), m.group(1), int(m.group(2)), m.start(), m.end()))
    return out
