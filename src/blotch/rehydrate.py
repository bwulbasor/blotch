"""Re-identification of an external service's response (plan §10).

The return trip is treated as untrusted. We rehydrate **only tokens the vault
issued** - never guessing at a malformed or invented one - and report anything
anomalous so the caller can decide rather than silently trusting model output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .tokens import TOKEN_RE, find_tokens
from .vault import Vault

# A token region tolerant of what models do to tokens: internal spaces
# ("[[ PERSON_001 ]]") and markdown backslash-escapes ("\[\[PERSON\_001\]\]").
# The inner text is normalised (escapes + spaces stripped) and checked against
# the strict TYPE_NNN shape, so ordinary "[[not a token]]" is left untouched.
_TOK_REGION = re.compile(r"\\?\[\s*\\?\[(.*?)\\?\]\s*\\?\]", re.S)
_INNER = re.compile(r"([A-Z][A-Z_]*)_(\d{3,})")


@dataclass
class RestoreResult:
    text: str
    restored: list[str] = field(default_factory=list)   # tokens replaced
    invented: list[str] = field(default_factory=list)   # token-shaped, not issued
    dropped: list[str] = field(default_factory=list)     # issued but absent in input

    @property
    def has_anomalies(self) -> bool:
        return bool(self.invented or self.dropped)

    def summary(self) -> str:
        bits = [f"restored {len(self.restored)}"]
        if self.invented:
            bits.append(f"INVENTED {len(self.invented)} (not rehydrated): {self.invented}")
        if self.dropped:
            bits.append(f"dropped {len(self.dropped)}")
        return "; ".join(bits)


def restore(text: str, vault: Vault) -> RestoreResult:
    """Replace known tokens in ``text`` with their original values.

    Unknown/invented tokens are left verbatim and reported, never resolved.
    """

    issued = set(vault.tokens())
    seen: set[str] = set()
    restored: list[str] = []
    invented: list[str] = []

    def _sub(m) -> str:
        inner = m.group(1).replace("\\", "").replace(" ", "").replace("\t", "")
        im = _INNER.fullmatch(inner)
        if not im:
            return m.group(0)  # "[[not a token]]" - leave it alone
        token = f"[[{inner}]]"
        seen.add(token)
        if token in issued:
            if token not in restored:
                restored.append(token)
            return vault.value_for(token) or token
        if token not in invented:
            invented.append(token)
        return m.group(0)  # leave invented tokens (in original form) untouched

    out = _TOK_REGION.sub(_sub, text)
    dropped = [t for t in issued if t not in seen]
    return RestoreResult(text=out, restored=restored, invented=invented, dropped=dropped)


def validate_response(text: str, vault: Vault) -> RestoreResult:
    """Inspect a response *without* rewriting it (dry run of :func:`restore`)."""

    issued = set(vault.tokens())
    restored, invented, seen = [], [], set()
    for token, _type, _idx, _s, _e in find_tokens(text):
        seen.add(token)
        if token in issued:
            if token not in restored:
                restored.append(token)
        elif token not in invented:
            invented.append(token)
    dropped = [t for t in issued if t not in seen]
    return RestoreResult(text=text, restored=restored, invented=invented, dropped=dropped)
