"""Leakage metrics stricter than span overlap.

Overlap recall counts a gold identifier as "caught" if ANY predicted span
touches it, so hiding "Jose" in "Jose Gomez Ruiz" scores as a hit while
"Gomez Ruiz" leaks. These measure what actually survives:

* **SPriV** (token leakage, after the PRvL study): the share of PII tokens -
  alphanumeric words inside gold spans - that are left even partly unmasked.
  Lower is better; 0% means no token of any gold identifier survives.
* **full-coverage recall**: the share of gold spans with every identifying
  character hidden.

``ignore`` drops non-identifying tokens that a gold span may include - blotch
deliberately leaves honorifics ("Mr", "Dr") as plaintext, and TAB's gold PERSON
spans include them, so TAB reports are computed both with and without them.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\S+")
_EDGE = ".,;:()[]'\"!?"


def coverage_mask(text: str, spans) -> bytearray:
    mask = bytearray(len(text))
    for s in spans:
        mask[s.start:s.end] = b"\x01" * (s.end - s.start)
    return mask


class Leakage:
    """Accumulates SPriV and full-coverage recall over many gold spans."""

    def __init__(self, ignore=frozenset()):
        self.ignore = ignore
        self.tokens = self.leaked_tokens = 0
        self.spans = self.full_spans = 0

    def add(self, text: str, mask: bytearray, start: int, end: int) -> None:
        span_leaks = False
        counted = False
        for m in _TOKEN.finditer(text, start, end):
            tok = m.group(0)
            if not any(ch.isalnum() for ch in tok):
                continue
            if tok.strip(_EDGE).lower() in self.ignore:
                continue
            counted = True
            self.tokens += 1
            if any(text[i].isalnum() and not mask[i] for i in range(m.start(), m.end())):
                self.leaked_tokens += 1
                span_leaks = True
        if counted:
            self.spans += 1
            self.full_spans += not span_leaks

    @property
    def spriv(self) -> float:
        return self.leaked_tokens / self.tokens if self.tokens else 0.0

    @property
    def full_recall(self) -> float:
        return self.full_spans / self.spans if self.spans else 1.0
