"""Detection layers.

* :mod:`.deterministic` - Layer A, regex + checksum validation.
* :mod:`.ner` - Layer B, contextual named entities (spaCy or heuristic).
"""

from ..spans import Span
from . import deterministic, ner


def detect_all(text: str, use_ner: bool = True, use_spacy: bool = True) -> list[Span]:
    """Run all detection layers and return the combined (unresolved) spans."""

    spans = deterministic.detect(text)
    if use_ner:
        spans += ner.detect(text, use_spacy=use_spacy)
    return spans


__all__ = ["deterministic", "ner", "detect_all", "Span"]
