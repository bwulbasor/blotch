"""Detection layers.

* :mod:`.deterministic` - Layer A, regex + checksum validation.
* :mod:`.ner` - Layer B, contextual named entities (spaCy or heuristic).
* :mod:`.custom` - user-declared recognizers for organisation-specific IDs.
"""

from ..spans import Span
from . import custom, deterministic, gazetteer, ner
from .custom import Recognizer


def detect_all(text: str, use_ner: bool = True, use_spacy: bool = True,
               recognizers=()) -> list[Span]:
    """Run all detection layers and return the combined (unresolved) spans.

    ``recognizers`` are extra :class:`Recognizer` objects (usually from the
    policy) run alongside the built-in detectors.
    """

    spans = deterministic.detect(text)
    spans += gazetteer.detect(text)
    spans += custom.detect(text, recognizers)
    if use_ner:
        spans += ner.detect(text, use_spacy=use_spacy)
    return spans


__all__ = ["custom", "deterministic", "gazetteer", "ner", "detect_all",
           "Recognizer", "Span"]
