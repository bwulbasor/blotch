"""Layer B: named-entity detection for contextual entities (PERSON, ORG, ...).

Uses spaCy when installed (``pip install 'censorbot[ner]'``), otherwise a
dependency-free heuristic fallback so the pipeline still runs everywhere. The
fallback is intentionally high-recall / lower-precision: for a privacy gateway a
false positive is an annoyance, a false negative is a leak (plan §4). The review
UI is where precision is recovered.
"""

from __future__ import annotations

import re

from ..spans import EntityType, Span

_TITLES = r"(?:Mr|Mrs|Ms|Miss|Dr|Prof|Herr|Frau|Sir|Madam|Mx)\.?"
_ORG_SUFFIX = (
    r"(?:Inc|LLC|Ltd|GmbH|AG|PLC|Corp|Co|Company|Hospital|Clinic|Klinik|"
    r"University|Universität|Bank|Group|Holdings|Foundation|Court|Gericht)"
)

# A run of Capitalised words, optionally preceded by a title.
_NAME_RUN = re.compile(
    rf"(?:{_TITLES}\s+)?(?:[A-ZÄÖÜ][a-zäöüß'\-]+)(?:\s+[A-ZÄÖÜ][a-zäöüß'\-]+){{0,3}}"
)
_ORG_RUN = re.compile(
    rf"(?:[A-ZÄÖÜ][A-Za-zäöüß'\-]+\s+)*[A-ZÄÖÜ][A-Za-zäöüß'\-]+\s+{_ORG_SUFFIX}\b"
)

# Sentence-leading capitalised words that are usually not names.
_STOPWORDS = {
    "The", "A", "An", "This", "That", "These", "Those", "His", "Her", "Their",
    "It", "He", "She", "They", "We", "You", "I", "On", "In", "At", "For", "And",
    "But", "Or", "If", "When", "According", "Patient", "Mr", "Mrs", "Ms", "Dr",
}


def _spacy_detect(text: str):  # pragma: no cover - exercised only when spaCy present
    try:
        import spacy
    except Exception:
        return None
    try:
        nlp = _spacy_detect._nlp  # type: ignore[attr-defined]
    except AttributeError:
        try:
            nlp = spacy.load("en_core_web_sm")
        except Exception:
            return None
        _spacy_detect._nlp = nlp  # type: ignore[attr-defined]

    label_map = {
        "PERSON": EntityType.PERSON,
        "ORG": EntityType.ORGANIZATION,
        "GPE": EntityType.LOCATION,
        "LOC": EntityType.LOCATION,
        "FAC": EntityType.LOCATION,
    }
    spans: list[Span] = []
    for ent in nlp(text).ents:
        etype = label_map.get(ent.label_)
        if etype is None:
            continue
        spans.append(Span(ent.start_char, ent.end_char, etype, ent.text, 0.85, "spacy"))
    return spans


def _is_sentence_initial(text: str, start: int) -> bool:
    """True if the match at ``start`` begins a sentence (or the text)."""

    i = start - 1
    while i >= 0 and text[i] in " \t":
        i -= 1
    return i < 0 or text[i] in ".!?…\n\r;:"


def _heuristic_detect(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _ORG_RUN.finditer(text):
        spans.append(Span(m.start(), m.end(), EntityType.ORGANIZATION, m.group(0), 0.55, "ner_heur"))
    for m in _NAME_RUN.finditer(text):
        value = m.group(0)
        words = value.split()
        titled = bool(re.match(_TITLES, value))
        first = words[0].rstrip(".")
        # A lone capitalised word is only weak evidence of a name. Drop it when it
        # is a known stopword, or when it merely opens a sentence ("Later, ..."),
        # unless it carries a title. Multi-word runs are always kept (high recall).
        if not titled and len(words) == 1:
            if first in _STOPWORDS or _is_sentence_initial(text, m.start()):
                continue
        spans.append(Span(m.start(), m.end(), EntityType.PERSON, value, 0.5, "ner_heur"))
    return spans


def detect(text: str, use_spacy: bool = True) -> list[Span]:
    """Detect contextual entities. Falls back to heuristics if spaCy is absent."""

    if use_spacy:
        spacy_spans = _spacy_detect(text)
        if spacy_spans is not None:
            return spacy_spans
    return _heuristic_detect(text)
