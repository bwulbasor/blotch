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

_TITLE_WORDS = {"mr", "mrs", "ms", "miss", "dr", "prof", "herr", "frau", "sir",
                "madam", "mx", "st"}
_ORG_SUFFIX_WORDS = {
    "inc", "llc", "ltd", "gmbh", "ag", "plc", "corp", "co", "company", "hospital",
    "clinic", "klinik", "university", "universität", "bank", "group", "holdings",
    "foundation", "court", "gericht", "sons", "partners", "associates",
}
# A single letter-led "word" (Unicode-aware: any letter start, then letters /
# apostrophe / hyphen). Uppercase is judged with str.isupper(), which is correct
# for accented and non-Latin letters that an ASCII char class ([A-Z]) misses.
_WORD = re.compile(r"[^\W\d_][^\W\d_'’\-]*", re.UNICODE)

# Sentence-leading capitalised words that are usually not names.
_STOPWORDS = {
    "The", "A", "An", "This", "That", "These", "Those", "His", "Her", "Their",
    "It", "He", "She", "They", "We", "You", "I", "On", "In", "At", "For", "And",
    "But", "Or", "If", "When", "According", "Patient",
}

# Words that are never a person's name: function words and document-structure
# / form-label words. A candidate run has these trimmed from its ends (so
# "In Vienna" -> "Vienna", "DISCHARGE SUMMARY" -> dropped) without touching real
# names in the middle. Lower-cased for lookup. Titles are handled separately and
# are deliberately NOT included here.
_NON_NAME = {w.lower() for w in _STOPWORDS} | {
    "of", "to", "from", "by", "with", "as", "is", "was", "were", "be", "been",
    "re", "cc", "bcc", "attn", "dear", "sincerely", "regards", "subject",
    "summary", "invoice", "discharge", "confidential", "draft", "section",
    "article", "chapter", "page", "figure", "note", "notes", "total",
    "subtotal", "amount", "balance", "date", "ref", "reference",
    "contact", "billing", "emergency", "plaintiff", "defendant", "exhibit",
    "appendix", "memo", "report", "statement", "notice", "admitting",
    "regarding", "dob", "name", "address", "phone", "email", "questions", "due",
    # currency codes and financial labels (all-caps codes, never names)
    "eur", "usd", "gbp", "chf", "jpy", "cad", "aud", "cny", "sek", "nok", "dkk",
    "pln", "czk", "huf", "iban", "bic", "swift", "vat", "pin", "otp", "url",
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
    """True if the match at ``start`` begins a sentence (or the text).

    Only real sentence terminators and line breaks count - notably NOT ':' or
    ';', because names very often follow a label colon ("Emergency contact: ...").
    """

    i = start - 1
    while i >= 0 and text[i] in " \t":
        i -= 1
    return i < 0 or text[i] in ".!?…\n\r"


def _is_title(word: str) -> bool:
    return word.lower().rstrip(".") in _TITLE_WORDS


def _heuristic_detect(text: str) -> list[Span]:
    """Group consecutive capitalised words into PERSON / ORGANIZATION runs.

    Uppercase is tested with ``str.isupper()`` so accented and non-Latin names
    ("Škoda", "Łukasz", "Øthen") are caught. Words are joined only across plain
    horizontal whitespace - a run never crosses a line break or punctuation -
    except that a title may be followed by "." (e.g. "Dr. Keller").
    """

    words = list(_WORD.finditer(text))
    spans: list[Span] = []
    i, n = 0, len(words)
    while i < n:
        w = words[i]
        if not (w.group(0)[:1].isupper() or _is_title(w.group(0))):
            i += 1
            continue
        run = [w]
        j = i + 1
        while j < n and len(run) < 5:
            prev, cur = run[-1], words[j]
            gap = text[prev.end():cur.start()]
            prev_is_title = _is_title(prev.group(0))
            gap_ok = (all(c in " \t" for c in gap) and gap != "") or (
                prev_is_title and re.fullmatch(r"\.?[ \t]+", gap) is not None)
            if gap_ok and cur.group(0)[:1].isupper():
                run.append(cur)
                j += 1
            else:
                break
        lowered = {r.group(0).lower().rstrip(".") for r in run}
        titled = _is_title(run[0].group(0))

        # ORG is decided on the FULL run (suffix words must not be trimmed away).
        if lowered & _ORG_SUFFIX_WORDS:
            start, end = run[0].start(), run[-1].end()
            spans.append(Span(start, end, EntityType.ORGANIZATION, text[start:end],
                              0.55, "ner_heur"))
            i = j
            continue

        # PERSON candidate: trim function / structure words from both ends so
        # "In Vienna" -> "Vienna" and "DISCHARGE SUMMARY" -> nothing, without
        # touching a real name in the middle. Titles are kept as the leading word.
        person = list(run)
        while person and not _is_title(person[0].group(0)) \
                and person[0].group(0).lower().rstrip(".") in _NON_NAME:
            person.pop(0)
        while person and person[-1].group(0).lower().rstrip(".") in _NON_NAME:
            person.pop()
        if not person:
            i = j
            continue
        content = [r for r in person if not _is_title(r.group(0))]
        titled = _is_title(person[0].group(0))
        if not titled and len(content) == 1:
            first = content[0].group(0)
            # A lone single letter is an initial, not a name; a stopword or a
            # sentence-opening lone word is too weak to treat as a person.
            if (len(first) < 2 or first in _STOPWORDS
                    or _is_sentence_initial(text, content[0].start())):
                i = j
                continue
        if content:  # a bare title alone is not a person
            start, end = person[0].start(), person[-1].end()
            spans.append(Span(start, end, EntityType.PERSON, text[start:end], 0.5,
                              "ner_heur"))
        i = j
    return spans


def detect(text: str, use_spacy: bool = True) -> list[Span]:
    """Detect contextual entities. Falls back to heuristics if spaCy is absent."""

    if use_spacy:
        spacy_spans = _spacy_detect(text)
        if spacy_spans is not None:
            return spacy_spans
    return _heuristic_detect(text)
