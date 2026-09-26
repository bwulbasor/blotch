"""Layer B: named-entity detection for contextual entities (PERSON, ORG, ...).

Uses spaCy when installed (``pip install 'blotch[ner]'``), otherwise a
dependency-free heuristic fallback so the pipeline still runs everywhere. The
fallback is intentionally high-recall / lower-precision: for a privacy gateway a
false positive is an annoyance, a false negative is a leak (plan §4). The review
UI is where precision is recovered.
"""

from __future__ import annotations

import re

# The name word lists live in blotch.lexicon (shared with the resolver and the
# pipeline); aliased to the historical private names used throughout this module.
from ..lexicon import (
    NAME_WORD as _WORD,
    NON_NAME as _NON_NAME,
    ORG_SUFFIX_WORDS as _ORG_SUFFIX_WORDS,
    PARTICLES as _PARTICLES,
    SENTENCE_OPENERS as _SENTENCE_OPENERS,
    STOPWORDS as _STOPWORDS,
    TITLE_WORDS as _TITLE_WORDS,
)
from ..spans import EntityType, Span

# _WORD (from the lexicon) is Unicode-aware; upper-case is judged with
# str.isupper(), which is correct for accented and non-Latin letters that an
# ASCII char class ([A-Z]) misses.
_MAX_NAME_GAP = 2  # max spaces/tabs between two words of one name run


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
    # spaCy raises over nlp.max_length (default 1M chars) as a memory guard, so
    # process large documents in offset-adjusted chunks split on line boundaries.
    limit = max(1, int(getattr(nlp, "max_length", 1_000_000) * 0.9))
    for base, chunk in _chunk_on_lines(text, limit):
        for ent in nlp(chunk).ents:
            etype = label_map.get(ent.label_)
            if etype is None:
                continue
            # A named-entity token never starts or ends with whitespace/newline;
            # spaCy sometimes glues a trailing wrap onto a span ("the \n"). Trim
            # the offsets so the surface is clean (interior bytes are untouched,
            # so a soft-wrapped name is still fully covered - no recall loss).
            surface = ent.text
            lead = len(surface) - len(surface.lstrip())
            trail = len(surface) - len(surface.rstrip())
            start = base + ent.start_char + lead
            end = base + ent.end_char - trail
            if end - start < 2:
                continue
            spans.append(Span(start, end, etype, surface.strip(), 0.85, "spacy"))
    return spans


def _chunk_on_lines(text: str, limit: int):
    """Yield ``(offset, chunk)`` pieces of ``text`` each <= ``limit`` chars, split
    at newlines so an entity is never cut across a chunk boundary."""
    if len(text) <= limit:
        yield 0, text
        return
    pos = 0
    n = len(text)
    while pos < n:
        end = min(pos + limit, n)
        if end < n:
            nl = text.rfind("\n", pos, end)
            if nl > pos:
                end = nl + 1
        yield pos, text[pos:end]
        pos = end


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

    # Words that also occur lower-case somewhere in the document are common words,
    # not names - a name is capitalised every time ("Content"/"content" -> common;
    # "Klensin" -> only ever capitalised). This document-internal, language- and
    # domain-agnostic signal removes most technical-term false positives with, on
    # the TAB/AI4Privacy benchmarks, zero loss of real names.
    doc_lower = set(re.findall(r"[a-zà-öø-ÿ][a-zà-öø-ÿ']{1,}", text))

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
            # Words of a name are separated by a single space (rarely two), never
            # a wide column gap - "SMTP          October" in a table of contents
            # must NOT merge into one entity.
            gap_ok = (0 < len(gap) <= _MAX_NAME_GAP and all(c in " \t" for c in gap)) or (
                prev_is_title and re.fullmatch(r"\.?[ \t]{1,3}", gap) is not None)
            if not gap_ok:
                break
            if cur.group(0)[:1].isupper():
                run.append(cur)
                j += 1
            elif (cur.group(0).lower() in _PARTICLES and j + 1 < n
                  and (words[j + 1].group(0)[:1].isupper()
                       or words[j + 1].group(0).lower() in _PARTICLES)
                  and 0 < len(text[cur.end():words[j + 1].start()]) <= _MAX_NAME_GAP
                  and all(c in " \t" for c in text[cur.end():words[j + 1].start()])):
                run.append(cur)  # bridge particle(s); the capitalised word joins next
                j += 1
            else:
                break
        # drop any trailing particle left by the bridge (e.g. an over-run "van");
        # j already points past it, so the outer loop still advances correctly.
        while len(run) > 1 and run[-1].group(0).lower() in _PARTICLES:
            run.pop()
        lowered = {r.group(0).lower().rstrip(".") for r in run}
        titled = _is_title(run[0].group(0))

        # An entirely upper-case run is an acronym, protocol keyword, or heading
        # (SMTP, RFC, MUST, STANDARDS TRACK), never a person's name in body text.
        # This removes the dominant source of over-detection in technical
        # documents. The deterministic detectors still catch any actual PII.
        content_words = [r for r in run if not _is_title(r.group(0))]
        # Judge the "all upper-case heading" test on the multi-letter words only:
        # a stray single upper-case letter is a PDF artifact or an initial
        # ("T HE CHIEF" from a broken heading), and should not rescue the run
        # from being recognised as a heading.
        caps = [w for w in content_words if len(w.group(0)) > 1]
        if caps and all(w.group(0).isupper() for w in caps):
            i = j
            continue

        # NB: the case-consistency signal is applied only to LONE words below, not
        # to multi-word runs - a multi-word name of common words ("May Rich") would
        # otherwise be dropped, which is a leak.

        # ORG needs a suffix word AND a distinguishing word that is neither a
        # stopword nor a suffix - "Vienna General Hospital" is an org, but "Court",
        # "The Court" and "European Court" (only stopwords + a suffix) are not.
        if lowered & _ORG_SUFFIX_WORDS:
            distinguishing = [r for r in run
                              if r.group(0).lower().rstrip(".") not in _NON_NAME
                              and r.group(0).lower().rstrip(".") not in _ORG_SUFFIX_WORDS]
            if distinguishing:
                start, end = run[0].start(), run[-1].end()
                spans.append(Span(start, end, EntityType.ORGANIZATION,
                                  text[start:end], 0.55, "ner_heur"))
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
            # A lone single letter is an initial, not a name. A lone word is
            # dropped if: it is a stopword; it also appears lower-case in the
            # document (a common word, not a name); or it opens a sentence and is
            # a known opener. An unknown, consistently-capitalised word is kept.
            if (len(first) < 2 or first in _STOPWORDS
                    or first.lower() in doc_lower
                    or (_is_sentence_initial(text, content[0].start())
                        and first.lower() in _SENTENCE_OPENERS)):
                i = j
                continue
        if content:  # a bare title alone is not a person
            # Span the name words only, leaving an honorific ("Mr", "Dr") as
            # plaintext: it is not PII, and excluding it keeps the token's value
            # the bare name so a later bare surname round-trips exactly (no
            # spurious "Mr" reinserted on restore). `titled` above still lets a
            # lone titled surname through.
            start, end = content[0].start(), content[-1].end()
            spans.append(Span(start, end, EntityType.PERSON, text[start:end], 0.5,
                              "ner_heur"))
        i = j
    return spans


def detect(text: str, use_spacy: bool = True) -> list[Span]:
    """Detect contextual entities.

    When spaCy is available it is *unioned* with the heuristic, not substituted
    for it. spaCy alone misses the cases most dangerous for a privacy tool -
    common-word names ("May", "Summer") and non-Latin names ("Łukasz Škoda") -
    so replacing the heuristic would drop recall and leak those. The union keeps
    the heuristic as a recall safety net (its spans are never lost) while spaCy
    adds correctly-typed ORG/LOCATION and names caught in natural context; where
    both cover the same text, spaCy's higher confidence wins overlap resolution,
    so its better typing prevails.
    """

    heuristic = _heuristic_detect(text)
    if use_spacy:
        spacy_spans = _spacy_detect(text)
        if spacy_spans is not None:
            return spacy_spans + heuristic
    return heuristic
