"""Core data model: entity types and detected spans.

A ``Span`` is a single detected stretch of sensitive text with a location,
a type, and a confidence. Detectors emit spans; the resolver groups them into
entities; the pipeline replaces them with tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    """Canonical sensitive-entity categories.

    Values double as the ``TYPE`` portion of a token (see :mod:`blotch.tokens`),
    so they must be uppercase ``[A-Z_]+`` with no digits.
    """

    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ADDRESS = "ADDRESS"
    DATE = "DATE"
    DOB = "DOB"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    IBAN = "IBAN"
    CREDIT_CARD = "CREDIT_CARD"
    IP = "IP"
    URL = "URL"
    GOV_ID = "GOV_ID"
    PATIENT_ID = "PATIENT_ID"
    CASE_ID = "CASE_ID"
    ACCOUNT_ID = "ACCOUNT_ID"
    MAC = "MAC"
    COORDINATES = "COORDINATES"
    CRYPTO = "CRYPTO"
    AGE = "AGE"          # quasi-identifier ("88 years old", "aged 45")
    TIME = "TIME"        # clock time ("10:18 PM", "4 PM")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True)
class Span:
    """A single detected sensitive span within a source text.

    Attributes
    ----------
    start, end:
        Character offsets into the source text (``text[start:end]`` == ``value``).
    entity_type:
        One of :class:`EntityType`.
    value:
        The exact substring detected.
    confidence:
        ``0.0``-``1.0``. Validated detectors (IBAN, card) score high; heuristic
        NER scores lower. Used only for the leak scanner / review UI, never to
        silently drop a candidate.
    detector:
        Name of the detector that produced the span (for debugging / audit).
    """

    start: int
    end: int
    entity_type: EntityType
    value: str
    confidence: float = 1.0
    detector: str = ""

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span offsets: {self.start}..{self.end}")

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


def resolve_overlaps(spans: list[Span]) -> list[Span]:
    """Resolve overlapping spans into non-overlapping coverage.

    Detectors run independently and may double-cover text (e.g. an ADDRESS that
    contains a POSTAL code). We keep the widest, most confident coverage, and
    when a span loses to one that overlaps only part of it, its uncovered
    remainder is kept too - so the replaced region is never left with a leaked
    fragment.
    """

    if not spans:
        return []
    # Confidence *band* first (rounded to 0.1), then width, then exact confidence:
    #
    #   * A structural, clearly higher-confidence span still wins over a longer
    #     weaker one that merely bridges it - an IPv4/MAC (0.9+) beats a greedy
    #     phone run spanning "192.168.5.10 (01" (0.6), and a MAC (0.95) beats the
    #     IPv6-shaped match of the same bytes.
    #   * But when two spans are within the same confidence band, the *longer* one
    #     wins - so a full person name ("Kianna London Barrows", 0.5) is not
    #     evicted by a one-word city inside it ("London", 0.52), which would drop
    #     the first and last name entirely (a leak). Banding stops a 0.02 gap from
    #     overriding a real name; a 0.3 gap (structural) still does.
    ordered = sorted(
        spans,
        key=lambda s: (-round(s.confidence * 10), -(s.end - s.start),
                       -s.confidence, s.start),
    )
    # A covered bitmap makes overlap checks O(span length) instead of O(kept),
    # so this is linear in total span length rather than quadratic in span count
    # (which mattered on multi-MB documents with tens of thousands of spans).
    end = max(s.end for s in ordered)
    covered = bytearray(end)
    kept: list[Span] = []
    for span in ordered:
        if covered.find(1, span.start, span.end) == -1:
            kept.append(span)
            covered[span.start:span.end] = b"\x01" * (span.end - span.start)
            continue
        # The span lost to a higher-ranked one that overlaps only PART of it.
        # Discarding it whole would leave its uncovered part - text a detector
        # flagged as sensitive - in the clear: spaCy tagging "Martinez" used to
        # evict the heuristic's "Alejandro Martinez" and leak "Alejandro". Keep
        # the uncovered remainder(s) instead.
        for frag in _remainders(span, covered):
            kept.append(frag)
            covered[frag.start:frag.end] = b"\x01" * (frag.end - frag.start)
    kept.sort(key=lambda s: s.start)
    return kept


# Greedy digit-run detectors: a partial loss is often regex over-reach (a phone
# run bridging into an IP: "192.168.5.10 (01"), so their remainder is kept only
# when it still carries a real chunk of digits ("... 5609").
_DIGIT_RUNS = {EntityType.PHONE, EntityType.CREDIT_CARD}
_MIN_DIGIT_REMAINDER = 4


def _remainders(span: Span, covered: bytearray) -> list[Span]:
    """Uncovered sub-ranges of ``span``, trimmed to their alphanumeric core."""

    if len(span.value) != span.end - span.start:
        return []  # value not aligned with offsets -> can't slice it safely
    out: list[Span] = []
    i = span.start
    while i < span.end:
        if covered[i]:
            i += 1
            continue
        j = i
        while j < span.end and not covered[j]:
            j += 1
        # trim non-alphanumeric edges ("-Jose Gomez Ruiz " -> "Jose Gomez Ruiz")
        a, b = i, j
        while a < b and not span.value[a - span.start].isalnum():
            a += 1
        while b > a and not span.value[b - 1 - span.start].isalnum():
            b -= 1
        frag = span.value[a - span.start:b - span.start]
        keep = (sum(ch.isdigit() for ch in frag) >= _MIN_DIGIT_REMAINDER
                if span.entity_type in _DIGIT_RUNS
                else sum(ch.isalnum() for ch in frag) >= 2)
        if keep:
            out.append(Span(a, b, span.entity_type, frag, span.confidence,
                            f"{span.detector}:remainder"))
        i = j
    return out
