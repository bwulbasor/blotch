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
    """Drop overlapping spans, keeping the longest (ties broken by confidence).

    Detectors run independently and may double-cover text (e.g. an ADDRESS that
    contains a POSTAL code). We keep the widest, most confident coverage so the
    replaced region is never left with a leaked fragment.
    """

    if not spans:
        return []
    # Confidence first, then width: a structural high-confidence span (an IPv4 or
    # MAC) beats a longer but weaker one that merely bridges it (a greedy phone
    # run spanning "192.168.5.10 (01"). Length breaks ties among equal-confidence
    # spans so "Marie Curie" still wins over "Marie".
    ordered = sorted(
        spans,
        key=lambda s: (-s.confidence, -(s.end - s.start), s.start),
    )
    # A covered bitmap makes overlap checks O(span length) instead of O(kept),
    # so this is linear in total span length rather than quadratic in span count
    # (which mattered on multi-MB documents with tens of thousands of spans).
    end = max(s.end for s in ordered)
    covered = bytearray(end)
    kept: list[Span] = []
    for span in ordered:
        if covered.find(1, span.start, span.end) != -1:
            continue
        kept.append(span)
        covered[span.start:span.end] = b"\x01" * (span.end - span.start)
    kept.sort(key=lambda s: s.start)
    return kept
