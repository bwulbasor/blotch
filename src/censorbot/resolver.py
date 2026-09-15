"""Layer C: entity resolution.

Groups spans that refer to the *same* real-world entity so they receive the same
token. Two failure modes matter and both corrupt meaning and rehydration:

* **over-merging** two distinct people into one token, and
* **under-merging** one person across several tokens.

We therefore link only on *high-confidence* evidence (exact normalised identity,
or an unambiguous surname/first-name match to exactly one full name). Ambiguous
mentions stay as their own entity rather than guessing. Distinct entities always
get distinct tokens, so relationship structure (plan §11) is preserved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .spans import EntityType, Span

# Types whose identity is the (normalised) literal value.
_VALUE_IDENTITY = {
    EntityType.EMAIL, EntityType.PHONE, EntityType.IBAN, EntityType.CREDIT_CARD,
    EntityType.IP, EntityType.URL, EntityType.GOV_ID, EntityType.PATIENT_ID,
    EntityType.CASE_ID, EntityType.ACCOUNT_ID, EntityType.DATE, EntityType.DOB,
    EntityType.ORGANIZATION, EntityType.LOCATION, EntityType.ADDRESS,
}
_TITLE_RE = re.compile(r"^(?:mr|mrs|ms|miss|dr|prof|herr|frau|sir|madam|mx)\.?\s+", re.I)


@dataclass
class Entity:
    """A resolved entity: one token, one or more member spans."""

    entity_type: EntityType
    canonical: str
    members: list[Span] = field(default_factory=list)
    index: int = 0  # per-type sequential index, assigned by :func:`resolve`

    @property
    def first_offset(self) -> int:
        return min(s.start for s in self.members)


def _norm_value(entity_type: EntityType, value: str) -> str:
    v = value.strip()
    if entity_type in (EntityType.EMAIL, EntityType.URL):
        return v.lower()
    if entity_type in (EntityType.IBAN, EntityType.CREDIT_CARD, EntityType.PHONE):
        return re.sub(r"[\s\-.()]", "", v)
    return " ".join(v.lower().split())


def _name_parts(value: str) -> list[str]:
    stripped = _TITLE_RE.sub("", value.strip())
    return [p.lower().strip(".") for p in stripped.split() if p]


def resolve(spans: list[Span]) -> list[Entity]:
    """Group ``spans`` into entities and assign per-type sequential indices."""

    entities: list[Entity] = []

    # 1. value-identity types: group by normalised literal.
    by_value: dict[tuple[EntityType, str], Entity] = {}
    persons: list[Span] = []
    for span in spans:
        if span.entity_type == EntityType.PERSON:
            persons.append(span)
            continue
        key = (span.entity_type, _norm_value(span.entity_type, span.value))
        ent = by_value.get(key)
        if ent is None:
            ent = Entity(span.entity_type, span.value.strip())
            by_value[key] = ent
            entities.append(ent)
        ent.members.append(span)

    # 2. persons: build full-name entities, then attach unambiguous partials.
    full: list[Entity] = []
    partials: list[Span] = []
    full_by_norm: dict[str, Entity] = {}
    for span in sorted(persons, key=lambda s: s.start):
        parts = _name_parts(span.value)
        if len(parts) >= 2:
            norm = " ".join(parts)
            ent = full_by_norm.get(norm)
            if ent is None:
                ent = Entity(EntityType.PERSON, _TITLE_RE.sub("", span.value.strip()))
                full_by_norm[norm] = ent
                full.append(ent)
            ent.members.append(span)
        else:
            partials.append(span)

    # Index full-name entities by each of their name parts once, so matching a
    # partial is O(parts) instead of O(full) - this was the dominant cost on
    # large documents (millions of _name_parts calls).
    part_index: dict[str, list[Entity]] = {}
    for ent in full:
        for part in set(_name_parts(ent.canonical)):
            part_index.setdefault(part, []).append(ent)

    unmatched_by_norm: dict[str, Entity] = {}
    for span in partials:
        parts = _name_parts(span.value)
        cand: list[Entity] = []
        seen_ids: set[int] = set()
        for part in parts:
            for ent in part_index.get(part, ()):
                if id(ent) not in seen_ids:
                    seen_ids.add(id(ent))
                    cand.append(ent)
        if len(cand) == 1:
            cand[0].members.append(span)
        else:
            # Zero or ambiguous full-name match. Group all occurrences of the same
            # surface into ONE entity (not one-per-occurrence): every "Curie" that
            # can't be pinned to a single full name is still the same token, so the
            # surface propagates consistently and doesn't leak at sentence starts.
            norm = " ".join(_name_parts(span.value))
            ent = unmatched_by_norm.get(norm)
            if ent is None:
                ent = Entity(EntityType.PERSON, span.value.strip(), [])
                unmatched_by_norm[norm] = ent
                full.append(ent)
            ent.members.append(span)

    entities.extend(full)

    # 3. canonical = the longest *verbatim* surface among the members. Restore
    #    reproduces exactly what a token replaced, so the value must be text that
    #    actually appeared (title-stripping was only for *matching*, not storage).
    #    Note: co-referent mentions with different surfaces ("Alejandro Martinez"
    #    vs "Mr. Martinez") share one token and all restore to this canonical -
    #    a deliberate coreference/fidelity trade-off (see README).
    for ent in entities:
        ent.canonical = max((s.value for s in ent.members), key=len)

    # 4. assign per-type sequential indices by first appearance.
    entities.sort(key=lambda e: e.first_offset)
    counters: dict[EntityType, int] = {}
    for ent in entities:
        counters[ent.entity_type] = counters.get(ent.entity_type, 0) + 1
        ent.index = counters[ent.entity_type]

    return entities
