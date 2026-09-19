"""Sanitisation pipeline: original text -> pseudonymised text + vault.

    detect -> resolve overlaps -> resolve entities -> apply policy -> tokenise
    -> leak-scan

Only the pseudonymised text should ever leave the device; the vault stays local.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detectors import detect_all
from .detectors.gazetteer import PLACE_WORDS
from .detectors.ner import _NON_NAME, _PARTICLES, _TITLE_WORDS
from .leakscan import LeakReport, scan
from .policy import Action, Policy
from .resolver import Entity, resolve
from .spans import EntityType, Span, resolve_overlaps
from .vault import Vault

_REDACTED = "[REDACTED]"
_PROPAGATE_CHUNK = 400  # max surfaces per combined propagation regex
# A person name part is only safe to propagate on its own if it is not also a
# common word, a place, a title, or a nobiliary particle - otherwise "London"
# (a middle name) or "Green" (a colour) would over-redact unrelated text.
_NOT_A_NAME_PART = _NON_NAME | _TITLE_WORDS | _PARTICLES | PLACE_WORDS
_NAME_WORD = re.compile(r"[^\W\d_][^\W\d_'’\-]*", re.UNICODE)


def _propagatable_name_parts(canonical: str) -> list[str]:
    """Individual name words of a PERSON worth propagating on their own.

    So a bare surname later in the document ("Green" after "Mr Green", "Barrows"
    after "Kianna London Barrows") is caught. Returns parts only when the name is
    confidently a person - it carries an honorific, or has >= 2 real name words -
    and drops any part that is a common word / place / title (matched
    case-sensitively at propagation time, so only the Capitalised form is hit).
    """
    words = _NAME_WORD.findall(canonical)
    has_title = any(w.lower().rstrip(".") in _TITLE_WORDS for w in words)
    real = [w for w in words if w.lower().rstrip(".") not in _TITLE_WORDS]
    if not (has_title or len(real) >= 2):
        return []
    return [w for w in real
            if len(w) >= 3 and w.lower() not in _NOT_A_NAME_PART]


def _word_bounded(surface: str) -> str:
    """Regex matching ``surface`` as a whole token (word boundaries on word-char edges)."""
    left = r"(?<!\w)" if surface[:1].isalnum() or surface[:1] == "_" else ""
    right = r"(?!\w)" if surface[-1:].isalnum() or surface[-1:] == "_" else ""
    return left + re.escape(surface) + right


def _sweep_values(out: str, value_token: dict[str, str]) -> str:
    """Replace any residual whole-word vault value in ``out`` with its token.

    Deterministic (values ordered longest-first, then lexicographically) and
    chunked. A value can't match inside an existing ``[[TYPE_NNN]]`` token because
    a token's type is followed by ``_`` (a word char), so the boundary fails.
    """
    values = sorted((v for v in value_token if len(v) >= 2), key=lambda s: (-len(s), s))
    for start in range(0, len(values), _PROPAGATE_CHUNK):
        chunk = values[start:start + _PROPAGATE_CHUNK]
        pat = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(v) for v in chunk) + r")(?!\w)")
        out = pat.sub(lambda m: value_token.get(m.group(0), m.group(0)), out)
    return out


@dataclass
class SanitizeResult:
    sanitized_text: str
    vault: Vault
    entities: list[Entity] = field(default_factory=list)
    leak_report: LeakReport | None = None
    num_tokenized: int = 0
    num_redacted: int = 0
    #: The actual replacements applied, in original-text coordinates:
    #: (start, end, replacement). Includes propagated occurrences, so a masked
    #: preview built from these matches the sanitized output exactly.
    edit_spans: list[tuple[int, int, str]] = field(default_factory=list)
    #: Confidence (0.0-1.0) of each edit in ``edit_spans``, same order. Lets the
    #: review UI flag shaky detections (a lone-word PERSON at 0.5) apart from
    #: rock-solid structural ones (a checksum-validated IBAN at 0.97).
    edit_confidence: list[float] = field(default_factory=list)

    def entity_count(self) -> int:
        return len(self.entities)


def sanitize(text: str, policy: Policy, *, use_ner: bool = True,
             use_spacy: bool = True, run_leak_scan: bool = True,
             vault: Vault | None = None, registry=None) -> SanitizeResult:
    """Pseudonymise ``text`` under ``policy``. Returns a :class:`SanitizeResult`.

    Pass a shared :class:`~blotch.tokens.TokenRegistry` (and a shared ``vault``)
    across several documents to give the same entity the same token in all of them
    (opt-in cross-document consistency).
    """

    # Not `vault or Vault()`: an empty Vault is falsy (its __len__ is 0), which
    # would silently discard a shared vault on the first, still-empty call.
    vault = Vault() if vault is None else vault
    spans = detect_all(text, use_ner=use_ner, use_spacy=use_spacy)
    spans = resolve_overlaps(spans)
    entities = resolve(spans)

    # Decide a replacement per member span, honouring the policy per type.
    edits: list[tuple[int, int, str, float]] = []  # (start, end, replacement, conf)
    kept_entities: list[Entity] = []
    covered = bytearray(len(text))  # 1 where a char is already claimed by an edit
    surface_token: dict[str, str | None] = {}  # surface -> token, None if ambiguous
    surface_conf: dict[str, float] = {}         # surface -> owning entity confidence
    n_tok = n_red = 0
    for entity in entities:
        action = policy.action_for(entity.entity_type)
        if action == Action.KEEP:
            continue
        kept_entities.append(entity)
        if action == Action.TOKENIZE:
            tok = registry.token_for(entity.entity_type, entity.canonical) if registry else None
            replacement = vault.add_entity(entity, action.value, token=tok)
            n_tok += 1
        else:  # REDACT
            replacement = _REDACTED
            n_red += 1
        econf = max((m.confidence for m in entity.members), default=0.5)
        for span in entity.members:
            edits.append((span.start, span.end, replacement, span.confidence))
            covered[span.start:span.end] = b"\x01" * (span.end - span.start)
        # Record each surface for propagation (both TOKENIZE and REDACT, so a
        # redacted value is removed at every occurrence, not just detected ones).
        # First writer wins on a conflict (the earliest-appearing entity, since
        # entities are ordered by first offset): a surface owned by two entities
        # - e.g. spaCy typing "Babbage" as ORG here and LOCATION there, or a
        # surname shared by two people - still propagates to ONE token rather than
        # being dropped. Hiding every occurrence matters more than perfect typing;
        # a not-propagated surface would leak at positions no detector covered.
        # sorted() makes the first-writer-wins choice deterministic (set iteration
        # order is hash-randomized, which must never affect what gets hidden).
        for surface in sorted({m.value for m in entity.members} | {entity.canonical}):
            if len(surface) >= 2:
                surface_token.setdefault(surface, replacement)
                surface_conf.setdefault(surface, econf)
        # For a confident PERSON, also propagate its individual name parts so a
        # later bare surname ("Green" after "Mr Green") doesn't leak. Parts that
        # are common words / places / titles are excluded; matching is
        # case-sensitive, so "Green" is caught but "green" is not.
        if entity.entity_type == EntityType.PERSON:
            for part in _propagatable_name_parts(entity.canonical):
                surface_token.setdefault(part, replacement)
                surface_conf.setdefault(part, econf)

    # Occurrence propagation (plan §2): once a surface is known sensitive, catch
    # *every* whole-word occurrence, including ones the detectors skipped (e.g. a
    # sentence-initial "Curie" that the single-word heuristic dropped). This keeps
    # tokenisation consistent so the leak scanner stays clean. Only surfaces owned
    # unambiguously by one entity propagate, to avoid merging distinct people.
    # One combined regex, longest surface first, so the pass is a single scan.
    # Total, deterministic order (length desc, then the string) so same-length
    # surfaces never swap between chunks run-to-run.
    surfaces = sorted((s for s, t in surface_token.items() if t),
                      key=lambda s: (-len(s), s))
    # Chunk the alternation so a document with thousands of distinct surfaces
    # never builds one pathologically large pattern. Longest-first ordering is
    # preserved within each chunk; cross-chunk overlaps are handled by the
    # `covered` mask, so the split does not change results.
    for start in range(0, len(surfaces), _PROPAGATE_CHUNK):
        chunk = surfaces[start:start + _PROPAGATE_CHUNK]
        combined = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(s) for s in chunk)
                              + r")(?!\w)")
        for m in combined.finditer(text):
            s, e = m.start(), m.end()
            token = surface_token.get(m.group(0))
            if token is None or covered[s] or covered[e - 1]:
                continue
            edits.append((s, e, token, surface_conf.get(m.group(0), 0.5)))
            covered[s:e] = b"\x01" * (e - s)

    # Apply all edits in a single left-to-right pass (O(text + edits)); repeated
    # slicing would be O(edits x text) and dominated large documents.
    edits.sort(key=lambda ed: ed[0])
    parts: list[str] = []
    pos = 0
    applied: list[tuple[int, int, str]] = []
    applied_conf: list[float] = []
    for start, end, replacement, conf in edits:
        if start < pos:
            continue  # safety: skip any accidental overlap
        parts.append(text[pos:start])
        parts.append(replacement)
        pos = end
        applied.append((start, end, replacement))
        applied_conf.append(conf)
    parts.append(text[pos:])
    out = "".join(parts)

    # Guaranteed final sweep: whatever the propagation edge cases, no tokenised
    # value may survive whole-word in the output. Replace any residual occurrence
    # of a vault value with its token. This is the deterministic backstop that
    # makes "no known value leaks" a guarantee, not a best-effort.
    if vault.tokens():
        value_token: dict[str, str] = {}
        for tok in vault.tokens():
            v = vault.value_for(tok)
            if v and len(v) >= 2:
                value_token.setdefault(v, tok)
        out = _sweep_values(out, value_token)

    result = SanitizeResult(
        sanitized_text=out,
        vault=vault,
        entities=kept_entities,
        num_tokenized=n_tok,
        num_redacted=n_red,
        edit_spans=applied,  # sorted ascending, non-overlapping, actually applied
        edit_confidence=applied_conf,
    )
    if run_leak_scan:
        result.leak_report = scan(out, vault)
    return result


def preview(text: str, policy: Policy, *, block: str = "█",
            use_ner: bool = True, use_spacy: bool = True) -> str:
    """Render a masked preview of ``text`` for the review UI (plan §15).

    Sensitive spans become blocks of ``block`` characters. This shows the user
    what will be hidden *before* anything is transmitted.
    """

    spans = detect_all(text, use_ner=use_ner, use_spacy=use_spacy)
    spans = resolve_overlaps(spans)
    entities = resolve(spans)
    edits: list[tuple[int, int]] = []
    for entity in entities:
        if policy.action_for(entity.entity_type) == Action.KEEP:
            continue
        edits.extend((s.start, s.end) for s in entity.members)
    edits.sort(key=lambda e: e[0], reverse=True)
    out = text
    for start, end in edits:
        out = out[:start] + block * (end - start) + out[end:]
    return out
