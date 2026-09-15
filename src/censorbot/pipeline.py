"""Sanitisation pipeline: original text -> pseudonymised text + vault.

    detect -> resolve overlaps -> resolve entities -> apply policy -> tokenise
    -> leak-scan

Only the pseudonymised text should ever leave the device; the vault stays local.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detectors import detect_all
from .leakscan import LeakReport, scan
from .policy import Action, Policy
from .resolver import Entity, resolve
from .spans import Span, resolve_overlaps
from .vault import Vault

_REDACTED = "[REDACTED]"
_PROPAGATE_CHUNK = 400  # max surfaces per combined propagation regex


def _word_bounded(surface: str) -> str:
    """Regex matching ``surface`` as a whole token (word boundaries on word-char edges)."""
    left = r"(?<!\w)" if surface[:1].isalnum() or surface[:1] == "_" else ""
    right = r"(?!\w)" if surface[-1:].isalnum() or surface[-1:] == "_" else ""
    return left + re.escape(surface) + right


@dataclass
class SanitizeResult:
    sanitized_text: str
    vault: Vault
    entities: list[Entity] = field(default_factory=list)
    leak_report: LeakReport | None = None
    num_tokenized: int = 0
    num_redacted: int = 0

    def entity_count(self) -> int:
        return len(self.entities)


def sanitize(text: str, policy: Policy, *, use_ner: bool = True,
             use_spacy: bool = True, run_leak_scan: bool = True,
             vault: Vault | None = None) -> SanitizeResult:
    """Pseudonymise ``text`` under ``policy``. Returns a :class:`SanitizeResult`."""

    vault = vault or Vault()
    spans = detect_all(text, use_ner=use_ner, use_spacy=use_spacy)
    spans = resolve_overlaps(spans)
    entities = resolve(spans)

    # Decide a replacement per member span, honouring the policy per type.
    edits: list[tuple[int, int, str]] = []  # (start, end, replacement)
    kept_entities: list[Entity] = []
    covered = bytearray(len(text))  # 1 where a char is already claimed by an edit
    surface_token: dict[str, str | None] = {}  # surface -> token, None if ambiguous
    n_tok = n_red = 0
    for entity in entities:
        action = policy.action_for(entity.entity_type)
        if action == Action.KEEP:
            continue
        kept_entities.append(entity)
        if action == Action.TOKENIZE:
            replacement = vault.add_entity(entity, action.value)
            n_tok += 1
        else:  # REDACT
            replacement = _REDACTED
            n_red += 1
        for span in entity.members:
            edits.append((span.start, span.end, replacement))
            for k in range(span.start, span.end):
                covered[k] = 1
        # Record each surface for propagation (tokenised entities only).
        if action == Action.TOKENIZE:
            for surface in {m.value for m in entity.members} | {entity.canonical}:
                if len(surface) < 2:
                    continue
                if surface in surface_token and surface_token[surface] != replacement:
                    surface_token[surface] = None  # shared by 2 entities -> ambiguous
                elif surface not in surface_token:
                    surface_token[surface] = replacement

    # Occurrence propagation (plan §2): once a surface is known sensitive, catch
    # *every* whole-word occurrence, including ones the detectors skipped (e.g. a
    # sentence-initial "Curie" that the single-word heuristic dropped). This keeps
    # tokenisation consistent so the leak scanner stays clean. Only surfaces owned
    # unambiguously by one entity propagate, to avoid merging distinct people.
    # One combined regex, longest surface first, so the pass is a single scan.
    surfaces = sorted((s for s, t in surface_token.items() if t), key=len,
                      reverse=True)
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
            edits.append((s, e, token))
            for k in range(s, e):
                covered[k] = 1

    # Apply edits right-to-left so earlier offsets stay valid.
    edits.sort(key=lambda ed: ed[0], reverse=True)
    out = text
    for start, end, replacement in edits:
        out = out[:start] + replacement + out[end:]

    result = SanitizeResult(
        sanitized_text=out,
        vault=vault,
        entities=kept_entities,
        num_tokenized=n_tok,
        num_redacted=n_red,
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
