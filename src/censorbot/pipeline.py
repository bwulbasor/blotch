"""Sanitisation pipeline: original text -> pseudonymised text + vault.

    detect -> resolve overlaps -> resolve entities -> apply policy -> tokenise
    -> leak-scan

Only the pseudonymised text should ever leave the device; the vault stays local.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import detect_all
from .leakscan import LeakReport, scan
from .policy import Action, Policy
from .resolver import Entity, resolve
from .spans import Span, resolve_overlaps
from .vault import Vault

_REDACTED = "[REDACTED]"


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
    n_tok = n_red = 0
    for entity in entities:
        action = policy.action_for(entity.entity_type)
        if action == Action.KEEP:
            continue
        kept_entities.append(entity)
        if action == Action.TOKENIZE:
            token = vault.add_entity(entity, action.value)
            replacement = token
            n_tok += 1
        else:  # REDACT
            replacement = _REDACTED
            n_red += 1
        for span in entity.members:
            edits.append((span.start, span.end, replacement))

    # Apply edits right-to-left so earlier offsets stay valid.
    edits.sort(key=lambda e: e[0], reverse=True)
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
