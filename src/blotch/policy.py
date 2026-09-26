"""Privacy policies: modes instead of dozens of per-run switches (plan §5).

A policy maps each :class:`~blotch.spans.EntityType` to an action. The MVP ships
one reversible action (``TOKENIZE``) plus ``KEEP``; ``REDACT`` (permanent, no
rehydration) is available for values that should never come back. Synthetic /
generalising strategies are deliberately deferred (see README "Why opaque tokens
only, for now").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .detectors.custom import Recognizer
from .spans import EntityType


class Action(str, Enum):
    TOKENIZE = "tokenize"  # reversible opaque token
    REDACT = "redact"      # permanent [REDACTED], not rehydratable
    KEEP = "keep"          # leave in place


@dataclass
class Policy:
    name: str
    actions: dict[EntityType, Action] = field(default_factory=dict)
    default: Action = Action.KEEP
    #: Organisation-specific detectors run alongside the built-in ones (and by
    #: the outbound leak scanner). See :mod:`blotch.detectors.custom`.
    recognizers: tuple[Recognizer, ...] = ()

    def action_for(self, entity_type: EntityType) -> Action:
        return self.actions.get(entity_type, self.default)

    def with_recognizers(self, recognizers) -> "Policy":
        """Return a copy of this policy that also runs ``recognizers``.

        Handy for adding a custom ID format to a built-in policy::

            get_policy("personal").with_recognizers([Recognizer(...)])
        """
        combined = tuple(self.recognizers) + tuple(recognizers)
        _check_recognizers(combined, self)
        return Policy(self.name, dict(self.actions), self.default, combined)


_ALL = list(EntityType)
_CONTACT = [EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE, EntityType.ADDRESS]
_IDS = [
    EntityType.IBAN, EntityType.CREDIT_CARD, EntityType.GOV_ID, EntityType.PATIENT_ID,
    EntityType.CASE_ID, EntityType.ACCOUNT_ID, EntityType.MAC, EntityType.COORDINATES,
    EntityType.CRYPTO,
]


def _mode(name: str, tokenize: list[EntityType], default: Action = Action.KEEP) -> Policy:
    return Policy(name, {t: Action.TOKENIZE for t in tokenize}, default)


#: Remove anything that could reasonably identify a person or organisation.
MAXIMUM = _mode("maximum", _ALL, default=Action.TOKENIZE)

#: Names, contact info, identifiers. Dates/orgs preserved unless they are IDs.
PERSONAL = _mode(
    "personal",
    _CONTACT + _IDS + [EntityType.DOB, EntityType.IP, EntityType.URL],
)

#: PHI: patient identity plus health identifiers; keep generic dates? No - in
#: medical text dates are often identifying (admission/DOB), so tokenize them.
MEDICAL = _mode(
    "medical",
    _CONTACT + _IDS + [EntityType.DOB, EntityType.DATE, EntityType.ORGANIZATION,
                       EntityType.IP, EntityType.URL,
                       # HIPAA quasi-identifiers: age (esp. > 89) and clock times
                       # (admission/appointment) can re-identify with other fields.
                       EntityType.AGE, EntityType.TIME],
)

#: Parties, witnesses, addresses, case numbers, org identifiers.
LEGAL = _mode(
    "legal",
    _CONTACT + _IDS + [EntityType.ORGANIZATION, EntityType.LOCATION, EntityType.DATE,
                       EntityType.IP, EntityType.URL],
)

BUILTIN: dict[str, Policy] = {p.name: p for p in (MAXIMUM, PERSONAL, MEDICAL, LEGAL)}


def get_policy(name: str) -> Policy:
    try:
        return BUILTIN[name]
    except KeyError:
        raise ValueError(f"unknown policy {name!r}; choose from {sorted(BUILTIN)}")


def policy_from_dict(data: dict) -> Policy:
    """Build a custom :class:`Policy` from a plain dict (plan §5 "Custom").

    Shape::

        {"name": "my-policy", "default": "keep",
         "actions": {"PERSON": "tokenize", "DATE": "keep", "GOV_ID": "redact"}}

    Unknown entity types or actions raise ``ValueError`` rather than being
    silently ignored - a misspelled ``PERSN`` must not quietly leak persons.
    """

    name = data.get("name", "custom")
    default = Action(data.get("default", "keep"))
    actions: dict[EntityType, Action] = {}
    for key, val in data.get("actions", {}).items():
        try:
            etype = EntityType(key)
        except ValueError:
            raise ValueError(f"unknown entity type in policy: {key!r}")
        actions[etype] = Action(val)
    raw = data.get("recognizers", [])
    if not isinstance(raw, list):
        raise ValueError("policy 'recognizers' must be a list")
    recognizers = tuple(Recognizer.from_dict(r) for r in raw)
    policy = Policy(name=name, actions=actions, default=default,
                    recognizers=recognizers)
    _check_recognizers(recognizers, policy)
    return policy


def _check_recognizers(recognizers, policy: Policy) -> None:
    """Reject recognizer sets that would silently do nothing.

    A recognizer whose entity type the policy KEEPs would detect the value and
    then leave it in the clear - exactly the quiet leak a custom detector is
    meant to prevent - so that is an error, not a no-op. Names must be unique so
    the review UI / audit trail can tell recognizers apart.
    """
    seen: set[str] = set()
    for rec in recognizers:
        if rec.name in seen:
            raise ValueError(f"duplicate recognizer name {rec.name!r}")
        seen.add(rec.name)
        if policy.action_for(rec.entity_type) == Action.KEEP:
            raise ValueError(
                f"recognizer {rec.name!r} emits {rec.entity_type.value}, but policy "
                f"{policy.name!r} keeps {rec.entity_type.value} in the clear; add "
                f'"actions": {{"{rec.entity_type.value}": "tokenize"}} (or "redact")'
            )


def load_policy_file(path: str) -> Policy:
    import json
    with open(path, encoding="utf-8") as fh:
        return policy_from_dict(json.load(fh))
