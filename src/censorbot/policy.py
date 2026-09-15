"""Privacy policies: modes instead of dozens of per-run switches (plan §5).

A policy maps each :class:`~censorbot.spans.EntityType` to an action. The MVP ships
one reversible action (``TOKENIZE``) plus ``KEEP``; ``REDACT`` (permanent, no
rehydration) is available for values that should never come back. Synthetic /
generalising strategies are deliberately deferred (see README "Why opaque tokens
only, for now").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

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

    def action_for(self, entity_type: EntityType) -> Action:
        return self.actions.get(entity_type, self.default)


_ALL = list(EntityType)
_CONTACT = [EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE, EntityType.ADDRESS]
_IDS = [
    EntityType.IBAN, EntityType.CREDIT_CARD, EntityType.GOV_ID, EntityType.PATIENT_ID,
    EntityType.CASE_ID, EntityType.ACCOUNT_ID, EntityType.MAC, EntityType.COORDINATES,
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
                       EntityType.IP, EntityType.URL],
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
    return Policy(name=name, actions=actions, default=default)


def load_policy_file(path: str) -> Policy:
    import json
    with open(path, encoding="utf-8") as fh:
        return policy_from_dict(json.load(fh))
