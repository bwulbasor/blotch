"""User-defined recognizers: organisation-specific identifier formats.

Every company has identifiers no generic detector knows - employee IDs
("EMP-10442"), internal ticket or matter numbers, project codenames. A
:class:`Recognizer` lets a policy declare one as a regular expression mapped onto
an existing :class:`~blotch.spans.EntityType`, without touching blotch's source.

Recognizers run in the normal detection pass *and* in the outbound leak scanner,
so an identifier that slips past tokenisation still blocks transmission.

Declared in a policy file::

    "recognizers": [
      {"name": "employee_id", "pattern": "EMP-\\\\d{5}", "entity_type": "ACCOUNT_ID"},
      {"name": "matter_no", "pattern": "Matter No\\\\.? (?P<v>\\\\d{4}-\\\\d{3})",
       "entity_type": "CASE_ID", "group": "v", "confidence": 0.95}
    ]

``group`` (optional) selects the capture group that is the sensitive value, so a
label like "Matter No." can anchor the match without itself being redacted.
Validation is strict and happens once, at load: a typo must fail loudly rather
than produce a recognizer that quietly never matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..spans import EntityType, Span

_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_\-]{0,63}")


@dataclass(frozen=True)
class Recognizer:
    name: str
    pattern: str
    entity_type: EntityType
    confidence: float = 0.9
    group: str | int | None = None
    ignore_case: bool = False
    _regex: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME.fullmatch(self.name):
            raise ValueError(f"recognizer name {self.name!r} must be 1-64 chars, "
                             "letters/digits/_/- and start with a letter")
        if not isinstance(self.entity_type, EntityType):
            raise ValueError(f"recognizer {self.name!r}: entity_type must be an EntityType")
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError(f"recognizer {self.name!r}: confidence must be in [0, 1]")
        try:
            rx = re.compile(self.pattern, re.IGNORECASE if self.ignore_case else 0)
        except re.error as exc:
            raise ValueError(f"recognizer {self.name!r}: invalid pattern: {exc}") from None
        if rx.search("") is not None:
            # a pattern that can match empty text would emit zero-width spans
            # everywhere (and matches nothing meaningful)
            raise ValueError(f"recognizer {self.name!r}: pattern can match empty text")
        if isinstance(self.group, bool):
            # bool is an int subclass: JSON "group": true would silently mean 1
            raise ValueError(f"recognizer {self.name!r}: group must be a name or "
                             f"number, not {self.group!r}")
        if self.group is not None:
            known = isinstance(self.group, int) and 0 <= self.group <= rx.groups
            known = known or (isinstance(self.group, str) and self.group in rx.groupindex)
            if not known:
                raise ValueError(f"recognizer {self.name!r}: pattern has no group "
                                 f"{self.group!r}")
        object.__setattr__(self, "_regex", rx)

    @classmethod
    def from_dict(cls, data: dict) -> "Recognizer":
        if not isinstance(data, dict):
            raise ValueError(f"recognizer must be an object, got {type(data).__name__}")
        unknown = set(data) - {"name", "pattern", "entity_type", "confidence",
                               "group", "ignore_case"}
        if unknown:
            raise ValueError(f"recognizer {data.get('name')!r}: unknown field(s) "
                             f"{sorted(unknown)}")
        for req in ("name", "pattern", "entity_type"):
            if req not in data:
                raise ValueError(f"recognizer is missing required field {req!r}")
        try:
            etype = EntityType(data["entity_type"])
        except ValueError:
            raise ValueError(f"recognizer {data['name']!r}: unknown entity_type "
                             f"{data['entity_type']!r}") from None
        conf = data.get("confidence", 0.9)
        if isinstance(conf, bool) or not isinstance(conf, (int, float)):
            raise ValueError(f"recognizer {data['name']!r}: confidence must be a number "
                             f"in [0, 1], got {conf!r}")
        return cls(name=data["name"], pattern=data["pattern"], entity_type=etype,
                   confidence=float(conf),
                   group=data.get("group"),
                   ignore_case=bool(data.get("ignore_case", False)))

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        for m in self._regex.finditer(text):
            try:
                start, end = m.span(self.group) if self.group is not None else m.span()
            except IndexError:
                continue
            if start < 0 or end <= start:
                continue  # the selected group didn't participate / was empty
            out.append(Span(start, end, self.entity_type, text[start:end],
                            float(self.confidence), f"custom:{self.name}"))
        return out


def detect(text: str, recognizers) -> list[Span]:
    """Run every custom recognizer over ``text``."""
    spans: list[Span] = []
    for rec in recognizers or ():
        spans += rec.detect(text)
    return spans
