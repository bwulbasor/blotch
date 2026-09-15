"""Re-identification-risk advisory (plan §17).

Removing explicit identifiers (names, IDs, contact info) is necessary but not
sufficient. A document can still single out a person through *quasi-identifiers* -
attributes that, in combination, narrow to one individual:

    "the 47-year-old CEO of a Vienna firm who survived the 2024 helicopter crash"

has no name, yet is effectively unique. This module scans the text that would
actually leave the device and flags residual quasi-identifiers.

**This is an advisory, not a guarantee.** True k-anonymity / l-diversity requires
a population model this MVP does not have. We surface signal and a qualitative
level so a human can judge; we never claim the text is safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    category: str
    text: str
    start: int
    end: int


@dataclass
class ReidRisk:
    level: RiskLevel
    findings: list[Finding] = field(default_factory=list)

    @property
    def categories(self) -> set[str]:
        return {f.category for f in self.findings}

    def summary(self) -> str:
        if self.level == RiskLevel.NONE:
            return "re-id risk: none detected (advisory only, not a guarantee)"
        cats = ", ".join(sorted(self.categories))
        return (f"re-id risk: {self.level.value.upper()} - {len(self.findings)} "
                f"quasi-identifier(s) across [{cats}]; a human should confirm")


# --- quasi-identifier signals --------------------------------------------

_AGE = re.compile(r"\b(?:aged\s+)?\d{1,3}[\s\-]?(?:years?[\s\-]old|-?year-?old|yo)\b",
                  re.IGNORECASE)
_OCCUPATIONS = (
    "ceo|cto|cfo|coo|founder|co-founder|president|vice[\\s-]president|director|"
    "manager|head of|chief|professor|dean|surgeon|physician|consultant|judge|"
    "magistrate|mayor|minister|senator|governor|ambassador|chairman|chairwoman|"
    "chairperson|partner|principal|superintendent|commissioner|bishop|rabbi|imam"
)
_OCCUPATION = re.compile(rf"\b(?:{_OCCUPATIONS})\b", re.IGNORECASE)
# Uniqueness markers: "only", "sole", "first", "survived the ...", "won the ...".
_RARE = re.compile(
    r"\b(?:the\s+only|the\s+first|the\s+sole|sole\s+survivor|only\s+person|"
    r"survived\s+the|survivor\s+of|won\s+the|awarded\s+the|holder\s+of|"
    r"famous\s+for|known\s+for|convicted\s+of|accused\s+of)\b",
    re.IGNORECASE,
)
# Health/legal status descriptors that are identifying in small populations.
_STATUS = re.compile(
    r"\b(?:diagnosed\s+with|suffers?\s+from|HIV|cancer|schizophreni\w+|"
    r"pregnan\w+|disab\w+|refugee|asylum|whistleblow\w+|LGBTQ?\+?)\b",
    re.IGNORECASE,
)

_CATEGORIES = [
    ("age", _AGE),
    ("occupation", _OCCUPATION),
    ("uniqueness", _RARE),
    ("sensitive-status", _STATUS),
]


def assess(text: str) -> ReidRisk:
    """Assess residual re-identification risk of ``text``.

    Level is driven by how many *distinct* quasi-identifier categories co-occur -
    a single attribute is weak; several together are what single people out.
    """

    findings: list[Finding] = []
    for category, pattern in _CATEGORIES:
        for m in pattern.finditer(text):
            findings.append(Finding(category, m.group(0), m.start(), m.end()))

    distinct = len({f.category for f in findings})
    if distinct == 0:
        level = RiskLevel.NONE
    elif distinct == 1:
        level = RiskLevel.LOW
    elif distinct == 2:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH
    # A sensitive-status attribute alone lifts to at least MEDIUM.
    if "sensitive-status" in {f.category for f in findings} and level == RiskLevel.LOW:
        level = RiskLevel.MEDIUM
    return ReidRisk(level=level, findings=findings)
