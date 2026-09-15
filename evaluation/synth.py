"""Synthetic labelled-document generator with a hard-case bank.

Every entity inserted is recorded with its exact character span and type, so the
evaluator can compute true precision/recall. Generation is seeded for
reproducibility. The pools deliberately include the cases that break naive PII
detectors:

* PERSON names that are also common English words ("May", "Mark", "Grace",
  "Frank", "Rich", "Hope", "Summer");
* Unicode / apostrophe / hyphen names ("José Müller", "Zoë O'Brien",
  "Anne-Marie Škoda");
* international phone formats and multi-country **checksum-valid** IBANs;
* numbers that look like phones but are amounts, and dates in many formats;
* entities placed adjacent to punctuation and across line breaks.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from censorbot.spans import EntityType


@dataclass
class GoldSpan:
    start: int
    end: int
    entity_type: EntityType
    value: str


@dataclass
class LabeledDoc:
    text: str
    spans: list[GoldSpan]
    domain: str


class _Builder:
    """Accumulates literal text and labelled entities, tracking offsets."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._spans: list[GoldSpan] = []
        self._len = 0

    def lit(self, s: str) -> "_Builder":
        self._parts.append(s)
        self._len += len(s)
        return self

    def ent(self, etype: EntityType, value: str) -> "_Builder":
        start = self._len
        self._parts.append(value)
        self._len += len(value)
        self._spans.append(GoldSpan(start, self._len, etype, value))
        return self

    def build(self, domain: str) -> LabeledDoc:
        return LabeledDoc("".join(self._parts), list(self._spans), domain)


# --- pools ----------------------------------------------------------------

# First/last names, heavy on the ones that are also ordinary words.
_FIRST = [
    "May", "Mark", "Grace", "Frank", "Rich", "Hope", "Summer", "Faith", "Dawn",
    "Art", "Bill", "Rose", "Jack", "Alejandro", "Maria", "Thomas", "Sabine",
    "José", "Zoë", "Anne-Marie", "Łukasz", "Ingrid", "Mohammed", "Wei",
]
_LAST = [
    "Baker", "Cook", "Rich", "Frank", "Young", "Green", "Long", "Martinez",
    "Gomez", "Weber", "Keller", "Müller", "O'Brien", "Škoda", "Nowak", "Rossi",
    "Nakamura", "Okonkwo",
]
_CITIES = ["Vienna", "Graz", "Linz", "Berlin", "Zürich", "Lyon", "Turin", "Kraków"]
_ORGS = [
    "Vienna General Hospital", "St. Anne's Clinic", "Frank & Sons Ltd",
    "Meridian Bank AG", "Danube University", "Regional Court Graz",
    "Okonkwo Holdings GmbH",
]
_EMAML_DOMAINS = ["example.com", "example.org", "mail.example.net", "corp.example"]
# checksum-valid IBANs (verified) from several countries
_IBANS = [
    "GB82 WEST 1234 5698 7654 32",
    "DE89 3704 0044 0532 0130 00",
    "FR14 2004 1010 0505 0001 3M02 606",
    "AT61 1904 3002 3457 3201",
    "NL91 ABNA 0417 1643 00",
]
# Luhn-valid test card numbers
_CARDS = ["4111 1111 1111 1111", "5500 0055 5555 5559", "3400 000000 00009"]
_PHONES = [
    "+43 660 1234567", "+44 20 7946 0958", "06601234567", "+1 (415) 555-0132",
    "0512 / 1234-567", "+49 30 123456",
]
_DATE_FORMS = [
    "14 March 2026", "2026-03-14", "March 14, 2026", "14/03/2026", "3.14.2026",
    "1 Jan 1990",
]
_ADDRESSES = [
    "221 Baker Street", "1600 Pennsylvania Avenue", "10 Downing Street",
    "Hauptstraße 12", "Ringgasse 4a", "45 Maple Drive", "SW1A 1AA",
]


def _name(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"


def _email(rng: random.Random, name: str) -> str:
    handle = name.lower().replace(" ", ".")
    for a, b in [("ö", "o"), ("ü", "u"), ("ë", "e"), ("é", "e"), ("ł", "l"),
                 ("š", "s"), ("'", "")]:
        handle = handle.replace(a, b)
    return f"{handle}@{rng.choice(_EMAML_DOMAINS)}"


def medical_doc(rng: random.Random) -> LabeledDoc:
    b = _Builder()
    patient = _name(rng)
    doctor = "Dr. " + _name(rng)
    hosp = rng.choice(_ORGS)
    b.lit("DISCHARGE SUMMARY\n\nPatient: ").ent(EntityType.PERSON, patient)
    b.lit(" (DOB ").ent(EntityType.DOB, rng.choice(_DATE_FORMS)).lit(")\n")
    b.lit("Patient number: ").ent(EntityType.PATIENT_ID, str(rng.randint(10_000_000, 99_999_999)))
    b.lit("\nAdmitting hospital: ").ent(EntityType.ORGANIZATION, hosp).lit("\n\n")
    # co-reference: surname-only mention
    surname = patient.split()[1]
    b.lit("Mr. ").ent(EntityType.PERSON, "Mr. " + surname).lit(" was admitted on ")
    b.ent(EntityType.DATE, rng.choice(_DATE_FORMS)).lit(" and treated by ")
    b.ent(EntityType.PERSON, doctor).lit(".\n")
    b.lit("Billing sent to ").ent(EntityType.EMAIL, _email(rng, patient))
    b.lit(" and IBAN ").ent(EntityType.IBAN, rng.choice(_IBANS)).lit(".\n")
    b.lit("Emergency contact: ").ent(EntityType.PERSON, _name(rng)).lit(", ")
    b.ent(EntityType.PHONE, rng.choice(_PHONES)).lit(".\n")
    b.lit("Home address: ").ent(EntityType.ADDRESS, rng.choice(_ADDRESSES)).lit(".\n")
    b.lit("Records server: ").ent(EntityType.IP, f"192.168.{rng.randint(0,255)}.{rng.randint(1,254)}")
    b.lit(".\n")
    return b.build("medical")


def legal_doc(rng: random.Random) -> LabeledDoc:
    b = _Builder()
    a, c, d = _name(rng), _name(rng), _name(rng)
    b.lit("IN THE ").ent(EntityType.ORGANIZATION, rng.choice(_ORGS)).lit("\n\n")
    b.lit("Case number ").ent(EntityType.CASE_ID, f"AZ {rng.randint(1,99)} C {rng.randint(100,999)}")
    b.lit(".\n\nPlaintiff ").ent(EntityType.PERSON, a).lit(" of ")
    b.ent(EntityType.LOCATION, rng.choice(_CITIES)).lit(" alleges that ")
    b.ent(EntityType.PERSON, c).lit(" owes EUR 4,000, while ")
    b.ent(EntityType.PERSON, c.split()[0]).lit(" claims ")  # first-name coref
    b.ent(EntityType.PERSON, d).lit(" is liable. Contact ")
    b.ent(EntityType.EMAIL, _email(rng, a)).lit(" or ")
    b.ent(EntityType.PHONE, rng.choice(_PHONES)).lit(".\n")
    return b.build("legal")


def finance_doc(rng: random.Random) -> LabeledDoc:
    b = _Builder()
    name = _name(rng)
    b.lit("INVOICE\n\nBill to: ").ent(EntityType.PERSON, name).lit("\n")
    b.lit("Ship to: ").ent(EntityType.ADDRESS, rng.choice(_ADDRESSES)).lit("\n")
    b.lit("Account: ").ent(EntityType.ACCOUNT_ID, f"ACC-{rng.randint(100000,999999)}").lit("\n")
    b.lit("Card on file: ").ent(EntityType.CREDIT_CARD, rng.choice(_CARDS)).lit("\n")
    b.lit("IBAN: ").ent(EntityType.IBAN, rng.choice(_IBANS)).lit("\n")
    # hard: an amount that superficially resembles a phone/number - NOT labelled
    b.lit(f"Amount due: EUR {rng.randint(1000,9999)},{rng.randint(100,999)}\n")
    b.lit("Due ").ent(EntityType.DATE, rng.choice(_DATE_FORMS)).lit(".\n")
    b.lit("Questions: ").ent(EntityType.EMAIL, _email(rng, name)).lit("\n")
    return b.build("finance")


_GENERATORS = [medical_doc, legal_doc, finance_doc]


def generate(n: int = 30, seed: int = 7) -> list[LabeledDoc]:
    rng = random.Random(seed)
    docs = []
    for i in range(n):
        gen = _GENERATORS[i % len(_GENERATORS)]
        docs.append(gen(rng))
    return docs
