"""Layer A: deterministic pattern detectors.

Fast, dependency-free, and (where a checksum exists) high precision. Each
detector yields :class:`~censorbot.spans.Span` objects. These run first and
essentially instantly.

Locale note: dates / phones / national IDs vary by country. We validate what is
structurally validatable (IBAN, card) at high confidence, and surface the rest as
lower-confidence high-recall candidates for the review layer rather than dropping
them.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..spans import EntityType, Span
from .validators import iban_valid, luhn_valid

# --- patterns -------------------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_URL = re.compile(r"\bhttps?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
# High-recall phone run: a digit-led token of digits / spaces / + ( ) . - that
# begins and ends on a digit. The 7-15 digit count is enforced in code so we
# catch both grouped ("+43 660 1234567") and contiguous ("06601234567") forms.
# Precision is recovered later: dates, IBANs and cards have their own (higher
# confidence, usually longer) spans and win overlap resolution.
_PHONE = re.compile(r"(?<![\w.])\+?\d[\d\s().\-]{5,17}\d(?![\w])")
# Guards so bibliography noise isn't mistaken for phone numbers.
_YEAR_RANGE = re.compile(r"^(?:19|20)\d{2}\s*[-–]\s*(?:19|20)\d{2}$")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){2,8}\b")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_US_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Street addresses. English form: number + name words + street-type suffix.
_STREET_TYPES = (
    "Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd|Drive|Dr|Way|Court|Ct|"
    "Place|Pl|Square|Sq|Terrace|Ter|Parkway|Pkwy|Highway|Hwy|Close|Crescent"
)
_STREET_EN = re.compile(
    rf"\b\d{{1,5}}[A-Za-z]?\s+(?:[A-ZÄÖÜ][A-Za-zäöüß.'\-]+\s+){{1,3}}"
    rf"(?:{_STREET_TYPES})\b\.?",
)
# German/Austrian compound street + number ("Hauptstraße 12", "Ringgasse 4a").
_STREET_DE = re.compile(
    r"\b[A-ZÄÖÜ][a-zäöüß]+(?:straße|strasse|gasse|weg|platz|allee|ring)\s+\d{1,4}[a-z]?\b"
)
# UK postcode - distinctive enough to detect standalone.
_UK_POSTCODE = re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s+\d[A-Z]{2}\b")
# US "State ZIP" in address context (comma-anchored to avoid matching "IN 12345"
# style false positives): e.g. "Springfield, IL 62704" / "..., CA 90210-1234".
_US_STATE_ZIP = re.compile(r",\s*(?P<sz>[A-Z]{2}\s+\d{5}(?:-\d{4})?)\b")
# Bank SWIFT/BIC code - only when labelled, since a bare 8-letter run is common.
_BIC = re.compile(
    r"\b(?:BIC|SWIFT)\b\s*(?:code)?\s*[:#]?\s*"
    r"(?P<bic>(?-i:[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?))\b",
    re.IGNORECASE,
)
# MAC address (colon or hyphen separated).
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# Crypto wallet addresses. ETH: 0x + 40 hex (very distinctive). BTC: base58
# (starts 1/3) or bech32 (bc1), lengths that make accidental matches unlikely.
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
# Decimal-degree geo coordinates (>=3 decimals each, to avoid version numbers).
_COORD = re.compile(r"[-+]?\d{1,2}\.\d{3,}\s*,\s*[-+]?\d{1,3}\.\d{3,}")
# Court / reference numbers like "AZ 73 C 226", "17 C 391/26", "5 Ob 12/25":
# number, short letter code, number, optional /year. Distinctive enough that a
# bare digit-letter-digit run in prose rarely collides.
_CASE_NUM = re.compile(r"\b(?:AZ\s+)?\d{1,4}\s+[A-Z][a-z]?\s+\d{1,4}(?:\s*/\s*\d{2,4})?\b")
# Explicitly-labelled identifiers: "Patient No: 48392017", "Case AZ 17 C 391/26".
_LABELLED = re.compile(
    r"\b(?P<label>patient|case|file|account|acct|reference|ref|invoice|policy|"
    r"member|customer|tax|vat|nino|nhs|passport|licence|license|driver|dl)\b"
    # optional filler words / punctuation between the label and the value
    r"(?:\s+(?:number|no\.?|id|ref|is|was|of))*\s*[:#\-]?\s*"
    # value: optional uppercase prefix (kept case-sensitive so lowercase filler
    # words are never swallowed), then digits.
    r"(?P<id>(?-i:[A-Z]{0,4})[\s\-]?\d[\d\-/]{2,})",
    re.IGNORECASE,
)
_LABEL_TYPE = {
    "patient": EntityType.PATIENT_ID,
    "case": EntityType.CASE_ID,
    "file": EntityType.CASE_ID,
    "reference": EntityType.CASE_ID,
    "ref": EntityType.CASE_ID,
    "invoice": EntityType.ACCOUNT_ID,
    "policy": EntityType.ACCOUNT_ID,
    "account": EntityType.ACCOUNT_ID,
    "acct": EntityType.ACCOUNT_ID,
    "member": EntityType.ACCOUNT_ID,
    "customer": EntityType.ACCOUNT_ID,
    "tax": EntityType.GOV_ID,
    "vat": EntityType.GOV_ID,
    "nino": EntityType.GOV_ID,
    "nhs": EntityType.GOV_ID,
    "passport": EntityType.GOV_ID,
    "licence": EntityType.GOV_ID,
    "license": EntityType.GOV_ID,
    "driver": EntityType.GOV_ID,
    "dl": EntityType.GOV_ID,
}
# Common date forms: 2026-03-14, 14/03/2026, 14 March 2026, March 14, 2026.
_MONTHS = (
    "January February March April May June July August September October "
    "November December"
).split()
_MONTH_RE = "|".join(_MONTHS + [m[:3] for m in _MONTHS])
_ORD = r"(?:st|nd|rd|th)?"
_DATE = re.compile(
    rf"\b(?:"
    rf"\d{{4}}-\d{{2}}-\d{{2}}(?:[T ]\d{{2}}:\d{{2}}(?::\d{{2}})?)?"    # ISO (+ time)
    rf"|\d{{4}}/\d{{1,2}}/\d{{1,2}}"                                    # 2026/03/14
    rf"|\d{{1,2}}[./]\d{{1,2}}[./]\d{{2,4}}"                            # 14/03/2026, 14.3.26
    rf"|\d{{1,2}}{_ORD}\s+(?:of\s+)?(?:{_MONTH_RE})\.?\s+\d{{2,4}}"     # 14th (of) March 2026
    rf"|(?:{_MONTH_RE})\.?\s+\d{{1,2}}{_ORD},?\s+\d{{2,4}}"             # March 14th, 2026
    rf")\b",
    re.IGNORECASE,
)


def _yield(pattern: re.Pattern[str], text: str, etype: EntityType, name: str,
           conf: float) -> Iterator[Span]:
    for m in pattern.finditer(text):
        yield Span(m.start(), m.end(), etype, m.group(0), conf, name)


def detect(text: str) -> list[Span]:
    """Run every deterministic detector over ``text``."""

    spans: list[Span] = []
    spans += _yield(_EMAIL, text, EntityType.EMAIL, "email", 0.99)
    spans += _yield(_URL, text, EntityType.URL, "url", 0.98)
    spans += _yield(_IPV4, text, EntityType.IP, "ipv4", 0.9)
    spans += _yield(_IPV6, text, EntityType.IP, "ipv6", 0.9)
    spans += _yield(_US_SSN, text, EntityType.GOV_ID, "us_ssn", 0.9)
    spans += _yield(_STREET_EN, text, EntityType.ADDRESS, "street_en", 0.85)
    spans += _yield(_STREET_DE, text, EntityType.ADDRESS, "street_de", 0.85)
    spans += _yield(_UK_POSTCODE, text, EntityType.ADDRESS, "uk_postcode", 0.85)
    for m in _US_STATE_ZIP.finditer(text):
        spans.append(Span(m.start("sz"), m.end("sz"), EntityType.ADDRESS,
                          m.group("sz"), 0.8, "us_state_zip"))
    for m in _BIC.finditer(text):
        spans.append(Span(m.start("bic"), m.end("bic"), EntityType.ACCOUNT_ID,
                          m.group("bic"), 0.9, "bic"))
    spans += _yield(_MAC, text, EntityType.MAC, "mac", 0.95)
    spans += _yield(_ETH, text, EntityType.CRYPTO, "eth", 0.97)
    spans += _yield(_BTC, text, EntityType.CRYPTO, "btc", 0.9)
    spans += _yield(_COORD, text, EntityType.COORDINATES, "coord", 0.8)
    spans += _yield(_CASE_NUM, text, EntityType.CASE_ID, "case_num", 0.8)
    spans += _yield(_DATE, text, EntityType.DATE, "date", 0.7)

    # Validated detectors: only emit on checksum pass (high precision).
    for m in _IBAN.finditer(text):
        if iban_valid(m.group(0)):
            spans.append(Span(m.start(), m.end(), EntityType.IBAN, m.group(0), 0.99, "iban"))
    for m in _CARD.finditer(text):
        if luhn_valid(m.group(0)):
            spans.append(
                Span(m.start(), m.end(), EntityType.CREDIT_CARD, m.group(0), 0.97, "card_luhn")
            )

    # Phones: skip anything already claimed by a validated card/IBAN region later
    # via overlap resolution; emit as medium confidence.
    for m in _PHONE.finditer(text):
        val = m.group(0)
        digits_only = re.sub(r"\D", "", val)
        n_digits = len(digits_only)
        if not (7 <= n_digits <= 15):
            continue
        if _YEAR_RANGE.match(val.strip()):
            continue  # "2012-2013" is a year range, not a phone
        if n_digits == 13 and digits_only.startswith(("978", "979")):
            continue  # ISBN-13
        spans.append(Span(m.start(), m.end(), EntityType.PHONE, val, 0.6, "phone"))

    # Labelled identifiers.
    for m in _LABELLED.finditer(text):
        etype = _LABEL_TYPE.get(m.group("label").lower(), EntityType.ACCOUNT_ID)
        spans.append(
            Span(m.start("id"), m.end("id"), etype, m.group("id").strip(), 0.85, "labelled_id")
        )

    return spans
