"""Checksum validators.

These let deterministic detectors keep *precision* high on the categories where
a structural check exists, so aggressive recall elsewhere doesn't drown the user
in false positives. A string that merely *looks* like an IBAN but fails mod-97 is
almost never a real IBAN.
"""

from __future__ import annotations


def luhn_valid(number: str) -> bool:
    """Validate a card/number string by the Luhn algorithm."""

    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:  # shortest real PAN-like lengths
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def iban_valid(iban: str) -> bool:
    """Validate an IBAN by length heuristics and the ISO 7064 mod-97 checksum."""

    s = iban.replace(" ", "").upper()
    if not (15 <= len(s) <= 34):
        return False
    if not (s[:2].isalpha() and s[2:4].isdigit()):
        return False
    if not s.isalnum():
        return False
    # Move the first four chars to the end, map letters A=10..Z=35, take mod 97.
    rearranged = s[4:] + s[:4]
    digits = []
    for ch in rearranged:
        if ch.isdigit():
            digits.append(ch)
        else:
            digits.append(str(ord(ch) - 55))
    remainder = int("".join(digits)) % 97
    return remainder == 1
