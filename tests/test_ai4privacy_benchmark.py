"""Regression gate against an English AI4Privacy sample (skipped unless present).

Fetch: python -m benchmarks.fetch_ai4privacy --n 2000
"""

import os

import pytest

_DATA = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "data",
                     "ai4privacy_en.json")
if not os.path.exists(_DATA):
    pytest.skip("AI4Privacy sample not downloaded", allow_module_level=True)

from benchmarks.ai4privacy_eval import evaluate


def test_ai4privacy_targeted_recall_floor():
    # floor set just below the measured 93.3%; raise as recall improves
    r = evaluate(use_spacy=False)
    assert r["targeted_recall"] >= 0.92, f"recall regressed to {r['targeted_recall']:.1%}"


def test_ai4privacy_precision_floor():
    # floor just below the measured 85.2%
    r = evaluate(use_spacy=False)
    assert r["precision"] >= 0.83, f"precision regressed to {r['precision']:.1%}"


# Structural identifiers + surnames must NEVER survive in the output. This is the
# real leak guarantee, checked directly against gold PII values (not span
# overlap): a regression that lets any of these leak fails the build.
_STRONG = {
    "EMAIL", "PHONENUMBER", "SSN", "IBAN", "CREDITCARDNUMBER", "IP", "IPV4",
    "IPV6", "MAC", "URL", "BITCOINADDRESS", "ETHEREUMADDRESS", "LASTNAME",
    "NEARBYGPSCOORDINATE",
}


def test_no_strong_identifier_leaks():
    import json
    import re

    from blotch import get_policy, sanitize

    with open(_DATA, encoding="utf-8") as fh:
        rows = json.load(fh)
    policy = get_policy("maximum")
    leaks = []
    for row in rows:
        text = row["source_text"]
        out = sanitize(text, policy, use_spacy=False).sanitized_text
        for m in row["privacy_mask"]:
            if m["label"] not in _STRONG:
                continue
            val = (m.get("value") or text[m["start"]:m["end"]]).strip()
            if len(val) < 3:
                continue
            if re.search(r"(?<!\w)" + re.escape(val) + r"(?!\w)", out):
                leaks.append((m["label"], val))
    assert not leaks, f"{len(leaks)} strong identifier(s) leaked, e.g. {leaks[:5]}"
