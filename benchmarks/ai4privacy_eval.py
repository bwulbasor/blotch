"""Evaluate censorbot against an English sample of AI4Privacy pii-masking-200k.

AI4Privacy is synthetic but has broad, gold-annotated PII spans - especially the
contact/financial types (email, phone, card, IP) that the legal TAB set lacks.
We report recall per label, split into the types censorbot *targets* (its
headline claim) and the ones it does not (device IDs, passwords, demographics,
job/appearance attributes - out of scope / quasi).

    python -m benchmarks.ai4privacy_eval [--spacy] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict

from censorbot.detectors import detect_all
from censorbot.spans import resolve_overlaps

_HERE = os.path.dirname(__file__)

# AI4Privacy labels censorbot claims to detect (recall counts against these).
TARGETED = {
    "EMAIL", "PHONENUMBER", "FIRSTNAME", "LASTNAME", "MIDDLENAME",
    "IP", "IPV4", "IPV6", "CREDITCARDNUMBER", "DATE", "DOB",
    "STREET", "BUILDINGNUMBER", "SECONDARYADDRESS", "ZIPCODE", "CITY", "STATE",
    "COUNTY", "NEARBYGPSCOORDINATE", "URL", "SSN", "IBAN", "BITCOINADDRESS",
    "ETHEREUMADDRESS", "MAC",
}


def _load():
    with open(os.path.join(_HERE, "data", "ai4privacy_en.json"), encoding="utf-8") as fh:
        return json.load(fh)


def evaluate(use_spacy: bool = False, limit: int | None = None):
    rows = _load()
    if limit:
        rows = rows[:limit]
    tot = defaultdict(int)
    cov = defaultdict(int)

    for row in rows:
        text = row["source_text"]
        preds = [(p.start, p.end) for p in resolve_overlaps(detect_all(text, use_spacy=use_spacy))]
        for m in row["privacy_mask"]:
            s, e, label = m["start"], m["end"], m["label"]
            tot[label] += 1
            if any(ps < e and s < pe for ps, pe in preds):
                cov[label] += 1

    tgt_tot = sum(tot[l] for l in tot if l in TARGETED)
    tgt_cov = sum(cov[l] for l in tot if l in TARGETED)
    print(f"=== AI4Privacy EN ({len(rows)} rows, {'spaCy union' if use_spacy else 'heuristic'}) ===")
    print(f"recall on TARGETED types: {tgt_cov/tgt_tot:6.1%}  ({tgt_cov}/{tgt_tot})\n")
    print("recall by label (targeted):")
    for l in sorted(tot, key=lambda x: -tot[x]):
        if l in TARGETED and tot[l] >= 5:
            print(f"  {l:<20} {cov[l]/tot[l]:6.1%}  ({cov[l]}/{tot[l]})")
    print("\nnot targeted (out of scope / quasi - shown for coverage, not scored):")
    for l in sorted(tot, key=lambda x: -tot[x]):
        if l not in TARGETED and tot[l] >= 20:
            print(f"  {l:<20} {cov[l]/tot[l]:6.1%}  ({cov[l]}/{tot[l]})")
    return tgt_cov / tgt_tot if tgt_tot else 1.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spacy", action="store_true")
    ap.add_argument("--limit", type=int)
    evaluate(use_spacy=ap.parse_args().spacy, limit=ap.parse_args().limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
