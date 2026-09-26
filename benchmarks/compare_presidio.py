"""Head-to-head: blotch vs Microsoft Presidio on the AI4Privacy sample.

Same texts, same overlap metric, so the numbers are comparable. Presidio is the
de-facto open-source baseline for PII detection, so this answers the obvious
"why not just Presidio?" question with data rather than opinion.

    pip install presidio-analyzer && python -m spacy download en_core_web_sm
    python -m benchmarks.compare_presidio [N]

Recall is measured over the identifier types blotch targets (a miss is a leak).
Precision~ is the fraction of predicted spans that overlap any gold span. Presidio
is run with en_core_web_sm for a fair, lightweight comparison; a larger model
raises its recall at a further speed cost.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict

from blotch.detectors import detect_all
from blotch.spans import resolve_overlaps

_DATA = os.path.join(os.path.dirname(__file__), "data", "ai4privacy_en.json")

TARGETED = {
    "EMAIL", "PHONENUMBER", "FIRSTNAME", "LASTNAME", "MIDDLENAME", "IP", "IPV4",
    "IPV6", "CREDITCARDNUMBER", "DATE", "DOB", "STREET", "BUILDINGNUMBER",
    "SECONDARYADDRESS", "ZIPCODE", "CITY", "STATE", "COUNTY",
    "NEARBYGPSCOORDINATE", "URL", "SSN", "IBAN", "BITCOINADDRESS",
    "ETHEREUMADDRESS", "MAC",
}


def _score(rows, predict, name):
    tot: dict = defaultdict(int)
    cov: dict = defaultdict(int)
    ptot = phit = 0
    t0 = time.time()
    for row in rows:
        text = row["source_text"]
        preds = predict(text)
        gold = [(m["start"], m["end"]) for m in row["privacy_mask"]]
        for ps, pe in preds:
            ptot += 1
            if any(gs < pe and ps < ge for gs, ge in gold):
                phit += 1
        for m in row["privacy_mask"]:
            if m["label"] not in TARGETED:
                continue
            s, e = m["start"], m["end"]
            tot[m["label"]] += 1
            if any(ps < e and s < pe for ps, pe in preds):
                cov[m["label"]] += 1
    total, covered = sum(tot.values()), sum(cov.values())
    dt = time.time() - t0
    print(f"\n=== {name} ===  ({dt / len(rows) * 1000:.1f} ms/doc)")
    print(f"targeted recall: {covered / total:.4f} ({covered}/{total})   "
          f"precision~: {phit / ptot:.4f} ({phit}/{ptot})")
    return tot, cov


def main(argv=None):
    argv = argv or sys.argv[1:]
    n = int(argv[0]) if argv else 800
    if not os.path.exists(_DATA):
        print("AI4Privacy sample not found; run: python -m benchmarks.fetch_ai4privacy")
        return 1
    rows = json.load(open(_DATA, encoding="utf-8"))[:n]

    def blotch_predict(text):
        return [(s.start, s.end)
                for s in resolve_overlaps(detect_all(text, use_spacy=False))]

    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except Exception:
        print("presidio-analyzer not installed; showing blotch only.")
        _score(rows, blotch_predict, "blotch (heuristic)")
        return 0

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]})
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())

    def presidio_predict(text):
        return [(r.start, r.end) for r in analyzer.analyze(text=text, language="en")]

    bt, bc = _score(rows, blotch_predict, "blotch (heuristic, no spaCy)")
    pt, pc = _score(rows, presidio_predict, "Presidio (spaCy en_core_web_sm)")
    print("\n=== per-label recall (blotch / presidio) ===")
    for lab in sorted(bt, key=lambda x: -bt[x]):
        b = bc[lab] / bt[lab] if bt[lab] else 0.0
        p = pc.get(lab, 0) / pt[lab] if pt.get(lab) else 0.0
        print(f"  {lab:20} {b * 100:5.1f}% / {p * 100:5.1f}%   (n={bt[lab]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
