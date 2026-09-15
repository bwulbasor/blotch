"""Evaluate censorbot against the Text Anonymization Benchmark (TAB).

TAB is 1,268 real European Court of Human Rights judgments with gold, manually
annotated spans, each labelled DIRECT / QUASI / NO_MASK. This is a *real*
external benchmark - not our own synthetic data - so the numbers here are the
honest measure of how well detection works on real documents.

The headline metric is **DIRECT recall**: of the spans a human marked as direct
identifiers (names, case codes, ...), how many does censorbot cover? A missed
DIRECT span is a real leak. We also report QUASI recall and precision.

    python -m benchmarks.tab_eval [--spacy] [--split test|dev] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict

from censorbot.detectors import detect_all
from censorbot.spans import resolve_overlaps

_HERE = os.path.dirname(__file__)


def _load(split: str):
    path = os.path.join(_HERE, "data", f"echr_{split}.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _gold_mentions(doc):
    """Return the first annotator's mentions as (start, end, type, identifier)."""
    ann = doc["annotations"]
    first = ann[sorted(ann)[0]]
    out = []
    for m in first["entity_mentions"]:
        out.append((m["start_offset"], m["end_offset"], m["entity_type"],
                    m["identifier_type"]))
    return out


def _covered(gs, ge, preds) -> bool:
    return any(ps < ge and gs < pe for ps, pe in preds)


def evaluate(split: str = "test", use_spacy: bool = False, limit: int | None = None):
    docs = _load(split)
    if limit:
        docs = docs[:limit]

    tot = defaultdict(int)       # identifier_type -> gold count
    cov = defaultdict(int)       # identifier_type -> covered count
    type_tot = defaultdict(int)  # entity_type (DIRECT only) -> gold
    type_cov = defaultdict(int)
    pred_total = pred_hit = 0
    missed_direct = []

    for doc in docs:
        text = doc["text"]
        preds = resolve_overlaps(detect_all(text, use_spacy=use_spacy))
        pspans = [(p.start, p.end) for p in preds]
        pred_total += len(pspans)
        # gold spans (dedup overlapping identical) for precision
        gold = _gold_mentions(doc)
        gspans = [(s, e) for s, e, _t, _i in gold]
        for ps, pe in pspans:
            if any(gs < pe and ps < ge for gs, ge in gspans):
                pred_hit += 1
        for s, e, etype, idt in gold:
            tot[idt] += 1
            hit = _covered(s, e, pspans)
            if hit:
                cov[idt] += 1
            if idt == "DIRECT":
                type_tot[etype] += 1
                if hit:
                    type_cov[etype] += 1
                elif len(missed_direct) < 40:
                    missed_direct.append((etype, text[s:e]))

    def rec(k):
        return cov[k] / tot[k] if tot[k] else 1.0

    print(f"=== TAB {split} ({len(docs)} docs, {'spaCy union' if use_spacy else 'heuristic'}) ===")
    print(f"DIRECT recall : {rec('DIRECT'):6.1%}  ({cov['DIRECT']}/{tot['DIRECT']})   <-- leak metric")
    print(f"QUASI  recall : {rec('QUASI'):6.1%}  ({cov['QUASI']}/{tot['QUASI']})")
    prec = pred_hit / pred_total if pred_total else 1.0
    print(f"precision~    : {prec:6.1%}  ({pred_hit}/{pred_total} predictions overlap a gold span)")
    print("\nDIRECT recall by gold entity type:")
    for t in sorted(type_tot, key=lambda x: -type_tot[x]):
        print(f"  {t:<10} {type_cov[t]/type_tot[t]:6.1%}  ({type_cov[t]}/{type_tot[t]})")
    if missed_direct:
        print(f"\nsample MISSED DIRECT identifiers ({len(missed_direct)} shown):")
        for t, v in missed_direct[:30]:
            print(f"  {t:<10} {v!r}")
    return rec("DIRECT")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test", choices=["test", "dev"])
    ap.add_argument("--spacy", action="store_true")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()
    evaluate(args.split, use_spacy=args.spacy, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
