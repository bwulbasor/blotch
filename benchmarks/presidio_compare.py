"""Head-to-head: blotch vs Microsoft Presidio on the same benchmarks.

Presidio is the de-facto open-source PII detector everyone compares against, so
"why not just use Presidio?" is the question blotch has to answer with data. This
runs both detectors over the same TAB (real court cases) and AI4Privacy
(synthetic broad PII) samples, scored identically:

  * recall    = fraction of gold PII spans covered by >=1 predicted span
  * precision = fraction of predicted spans overlapping >=1 gold span

It is span-overlap, entity-type-agnostic (both tools use different type
taxonomies), which is exactly how blotch's own evals score, so the numbers are
comparable. Run in the spaCy venv (Presidio needs spaCy + a model):

    .venv-spacy/Scripts/python.exe -m benchmarks.presidio_compare
"""

from __future__ import annotations

import json
import os

_HERE = os.path.dirname(__file__)
_AI4 = os.path.join(_HERE, "data", "ai4privacy_en.json")
_TAB = os.path.join(_HERE, "data", "echr_test.json")


def _overlap(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _score(rows, predict):
    """rows: list of (text, gold_spans). predict: text -> list[(start,end)]."""
    gold_total = gold_hit = pred_total = pred_hit = 0
    for text, gold in rows:
        preds = predict(text)
        for g in gold:
            gold_total += 1
            if any(_overlap(g, p) for p in preds):
                gold_hit += 1
        for p in preds:
            pred_total += 1
            if any(_overlap(g, p) for g in gold):
                pred_hit += 1
    return {
        "recall": gold_hit / gold_total if gold_total else 0.0,
        "precision": pred_hit / pred_total if pred_total else 0.0,
        "gold": gold_total, "pred": pred_total,
    }


# -- data loaders (gold spans) -------------------------------------------------

def _ai4_rows(limit=None):
    rows = json.load(open(_AI4, encoding="utf-8"))
    if limit:
        rows = rows[:limit]
    out = []
    for r in rows:
        gold = [(m["start"], m["end"]) for m in r["privacy_mask"]]
        out.append((r["source_text"], gold))
    return out


def _tab_rows(limit=None):
    """TAB: keep DIRECT identifier gold spans (the leak-critical ones)."""
    docs = json.load(open(_TAB, encoding="utf-8"))
    if limit:
        docs = docs[:limit]
    out = []
    for d in docs:
        text = d["text"]
        ann = d["annotations"]
        first = ann[sorted(ann)[0]]  # first annotator, as in tab_eval
        gold = [(e["start_offset"], e["end_offset"])
                for e in first["entity_mentions"]
                if e.get("identifier_type") == "DIRECT"]
        if gold:
            out.append((text, gold))
    return out


# -- predictors ----------------------------------------------------------------

def _blotch_predict(use_spacy):
    from blotch.detectors import detect_all
    from blotch.spans import resolve_overlaps

    def predict(text):
        return [(s.start, s.end)
                for s in resolve_overlaps(detect_all(text, use_spacy=use_spacy))]
    return predict


def _presidio_predict():
    from presidio_analyzer import AnalyzerEngine
    engine = AnalyzerEngine()

    def predict(text):
        # cap very long docs to Presidio's comfort zone; TAB docs are long
        results = engine.analyze(text=text, language="en")
        return [(r.start, r.end) for r in results]
    return predict


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300)
    args = ap.parse_args()

    datasets = []
    if os.path.exists(_AI4):
        datasets.append(("AI4Privacy", _ai4_rows(args.limit)))
    if os.path.exists(_TAB):
        datasets.append(("TAB-DIRECT", _tab_rows(args.limit)))

    blotch_h = _blotch_predict(False)
    try:
        blotch_s = _blotch_predict(True)
    except Exception:
        blotch_s = None
    try:
        presidio = _presidio_predict()
    except Exception as exc:  # pragma: no cover
        presidio = None
        print(f"(Presidio unavailable: {exc})")

    for name, rows in datasets:
        print(f"\n===== {name}  ({len(rows)} docs) =====")
        print(f"{'detector':22} {'recall':>8} {'precision':>10}")
        b = _score(rows, blotch_h)
        print(f"{'blotch (heuristic)':22} {b['recall']:>7.1%} {b['precision']:>10.1%}")
        if blotch_s:
            bs = _score(rows, blotch_s)
            print(f"{'blotch (spaCy union)':22} {bs['recall']:>7.1%} {bs['precision']:>10.1%}")
        if presidio:
            p = _score(rows, presidio)
            print(f"{'presidio':22} {p['recall']:>7.1%} {p['precision']:>10.1%}")


if __name__ == "__main__":
    main()
