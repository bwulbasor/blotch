"""Score blotch detection against ground-truth labels.

Key metrics (privacy framing):

* **coverage_recall** - fraction of gold PII spans overlapped by *some* detected
  span. Under the ``maximum`` policy every detection is tokenised, so an uncovered
  gold span is a real leak. This is the number that matters most.
* **type_accuracy** - of covered gold spans, fraction where an overlapping
  prediction has a compatible type (right token category).
* **precision** - fraction of predictions that overlap a gold span (false
  positives over-redact but never leak).

Run: ``python -m evaluation.evaluate``
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from blotch.detectors import detect_all
from blotch.spans import EntityType, Span, resolve_overlaps

from .synth import GoldSpan, LabeledDoc, generate

# Types that count as "the same category" for type_accuracy.
_FAMILIES = [
    {EntityType.DATE, EntityType.DOB},
    {EntityType.GOV_ID, EntityType.PATIENT_ID, EntityType.CASE_ID,
     EntityType.ACCOUNT_ID},
]


def _compatible(a: EntityType, b: EntityType) -> bool:
    if a == b:
        return True
    return any(a in fam and b in fam for fam in _FAMILIES)


def _overlap(a_start: int, a_end: int, b: Span) -> bool:
    return a_start < b.end and b.start < a_end


@dataclass
class EvalResult:
    total_gold: int = 0
    covered: int = 0
    type_ok: int = 0
    total_pred: int = 0
    pred_hits: int = 0
    per_type_gold: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    per_type_covered: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    misses: list[tuple[str, str, str]] = field(default_factory=list)  # (type, value, domain)

    @property
    def coverage_recall(self) -> float:
        return self.covered / self.total_gold if self.total_gold else 1.0

    @property
    def type_accuracy(self) -> float:
        return self.type_ok / self.covered if self.covered else 1.0

    @property
    def precision(self) -> float:
        return self.pred_hits / self.total_pred if self.total_pred else 1.0

    @property
    def leak_rate(self) -> float:
        return 1.0 - self.coverage_recall

    def report(self) -> str:
        lines = [
            f"documents scored : (gold spans {self.total_gold}, predictions {self.total_pred})",
            f"coverage_recall  : {self.coverage_recall:6.1%}  ({self.covered}/{self.total_gold})"
            f"   [leak_rate {self.leak_rate:.1%}]",
            f"type_accuracy    : {self.type_accuracy:6.1%}  ({self.type_ok}/{self.covered})",
            f"precision        : {self.precision:6.1%}  ({self.pred_hits}/{self.total_pred})",
            "",
            "per-type coverage recall:",
        ]
        for t in sorted(self.per_type_gold):
            g, c = self.per_type_gold[t], self.per_type_covered[t]
            lines.append(f"  {t:<14} {c/g:6.1%}  ({c}/{g})")
        if self.misses:
            lines.append("")
            lines.append(f"LEAKS ({len(self.misses)}) - gold spans no detector covered:")
            for t, v, dom in self.misses[:40]:
                lines.append(f"  [{dom:<8}] {t:<12} {v!r}")
        return "\n".join(lines)


def evaluate(docs: list[LabeledDoc] | None = None, *, use_spacy: bool = False) -> EvalResult:
    docs = docs or generate()
    res = EvalResult()
    for doc in docs:
        preds = resolve_overlaps(detect_all(doc.text, use_spacy=use_spacy))
        res.total_pred += len(preds)
        for p in preds:
            if any(_overlap(g.start, g.end, p) for g in doc.spans):
                res.pred_hits += 1
        for g in doc.spans:
            res.total_gold += 1
            res.per_type_gold[g.entity_type.value] += 1
            overlapping = [p for p in preds if _overlap(g.start, g.end, p)]
            if overlapping:
                res.covered += 1
                res.per_type_covered[g.entity_type.value] += 1
                if any(_compatible(p.entity_type, g.entity_type) for p in overlapping):
                    res.type_ok += 1
            else:
                res.misses.append((g.entity_type.value, g.value, doc.domain))
    return res


def main() -> int:
    res = evaluate()
    print("=== blotch synthetic evaluation (heuristic NER) ===")
    print(res.report())
    # Fail (for CI) if any gold PII span leaked.
    return 1 if res.leak_rate > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
