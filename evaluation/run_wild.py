"""Run detection over the fetched real-document corpus (robustness, not accuracy).

Real public-domain / public-record text has no PII ground truth, so this doesn't
score recall. It checks the things that matter on messy real input:

* **no crashes** on odd formatting, Unicode, huge inputs;
* **throughput** (chars/sec) at document scale;
* **leak-scan cleanliness** - after ``maximum`` sanitisation, the outbound scan
  must be clean (no high-confidence identifier or known value left);
* a **false-positive eyeball** - the most frequent PERSON/ORG detections per
  category, so over-redaction is visible.

    python -m evaluation.run_wild
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter

from censorbot import get_policy, sanitize
from censorbot.detectors import detect_all
from censorbot.spans import resolve_overlaps

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CORPUS_DIR = os.path.join(_ROOT, "corpus")


def run() -> int:
    index_path = os.path.join(CORPUS_DIR, "index.json")
    if not os.path.exists(index_path):
        print("no corpus found - run: python -m evaluation.fetch_corpus")
        return 1
    with open(index_path, encoding="utf-8") as fh:
        index = [e for e in json.load(fh) if e.get("status") == "ok"]

    total_chars = total_time = 0.0
    total_entities = 0
    type_totals: Counter[str] = Counter()
    not_clean: list[tuple[str, str]] = []
    crashes: list[tuple[str, str]] = []
    person_samples: dict[str, Counter[str]] = {}

    print(f"{'document':<26} {'cat':<16} {'chars':>8} {'ents':>6} {'k/s':>7}  leak")
    print("-" * 76)
    for entry in index:
        path = os.path.join(_ROOT, entry["path"])
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        try:
            t0 = time.perf_counter()
            result = sanitize(text, get_policy("maximum"), use_spacy=False)
            dt = time.perf_counter() - t0
        except Exception as exc:  # noqa: BLE001
            crashes.append((entry["id"], repr(exc)))
            print(f"{entry['id']:<26} {entry['category']:<16} CRASH: {exc}")
            continue

        ents = result.entities
        total_chars += len(text)
        total_time += dt
        total_entities += len(ents)
        for e in ents:
            type_totals[e.entity_type.value] += 1
        clean = result.leak_report.clean if result.leak_report else True
        if not clean:
            not_clean.append((entry["id"], result.leak_report.summary()))

        cat = entry["category"]
        pc = person_samples.setdefault(cat, Counter())
        for e in ents:
            if e.entity_type.value in ("PERSON", "ORGANIZATION"):
                pc[e.canonical] += 1

        kps = (len(text) / dt / 1000) if dt else 0
        print(f"{entry['id']:<26} {cat:<16} {len(text):>8} {len(ents):>6} "
              f"{kps:>7.1f}  {'clean' if clean else 'NOT CLEAN'}")

    print("-" * 76)
    kps = (total_chars / total_time / 1000) if total_time else 0
    print(f"TOTAL: {int(total_chars):,} chars, {total_entities:,} entities, "
          f"{kps:.1f}k chars/sec, {total_time:.2f}s")
    print(f"crashes: {len(crashes)}   leak-scan not-clean: {len(not_clean)}")
    for cid, summary in not_clean:
        print(f"  [{cid}] {summary}")
    for cid, exc in crashes:
        print(f"  CRASH [{cid}] {exc}")

    print("\nmost-detected PERSON/ORG per category (false-positive eyeball):")
    for cat, counter in person_samples.items():
        top = ", ".join(f"{v!r}×{n}" for v, n in counter.most_common(6))
        print(f"  {cat:<16} {top}")

    print("\nentity type totals:")
    for t, n in type_totals.most_common():
        print(f"  {t:<14} {n}")

    return 1 if crashes else 0


if __name__ == "__main__":
    raise SystemExit(run())
