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
    r = evaluate(use_spacy=False)
    assert r["targeted_recall"] >= 0.90, f"recall regressed to {r['targeted_recall']:.1%}"


def test_ai4privacy_precision_floor():
    r = evaluate(use_spacy=False)
    assert r["precision"] >= 0.80, f"precision regressed to {r['precision']:.1%}"
