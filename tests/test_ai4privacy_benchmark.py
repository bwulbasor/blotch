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
    recall = evaluate(use_spacy=False)
    assert recall >= 0.88, f"targeted recall regressed to {recall:.1%}"
