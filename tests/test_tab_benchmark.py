"""Regression gate against the real Text Anonymization Benchmark.

Skipped unless the TAB data is present (it is downloaded on demand and
git-ignored). When present, it enforces a high floor on DIRECT-identifier recall
- the leak metric - so a detector change that regresses real-world recall fails.

Fetch the data:
    mkdir -p benchmarks/data && cd benchmarks/data
    curl -LO https://raw.githubusercontent.com/NorskRegnesentral/text-anonymization-benchmark/master/echr_test.json
"""

import os

import pytest

_DATA = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "data",
                     "echr_test.json")
if not os.path.exists(_DATA):
    pytest.skip("TAB data not downloaded (see module docstring)",
                allow_module_level=True)

from benchmarks.tab_eval import evaluate


def test_tab_direct_recall_floor():
    # a missed DIRECT identifier is a real leak; enforce >= 99% on real documents
    direct_recall = evaluate("test", use_spacy=False)
    assert direct_recall >= 0.99, f"DIRECT recall regressed to {direct_recall:.1%}"
