"""Real-spaCy tests (skipped unless spaCy + the English model are installed).

These run in an environment with the `ner` extra + `en_core_web_sm` (e.g. the
project's 3.11 venv, or CI). They verify the union behaviour and, critically,
that spaCy's inconsistent per-occurrence typing never causes a leak.
"""

import pytest

spacy = pytest.importorskip("spacy")
try:
    spacy.load("en_core_web_sm")
except Exception:  # pragma: no cover - model not downloaded
    pytest.skip("en_core_web_sm not installed", allow_module_level=True)

from blotch import get_policy, sanitize
from blotch.detectors import ner
from blotch.spans import EntityType


def test_spacy_union_keeps_heuristic_recall():
    # a common-word name spaCy tends to miss must still be caught (heuristic net)
    spans = ner.detect("Emergency contact: May Rich, then Summer called.",
                       use_spacy=True)
    persons = {s.value for s in spans if s.entity_type == EntityType.PERSON}
    assert any("May" in p for p in persons)


def test_spacy_inconsistent_typing_does_not_leak():
    # spaCy types a surname as ORG in one sentence and PERSON in another; the
    # final sweep must still ensure it never survives whole-word in the output.
    text = ("Charles Babbage designed engines. Babbage was a mathematician. "
            "The Babbage machine was famous. Later, Babbage retired near London. "
            "Babbage's notes survive. " * 10)
    r = sanitize(text, get_policy("maximum"), use_spacy=True)
    assert r.leak_report.clean, r.leak_report.summary()
    import re
    assert not re.search(r"(?<!\w)Babbage(?!\w)", r.sanitized_text)


def test_spacy_round_trips():
    text = "Ada Lovelace worked with Charles Babbage in London in 1843."
    r = sanitize(text, get_policy("maximum"), use_spacy=True)
    from blotch import restore
    assert restore(r.sanitized_text, r.vault).text == text
