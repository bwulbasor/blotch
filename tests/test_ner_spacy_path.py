"""Exercise the spaCy integration wiring with a fake spaCy module.

Real spaCy isn't importable here (no wheels for this Python), and CI covers the
heuristic path. This injects a stand-in `spacy` so the _spacy_detect mapping
(label -> EntityType, char offsets, caching, graceful skip of unknown labels) is
actually tested rather than assumed.
"""

import sys
import types

import pytest

from blotch.detectors import ner
from blotch.spans import EntityType


class _Ent:
    def __init__(self, text, label, start, end):
        self.text, self.label_, self.start_char, self.end_char = text, label, start, end


class _Doc:
    def __init__(self, ents):
        self.ents = ents


def _make_fake_spacy(ents):
    mod = types.ModuleType("spacy")
    mod.load = lambda name: (lambda text: _Doc(ents))
    return mod


@pytest.fixture(autouse=True)
def _clear_nlp_cache():
    if hasattr(ner._spacy_detect, "_nlp"):
        del ner._spacy_detect._nlp
    yield
    sys.modules.pop("spacy", None)
    if hasattr(ner._spacy_detect, "_nlp"):
        del ner._spacy_detect._nlp


def test_spacy_labels_mapped(monkeypatch):
    text = "Alan Turing worked at GCHQ in London."
    ents = [_Ent("Alan Turing", "PERSON", 0, 11),
            _Ent("GCHQ", "ORG", 22, 26),
            _Ent("London", "GPE", 30, 36),
            _Ent("yesterday", "DATE", 37, 46)]  # unmapped label -> skipped
    monkeypatch.setitem(sys.modules, "spacy", _make_fake_spacy(ents))

    spans = ner.detect(text, use_spacy=True)
    got = {(s.entity_type, s.value) for s in spans}
    assert (EntityType.PERSON, "Alan Turing") in got
    assert (EntityType.ORGANIZATION, "GCHQ") in got
    assert (EntityType.LOCATION, "London") in got
    # DATE label isn't in the map -> not emitted by the spaCy layer
    assert not any(s.value == "yesterday" for s in spans)


def test_falls_back_to_heuristic_when_spacy_absent(monkeypatch):
    # no 'spacy' in sys.modules -> import fails -> heuristic path
    monkeypatch.setitem(sys.modules, "spacy", None)
    spans = ner.detect("Contact Maria Gomez today.", use_spacy=True)
    assert any(s.entity_type == EntityType.PERSON and "Maria Gomez" in s.value
               for s in spans)
