"""Custom (organisation-specific) recognizers, plus the pipeline consistency fixes
that came with them: preview/inspect now reflect exactly what sanitize does."""

import json

import pytest

from blotch import get_policy, restore, sanitize
from blotch.detectors import Recognizer
from blotch.leakscan import scan
from blotch.pipeline import entity_report, preview
from blotch.policy import policy_from_dict
from blotch.spans import EntityType

EMP = {"name": "employee_id", "pattern": r"EMP-\d{5}", "entity_type": "ACCOUNT_ID"}


def _policy(*recs, actions=None):
    return policy_from_dict({"name": "corp", "default": "keep",
                             "actions": actions or {"ACCOUNT_ID": "tokenize",
                                                    "CASE_ID": "tokenize",
                                                    "PERSON": "tokenize"},
                             "recognizers": list(recs)})


# -- detection -----------------------------------------------------------------

def test_custom_id_is_tokenized_and_round_trips():
    text = "Badge EMP-10442 belongs to staff; EMP-10442 renewed."
    r = sanitize(text, _policy(EMP), use_spacy=False)
    assert "EMP-10442" not in r.sanitized_text
    assert r.sanitized_text.count("[[ACCOUNT_ID_001]]") == 2
    assert restore(r.sanitized_text, r.vault).text == text


def test_group_redacts_only_the_value_not_the_label():
    rec = {"name": "matter", "pattern": r"Matter No\.? (?P<v>\d{4}-\d{3})",
           "entity_type": "CASE_ID", "group": "v"}
    # isolate the recognizer (no PERSON tokenizing, so the NER heuristic's own
    # opinion of the word "Matter" doesn't enter into it)
    r = sanitize("See Matter No. 2291-004 today.",
                 _policy(rec, actions={"CASE_ID": "tokenize"}), use_spacy=False)
    assert r.sanitized_text == "See Matter No. [[CASE_ID_001]] today."


def test_builtin_policy_plus_recognizer():
    pol = get_policy("personal").with_recognizers(
        [Recognizer("employee_id", r"EMP-\d{5}", EntityType.ACCOUNT_ID)])
    r = sanitize("Ask EMP-77001 or mail a@example.com", pol, use_spacy=False)
    assert "EMP-77001" not in r.sanitized_text and "a@example.com" not in r.sanitized_text


def test_without_a_recognizer_the_id_is_not_protected():
    # The built-in detectors don't know this format: the name heuristic grabs
    # "Badge EMP" and the ID's digits leak. This is why custom recognizers exist.
    r = sanitize("Badge EMP-10442.", get_policy("personal"), use_spacy=False)
    assert "10442" in r.sanitized_text
    # ...and with one, the whole ID is tokenized as the right type
    pol = get_policy("personal").with_recognizers(
        [Recognizer("employee_id", r"EMP-\d{5}", EntityType.ACCOUNT_ID)])
    r = sanitize("Badge EMP-10442.", pol, use_spacy=False)
    assert "10442" not in r.sanitized_text and "[[ACCOUNT_ID_001]]" in r.sanitized_text


# -- the leak scanner enforces custom recognizers ------------------------------

def test_leak_scanner_blocks_residual_custom_id():
    rec = Recognizer("employee_id", r"EMP-\d{5}", EntityType.ACCOUNT_ID, confidence=0.95)
    report = scan("forwarding EMP-10442 to the vendor", recognizers=[rec])
    assert not report.clean
    assert any(s.value == "EMP-10442" for s in report.residual_spans)


def test_leak_scanner_ignores_custom_match_inside_a_token():
    rec = Recognizer("employee_id", r"EMP-\d{5}", EntityType.ACCOUNT_ID, confidence=0.95)
    assert scan("forwarding [[ACCOUNT_ID_001]]", recognizers=[rec]).clean


# -- validation: typos fail loudly ---------------------------------------------

@pytest.mark.parametrize("bad, msg", [
    ({**EMP, "pattern": "EMP-("}, "invalid pattern"),
    ({**EMP, "pattern": r"\d*"}, "empty text"),
    ({**EMP, "entity_type": "EMPLOYEE"}, "unknown entity_type"),
    ({**EMP, "confidence": 1.5}, "confidence"),
    ({**EMP, "group": "v"}, "no group"),
    ({**EMP, "colour": "red"}, "unknown field"),
    ({"name": "x", "pattern": "a"}, "entity_type"),
    ({**EMP, "name": "9bad name"}, "name"),
])
def test_invalid_recognizers_are_rejected(bad, msg):
    with pytest.raises(ValueError, match=msg):
        _policy(bad)


def test_recognizer_for_a_kept_type_is_rejected():
    # would detect the ID and then leave it in the clear - an error, not a no-op
    with pytest.raises(ValueError, match="keeps ACCOUNT_ID"):
        _policy(EMP, actions={"PERSON": "tokenize"})


def test_duplicate_recognizer_names_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        _policy(EMP, {**EMP, "pattern": r"E-\d{4}"})


def test_recognizers_load_from_policy_file(tmp_path):
    f = tmp_path / "corp.json"
    f.write_text(json.dumps({"name": "corp", "default": "tokenize",
                             "recognizers": [EMP]}), encoding="utf-8")
    from blotch.policy import load_policy_file
    pol = load_policy_file(str(f))
    assert [r.name for r in pol.recognizers] == ["employee_id"]


# -- preview / inspect now match sanitize exactly ------------------------------

def test_preview_masks_propagated_occurrences():
    # "Green signed" is only caught by name-part propagation; the old preview
    # re-derived spans itself and showed it unmasked while the output hid it.
    text = "Mr Green arrived. Green signed the form."
    masked = preview(text, get_policy("personal"), use_spacy=False)
    assert "Green" not in masked
    assert masked.startswith("Mr ")


def test_preview_masks_custom_recognizer_matches():
    masked = preview("Badge EMP-10442 ok", _policy(EMP), use_spacy=False)
    assert "EMP-10442" not in masked and "█" in masked


def test_entity_report_counts_propagated_occurrences():
    text = "Mr Green arrived. Green signed. Later Green left."
    r = sanitize(text, get_policy("personal"), use_spacy=False)
    person = [e for e in entity_report(r, get_policy("personal")) if e["type"] == "PERSON"]
    assert person and person[0]["occurrences"] == 3
    assert person[0]["token"] == "[[PERSON_001]]"
