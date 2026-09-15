"""Committed, network-free guards derived from the evaluation subsystem.

The synthetic generator is deterministic, so these assert hard thresholds in CI
without fetching anything. They lock in the fixes the real-document corpus drove
out (Unicode names, court case numbers, occurrence propagation, single-char
initials).
"""

from censorbot import get_policy, restore, sanitize
from evaluation.evaluate import evaluate
from evaluation.synth import generate


def test_synthetic_zero_leak_and_full_coverage():
    res = evaluate(use_spacy=False)
    assert res.coverage_recall == 1.0, res.report()
    assert res.leak_rate == 0.0, res.report()


def test_synthetic_precision_high():
    # header/label/currency words must not be flagged (over-redaction guard).
    res = evaluate(use_spacy=False)
    assert res.precision >= 0.98, res.report()


def test_synthetic_type_accuracy_high():
    res = evaluate(use_spacy=False)
    assert res.type_accuracy >= 0.97, res.report()


def test_headers_and_currency_not_persons():
    from censorbot.detectors import ner
    from censorbot.spans import EntityType
    spans = ner.detect("DISCHARGE SUMMARY\nBill to: Grace Baker\nAmount: EUR 4,000",
                       use_spacy=False)
    persons = {s.value for s in spans if s.entity_type == EntityType.PERSON}
    assert "Grace Baker" in persons
    assert not any(v in persons for v in ("DISCHARGE SUMMARY", "EUR", "Amount", "DISCHARGE"))


def test_synthetic_round_trip_and_leak_scan_clean():
    for doc in generate():
        result = sanitize(doc.text, get_policy("maximum"), use_spacy=False)
        assert result.leak_report.clean, (doc.domain, result.leak_report.summary())
        # every gold value must be gone from the sanitized text
        for g in doc.spans:
            assert g.value not in result.sanitized_text or len(g.value) < 2
        # tokens rehydrate without anomalies
        assert restore(result.sanitized_text, result.vault).invented == []


def test_unicode_name_detected():
    # non-ASCII uppercase starts must be caught (regression: "Škoda" leaked)
    r = sanitize("Contact Rich Škoda and Łukasz Nowak today.",
                 get_policy("maximum"), use_spacy=False)
    assert "Škoda" not in r.sanitized_text
    assert "Łukasz" not in r.sanitized_text


def test_court_case_number_detected():
    r = sanitize("Regarding case AZ 73 C 226 and 17 C 391/26.",
                 get_policy("legal"), use_spacy=False)
    assert "AZ 73 C 226" not in r.sanitized_text
    assert "17 C 391/26" not in r.sanitized_text


def test_occurrence_propagation_catches_sentence_initial():
    # "Curie" mid-sentence is tokenized; the sentence-initial one must be too.
    text = "We studied Marie Curie. Curie won a prize. Later, Curie moved."
    r = sanitize(text, get_policy("maximum"), use_spacy=False)
    assert "Curie" not in r.sanitized_text


def test_single_letter_is_not_an_entity():
    r = sanitize("The value of X and the point P are noted.",
                 get_policy("maximum"), use_spacy=False)
    # single capital letters must not become PERSON tokens
    assert "[[PERSON" not in r.sanitized_text
