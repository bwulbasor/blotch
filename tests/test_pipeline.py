from censorbot import get_policy, restore, sanitize
from censorbot.pipeline import preview
from censorbot.tokens import TOKEN_RE

SAMPLE = (
    "Alejandro Martinez was admitted to Vienna General Hospital on 14 March 2026. "
    "His patient number is 48392017. Contact a.martinez@example.com."
)


def test_sanitize_removes_original_values():
    result = sanitize(SAMPLE, get_policy("medical"), use_spacy=False)
    out = result.sanitized_text
    assert "Alejandro Martinez" not in out
    assert "48392017" not in out
    assert "a.martinez@example.com" not in out
    assert TOKEN_RE.search(out)  # tokens were inserted


def test_round_trip_restores_original():
    result = sanitize(SAMPLE, get_policy("medical"), use_spacy=False)
    restored = restore(result.sanitized_text, result.vault)
    assert "Alejandro Martinez" in restored.text
    assert "48392017" in restored.text
    assert restored.invented == []


def test_same_entity_same_token():
    text = "Alejandro Martinez called. Later, Mr. Martinez called again."
    result = sanitize(text, get_policy("personal"), use_spacy=False)
    tokens = [m.group(0) for m in TOKEN_RE.finditer(result.sanitized_text)]
    # both mentions should resolve to the same PERSON token
    person_tokens = [t for t in tokens if t.startswith("[[PERSON_")]
    assert len(person_tokens) == 2
    assert len(set(person_tokens)) == 1


def test_relationships_preserved_distinct_people():
    text = "Alejandro Martinez owes Maria Gomez money."
    result = sanitize(text, get_policy("personal"), use_spacy=False)
    person_tokens = {m.group(0) for m in TOKEN_RE.finditer(result.sanitized_text)
                     if m.group(1) == "PERSON"}
    assert len(person_tokens) == 2  # two distinct people -> two distinct tokens


def test_preview_masks_sensitive():
    masked = preview(SAMPLE, get_policy("medical"), use_spacy=False)
    assert "█" in masked
    assert "Alejandro Martinez" not in masked


def test_large_repeated_document_round_trips():
    # exercises the single-pass edit application and linear overlap resolution;
    # a value repeated many times must be fully removed and restored.
    doc = ("Alejandro Martinez met Maria Gomez in Berlin. " * 4000)
    result = sanitize(doc, get_policy("maximum"), use_spacy=False)
    assert "Alejandro Martinez" not in result.sanitized_text
    assert result.leak_report.clean
    assert restore(result.sanitized_text, result.vault).text == doc


def test_no_vault_value_survives_in_output():
    # the guaranteed final sweep: no tokenised value may remain whole-word in the
    # output, even with many shared surnames (an entity-typing conflict source).
    text = ("Frank Baker met May Rich and Rich Frank. Baker called. Rich replied. "
            "Frank Cook owes Frank Baker money. May saw Rich. " * 20)
    r = sanitize(text, get_policy("maximum"), use_spacy=False)
    assert r.leak_report.clean, r.leak_report.summary()
    import re as _re
    for v in set(r.vault.values()):
        if len(v) >= 2:
            assert not _re.search(r"(?<!\w)" + _re.escape(v) + r"(?!\w)",
                                  r.sanitized_text), f"leaked {v!r}"


def test_empty_and_no_entity_text():
    r = sanitize("", get_policy("maximum"), use_spacy=False)
    assert r.sanitized_text == "" and r.leak_report.clean
    r2 = sanitize("just some ordinary words here", get_policy("maximum"),
                  use_spacy=False)
    assert r2.leak_report.clean


def test_redact_propagates_all_occurrences():
    from censorbot.policy import policy_from_dict
    p = policy_from_dict({"name": "r", "default": "keep",
                          "actions": {"PERSON": "redact"}})
    text = "Curie won it. Later, Curie spoke. Marie Curie was cited."
    r = sanitize(text, p, use_spacy=False)
    assert "Curie" not in r.sanitized_text
    assert "[REDACTED]" in r.sanitized_text


def test_keep_policy_leaves_dates_in_personal():
    # personal policy keeps generic DATE
    result = sanitize("Meeting on 14 March 2026.", get_policy("personal"), use_spacy=False)
    assert "14 March 2026" in result.sanitized_text
