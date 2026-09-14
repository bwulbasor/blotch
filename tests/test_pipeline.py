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


def test_keep_policy_leaves_dates_in_personal():
    # personal policy keeps generic DATE
    result = sanitize("Meeting on 14 March 2026.", get_policy("personal"), use_spacy=False)
    assert "14 March 2026" in result.sanitized_text
