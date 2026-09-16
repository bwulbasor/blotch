from blotch import get_policy, sanitize, scan
from blotch.rehydrate import restore, validate_response


def _san(text, policy="personal"):
    return sanitize(text, get_policy(policy), use_spacy=False)


def test_invented_token_not_rehydrated():
    result = _san("Contact a.martinez@example.com.")
    # model invents a token that was never issued
    tampered = result.sanitized_text + " see also [[PERSON_842]]"
    r = restore(tampered, result.vault)
    assert "[[PERSON_842]]" in r.text        # left verbatim, not resolved
    assert "[[PERSON_842]]" in r.invented
    assert r.has_anomalies


def test_tolerant_rehydration_of_mangled_tokens():
    result = _san("Alejandro Martinez, patient 48392017.", "medical")
    v = result.vault
    # spaces inside brackets
    assert "Alejandro Martinez" in restore("see [[ PERSON_001 ]] ok", v).text
    # markdown backslash-escaped brackets/underscores
    assert "Alejandro Martinez" in restore(r"see \[\[PERSON\_001\]\] ok", v).text
    # multi-word type still works
    assert "48392017" in restore("id **[[PATIENT_ID_001]]**", v).text
    # a genuine non-token is left untouched
    assert restore("keep [[hello world]] here", v).text == "keep [[hello world]] here"


def test_dropped_token_reported():
    result = _san("Email a.martinez@example.com and b@example.com.")
    # response drops all tokens
    r = validate_response("The model said nothing sensitive.", result.vault)
    assert set(r.dropped) == set(result.vault.tokens())
    assert r.restored == []


def test_leak_scan_clean_after_sanitize():
    result = _san("IBAN GB82 WEST 1234 5698 7654 32 and card 4111 1111 1111 1111.")
    report = scan(result.sanitized_text, result.vault)
    assert report.clean, report.summary()


def test_leak_scan_blocks_residual_value():
    result = _san("Contact a.martinez@example.com.")
    # simulate a value that slipped through into outbound text
    leaked = result.sanitized_text + " oops a.martinez@example.com"
    report = scan(leaked, result.vault)
    assert report.blocked
    assert "a.martinez@example.com" in report.leaked_values
