from censorbot import get_policy, sanitize, scan
from censorbot.rehydrate import restore, validate_response


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
