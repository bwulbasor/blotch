from censorbot.detectors import deterministic
from censorbot.spans import EntityType


def _types(text):
    return {s.entity_type for s in deterministic.detect(text)}


def test_email_detected():
    spans = deterministic.detect("write to a.martinez@example.com please")
    assert any(s.entity_type == EntityType.EMAIL and s.value == "a.martinez@example.com"
               for s in spans)


def test_valid_iban_detected_invalid_ignored():
    good = deterministic.detect("IBAN GB82 WEST 1234 5698 7654 32 ok")
    assert any(s.entity_type == EntityType.IBAN for s in good)
    bad = deterministic.detect("IBAN GB82 WEST 1234 5698 7654 31 bad")
    assert not any(s.entity_type == EntityType.IBAN for s in bad)


def test_valid_card_detected():
    spans = deterministic.detect("card 4111 1111 1111 1111 exp")
    assert any(s.entity_type == EntityType.CREDIT_CARD for s in spans)


def test_labelled_patient_id():
    spans = deterministic.detect("Patient number: 48392017")
    assert any(s.entity_type == EntityType.PATIENT_ID and "48392017" in s.value
               for s in spans)


def test_dates_and_ip():
    assert EntityType.DATE in _types("admitted on 14 March 2026")
    assert EntityType.DATE in _types("date 2026-03-14")
    assert EntityType.IP in _types("host 192.168.1.100 down")


def test_addresses():
    assert EntityType.ADDRESS in _types("Home: 221 Baker Street, London")
    assert EntityType.ADDRESS in _types("lives at Hauptstraße 12 now")
    assert EntityType.ADDRESS in _types("postcode SW1A 1AA on file")


def test_address_no_false_positive_on_plain_numbers():
    assert EntityType.ADDRESS not in _types("I have 3 cats and 2 dogs")
    assert EntityType.ADDRESS not in _types("see Section 5 Way forward")
