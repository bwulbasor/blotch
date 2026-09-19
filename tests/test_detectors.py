from blotch.detectors import deterministic
from blotch.spans import EntityType


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


def test_extended_date_formats():
    for s in ["stamp 2026-03-14T10:30:00 utc", "date 2026/03/14 ok",
              "the 5th of January 2020", "March 14th, 2026 was", "14th March 2026"]:
        assert EntityType.DATE in _types(s), s


def test_year_less_month_dates():
    # ordinal / year-less month-name dates (common in DOBs and letters)
    for s in ["seen 20th September", "born 1st November", "on September 4th",
              "renewed September 2026", "meeting 26th June again"]:
        assert EntityType.DATE in _types(s), s


def test_month_word_in_prose_is_not_a_date():
    # a lower-case month word next to a number in prose must NOT be a date
    for s in ["you may 5 items", "we march 3 miles", "add august flavour 2 cups"]:
        assert EntityType.DATE not in _types(s), s


def test_addresses():
    assert EntityType.ADDRESS in _types("Home: 221 Baker Street, London")


def test_numbered_and_directional_streets():
    # numbered / directional US streets ("78244 N 5th Street", "350 42nd Avenue")
    for s in ["arranged at 78244 N 5th Street", "office at 350 42nd Avenue"]:
        assert EntityType.ADDRESS in _types(s), s
    assert EntityType.ADDRESS in _types("lives at Hauptstraße 12 now")
    assert EntityType.ADDRESS in _types("postcode SW1A 1AA on file")


def test_address_no_false_positive_on_plain_numbers():
    assert EntityType.ADDRESS not in _types("I have 3 cats and 2 dogs")
    assert EntityType.ADDRESS not in _types("see Section 5 Way forward")


def test_us_zip_and_bic():
    from blotch.spans import resolve_overlaps
    def vals(t):
        return {s.value for s in resolve_overlaps(deterministic.detect(t))}
    assert "IL 62704" in vals("Office at Springfield, IL 62704 now")
    assert "DEUTDEFF500" in vals("BIC: DEUTDEFF500 for transfer")
    # no comma -> not a state/zip; bare ZIP alone not matched
    assert EntityType.ADDRESS not in _types("the IN 12345 reference")


def test_gazetteer_locations():
    from blotch.detectors import gazetteer
    vals = {(s.entity_type, s.value) for s in gazetteer.detect(
        "She moved from Vienna to New York, then to Japan.")}
    assert (EntityType.LOCATION, "Vienna") in vals
    assert (EntityType.LOCATION, "New York") in vals
    assert (EntityType.LOCATION, "Japan") in vals


def test_mac_and_coordinates_and_ids():
    assert EntityType.MAC in _types("device 01:23:45:67:89:ab online")
    assert EntityType.COORDINATES in _types("at 48.2082, 16.3738 today")
    assert EntityType.GOV_ID in _types("Passport X1234567 issued")
    assert EntityType.GOV_ID in _types("driver licence AB123456")


def test_crypto_wallets():
    assert EntityType.CRYPTO in _types(
        "send to 0x52908400098527886E0F7030069857D2E4169EE7")
    assert EntityType.CRYPTO in _types("btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    # short/partial hex is not a wallet
    assert EntityType.CRYPTO not in _types("value 0x1234 only")


def test_mac_not_confused_with_ipv6():
    spans = deterministic.detect("mac 01:23:45:67:89:ab here")
    macs = [s for s in spans if s.entity_type == EntityType.MAC]
    # after overlap resolution MAC must win over the IPv6-shaped match
    from blotch.spans import resolve_overlaps
    kept = resolve_overlaps(deterministic.detect("mac 01:23:45:67:89:ab"))
    assert any(s.entity_type == EntityType.MAC for s in kept)
    assert macs


def test_detectors_do_not_bridge_newlines():
    # a footer year and the next line's section number must not merge into a phone
    text = "page 5\n\nOctober 2008\n\n\n3.9.2 Section"
    spans = deterministic.detect(text)
    assert not any("\n" in s.value for s in spans)
    # real phone on one line still works
    assert EntityType.PHONE in _types("ring +43 660 1234567 today")


def test_phone_ignores_isbn_and_year_range():
    assert EntityType.PHONE not in _types("ISBN 978-0-262-01202-7 in refs")
    assert EntityType.PHONE not in _types("active 2012-2013 period")
    # a genuine phone is still caught
    assert EntityType.PHONE in _types("call +1 (415) 555-0132 today")


def test_short_month_date_not_case_id():
    # "1 Jan 1990" is a date, not a court case number
    types = _types("born 1 Jan 1990 in town")
    assert EntityType.DATE in types
    assert EntityType.CASE_ID not in types


def test_name_particles_kept_whole():
    from blotch.detectors import ner
    def persons(t):
        return {s.value for s in ner.detect(t, use_spacy=False)
                if s.entity_type == EntityType.PERSON}
    assert "Ludwig van Beethoven" in persons("Ludwig van Beethoven composed.")
    assert "Charles de Gaulle" in persons("Charles de Gaulle led France.")
    assert "Vincent van der Berg" in persons("Vincent van der Berg arrived.")


def test_city_typed_as_location_not_person():
    from blotch import get_policy, sanitize
    from blotch.tokens import find_tokens
    r = sanitize("The meeting is in Berlin next week.", get_policy("maximum"),
                 use_spacy=False)
    types = {t[1] for t in find_tokens(r.sanitized_text)}
    assert "LOCATION" in types and "PERSON" not in types
