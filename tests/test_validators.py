from blotch.detectors.validators import iban_valid, luhn_valid


def test_luhn_valid_card():
    assert luhn_valid("4111 1111 1111 1111")   # Visa test number
    assert luhn_valid("5500005555555559")


def test_luhn_rejects_bad_checksum():
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("1234")  # too short


def test_iban_valid():
    assert iban_valid("GB82 WEST 1234 5698 7654 32")
    assert iban_valid("DE89370400440532013000")


def test_iban_rejects_bad_checksum():
    assert not iban_valid("GB82 WEST 1234 5698 7654 31")
    assert not iban_valid("XX00")
