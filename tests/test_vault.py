import pytest

from censorbot import get_policy, sanitize
from censorbot.vault import Vault

crypto = pytest.importorskip("cryptography")


def test_vault_encrypt_round_trip(tmp_path):
    result = sanitize("Contact a.martinez@example.com.", get_policy("personal"),
                      use_spacy=False)
    path = tmp_path / "vault.cbv"
    result.vault.save(str(path), passphrase="correct horse battery staple")

    loaded = Vault.load(str(path), passphrase="correct horse battery staple")
    assert set(loaded.tokens()) == set(result.vault.tokens())
    assert loaded.values() == result.vault.values()


def test_wrong_passphrase_fails(tmp_path):
    result = sanitize("Contact a.martinez@example.com.", get_policy("personal"),
                      use_spacy=False)
    path = tmp_path / "vault.cbv"
    result.vault.save(str(path), passphrase="right")
    with pytest.raises(ValueError, match="wrong passphrase"):
        Vault.load(str(path), passphrase="wrong")


def test_refuses_plaintext_without_optin(tmp_path):
    v = Vault()
    with pytest.raises(ValueError):
        v.save(str(tmp_path / "v.json"))
