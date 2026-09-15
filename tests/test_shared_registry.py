from censorbot import get_policy, sanitize
from censorbot.tokens import TokenRegistry, find_tokens
from censorbot.vault import Vault


def _person_token(text):
    r = sanitize(text, get_policy("maximum"), use_spacy=False,
                 vault=_person_token.vault, registry=_person_token.reg)
    toks = {t[0] for t in find_tokens(r.sanitized_text) if t[1] == "PERSON"}
    return r, toks


def test_shared_registry_gives_same_token_across_documents():
    reg = TokenRegistry()
    vault = Vault()
    r1 = sanitize("Alejandro Martinez wrote a.m@example.com.", get_policy("maximum"),
                  use_spacy=False, vault=vault, registry=reg)
    r2 = sanitize("Later, Alejandro Martinez met Maria Gomez.", get_policy("maximum"),
                  use_spacy=False, vault=vault, registry=reg)
    # same person -> same token in both documents
    def person_tokens(res):
        return {find_tokens(res.sanitized_text)[i][0]
                for i, t in enumerate(find_tokens(res.sanitized_text)) if t[1] == "PERSON"}
    assert "[[PERSON_001]]" in r1.sanitized_text
    assert "[[PERSON_001]]" in r2.sanitized_text  # Alejandro is PERSON_001 in both
    # the shared vault accumulates both documents' entities
    assert len(vault) >= 3  # Alejandro, email, Maria
    assert "Alejandro Martinez" in vault.values()


def test_empty_shared_vault_is_not_discarded():
    # regression: an empty Vault is falsy; it must still be used, not replaced.
    vault = Vault()
    sanitize("Contact Maria Gomez.", get_policy("maximum"), use_spacy=False, vault=vault)
    assert len(vault) >= 1
