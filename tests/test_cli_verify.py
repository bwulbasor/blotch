from censorbot.cli import main


def test_verify_flags_residual_pii(tmp_path):
    f = tmp_path / "leaky.txt"
    f.write_text("John Smith and phone +1 (415) 555-0132 remain.", encoding="utf-8")
    assert main(["verify", str(f)]) == 2


def test_verify_clean_on_tokens_only(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("[[PERSON_001]] met [[PERSON_002]] in [[LOCATION_001]].",
                 encoding="utf-8")
    assert main(["verify", str(f)]) == 0


def test_verify_against_vault(tmp_path):
    import pytest
    pytest.importorskip("cryptography")
    src = tmp_path / "n.txt"
    src.write_text("Contact Maria Gomez at m@example.com.", encoding="utf-8")
    out, vault = tmp_path / "s.txt", tmp_path / "v.cbv"
    assert main(["sanitize", str(src), "--out", str(out), "--vault", str(vault),
                 "--policy", "maximum", "--no-spacy", "--passphrase", "pw"]) == 0
    assert main(["verify", str(out), "--vault", str(vault), "--passphrase", "pw"]) == 0
