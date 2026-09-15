import pytest

from censorbot.cli import main

pytest.importorskip("cryptography")


def test_batch_sanitizes_tree(tmp_path):
    indir = tmp_path / "in"
    (indir / "sub").mkdir(parents=True)
    (indir / "a.txt").write_text("Alejandro Martinez, a.martinez@example.com.",
                                 encoding="utf-8")
    (indir / "sub" / "b.txt").write_text("Contact Maria Gomez in Vienna.",
                                         encoding="utf-8")
    outdir, vaultdir = tmp_path / "out", tmp_path / "vault"

    rc = main(["batch", str(indir), "--outdir", str(outdir), "--vaultdir",
               str(vaultdir), "--policy", "legal", "--no-spacy",
               "--passphrase", "pw"])
    assert rc == 0
    a = (outdir / "a.txt").read_text(encoding="utf-8")
    assert "Alejandro Martinez" not in a and "[[PERSON_001]]" in a
    assert (outdir / "sub__b.txt").exists()
    assert (vaultdir / "a.cbv").exists()
    assert (vaultdir / "sub__b.cbv").exists()


def test_batch_requires_passphrase(tmp_path, capsys):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "a.txt").write_text("hello", encoding="utf-8")
    rc = main(["batch", str(indir), "--outdir", str(tmp_path / "o"),
               "--vaultdir", str(tmp_path / "v"), "--no-spacy"])
    assert rc == 2
