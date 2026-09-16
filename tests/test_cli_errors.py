from blotch.cli import main


def test_missing_file_clean_error(capsys):
    rc = main(["inspect", "does_not_exist_12345.txt", "--no-spacy"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_unsupported_output_clean_error(tmp_path, capsys):
    f = tmp_path / "n.txt"
    f.write_text("hi", encoding="utf-8")
    rc = main(["sanitize", str(f), "--out", str(tmp_path / "o.weird"),
               "--vault", str(tmp_path / "v.cbv"), "--no-spacy", "--allow-plaintext"])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()
