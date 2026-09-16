import os

import pytest

from censorbot import get_policy, sanitize
from censorbot.docwriter import write_document

TEXT = "Alejandro Martinez, patient 48392017, a.martinez@example.com."


def _san():
    return sanitize(TEXT, get_policy("medical"), use_spacy=False)


def test_txt_regeneration_and_verify(tmp_path):
    result = _san()
    out = tmp_path / "safe.txt"
    write_document(str(out), result.sanitized_text, vault=result.vault, verify=True)
    content = out.read_text(encoding="utf-8")
    assert "Alejandro Martinez" not in content
    assert "[[PERSON_001]]" in content


def test_docx_regeneration(tmp_path):
    pytest.importorskip("docx")
    result = _san()
    out = tmp_path / "safe.docx"
    write_document(str(out), result.sanitized_text, vault=result.vault, verify=True)
    assert os.path.getsize(out) > 0
    # read back through the ingest loader; originals must be gone
    from censorbot.ingest import load_text
    back = load_text(str(out))
    assert "Alejandro Martinez" not in back
    assert "48392017" not in back


def test_pdf_regeneration(tmp_path):
    pytest.importorskip("reportlab")
    pytest.importorskip("pypdf")
    result = _san()
    out = tmp_path / "safe.pdf"
    write_document(str(out), result.sanitized_text, vault=result.vault, verify=True)
    assert os.path.getsize(out) > 0
    from censorbot.ingest import load_text
    back = load_text(str(out))
    assert "48392017" not in back


def test_csv_structure_preserved(tmp_path):
    csv = "name,email,city\nAlejandro Martinez,a.m@example.com,Vienna\n"
    src = tmp_path / "d.csv"
    src.write_text(csv, encoding="utf-8")
    from censorbot.ingest import load_text
    r = sanitize(load_text(str(src)), get_policy("maximum"), use_spacy=False)
    out = tmp_path / "d_safe.csv"
    write_document(str(out), r.sanitized_text, vault=r.vault, verify=True)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "name,email,city"          # header untouched
    assert lines[1].count(",") == 2               # structure preserved
    assert "Alejandro Martinez" not in lines[1]


def test_extract_bytes_pdf_roundtrip(tmp_path):
    pytest.importorskip("reportlab")
    pytest.importorskip("pypdf")
    from censorbot.ingest import extract_bytes
    out = tmp_path / "d.pdf"
    write_document(str(out), "Contact Maria Gomez at m@example.com.")
    text = extract_bytes(out.read_bytes(), ".pdf")
    assert "Maria Gomez" in text and "m@example.com" in text


def test_extract_bytes_txt():
    from censorbot.ingest import extract_bytes
    assert extract_bytes(b"hello Alejandro", ".txt") == "hello Alejandro"


def test_unsupported_extension(tmp_path):
    result = _san()
    with pytest.raises(ValueError):
        write_document(str(tmp_path / "x.xyz"), result.sanitized_text)
