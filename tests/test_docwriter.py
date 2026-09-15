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


def test_unsupported_extension(tmp_path):
    result = _san()
    with pytest.raises(ValueError):
        write_document(str(tmp_path / "x.xyz"), result.sanitized_text)
