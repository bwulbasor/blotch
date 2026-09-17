"""OCR fallback for scanned PDFs.

The heuristic tests run everywhere. The end-to-end recognition test builds a
genuine image-only PDF (no text layer) and is skipped unless both PyMuPDF and an
OCR engine (Tesseract or RapidOCR) are installed - the same pattern as the real
spaCy test.
"""

import pytest

from blotch.ingest import ocr
from blotch.ingest.loaders import extract_bytes


# -- heuristic (no dependencies) -----------------------------------------------

def test_looks_scanned_on_empty():
    assert ocr.looks_scanned("", 1) is True
    assert ocr.looks_scanned("   \n\n  \t ", 3) is True


def test_looks_scanned_on_real_text():
    assert ocr.looks_scanned("Patient Maria Gomez, MRN 55512345, seen today.", 1) is False


def test_looks_scanned_scales_with_pages():
    # a single stray word across a 50-page PDF still reads as a scan
    assert ocr.looks_scanned("page", 50) is True


def test_extract_bytes_rejects_bad_ocr_mode():
    with pytest.raises(ValueError):
        extract_bytes(b"hi", ".txt", ocr="sometimes")


def test_plain_text_ignores_ocr():
    assert extract_bytes(b"hello world", ".txt", ocr="always") == "hello world"


# -- end-to-end recognition (needs an engine) ----------------------------------

def _image_only_pdf(text: str) -> bytes:
    """Build a PDF that is a picture of ``text`` with no extractable text layer."""
    fitz = pytest.importorskip("fitz")
    src = fitz.open()
    page = src.new_page()
    page.insert_text((72, 100), text, fontsize=22)
    pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
    out = fitz.open()
    opage = out.new_page(width=pix.width, height=pix.height)
    opage.insert_image(opage.rect, stream=pix.tobytes("png"))
    return out.tobytes()


def test_scanned_pdf_has_no_text_layer():
    """Sanity: our synthetic scan really is image-only (justifies the fallback)."""
    pytest.importorskip("fitz")
    pytest.importorskip("pypdf")
    from pypdf import PdfReader
    import io
    data = _image_only_pdf("Patient Maria Gomez MRN 55512345")
    reader = PdfReader(io.BytesIO(data))
    layer = "".join((p.extract_text() or "") for p in reader.pages)
    assert ocr.looks_scanned(layer, len(reader.pages))


def test_ocr_recovers_text_from_scan():
    if not ocr.ocr_available():
        pytest.skip("no OCR engine (Tesseract / RapidOCR) installed")
    data = _image_only_pdf("Patient Maria Gomez")
    # auto mode should detect the empty text layer and OCR it
    text = extract_bytes(data, ".pdf", ocr="auto")
    assert "Maria" in text and "Gomez" in text


def _text_image(text: str) -> bytes:
    """Render ``text`` to a PNG (a picture of the words, for image-upload tests)."""
    fitz = pytest.importorskip("fitz")
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 100), text, fontsize=22)
    return page.get_pixmap(matrix=fitz.Matrix(3, 3)).tobytes("png")


def test_image_never_mode_returns_empty():
    # an image has no text layer; ocr="never" yields nothing, no engine needed
    png = _text_image("Ada Lovelace")
    assert extract_bytes(png, ".png", ocr="never") == ""


def test_image_upload_ocr():
    if not ocr.ocr_available():
        pytest.skip("no OCR engine installed")
    png = _text_image("Ada Lovelace")
    text = extract_bytes(png, ".png")  # auto -> OCR
    assert "Ada" in text and "Lovelace" in text


def test_hybrid_ocrs_only_the_scanned_page():
    """A mixed PDF: a real text page plus an image-only page. The text page is
    kept verbatim; the scanned page is recovered by OCR."""
    if not ocr.ocr_available():
        pytest.skip("no OCR engine installed")
    fitz = pytest.importorskip("fitz")
    # page 0: real text layer
    doc = fitz.open()
    p0 = doc.new_page()
    p0.insert_text((72, 100), "Contact Bob Textlayer here", fontsize=18)
    # page 1: an image of text, no text layer
    img = _text_image("Scanned Carol Pixel")
    p1 = doc.new_page()
    p1.insert_image(p1.rect, stream=img)
    data = doc.tobytes()

    text = extract_bytes(data, ".pdf", ocr="auto")
    assert "Bob Textlayer" in text        # native text preserved
    assert "Carol" in text and "Pixel" in text  # scanned page OCR'd
