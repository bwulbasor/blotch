"""Optional OCR layer for scanned / image-only documents.

Most PDFs carry a real text layer, and :mod:`blotch.ingest.loaders` reads that
directly. A *scanned* PDF is just a picture of a page with no text layer, so the
normal extractor returns nothing and there is nothing to sanitise. This module
is the fallback: it renders each page to an image and runs OCR to recover the
text, which then flows through the same detection pipeline as any other document.

Everything here is **optional and degrades gracefully**. Page rendering needs
PyMuPDF (``pip install 'blotch[ocr]'``); the actual character recognition needs
an OCR *engine*. Two are supported, tried in this order:

1. **Tesseract** via ``pytesseract`` - accurate and standard, but needs the
   Tesseract binary installed on the system (not just the Python wrapper).
2. **RapidOCR** (``rapidocr-onnxruntime``) - pip-only, no system binary, bundles
   its own models. A good zero-install option.

If neither is present, :func:`ocr_available` returns ``False`` and callers keep
today's behaviour (an empty result for a scanned PDF) instead of crashing. OCR
text is a best-effort transcription: it can contain recognition errors, so the
review screen matters even more for OCR'd documents.
"""

from __future__ import annotations

import io

# Below this many non-whitespace characters per page, a PDF's text layer is
# treated as empty (i.e. the page is a scan) and OCR is worth attempting.
_MIN_CHARS_PER_PAGE = 16

# Rendering resolution. 300 DPI is the usual sweet spot for OCR accuracy vs
# speed / memory; lower blurs small print, higher rarely helps and costs RAM.
_OCR_DPI = 300


def looks_scanned(text: str, num_pages: int) -> bool:
    """Heuristic: does an extracted text layer look empty (a scan)?

    ``num_pages`` scales the threshold so a long document is not misjudged by a
    single stray character. Pure whitespace always counts as scanned.
    """

    dense = "".join(text.split())
    if not dense:
        return True
    pages = max(1, num_pages)
    return len(dense) < _MIN_CHARS_PER_PAGE * pages


def _engine():
    """Return a callable ``png_bytes -> text`` for the best available engine, or
    ``None`` if no usable OCR engine is installed.

    The result is cached on the function so model loading (RapidOCR) or the
    binary probe (Tesseract) happens once per process.
    """

    if getattr(_engine, "_cached", "unset") != "unset":
        return _engine._cached  # type: ignore[attr-defined]

    engine = _load_tesseract() or _load_rapidocr()
    _engine._cached = engine  # type: ignore[attr-defined]
    return engine


def _load_tesseract():
    """A pytesseract-backed engine, but only if the Tesseract binary actually
    runs - the Python wrapper installs fine on its own and would otherwise fail
    later with a confusing error."""

    try:
        import pytesseract
        from PIL import Image
    except Exception:
        return None
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        return None  # wrapper present, binary missing - fall through to RapidOCR

    def run(png: bytes) -> str:
        return pytesseract.image_to_string(Image.open(io.BytesIO(png)))

    return run


def _load_rapidocr():
    """A RapidOCR-backed engine (ONNX, no system binary)."""

    try:
        from rapidocr_onnxruntime import RapidOCR
    except Exception:
        return None
    reader = RapidOCR()

    def run(png: bytes) -> str:
        import numpy as np
        from PIL import Image

        img = np.array(Image.open(io.BytesIO(png)).convert("RGB"))
        result, _ = reader(img)
        if not result:
            return ""
        # RapidOCR returns [[box, text, score], ...] in reading order.
        return "\n".join(line[1] for line in result)

    return run


def ocr_available() -> bool:
    """True when both a page renderer (PyMuPDF) and an OCR engine are usable."""

    try:
        import fitz  # noqa: F401  (PyMuPDF)
    except Exception:
        return False
    return _engine() is not None


def render_pdf_pages(data: bytes, dpi: int = _OCR_DPI, indices=None):
    """Yield ``(page_index, png_bytes)`` for the PDF ``data``.

    ``indices`` limits rendering to a set/collection of 0-based page numbers,
    so a mixed document only pays to rasterise the pages that actually need OCR.
    """

    import fitz

    want = None if indices is None else set(indices)
    zoom = dpi / 72.0
    matrix = fitz.Matrix(zoom, zoom)
    with fitz.open(stream=data, filetype="pdf") as doc:
        for i, page in enumerate(doc):
            if want is None or i in want:
                yield i, page.get_pixmap(matrix=matrix).tobytes("png")


def ocr_image(image: bytes) -> str:
    """OCR a single image (PNG/JPEG/TIFF/... bytes) to text."""

    engine = _engine()
    if engine is None:
        raise RuntimeError(
            "OCR needs an engine: install Tesseract, or "
            "pip install rapidocr-onnxruntime"
        )
    return engine(image)


def ocr_pdf_pages(data: bytes, indices=None, dpi: int = _OCR_DPI) -> dict:
    """OCR selected pages of ``data``; return ``{page_index: text}``.

    With ``indices=None`` every page is OCR'd. Used for both whole-scan and
    per-page hybrid recovery.
    """

    try:
        import fitz  # noqa: F401
    except Exception as exc:
        raise RuntimeError(
            "OCR needs page rendering: pip install 'blotch[ocr]'"
        ) from exc
    return {i: ocr_image(png) for i, png in render_pdf_pages(data, dpi, indices)}


def ocr_pdf(data: bytes, dpi: int = _OCR_DPI) -> str:
    """OCR every page of a scanned PDF and join the pages with newlines."""

    pages = ocr_pdf_pages(data, None, dpi)
    return "\n".join(pages[i] for i in sorted(pages))
