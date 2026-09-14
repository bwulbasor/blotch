"""Document ingestion.

The MVP extracts plain text and, on output, **regenerates a clean document from
the sanitised text** rather than editing the original binary in place. This is a
deliberate anti-leak decision (see README): regeneration cannot carry forward a
hidden text layer, annotation, form field, metadata entry, or embedded file that
in-place redaction would miss.

PDF/DOCX support is optional (``pip install 'censorbot[docs]'``); ``.txt`` always
works. For a scanned PDF with no text layer, OCR would slot in here as a separate
step - out of scope for the MVP, which targets documents that already have text.
"""

from __future__ import annotations

import os

SUPPORTED = (".txt", ".md", ".text", ".pdf", ".docx")


def load_text(path: str) -> str:
    """Extract plain text from a supported document."""

    ext = os.path.splitext(path)[1].lower()
    if ext in (".txt", ".md", ".text"):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if ext == ".pdf":
        return _load_pdf(path)
    if ext == ".docx":
        return _load_docx(path)
    raise ValueError(f"unsupported file type {ext!r}; supported: {', '.join(SUPPORTED)}")


def _load_pdf(path: str) -> str:  # pragma: no cover - optional dependency
    try:
        from pypdf import PdfReader
    except Exception as exc:
        raise RuntimeError(
            "PDF support needs the optional 'docs' extra: pip install 'censorbot[docs]'"
        ) from exc
    reader = PdfReader(path)
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def _load_docx(path: str) -> str:  # pragma: no cover - optional dependency
    try:
        import docx
    except Exception as exc:
        raise RuntimeError(
            "DOCX support needs the optional 'docs' extra: pip install 'censorbot[docs]'"
        ) from exc
    document = docx.Document(path)
    return "\n".join(p.text for p in document.paragraphs)
