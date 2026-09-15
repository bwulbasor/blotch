"""Write the sanitised document by **regeneration**, not in-place editing.

This is the anti-leak core of "PDF processing is its own engineering problem"
(plan §7). A regenerated document is built from the sanitised text alone, so it
structurally cannot carry forward anything the sanitiser didn't see:

    hidden text layers · annotations · form fields · document metadata ·
    embedded files · OCR layers · bookmarks · comments · revision history

Supported outputs: ``.txt``/``.md`` (always), ``.docx`` (``python-docx``),
``.pdf`` (``reportlab``). The DOCX/PDF writers are optional extras.

Note: layout, fonts and images from the original are intentionally *not*
preserved - fidelity of appearance is explicitly traded for the guarantee that no
un-sanitised byte survives. Rich-layout-preserving output is future work and must
carry the same verification.
"""

from __future__ import annotations

import os

from .leakscan import LeakReport, scan
from .vault import Vault


class VerificationError(RuntimeError):
    """Raised if a written document still contains a known original value."""


def write_document(path: str, sanitized_text: str, *, vault: Vault | None = None,
                   verify: bool = True) -> None:
    """Regenerate a sanitised document at ``path`` from ``sanitized_text``.

    If ``verify`` and a ``vault`` is given, the produced file is read back and
    scanned; any surviving original value raises :class:`VerificationError`
    rather than silently shipping a leak.
    """

    ext = os.path.splitext(path)[1].lower()
    if ext in ("", ".txt", ".md", ".text"):
        _write_txt(path, sanitized_text)
    elif ext == ".docx":
        _write_docx(path, sanitized_text)
    elif ext == ".pdf":
        _write_pdf(path, sanitized_text)
    else:
        raise ValueError(f"unsupported output type {ext!r}")

    if verify and vault is not None:
        report = _verify_file(path, ext, vault)
        if not report.clean:
            raise VerificationError(report.summary())


def _write_txt(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _write_docx(path: str, text: str) -> None:
    try:
        import docx
    except Exception as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "DOCX output needs the optional 'docs' extra: pip install 'censorbot[docs]'"
        ) from exc
    document = docx.Document()  # a brand-new document, no inherited metadata
    for line in text.split("\n"):
        document.add_paragraph(line)
    document.save(path)


def _write_pdf(path: str, text: str) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
    except Exception as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "PDF output needs reportlab: pip install reportlab"
        ) from exc
    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    margin, leading = 2 * cm, 14
    y = height - margin
    c.setFont("Helvetica", 10)
    for raw_line in text.split("\n"):
        for line in _wrap(raw_line, 95):
            if y < margin:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - margin
            c.drawString(margin, y, line)
            y -= leading
    c.save()


def _wrap(line: str, width: int) -> list[str]:
    if not line:
        return [""]
    words, out, cur = line.split(" "), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    out.append(cur)
    return out


def _verify_file(path: str, ext: str, vault: Vault) -> LeakReport:
    from .ingest import load_text
    if ext in ("", ".txt", ".md", ".text", ".docx", ".pdf"):
        try:
            text = load_text(path if ext else path)
        except Exception:
            # if we can't read it back, be conservative and re-scan the source
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    else:  # pragma: no cover
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    return scan(text, vault)
