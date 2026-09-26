"""A local privacy-gateway daemon (plan §13).

Exposes the engine over HTTP on the loopback interface using only the standard
library (no web framework). A company can point internal tooling at it:

    POST /inspect   {"text", "policy"}          -> detected entities
    POST /sanitize  {"text", "policy"}          -> sanitized text + vault + leak
    POST /restore   {"text", "vault"}           -> rehydrated text + anomalies
    GET  /policies                               -> available policy names
    GET  /health                                 -> {"ok": true}

**The vault is returned in the /sanitize response and passed back to /restore.**
The server is stateless and binds to 127.0.0.1 only, so the mapping never leaves
the machine. This is the localhost daemon form of the "sensitive data never
leaves the trust boundary" guarantee - do not expose it on a public interface.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .pipeline import entity_report, sanitize
from .policy import BUILTIN, Policy
from .rehydrate import restore
from .templates import load as load_template
from .vault import Vault

MAX_BODY = 32 * 1024 * 1024  # 32 MiB (base64-encoded PDF uploads)

# Policies the daemon offers: the built-ins plus any loaded at startup with
# `blotch serve --policy-file`, so custom recognizers reach the web UI too.
_POLICIES: dict[str, Policy] = dict(BUILTIN)


def _resolve_policy(data: dict) -> Policy:
    name = data.get("policy", "personal")
    try:
        return _POLICIES[name]
    except KeyError:
        raise ValueError(f"unknown policy {name!r}; choose from {sorted(_POLICIES)}")


class _Handler(BaseHTTPRequestHandler):
    server_version = "blotch"

    # -- helpers -----------------------------------------------------------
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length < 0:
            # rfile.read(-n) means "read until EOF", which blocks this thread
            # while the client waits for our response
            raise ValueError("invalid Content-Length")
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def log_message(self, *args) -> None:  # quiet by default
        pass

    # -- routes ------------------------------------------------------------
    def _send_html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send_html(200, _UI_HTML)
        elif self.path == "/health":
            self._send(200, {"ok": True})
        elif self.path == "/policies":
            self._send(200, {"policies": sorted(_POLICIES)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            data = self._read_json()
        except Exception as exc:
            self._send(400, {"error": f"bad request: {exc}"})
            return
        try:
            if self.path == "/inspect":
                self._send(200, _inspect(data))
            elif self.path == "/sanitize":
                self._send(200, _sanitize(data))
            elif self.path == "/restore":
                self._send(200, _restore(data))
            elif self.path == "/review":
                self._send(200, _review(data))
            elif self.path == "/extract":
                self._send(200, _extract(data))
            else:
                self._send(404, {"error": "not found"})
        except KeyError as exc:
            self._send(400, {"error": f"missing field: {exc}"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except RuntimeError as exc:
            # optional dependency missing (e.g. an image upload with no OCR
            # engine, or a PDF without the 'docs' extra) - report, don't 500.
            self._send(400, {"error": str(exc)})


def _inspect(data: dict) -> dict:
    # Goes through the real pipeline (not a parallel re-implementation), so it
    # reports exactly what /sanitize would act on - propagated occurrences and
    # the policy's custom recognizers included.
    text = data["text"]
    policy = _resolve_policy(data)
    use_spacy = data.get("use_spacy", True)
    result = sanitize(text, policy, use_spacy=use_spacy, run_leak_scan=False)
    items = entity_report(result, policy)
    return {"policy": policy.name, "count": len(items), "entities": items}


def _sanitize(data: dict) -> dict:
    text = data["text"]
    policy = _resolve_policy(data)
    use_spacy = data.get("use_spacy", True)
    result = sanitize(text, policy, use_spacy=use_spacy)
    report = result.leak_report
    return {
        "sanitized": result.sanitized_text,
        "vault": result.vault.to_dict(),
        "leak": {
            "clean": report.clean if report else True,
            "summary": report.summary() if report else "not scanned",
        },
        "counts": {"tokenized": result.num_tokenized, "redacted": result.num_redacted},
    }


def _extract(data: dict) -> dict:
    """Extract text from an uploaded document (base64 in ``content``)."""
    import base64
    import os as _os
    from .ingest import extract_document
    name = data.get("filename", "upload.txt")
    ext = (_os.path.splitext(name)[1] or ".txt").lower()
    raw = base64.b64decode(data["content"])
    # The loader reports exactly which pages came from OCR, so the UI can flag
    # best-effort text - no re-parsing the upload to guess.
    doc = extract_document(raw, ext)
    return {"text": doc.text, "chars": len(doc.text), "ocr_used": doc.ocr_used,
            "ocr_pages": [p + 1 for p in doc.ocr_pages]}  # 1-based for humans


def _review(data: dict) -> dict:
    from .review import render_review_html
    text = data["text"]
    policy = _resolve_policy(data)
    use_spacy = data.get("use_spacy", True)
    return {"html": render_review_html(text, policy, use_spacy=use_spacy)}


def _restore(data: dict) -> dict:
    text = data["text"]
    vault = Vault.from_dict(data["vault"])
    result = restore(text, vault)
    return {
        "restored": result.text,
        "anomalies": result.has_anomalies,
        "invented": result.invented,
        "dropped": result.dropped,
        "restored_tokens": result.restored,
    }


# Plain HTML/CSS/JS in templates/ui.html (no slots).
_UI_HTML = load_template("ui.html")


def _warm_ocr() -> None:
    """Load the OCR engine (and its models) in the background so the first
    scanned upload isn't a cold multi-second/minute stall on the request path.
    Silent no-op when OCR isn't installed."""
    try:
        from .ingest import ocr
        if ocr.ocr_available():
            print("warming OCR engine...")
    except Exception:
        pass


def register_policies(policies) -> None:
    """Offer extra (custom) policies from the daemon alongside the built-ins.

    A custom policy may not reuse a built-in name: silently swapping what
    "personal" means for every client is exactly the kind of surprise a privacy
    tool must not have.
    """
    for p in policies:
        if p.name in BUILTIN:
            raise ValueError(f"custom policy name {p.name!r} clashes with a built-in "
                             f"policy; rename it")
        if p.name in _POLICIES:
            # two --policy-file's with the same name: the second must not
            # silently replace the first's rules
            raise ValueError(f"duplicate custom policy name {p.name!r}")
        _POLICIES[p.name] = p


def serve(host: str = "127.0.0.1", port: int = 8723, policies=()) -> None:
    """Run the daemon until interrupted. Loopback-only by default.

    ``policies`` are extra :class:`~blotch.policy.Policy` objects (e.g. with
    custom recognizers) offered by name next to the built-ins.
    """

    register_policies(policies)

    import threading
    threading.Thread(target=_warm_ocr, daemon=True).start()

    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"blotch gateway on http://{host}:{port} (local only) - open it in a browser")
    print(f"policies: {', '.join(sorted(_POLICIES))}")
    print("endpoints: GET / (web UI) /policies /health ; POST /inspect /sanitize /restore")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        print("\nshutting down")
    finally:
        httpd.server_close()
