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

from .detectors import detect_all
from .leakscan import scan
from .pipeline import sanitize
from .policy import BUILTIN, get_policy
from .rehydrate import restore
from .resolver import resolve
from .spans import resolve_overlaps
from .tokens import make_token
from .vault import Vault

MAX_BODY = 8 * 1024 * 1024  # 8 MiB


class _Handler(BaseHTTPRequestHandler):
    server_version = "censorbot"

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
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def log_message(self, *args) -> None:  # quiet by default
        pass

    # -- routes ------------------------------------------------------------
    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"ok": True})
        elif self.path == "/policies":
            self._send(200, {"policies": sorted(BUILTIN)})
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
            else:
                self._send(404, {"error": "not found"})
        except KeyError as exc:
            self._send(400, {"error": f"missing field: {exc}"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})


def _inspect(data: dict) -> dict:
    text = data["text"]
    policy = get_policy(data.get("policy", "personal"))
    use_spacy = data.get("use_spacy", True)
    spans = resolve_overlaps(detect_all(text, use_spacy=use_spacy))
    entities = resolve(spans)
    items = []
    for ent in entities:
        if policy.action_for(ent.entity_type).value == "keep":
            continue
        items.append({
            "token": make_token(ent.entity_type, ent.index),
            "type": ent.entity_type.value,
            "value": ent.canonical,
            "confidence": max((s.confidence for s in ent.members), default=0.0),
            "occurrences": len(ent.members),
        })
    return {"policy": policy.name, "count": len(items), "entities": items}


def _sanitize(data: dict) -> dict:
    text = data["text"]
    policy = get_policy(data.get("policy", "personal"))
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


def serve(host: str = "127.0.0.1", port: int = 8723) -> None:
    """Run the daemon until interrupted. Loopback-only by default."""

    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"censorbot gateway listening on http://{host}:{port} (local only)")
    print("endpoints: POST /inspect /sanitize /restore ; GET /policies /health")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        print("\nshutting down")
    finally:
        httpd.server_close()
