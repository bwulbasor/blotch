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

MAX_BODY = 32 * 1024 * 1024  # 32 MiB (base64-encoded PDF uploads)


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


def _extract(data: dict) -> dict:
    """Extract text from an uploaded document (base64 in ``content``)."""
    import base64
    import os as _os
    from .ingest import extract_bytes, ocr as _ocr
    name = data.get("filename", "upload.txt")
    ext = (_os.path.splitext(name)[1] or ".txt").lower()
    raw = base64.b64decode(data["content"])
    text = extract_bytes(raw, ext)
    # Tell the UI whether OCR was involved so it can flag best-effort text.
    ocr_used = ext in (".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp")
    if ext == ".pdf" and _ocr.ocr_available():
        try:
            from pypdf import PdfReader
            import io as _io
            layer = "\n".join((p.extract_text() or "")
                              for p in PdfReader(_io.BytesIO(raw)).pages)
            ocr_used = text.strip() != layer.strip()
        except Exception:
            ocr_used = False
    return {"text": text, "chars": len(text), "ocr_used": ocr_used}


def _review(data: dict) -> dict:
    from .review import render_review_html
    text = data["text"]
    policy = get_policy(data.get("policy", "personal"))
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


_UI_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>blotch</title><style>
 :root{color-scheme:light dark}
 body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:0 auto;padding:20px;
   background:#fafafa;color:#1a1a1a}
 @media(prefers-color-scheme:dark){body{background:#16181c;color:#e8e8e8}
   textarea,select,pre{background:#1f2228!important;color:#e8e8e8;border-color:#333!important}}
 h1{font-size:20px} .sub{color:#888;margin-top:-8px}
 textarea{width:100%;min-height:160px;font:13px/1.5 ui-monospace,monospace;padding:10px;
   border:1px solid #ccc;border-radius:8px;box-sizing:border-box}
 .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}
 button{font:inherit;padding:8px 14px;border-radius:8px;border:1px solid #0003;cursor:pointer;background:#f0f0f0}
 button.primary{background:#218380;color:#fff;border-color:#218380}
 select{padding:7px;border-radius:8px}
 pre{white-space:pre-wrap;word-wrap:break-word;background:#fff;border:1px solid #0001;
   border-radius:8px;padding:14px}
 .ok{color:#1e7d33;font-weight:700} .bad{color:#9a031e;font-weight:700}
 .chip{display:inline-block;font-size:12px;padding:2px 8px;border-radius:20px;background:#218380;color:#fff;margin:2px}
</style></head><body>
<h1>blotch</h1>
<p class="sub">Local privacy gateway. Text is processed on this machine; only the
sanitized version is shown for you to copy. Nothing is sent anywhere.</p>
<div class="row">
 <label style="cursor:pointer">📄 Upload PDF / DOCX / TXT / image
   <input type="file" id="file" accept=".pdf,.docx,.txt,.md,.csv,.png,.jpg,.jpeg,.tiff,.bmp,.webp" style="display:none"></label>
 <span id="fstatus" style="color:#888;font-size:13px"></span>
</div>
<textarea id="in" placeholder="Paste a document here, or upload one above..."></textarea>
<div class="row">
 <label>Policy <select id="policy"></select></label>
 <button class="primary" id="san">Sanitize</button>
 <button id="review">Review &amp; tag</button>
 <button id="insp">Inspect</button>
 <span id="status"></span>
</div>
<div id="out"></div>
<iframe id="rvframe" allow="clipboard-write" style="display:none;width:100%;height:70vh;border:1px solid #0002;border-radius:8px;margin-top:10px"></iframe>
<div id="rt" hidden>
 <h3>2 · Paste the external service's reply to rehydrate it locally</h3>
 <textarea id="reply" placeholder="Paste the model/service reply containing the [[TOKENS]]..."></textarea>
 <div class="row"><button id="res">Restore</button><span id="rstatus"></span></div>
 <div id="rout"></div>
</div>
<script>
 const $=s=>document.querySelector(s);
 let VAULT=null;
 fetch('/policies').then(r=>r.json()).then(d=>{
   $('#policy').innerHTML=d.policies.map(p=>`<option${p=='personal'?' selected':''}>${p}</option>`).join('');
 });
 async function post(path,body){const r=await fetch(path,{method:'POST',
   headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json();}
 function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
 $('#file').onchange=async(e)=>{
   const f=e.target.files[0]; if(!f) return;
   $('#fstatus').textContent='extracting '+f.name+'...';
   const bytes=new Uint8Array(await f.arrayBuffer());
   let bin=''; const CH=0x8000;
   for(let i=0;i<bytes.length;i+=CH) bin+=String.fromCharCode.apply(null,bytes.subarray(i,i+CH));
   const d=await post('/extract',{filename:f.name,content:btoa(bin)});
   if(d.error){$('#fstatus').textContent='error: '+d.error;return;}
   $('#in').value=d.text;
   $('#fstatus').textContent=f.name+' — '+d.chars+' chars extracted'+
     (d.ocr_used?' (via OCR — check for recognition errors)':'');
 };
 $('#san').onclick=async()=>{
   $('#status').textContent='working...';
   const d=await post('/sanitize',{text:$('#in').value,policy:$('#policy').value,use_spacy:false});
   VAULT=d.vault;  // kept in this page's memory only, never re-sent anywhere
   $('#status').innerHTML=d.leak.clean?'<span class="ok">leak scan: clean</span>':'<span class="bad">'+esc(d.leak.summary)+'</span>';
   $('#out').innerHTML='<h3>1 · Sanitized ('+d.counts.tokenized+' tokenized) \\u2014 send THIS to the model</h3>'+
     '<pre id="s">'+esc(d.sanitized)+'</pre><button id="cp">Copy sanitized</button>';
   $('#cp').onclick=async()=>{try{await navigator.clipboard.writeText(d.sanitized);
     $('#cp').textContent='Copied \\u2713';}catch(e){}};
   $('#rt').hidden=false;
 };
 $('#res').onclick=async()=>{
   if(!VAULT){$('#rstatus').textContent='sanitize a document first';return;}
   $('#rstatus').textContent='working...';
   const d=await post('/restore',{text:$('#reply').value,vault:VAULT});
   $('#rstatus').innerHTML=d.anomalies?'<span class="bad">token anomalies: invented '+JSON.stringify(d.invented)+'</span>':'<span class="ok">restored '+d.restored_tokens.length+' token(s)</span>';
   $('#rout').innerHTML='<h3>Rehydrated result</h3><pre>'+esc(d.restored)+'</pre>';
 };
 $('#review').onclick=async()=>{
   $('#status').textContent='working...';
   const d=await post('/review',{text:$('#in').value,policy:$('#policy').value,use_spacy:false});
   const f=$('#rvframe'); f.srcdoc=d.html; f.style.display='block'; $('#out').innerHTML=''; $('#rt').hidden=true;
   $('#status').textContent='review below: click to keep, select text to tag';
 };
 $('#insp').onclick=async()=>{
   $('#status').textContent='working...';
   const d=await post('/inspect',{text:$('#in').value,policy:$('#policy').value,use_spacy:false});
   $('#status').textContent=d.count+' entities';
   $('#out').innerHTML='<h3>Detected entities</h3>'+
     (d.entities.map(e=>`<span class="chip">${esc(e.type)}: ${esc(e.value)}</span>`).join('')||'<em>none</em>');
 };
</script></body></html>"""


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


def serve(host: str = "127.0.0.1", port: int = 8723) -> None:
    """Run the daemon until interrupted. Loopback-only by default."""

    import threading
    threading.Thread(target=_warm_ocr, daemon=True).start()

    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"blotch gateway on http://{host}:{port} (local only) - open it in a browser")
    print("endpoints: GET / (web UI) /policies /health ; POST /inspect /sanitize /restore")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        print("\nshutting down")
    finally:
        httpd.server_close()
