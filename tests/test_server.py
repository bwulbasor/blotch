import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from blotch.server import _Handler


@pytest.fixture()
def base_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode())


def test_health_and_policies(base_url):
    assert _get(base_url + "/health") == {"ok": True}
    assert "medical" in _get(base_url + "/policies")["policies"]


def test_web_ui_served(base_url):
    import urllib.request
    with urllib.request.urlopen(base_url + "/", timeout=5) as resp:
        assert resp.headers.get_content_type() == "text/html"
        html = resp.read().decode()
    assert "<title>blotch</title>" in html
    assert "/sanitize" in html  # the UI calls the JSON API


def test_sanitize_then_restore_over_http(base_url):
    text = "Alejandro Martinez, patient 48392017, a.martinez@example.com."
    san = _post(base_url + "/sanitize", {"text": text, "policy": "medical", "use_spacy": False})
    assert "Alejandro Martinez" not in san["sanitized"]
    assert san["leak"]["clean"] is True

    res = _post(base_url + "/restore", {"text": san["sanitized"], "vault": san["vault"]})
    assert "Alejandro Martinez" in res["restored"]
    assert res["anomalies"] is False


def test_review_over_http(base_url):
    out = _post(base_url + "/review",
                {"text": "Contact John Smith at j@x.com.", "policy": "personal",
                 "use_spacy": False})
    assert "buildOutput" in out["html"] and "const ORIGINAL" in out["html"]


def test_inspect_over_http(base_url):
    out = _post(base_url + "/inspect",
                {"text": "email a.b@example.com", "policy": "personal", "use_spacy": False})
    assert out["count"] >= 1
    assert any(e["type"] == "EMAIL" for e in out["entities"])
