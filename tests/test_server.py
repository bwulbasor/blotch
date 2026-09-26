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


@pytest.fixture()
def isolated_policies(monkeypatch):
    # give each test its own policy registry so registrations don't leak
    import blotch.server as server
    monkeypatch.setattr(server, "_POLICIES", dict(server._POLICIES))
    return server


def test_custom_policy_is_offered_and_used(base_url, isolated_policies):
    from blotch.policy import policy_from_dict
    corp = policy_from_dict({
        "name": "acme", "default": "keep", "actions": {"ACCOUNT_ID": "tokenize"},
        "recognizers": [{"name": "employee_id", "pattern": r"EMP-\d{5}",
                         "entity_type": "ACCOUNT_ID"}]})
    isolated_policies.register_policies([corp])
    assert "acme" in _get(base_url + "/policies")["policies"]
    out = _post(base_url + "/sanitize",
                {"text": "badge EMP-10442", "policy": "acme", "use_spacy": False})
    assert "EMP-10442" not in out["sanitized"]
    assert "[[ACCOUNT_ID_001]]" in out["sanitized"]


def test_custom_policy_cannot_shadow_a_builtin(isolated_policies):
    from blotch.policy import Policy
    with pytest.raises(ValueError, match="clashes"):
        isolated_policies.register_policies([Policy("personal")])


def test_unknown_policy_is_a_clear_400(base_url):
    import urllib.error
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(base_url + "/sanitize", {"text": "x", "policy": "nope"})
    assert exc.value.code == 400
    assert "unknown policy" in json.loads(exc.value.read().decode())["error"]


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
