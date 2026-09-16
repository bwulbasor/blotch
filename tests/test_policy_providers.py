import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blotch import Action, EntityType, sanitize
from blotch.policy import load_policy_file, policy_from_dict
from blotch.providers import HttpProvider, openai_chat_provider


def test_custom_policy_from_dict():
    p = policy_from_dict({
        "name": "mine", "default": "keep",
        "actions": {"PERSON": "tokenize", "EMAIL": "redact", "DATE": "keep"},
    })
    assert p.action_for(EntityType.PERSON) == Action.TOKENIZE
    assert p.action_for(EntityType.EMAIL) == Action.REDACT
    assert p.action_for(EntityType.DATE) == Action.KEEP


def test_custom_policy_rejects_unknown_type():
    with pytest.raises(ValueError):
        policy_from_dict({"actions": {"PERSN": "tokenize"}})


def test_custom_policy_file_roundtrip(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"name": "f", "actions": {"PERSON": "tokenize"}}))
    p = load_policy_file(str(path))
    out = sanitize("Contact Alejandro Martinez.", p, use_spacy=False)
    assert "Alejandro Martinez" not in out.sanitized_text


# --- provider adapters ----------------------------------------------------

class _EchoOpenAI(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length).decode())
        user_msg = req["messages"][-1]["content"]
        body = json.dumps({"choices": [{"message": {"content": f"echo:{user_msg}"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def echo_openai_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _EchoOpenAI)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}/v1/chat/completions"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_openai_provider_extracts_response(echo_openai_url):
    provider = openai_chat_provider(echo_openai_url, api_key="x", model="test")
    assert provider("[[PERSON_001]] here") == "echo:[[PERSON_001]] here"


def test_http_provider_custom_payload_and_path(echo_openai_url):
    provider = HttpProvider(
        echo_openai_url,
        build_payload=lambda t: {"model": "m", "messages": [{"role": "user", "content": t}]},
        response_path="choices.0.message.content",
    )
    assert provider("hi").startswith("echo:")
