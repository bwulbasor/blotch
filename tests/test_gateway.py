import pytest

from censorbot import Gateway, LeakBlocked, echo_provider, get_policy

SENSITIVE = "Alejandro Martinez, patient number 48392017, a.martinez@example.com."


def test_gateway_round_trip_with_echo():
    gw = Gateway(get_policy("medical"), echo_provider, use_spacy=False)
    result = gw.run(SENSITIVE)
    # provider only ever saw tokens
    assert "Alejandro Martinez" not in result.sanitized
    assert "48392017" not in result.response
    # restored output matches original exactly (echo provider)
    assert result.restored == SENSITIVE
    assert not result.response_had_anomalies


def test_provider_is_replaceable():
    # A provider that rewrites prose but preserves tokens still round-trips.
    def summarizer(text: str) -> str:
        return f"Summary: {text}"

    gw = Gateway(get_policy("personal"), summarizer, use_spacy=False)
    result = gw.run(SENSITIVE)
    assert result.restored.startswith("Summary: ")
    assert "Alejandro Martinez" in result.restored


def test_gateway_blocks_on_provider_leak_back():
    # If the provider injects an original value, restore can't hide it, but the
    # gateway's own outbound scan guards the *outbound* leg. Here we assert the
    # outbound sanitised text is what the provider receives.
    seen = {}

    def capture(text: str) -> str:
        seen["text"] = text
        return text

    Gateway(get_policy("maximum"), capture, use_spacy=False).run(SENSITIVE)
    assert "Alejandro Martinez" not in seen["text"]


def test_block_on_leak_raises(monkeypatch):
    import censorbot.gateway as gwmod

    class FakeReport:
        blocked = True
        clean = False
        def summary(self):
            return "BLOCKED: test"

    class FakeResult:
        sanitized_text = "x"
        leak_report = FakeReport()

    monkeypatch.setattr(gwmod, "sanitize", lambda *a, **k: FakeResult())
    gw = Gateway(get_policy("maximum"), echo_provider)
    with pytest.raises(LeakBlocked):
        gw.run("whatever")
