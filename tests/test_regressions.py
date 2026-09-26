"""Regression tests for bugs found in the September 2026 code review.

Each test reproduces the original failure; a revert of the fix makes it fail.
"""

import pytest

from blotch import EntityType, Recognizer, get_policy, restore, sanitize
from blotch.policy import policy_from_dict
from blotch.spans import Span, resolve_overlaps
from blotch.tokens import TokenRegistry
from blotch.vault import Vault


def test_partial_overlap_keeps_the_uncovered_remainder():
    # a higher-ranked span over PART of a name used to evict the whole name
    text = "Also Alejandro Martinez signed."
    spans = [Span(5, 23, EntityType.PERSON, "Alejandro Martinez", 0.5, "ner_heur"),
             Span(15, 23, EntityType.PERSON, "Martinez", 0.85, "spacy")]
    kept = resolve_overlaps(spans)
    covered = {text[s.start:s.end] for s in kept}
    assert "Martinez" in covered and "Alejandro" in covered


def test_remainder_is_trimmed_and_phone_runs_are_not_split():
    t = "Maria-Jose Gomez"
    kept = resolve_overlaps([Span(0, 16, EntityType.PERSON, t, 0.5, "h"),
                             Span(0, 5, EntityType.PERSON, "Maria", 0.85, "spacy")])
    assert [t[s.start:s.end] for s in kept] == ["Maria", "Jose Gomez"]
    # a greedy phone run that lost to an IP must not leave a "01" fragment
    t = "192.168.5.10 (01"
    kept = resolve_overlaps([Span(0, 16, EntityType.PHONE, t, 0.6, "phone"),
                             Span(0, 12, EntityType.IP, "192.168.5.10", 0.9, "ip")])
    assert [s.entity_type for s in kept] == [EntityType.IP]


def test_custom_recognizer_over_part_of_a_name_does_not_leak_the_rest():
    pol = get_policy("personal").with_recognizers(
        [Recognizer("x", r"Baker", EntityType.ACCOUNT_ID, confidence=0.99)])
    out = sanitize("Frank Baker called.", pol, use_spacy=False).sanitized_text
    assert "Frank" not in out


def test_iso_datetime_stays_one_date_and_time_keeps_spacing():
    r = sanitize("Admitted 2026-03-14T10:30:00 to ward 4.", get_policy("medical"),
                 use_spacy=False)
    assert "2026-03-14" not in r.sanitized_text
    assert "[[DATE_001]] to ward" in r.sanitized_text  # no "[[TIME_...]]to"
    r = sanitize("Seen at 10:30 today.", get_policy("medical"), use_spacy=False)
    assert "[[TIME_001]] today" in r.sanitized_text


def test_stray_double_bracket_does_not_block_restore():
    r = sanitize("Contact Alejandro Martinez today.", get_policy("personal"),
                 use_spacy=False)
    out = restore("Use [[ to open a wiki link. Then email [[PERSON_001]] please.", r.vault)
    assert "Alejandro Martinez" in out.text
    assert out.dropped == []


def test_ambiguous_shared_first_name_gets_its_own_token():
    # an undetected bare "Frank" could be either Frank; it must be hidden but
    # must not restore as "Frank Baker"
    text = "Frank Baker met Frank Cook. He was frank about it. Frank left early."
    r = sanitize(text, get_policy("personal"), use_spacy=False)
    assert "Frank left" not in r.sanitized_text
    assert restore(r.sanitized_text, r.vault).text == text


def test_shared_vault_values_are_recorded_as_edits():
    # a value from an earlier document in a shared vault, undetected in this
    # one, is now caught as a recorded edit (so preview/review show it)
    vault, reg = Vault(), TokenRegistry()
    sanitize("Mr Tan called.", get_policy("personal"), use_spacy=False,
             vault=vault, registry=reg)
    text = "Tan is tan today."
    r = sanitize(text, get_policy("personal"), use_spacy=False, vault=vault, registry=reg)
    assert r.sanitized_text.startswith("[[PERSON_001]]")
    assert any(text[s:e] == "Tan" for s, e, _ in r.edit_spans)


@pytest.mark.parametrize("bad, msg", [
    ({"group": True}, "not True"),
    ({"confidence": "high"}, "must be a number"),
    ({"confidence": True}, "must be a number"),
])
def test_recognizer_rejects_bool_and_string_values(bad, msg):
    rec = {"name": "g", "pattern": r"ID-(\d+)", "entity_type": "ACCOUNT_ID", **bad}
    with pytest.raises(ValueError, match=msg):
        policy_from_dict({"name": "c", "default": "tokenize", "recognizers": [rec]})


def test_duplicate_custom_policy_names_are_rejected(monkeypatch):
    import blotch.server as server
    monkeypatch.setattr(server, "_POLICIES", dict(server._POLICIES))
    from blotch.policy import Policy
    server.register_policies([Policy("acme")])
    with pytest.raises(ValueError, match="duplicate"):
        server.register_policies([Policy("acme")])


def test_negative_content_length_is_rejected_not_hung():
    # Raw socket, no body: urllib would still be sending one while the server
    # answers and closes, which Windows can report as ConnectionAbortedError.
    # If the bug returns, the server blocks reading and recv() times out.
    import socket
    import threading
    from http.server import ThreadingHTTPServer
    from blotch.server import _Handler
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]),
                                      timeout=5) as sock:
            sock.sendall(b"POST /sanitize HTTP/1.1\r\nHost: localhost\r\n"
                         b"Content-Type: application/json\r\n"
                         b"Content-Length: -1\r\n\r\n")
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)  # socket.timeout here == the hang
                if not chunk:
                    break
                resp += chunk
        status = resp.split(b"\r\n", 1)[0]
        assert b" 400 " in status, status
    finally:
        httpd.shutdown()
        httpd.server_close()


# -- found by the stricter full-coverage / SPriV metric --------------------------

def _exposed_within(text, secret, policy="maximum"):
    """Alphanumeric chars of ``secret`` (verbatim in ``text``) NOT replaced."""
    r = sanitize(text, get_policy(policy), use_spacy=False)
    mask = bytearray(len(text))
    for s, e, _ in r.edit_spans:
        mask[s:e] = b"\x01" * (e - s)
    i = text.index(secret)
    exposed = "".join(text[j] for j in range(i, i + len(secret))
                      if text[j].isalnum() and not mask[j])
    return r.sanitized_text, exposed


@pytest.mark.parametrize("text, secret", [
    ("Please provide your SSN132-65-3444 today.", "132-65-3444"),   # glued to label
    ("Routed through IP192.168.1.10 overnight.", "192.168.1.10"),
    ("Charge card4111111111111111 now.", "4111111111111111"),
    ("Pay to IBANGB82WEST12345698765432 today.", "GB82WEST12345698765432"),
    ("Delivered to Suite 786 downtown.", "786"),                    # unit number
    ("Use patient 756.1526.7359's record.", "756.1526.7359"),       # dotted labelled id
    ("Call us on +51.02.538 5609.", "51.02.538 5609"),              # not a date
    ("Born 1902-08-21T22:37:28.285Z here.", "1902-08-21T22:37:28.285Z"),
    ("MAC Address4e:b8:7f:2f:e4:72 on file.", "4e:b8:7f:2f:e4:72"),  # glued MAC
    ("Best regards, O'Hara.", "O'Hara"),                            # apostrophe name
    ("Represented by Mr H.İ. Er, a lawyer.", "H.İ. Er"),            # Unicode initial
])
def test_no_part_of_the_identifier_survives(text, secret):
    out, exposed = _exposed_within(text, secret)
    assert exposed == "", f"{exposed!r} of {secret!r} survived: {out!r}"


def test_card_does_not_swallow_the_following_space():
    out, _ = _exposed_within("card 4111 1111 1111 1111 exp soon", "4111")
    assert "[[CREDIT_CARD_001]] exp" in out


def test_impossible_numeric_date_is_not_a_date():
    from blotch.detectors import deterministic
    types = {s.entity_type for s in deterministic.detect("ref 51.02.538 here")}
    assert EntityType.DATE not in types
    types = {s.entity_type for s in deterministic.detect("on 14.03.2026 we met")}
    assert EntityType.DATE in types


def test_clock_time_is_not_an_ipv6_address():
    from blotch.detectors import deterministic
    types = {s.entity_type for s in deterministic.detect("at 10:30:00 sharp")}
    assert EntityType.IP not in types
