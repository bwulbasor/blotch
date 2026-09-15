import re

from censorbot.policy import get_policy
from censorbot.review import render_review_html

TEXT = "Alejandro Martinez, patient 48392017, a.martinez@example.com."


def test_review_renders_and_embeds_data():
    out = render_review_html(TEXT, get_policy("medical"), use_spacy=False)
    assert "<html" in out and "</html>" in out
    assert "const ORIGINAL" in out and "const AUTO" in out
    assert "policy" in out
    # the original text is embedded (all local) and detected entities are marked
    assert "Alejandro Martinez" in out
    assert 'data-idx=' in out


def test_review_escapes_html_in_body():
    # rendered doc text is escaped
    out = render_review_html("Ping <script>alert(1)</script> team.",
                             get_policy("personal"), use_spacy=False)
    assert "<script>alert(1)</script>" not in out


def test_review_script_embed_cannot_break_out():
    # a "</script>" in the embedded ORIGINAL/AUTO JSON must not break out
    out = render_review_html("note </script><img src=x onerror=alert(1)>",
                             get_policy("personal"), use_spacy=False)
    assert "</script><img" not in out


def test_review_is_interactive_tagging():
    out = render_review_html("Contact Maria Gomez at a@b.com.", get_policy("maximum"),
                             use_spacy=False)
    # the client-side engine: build output, tag by selection, keep/mask
    assert "buildOutput" in out
    assert "offsetOf" in out           # selection -> char offset (manual tagging)
    assert "picker" in out             # type picker for tagging missed PII


def test_review_has_risk_and_leak_banners():
    out = render_review_html("Contact a@b.com in Berlin.", get_policy("personal"),
                             use_spacy=False)
    assert "Leak scan" in out and "Re-ID risk" in out


def test_review_auto_spans_have_correct_offsets():
    # AUTO spans must index the original text correctly (so JS highlights align)
    import json
    text = "Email a.martinez@example.com now."
    out = render_review_html(text, get_policy("personal"), use_spacy=False)
    m = re.search(r"const AUTO = (\[.*?\]);", out)
    spans = json.loads(m.group(1).replace("\\u003c", "<"))
    assert spans, "expected at least one detected span"
    # every span slices to real text
    for s in spans:
        assert text[s["start"]:s["end"]]  # non-empty, valid offsets
    assert any(text[s["start"]:s["end"]] == "a.martinez@example.com" for s in spans)
