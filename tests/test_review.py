from censorbot.policy import get_policy
from censorbot.review import render_review_html

TEXT = "Alejandro Martinez, patient 48392017, a.martinez@example.com."


def test_review_masks_and_carries_metadata():
    out = render_review_html(TEXT, get_policy("medical"), use_spacy=False)
    assert "<html" in out and "</html>" in out
    # the mask block char is present
    assert "█" in out
    # tokens are exposed as data attributes for the tooltip
    assert 'data-token="[[PERSON_001]]"' in out
    assert "sensitive entities detected" in out


def test_review_escapes_html():
    out = render_review_html("Ping <script>alert(1)</script> team.",
                             get_policy("personal"), use_spacy=False)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_review_original_present_but_masked_by_default():
    out = render_review_html(TEXT, get_policy("medical"), use_spacy=False)
    # original is embedded (revealable) but inside an .orig span hidden by CSS
    assert 'class="orig"' in out
    assert "Alejandro Martinez" in out  # revealable, not sent
