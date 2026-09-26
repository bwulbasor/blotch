"""Packaged HTML templates and the single-pass slot filler."""

import pytest

from blotch.templates import fill, load


def test_templates_load():
    assert "@@ORIGINAL_JSON@@" in load("review.html")
    assert "<title>" in load("ui.html")


def test_fill_is_single_pass():
    # a value that looks like another slot must NOT be substituted again
    out = fill("@@A@@|@@B@@", {"A": "@@B@@", "B": "b"})
    assert out == "@@B@@|b"


def test_fill_rejects_missing_values():
    with pytest.raises(KeyError, match="MISSING"):
        fill("x @@MISSING@@ y", {})


def test_review_template_has_no_doubled_braces():
    # the point of moving it out of a str.format template: plain JS/CSS
    assert "{{" not in load("review.html")
