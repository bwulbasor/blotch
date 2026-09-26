"""The name lexicon is shared, not copied, so layers can't drift apart."""

from blotch import lexicon
from blotch.detectors import ner
from blotch import resolver


def test_ner_uses_the_shared_lexicon_objects():
    # identity, not equality: ner must alias the lexicon, never keep a copy
    assert ner._TITLE_WORDS is lexicon.TITLE_WORDS
    assert ner._NON_NAME is lexicon.NON_NAME
    assert ner._PARTICLES is lexicon.PARTICLES


def test_resolver_strips_every_title_ner_recognises():
    for title in lexicon.TITLE_WORDS:
        for form in (title.capitalize(), title.capitalize() + "."):
            assert resolver._TITLE_RE.sub("", f"{form} Smith") == "Smith", form


def test_lexicon_sets_are_immutable():
    for name in ("TITLE_WORDS", "PARTICLES", "NON_NAME", "STOPWORDS",
                 "SENTENCE_OPENERS", "ORG_SUFFIX_WORDS"):
        assert isinstance(getattr(lexicon, name), frozenset), name
