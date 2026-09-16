from blotch.reidrisk import RiskLevel, assess


def test_no_quasi_identifiers_is_none():
    assert assess("The meeting is scheduled for next week.").level == RiskLevel.NONE


def test_single_category_is_low():
    r = assess("She is 47 years old.")
    assert r.level == RiskLevel.LOW
    assert "age" in r.categories


def test_multiple_categories_escalate():
    text = ("The 47-year-old CEO, the sole survivor of the 2024 crash, "
            "was diagnosed with a rare condition.")
    r = assess(text)
    assert r.level == RiskLevel.HIGH
    assert {"age", "occupation", "uniqueness", "sensitive-status"} <= r.categories


def test_sensitive_status_alone_is_at_least_medium():
    r = assess("The patient was diagnosed with cancer.")
    assert r.level == RiskLevel.MEDIUM


def test_advisory_language_present():
    r = assess("The 30-year-old director resigned.")
    assert "advisory" in r.summary() or "confirm" in r.summary()
