"""End-to-end: the full gateway loop against a provider that behaves like a real
model — it paraphrases and reformats the tokens (spaces, markdown, escapes)."""

import re

from blotch import Gateway, get_policy

DOC = (
    "DISCHARGE SUMMARY\n"
    "Patient: Alejandro Martinez (DOB 12 April 1978)\n"
    "Patient number: 48392017\n"
    "Treated by Dr. Sabine Keller at Vienna General Hospital.\n"
    "Billing: a.martinez@example.com, IBAN GB82 WEST 1234 5698 7654 32.\n"
    "Emergency contact: Maria Gomez, +43 660 1234567. Home: 221 Baker Street.\n"
)


def _reformatting_model(sanitized: str) -> str:
    """A stand-in model: it never sees real PII, echoes a 'summary' that reformats
    the tokens the way a real LLM might (adds spaces, bolds, escapes some)."""
    tokens = re.findall(r"\[\[[A-Z_]+_\d{3,}\]\]", sanitized)
    lines = ["Summary of the record:"]
    for i, tok in enumerate(tokens):
        if i % 3 == 0:
            inner = tok[2:-2]
            tok = f"[[ {inner} ]]"          # internal spaces
        elif i % 3 == 1:
            tok = f"**{tok}**"               # markdown bold
        lines.append(f"- reference {tok}")
    return "\n".join(lines)


def test_full_loop_recovers_originals_despite_reformatting():
    gw = Gateway(get_policy("medical"), _reformatting_model, use_spacy=False)
    result = gw.run(DOC)

    # nothing sensitive ever reached the provider
    for secret in ("Alejandro Martinez", "48392017", "a.martinez@example.com",
                   "GB82 WEST 1234 5698 7654 32", "+43 660 1234567"):
        assert secret not in result.sanitized
        assert secret not in result.response

    # the outbound scan was clean and the reformatted tokens still rehydrated
    assert result.leak_report.clean
    restored = result.restored
    assert "Alejandro Martinez" in restored
    assert "48392017" in restored
    assert "Vienna General Hospital" in restored
    # no invented tokens, and no leftover token markup in the restored text
    assert result.restore_result.invented == []
    assert "[[" not in restored
