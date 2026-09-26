"""Interactive review + tagging page with a visible mapping table (plan §15).

Generates a self-contained HTML page (inline CSS/JS, no network) that renders the
original document with every detected entity highlighted, and lets the reviewer:

* see, live, the **mapping table** - each token and the original value it points
  to (the reversible pseudonym table);
* **click** a highlighted entity to keep it in the clear (un-mask it);
* **select any text and tag it** as PII the detectors missed (type picker);
* toggle tokens inline, and **build / copy** the sanitised text - all rebuilt in
  the browser from the reviewer's choices (nothing leaves the page).

The document shows the real text (all processing is local); the mapping table and
built output are what reveal the tokens.
"""

from __future__ import annotations

import html
import json

from .pipeline import sanitize
from .policy import Policy
from .reidrisk import RiskLevel, assess
from .spans import EntityType
from .templates import fill as fill_template
from .templates import load as load_template
from .tokens import parse_token

_COLORS = {
    "PERSON": "#d1495b", "EMAIL": "#00798c", "PHONE": "#2e86ab",
    "ADDRESS": "#8f5902", "DATE": "#6a4c93", "DOB": "#6a4c93",
    "ORGANIZATION": "#218380", "LOCATION": "#3d5a80", "IBAN": "#9a031e",
    "CREDIT_CARD": "#9a031e", "IP": "#5f0f40", "URL": "#0f4c5c",
    "GOV_ID": "#bb3e03", "PATIENT_ID": "#005f73", "CASE_ID": "#4a5759",
    "ACCOUNT_ID": "#582f0e", "MAC": "#7d4f00", "COORDINATES": "#1b4332",
    "CRYPTO": "#6d213c", "REDACT": "#333333",
}
_PICK_TYPES = [
    "PERSON", "EMAIL", "PHONE", "ADDRESS", "DATE", "ORGANIZATION", "LOCATION",
    "GOV_ID", "PATIENT_ID", "CASE_ID", "ACCOUNT_ID", "IBAN", "CREDIT_CARD", "IP",
    "CRYPTO", "REDACT",
]


def render_review_html(text: str, policy: Policy, *, use_spacy: bool = True,
                       title: str = "blotch review") -> str:
    """Return a standalone interactive review/tagging page with a mapping table."""

    result = sanitize(text, policy, use_spacy=use_spacy)
    auto_spans = []
    confs = result.edit_confidence or [1.0] * len(result.edit_spans)
    for (start, end, replacement), conf in zip(result.edit_spans, confs):
        parsed = parse_token(replacement)
        etype = parsed[0] if parsed else "REDACT"
        # carry the pipeline's token so co-reference (same entity -> same token,
        # via resolution + propagation) is preserved in the page, instead of being
        # re-derived by exact surface value. `conf` lets the page flag shaky
        # detections (a lone-word guess) apart from checksum-solid structural ones.
        auto_spans.append({"start": start, "end": end, "type": etype,
                           "token": replacement, "conf": round(conf, 2)})

    risk = assess(result.sanitized_text)
    leak_clean = result.leak_report.clean if result.leak_report else True
    risk_class = {RiskLevel.NONE: "ok", RiskLevel.LOW: "low",
                  RiskLevel.MEDIUM: "med", RiskLevel.HIGH: "high"}[risk.level]
    risk_banner = (
        f'<div class="risk {risk_class}"><strong>Re-ID risk: {risk.level.value.upper()}'
        f'</strong> — {html.escape(risk.summary())}</div>' if risk.level != RiskLevel.NONE
        else '<div class="risk ok"><strong>Re-ID risk: none detected</strong> (advisory)</div>'
    )
    leak_banner = (
        '<div class="risk ok"><strong>Leak scan: clean</strong></div>' if leak_clean else
        f'<div class="risk high"><strong>Leak scan: BLOCKED</strong> — '
        f'{html.escape(result.leak_report.summary())}</div>'
    )

    def esc_js(obj) -> str:
        return json.dumps(obj).replace("<", "\\u003c").replace("</", "<\\/")

    return fill_template(_TEMPLATE, {
        "TITLE": html.escape(title), "POLICY": html.escape(policy.name),
        "RISK_BANNER": risk_banner, "LEAK_BANNER": leak_banner,
        "ORIGINAL_JSON": esc_js(text), "AUTO_JSON": esc_js(auto_spans),
        "COLORS_JSON": esc_js(_COLORS), "TYPES_JSON": esc_js(_PICK_TYPES),
    })


# The page lives in templates/review.html as plain HTML/CSS/JS (no brace
# doubling), with @@NAME@@ slots filled in one pass.
_TEMPLATE = load_template("review.html")
