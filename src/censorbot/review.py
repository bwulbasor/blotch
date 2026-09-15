"""The review preview: show the user what will be hidden *before* sending (plan §15).

Generates a self-contained HTML page (inline CSS/JS, no network) that renders the
document with every sensitive span masked. Each mask is clickable and reveals its
type, detector confidence and the token it will become; a toggle reveals the
originals. This builds trust far better than silently transforming the document.
"""

from __future__ import annotations

import html
import json

from .pipeline import sanitize
from .policy import Policy
from .reidrisk import RiskLevel, assess
from .spans import EntityType
from .tokens import parse_token

# A colour-blind-safe-ish palette keyed by type family.
_COLORS = {
    EntityType.PERSON: "#d1495b", EntityType.EMAIL: "#00798c",
    EntityType.PHONE: "#2e86ab", EntityType.ADDRESS: "#8f5902",
    EntityType.DATE: "#6a4c93", EntityType.DOB: "#6a4c93",
    EntityType.ORGANIZATION: "#218380", EntityType.LOCATION: "#3d5a80",
    EntityType.IBAN: "#9a031e", EntityType.CREDIT_CARD: "#9a031e",
    EntityType.IP: "#5f0f40", EntityType.URL: "#0f4c5c",
    EntityType.GOV_ID: "#bb3e03", EntityType.PATIENT_ID: "#005f73",
    EntityType.CASE_ID: "#4a5759", EntityType.ACCOUNT_ID: "#582f0e",
}
_DEFAULT_COLOR = "#555"


def render_review_html(text: str, policy: Policy, *, use_spacy: bool = True,
                       title: str = "censorbot review") -> str:
    """Return a standalone HTML review page for ``text`` under ``policy``."""

    # One sanitisation pass drives everything: the masked body is built from the
    # *actual* edit spans (propagation included), so the preview matches the
    # outbound document exactly rather than diverging from it.
    result = sanitize(text, policy, use_spacy=use_spacy)
    sanitized = result.sanitized_text

    # Build ordered segments (literal text + pii) so the page can rebuild the
    # outbound text in the browser as the reviewer keeps/masks individual items.
    counts: dict[str, int] = {}
    segments: list[dict] = []
    parts: list[str] = []
    cursor = 0
    idx = 0
    for start, end, replacement in result.edit_spans:
        if start < cursor:
            continue  # safety: skip any residual overlap
        parsed = parse_token(replacement)
        etype = parsed[0] if parsed else "REDACTED"
        counts[etype] = counts.get(etype, 0) + 1
        value = text[start:end]
        try:
            color = _COLORS.get(EntityType(etype), _DEFAULT_COLOR)
        except ValueError:
            color = _DEFAULT_COLOR
        if cursor < start:
            segments.append({"t": "lit", "v": text[cursor:start]})
        segments.append({"t": "pii", "tok": replacement, "orig": value})
        parts.append(html.escape(text[cursor:start]))
        parts.append(
            f'<span class="pii" data-idx="{idx}" style="--c:{color}" '
            f'data-type="{html.escape(etype)}" data-token="{html.escape(replacement)}" '
            f'tabindex="0" role="button" '
            f'title="click to keep this in the clear">'
            f'<span class="mask">{"█" * min(len(value), 14)}</span>'
            f'<span class="orig">{html.escape(value)}</span></span>'
        )
        idx += 1
        cursor = end
    if cursor < len(text):
        segments.append({"t": "lit", "v": text[cursor:]})
    parts.append(html.escape(text[cursor:]))
    body = "".join(parts)

    total = sum(counts.values())
    legend = "".join(
        f'<span class="chip" style="--c:{_COLORS.get(EntityType(t), _DEFAULT_COLOR) if t != "REDACTED" else _DEFAULT_COLOR}">'
        f'{html.escape(t)} · {n}</span>'
        for t, n in sorted(counts.items())
    )

    risk = assess(sanitized)
    leak_clean = result.leak_report.clean if result.leak_report else True
    risk_class = {RiskLevel.NONE: "ok", RiskLevel.LOW: "low",
                  RiskLevel.MEDIUM: "med", RiskLevel.HIGH: "high"}[risk.level]
    risk_banner = (
        f'<div class="risk {risk_class}"><strong>Re-ID risk: {risk.level.value.upper()}'
        f'</strong> — {html.escape(risk.summary())}</div>' if risk.level != RiskLevel.NONE
        else '<div class="risk ok"><strong>Re-ID risk: none detected</strong> '
        '(advisory only)</div>'
    )
    leak_banner = (
        '<div class="risk ok"><strong>Leak scan: clean</strong> — safe to send</div>'
        if leak_clean else
        f'<div class="risk high"><strong>Leak scan: BLOCKED</strong> — '
        f'{html.escape(result.leak_report.summary())}</div>'
    )

    return _TEMPLATE.format(
        title=html.escape(title), policy=html.escape(policy.name),
        total=total, legend=legend, body=body,
        risk_banner=risk_banner, leak_banner=leak_banner,
        # Escape "<" so embedded data can't break out of the <script> block
        # (a "</script>" in the data) or inject markup.
        segments_json=json.dumps(segments).replace("<", "\\u003c"),
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.6 system-ui, sans-serif; margin: 0; background: #fafafa;
          color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{ body {{ background:#16181c; color:#e8e8e8; }}
    header, .doc {{ background:#1f2228 !important; }} }}
  header {{ position: sticky; top: 0; background: #fff; border-bottom: 1px solid #0002;
           padding: 14px 20px; display: flex; gap: 14px; align-items: center;
           flex-wrap: wrap; }}
  h1 {{ font-size: 15px; margin: 0; font-weight: 700; }}
  .count {{ font-weight: 700; color: #9a031e; }}
  .kept-note {{ font-weight: 700; color: #9a031e; font-size: 13px; }}
  .spacer {{ flex: 1; }}
  button {{ font: inherit; padding: 6px 12px; border-radius: 8px; cursor: pointer;
           border: 1px solid #0003; background: #f0f0f0; }}
  button.primary {{ background: #218380; color: #fff; border-color: #218380; }}
  .legend {{ display: flex; gap: 6px; flex-wrap: wrap; padding: 8px 20px; }}
  .chip {{ font-size: 12px; padding: 2px 8px; border-radius: 20px; color: #fff;
          background: var(--c); }}
  .doc {{ max-width: 820px; margin: 20px auto; padding: 28px 32px; background: #fff;
         border: 1px solid #0001; border-radius: 12px; white-space: pre-wrap;
         word-wrap: break-word; }}
  .pii {{ border-radius: 4px; padding: 0 2px; cursor: pointer; position: relative;
         outline: none; }}
  .pii .mask {{ color: var(--c); background: color-mix(in srgb, var(--c) 18%, transparent);
               border-bottom: 2px solid var(--c); letter-spacing: -1px; }}
  .pii .orig {{ display: none; background: color-mix(in srgb, var(--c) 14%, transparent);
               border-bottom: 2px dashed var(--c); }}
  body.reveal .pii .mask {{ display: none; }}
  body.reveal .pii .orig {{ display: inline; }}
  /* a "kept" entity will be sent in the clear: show the original, struck-through
     styling to warn, regardless of the global reveal toggle. */
  .pii.kept .mask {{ display: none; }}
  .pii.kept .orig {{ display: inline; background: #9a031e22;
                    border-bottom: 2px solid #9a031e; }}
  .pii:hover::after, .pii:focus::after {{
     content: attr(data-type) " → " attr(data-token);
     position: absolute; left: 0; top: 1.7em; z-index: 5; white-space: nowrap;
     background: #111; color: #fff; font-size: 12px; padding: 4px 8px;
     border-radius: 6px; box-shadow: 0 2px 8px #0004; }}
  .banners {{ display: flex; flex-wrap: wrap; gap: 8px; padding: 8px 20px; }}
  .risk {{ font-size: 13px; padding: 6px 12px; border-radius: 8px; flex: 1 1 280px; }}
  .risk.ok {{ background: #1e7d3322; border: 1px solid #1e7d3366; }}
  .risk.low {{ background: #b8860022; border: 1px solid #b8860066; }}
  .risk.med {{ background: #d9640022; border: 1px solid #d9640088; }}
  .risk.high {{ background: #9a031e22; border: 1px solid #9a031e88; }}
  footer {{ text-align: center; color: #888; font-size: 12px; padding: 20px; }}
</style></head><body>
<header>
  <h1>censorbot</h1>
  <span><span class="count">{total}</span> detected · policy <strong>{policy}</strong></span>
  <span id="kept-note" class="kept-note"></span>
  <span class="spacer"></span>
  <button id="toggle">Reveal originals</button>
  <button id="reset" hidden>Mask all</button>
  <button class="primary" id="copy">Copy sanitized text</button>
</header>
<div class="banners">{leak_banner}{risk_banner}</div>
<div class="legend">{legend}</div>
<div class="doc">{body}</div>
<footer>Click any entity to keep it in the clear. All detection ran locally;
only what you leave masked stays hidden from the external service.</footer>
<script>
  const SEGMENTS = {segments_json};
  const b = document.body, t = document.getElementById('toggle');
  const reset = document.getElementById('reset'), note = document.getElementById('kept-note');
  const kept = new Set();

  function refresh() {{
    note.textContent = kept.size
      ? '⚠ ' + kept.size + ' will be sent in the CLEAR' : '';
    reset.hidden = kept.size === 0;
  }}
  // Clicking a pii toggles whether it is kept (sent as the original).
  document.querySelectorAll('.pii').forEach(el => {{
    const idx = +el.dataset.idx;
    const toggle = () => {{ el.classList.toggle('kept');
      if (el.classList.contains('kept')) kept.add(idx); else kept.delete(idx);
      refresh(); }};
    el.addEventListener('click', toggle);
    el.addEventListener('keydown', e => {{ if (e.key === 'Enter' || e.key === ' ')
      {{ e.preventDefault(); toggle(); }} }});
  }});
  reset.onclick = () => {{ kept.clear();
    document.querySelectorAll('.pii.kept').forEach(el => el.classList.remove('kept'));
    refresh(); }};
  t.onclick = () => {{ b.classList.toggle('reveal');
    t.textContent = b.classList.contains('reveal') ? 'Hide originals' : 'Reveal originals'; }};

  // Rebuild the outbound text honouring the reviewer's keep choices.
  function buildOutput() {{
    let piiIdx = 0, out = '';
    for (const seg of SEGMENTS) {{
      if (seg.t === 'lit') {{ out += seg.v; }}
      else {{ out += kept.has(piiIdx) ? seg.orig : seg.tok; piiIdx++; }}
    }}
    return out;
  }}
  const copy = document.getElementById('copy');
  copy.onclick = async () => {{
    const text = buildOutput();
    try {{ await navigator.clipboard.writeText(text);
      copy.textContent = 'Copied ✓'; setTimeout(() => copy.textContent = 'Copy sanitized text', 1500);
    }} catch (e) {{ alert('Text to send:\\n\\n' + text); }}
  }};
</script>
</body></html>"""
