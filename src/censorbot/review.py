"""The review preview: show the user what will be hidden *before* sending (plan §15).

Generates a self-contained HTML page (inline CSS/JS, no network) that renders the
document with every sensitive span masked. Each mask is clickable and reveals its
type, detector confidence and the token it will become; a toggle reveals the
originals. This builds trust far better than silently transforming the document.
"""

from __future__ import annotations

import html
import json

from .detectors import detect_all
from .policy import Action, Policy
from .resolver import resolve
from .spans import EntityType, resolve_overlaps
from .tokens import make_token

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

    spans = resolve_overlaps(detect_all(text, use_spacy=use_spacy))
    entities = resolve(spans)

    # Map each member span -> (token, entity) for spans the policy acts on.
    marked: list[tuple[int, int, str, str, str, float]] = []
    counts: dict[str, int] = {}
    for ent in entities:
        action = policy.action_for(ent.entity_type)
        if action == Action.KEEP:
            continue
        token = ("[REDACTED]" if action == Action.REDACT
                 else make_token(ent.entity_type, ent.index))
        counts[ent.entity_type.value] = counts.get(ent.entity_type.value, 0) + 1
        conf = max((s.confidence for s in ent.members), default=0.0)
        for s in ent.members:
            marked.append((s.start, s.end, ent.entity_type.value, token, s.value, conf))
    marked.sort(key=lambda m: m[0])

    # Build the annotated body, escaping the non-sensitive text between spans.
    parts: list[str] = []
    cursor = 0
    for start, end, etype, token, value, conf in marked:
        if start < cursor:
            continue  # safety: skip any residual overlap
        parts.append(html.escape(text[cursor:start]))
        color = _COLORS.get(EntityType(etype), _DEFAULT_COLOR)
        parts.append(
            f'<span class="pii" style="--c:{color}" '
            f'data-type="{html.escape(etype)}" data-token="{html.escape(token)}" '
            f'data-conf="{conf:.0%}" data-orig="{html.escape(value)}" tabindex="0">'
            f'<span class="mask">{"█" * min(len(value), 14)}</span>'
            f'<span class="orig">{html.escape(value)}</span></span>'
        )
        cursor = end
    parts.append(html.escape(text[cursor:]))
    body = "".join(parts)

    total = sum(counts.values())
    legend = "".join(
        f'<span class="chip" style="--c:{_COLORS.get(EntityType(t), _DEFAULT_COLOR)}">'
        f'{html.escape(t)} · {n}</span>'
        for t, n in sorted(counts.items())
    )
    return _TEMPLATE.format(
        title=html.escape(title), policy=html.escape(policy.name),
        total=total, legend=legend, body=body,
        counts_json=html.escape(json.dumps(counts)),
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
  .pii:hover::after, .pii:focus::after {{
     content: attr(data-type) " → " attr(data-token) "  (" attr(data-conf) ")";
     position: absolute; left: 0; top: 1.7em; z-index: 5; white-space: nowrap;
     background: #111; color: #fff; font-size: 12px; padding: 4px 8px;
     border-radius: 6px; box-shadow: 0 2px 8px #0004; }}
  footer {{ text-align: center; color: #888; font-size: 12px; padding: 20px; }}
</style></head><body>
<header>
  <h1>censorbot</h1>
  <span><span class="count">{total}</span> sensitive entities detected · policy
  <strong>{policy}</strong></span>
  <span class="spacer"></span>
  <button id="toggle">Reveal originals</button>
  <button class="primary" id="send" title="In a real client this transmits the masked version">
    Send sanitized version</button>
</header>
<div class="legend">{legend}</div>
<div class="doc">{body}</div>
<footer>All detection ran locally. Only the masked tokens would leave your device.</footer>
<script>
  const b = document.body, t = document.getElementById('toggle');
  t.onclick = () => {{ b.classList.toggle('reveal');
    t.textContent = b.classList.contains('reveal') ? 'Hide originals' : 'Reveal originals'; }};
  document.getElementById('send').onclick = () =>
    alert('Demo: a real client would transmit the masked document only.');
</script>
</body></html>"""
