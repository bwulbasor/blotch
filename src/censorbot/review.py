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
                       title: str = "censorbot review") -> str:
    """Return a standalone interactive review/tagging page with a mapping table."""

    result = sanitize(text, policy, use_spacy=use_spacy)
    auto_spans = []
    for start, end, replacement in result.edit_spans:
        parsed = parse_token(replacement)
        etype = parsed[0] if parsed else "REDACT"
        auto_spans.append({"start": start, "end": end, "type": etype})

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

    return _TEMPLATE.format(
        title=html.escape(title), policy=html.escape(policy.name),
        risk_banner=risk_banner, leak_banner=leak_banner,
        original_json=esc_js(text), auto_json=esc_js(auto_spans),
        colors_json=esc_js(_COLORS), types_json=esc_js(_PICK_TYPES),
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.65 system-ui, sans-serif; margin: 0; background: #fafafa;
          color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{ body {{ background:#16181c; color:#e8e8e8; }}
    header,.doc,.panel,.out,table {{ background:#1f2228 !important; }}
    td,th {{ border-color:#333 !important; }} }}
  header {{ position: sticky; top: 0; z-index: 20; background: #fff;
    border-bottom: 1px solid #0002; padding: 12px 20px; display: flex; gap: 10px;
    align-items: center; flex-wrap: wrap; }}
  h1 {{ font-size: 15px; margin: 0; font-weight: 700; }}
  .count {{ font-weight: 700; }} .spacer {{ flex: 1; }}
  .kept-note {{ color:#9a031e; font-weight:700; font-size:13px; }}
  button {{ font: inherit; padding: 7px 11px; border-radius: 8px; cursor: pointer;
    border: 1px solid #0003; background: #f0f0f0; }}
  button.primary {{ background: #218380; color: #fff; border-color: #218380; }}
  button.on {{ background:#3d5a80; color:#fff; border-color:#3d5a80; }}
  .banners {{ display:flex; gap:8px; flex-wrap:wrap; padding:8px 20px; }}
  .risk {{ font-size:13px; padding:6px 12px; border-radius:8px; }}
  .risk.ok{{background:#1e7d3322}} .risk.low{{background:#b8860022}}
  .risk.med{{background:#d9640022}} .risk.high{{background:#9a031e22}}
  .hint {{ padding: 4px 20px; color:#888; font-size:12.5px; }}
  .wrap {{ display:flex; gap:14px; align-items:flex-start; max-width:1200px;
    margin: 12px auto; padding: 0 16px; flex-wrap: wrap; }}
  .doc {{ flex: 1 1 520px; padding: 24px 28px; background:#fff; border:1px solid #0001;
    border-radius:12px; white-space: pre-wrap; word-wrap: break-word; }}
  .panel {{ flex: 1 1 340px; padding: 14px 16px; background:#fff; border:1px solid #0001;
    border-radius:12px; position: sticky; top: 64px; max-height: 82vh; overflow:auto; }}
  .panel h3 {{ margin: .2em 0 .5em; font-size:14px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12.5px; }}
  th, td {{ border: 1px solid #0001; padding: 4px 7px; text-align: left; vertical-align: top; }}
  th {{ font-weight: 700; }}
  code {{ font: 12px ui-monospace, monospace; }}
  .tok {{ font: 11px ui-monospace, monospace; color: var(--c); font-weight:700; }}
  .ent {{ border-radius:4px; padding:0 1px; cursor:pointer;
    box-shadow: inset 0 -2px 0 var(--c);
    background: color-mix(in srgb, var(--c) 16%, transparent); }}
  .ent.kept {{ background: transparent; box-shadow:none; text-decoration: line-through;
    text-decoration-color:#9a031e; opacity:.6; }}
  .ent.user {{ box-shadow: inset 0 -2px 0 var(--c), 0 0 0 1px var(--c); }}
  body.showtok .ent::after {{ content: attr(data-tok); font: 10px ui-monospace,monospace;
    color: var(--c); vertical-align: super; margin-left: 1px; }}
  #picker {{ position:absolute; z-index:30; background:#111; color:#fff; padding:6px;
    border-radius:8px; box-shadow:0 4px 16px #0006; display:none; max-width:320px; }}
  #picker button {{ background:#333; color:#fff; border:0; margin:2px; font-size:12px; padding:4px 7px; }}
  .out {{ max-width:1200px; margin:12px auto; padding:16px 20px; background:#fff;
    border:1px solid #0001; border-radius:12px; }}
  .out pre {{ white-space:pre-wrap; word-wrap:break-word; font:13px/1.5 ui-monospace,monospace; }}
  footer {{ text-align:center; color:#888; font-size:12px; padding:18px; }}
</style></head><body>
<header>
  <h1>censorbot review</h1>
  <span><span class="count" id="mcount">0</span> to mask · policy <strong>{policy}</strong></span>
  <span id="kept-note" class="kept-note"></span>
  <span class="spacer"></span>
  <button id="toktoggle">Tokens inline</button>
  <button id="copy" class="primary">Copy sanitized</button>
</header>
<div class="banners">{leak_banner}{risk_banner}</div>
<div class="hint">Click a highlight to <b>keep it in the clear</b>. <b>Select any text</b>
to tag PII the detector missed. The <b>mapping</b> on the right shows what each token
points to. Everything stays in this page.</div>
<div class="wrap">
  <div class="doc" id="doc"></div>
  <div class="panel">
    <h3>Mapping — token → original <span id="mapn" style="color:#888;font-weight:400"></span></h3>
    <table><thead><tr><th>Token</th><th>Points to</th><th>Type</th></tr></thead>
      <tbody id="maprows"></tbody></table>
  </div>
</div>
<div id="picker"></div>
<div class="out" id="outwrap" hidden><h3 style="margin:.2em 0">Sanitized output (what leaves your device)</h3>
  <pre id="out"></pre></div>
<footer>All local. The mapping never leaves this page; only the sanitized output would be sent.</footer>
<script>
  const ORIGINAL = {original_json};
  const AUTO = {auto_json};
  const COLORS = {colors_json};
  const TYPES = {types_json};
  const color = t => COLORS[t] || "#555";
  const state = {{ spans: AUTO.map(s => ({{...s, user:false, kept:false}})) }};
  const doc = document.getElementById('doc');
  const picker = document.getElementById('picker');
  const esc = s => s.replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));
  const pad = n => String(n).padStart(3,'0');

  // Assign a token per active (non-kept) span; same (type,value) -> same token.
  function computeTokens() {{
    const act = state.spans.filter(s=>!s.kept).slice().sort((a,b)=>a.start-b.start);
    const counters={{}}, map={{}}, rows=[], spanTok=new Map();
    let pos=-1;
    for (const s of act) {{
      if (s.start < pos) {{ spanTok.set(s,null); continue; }}
      const val = ORIGINAL.slice(s.start, s.end);
      let tok;
      if (s.type === 'REDACT') tok = '[REDACTED]';
      else {{
        const key = s.type + '|' + val.trim().toLowerCase().replace(/\\s+/g,' ');
        if (map[key]) tok = map[key];
        else {{ counters[s.type] = (counters[s.type]||0)+1;
          tok = '[[' + s.type + '_' + pad(counters[s.type]) + ']]'; map[key] = tok;
          rows.push({{token: tok, value: val, type: s.type}}); }}
      }}
      spanTok.set(s, tok); pos = s.end;
    }}
    return {{spanTok, rows}};
  }}

  function render() {{
    const {{spanTok, rows}} = computeTokens();
    const act = state.spans.slice().sort((a,b)=>a.start-b.start);
    let html='', pos=0;
    for (const s of act) {{
      if (s.start < pos) continue;
      html += esc(ORIGINAL.slice(pos, s.start));
      const idx = state.spans.indexOf(s);
      const tok = spanTok.get(s) || '';
      const cls = 'ent' + (s.kept?' kept':'') + (s.user?' user':'');
      html += `<span class="${{cls}}" data-idx="${{idx}}" data-tok="${{esc(tok)}}" `
        + `style="--c:${{color(s.type)}}" title="${{s.type}}${{s.user?' (you)':''}} `
        + `${{s.kept?'— kept':'→ '+tok}} · click to ${{s.kept?'mask':'keep'}}">`
        + esc(ORIGINAL.slice(s.start, s.end)) + '</span>';
      pos = s.end;
    }}
    html += esc(ORIGINAL.slice(pos));
    doc.innerHTML = html;
    // mapping table
    document.getElementById('maprows').innerHTML = rows.map(r =>
      `<tr><td><span class="tok" style="--c:${{color(r.type)}}">${{esc(r.token)}}</span></td>`
      + `<td>${{esc(r.value)}}</td><td>${{esc(r.type)}}</td></tr>`).join('')
      || '<tr><td colspan=3 style="color:#888">nothing masked</td></tr>';
    document.getElementById('mapn').textContent = '(' + rows.length + ')';
    const masked = state.spans.filter(s=>!s.kept).length;
    const kept = state.spans.filter(s=>s.kept).length;
    document.getElementById('mcount').textContent = masked;
    document.getElementById('kept-note').textContent = kept ? ('⚠ '+kept+' kept in the clear') : '';
  }}

  doc.addEventListener('click', e => {{
    const el = e.target.closest('.ent'); if (!el) return;
    const s = state.spans[+el.dataset.idx];
    if (s.user && s.kept) state.spans.splice(state.spans.indexOf(s),1);
    else s.kept = !s.kept;
    render();
  }});

  function offsetOf(node, off) {{
    const r = document.createRange();
    r.selectNodeContents(doc); r.setEnd(node, off);
    return r.toString().length;
  }}

  doc.addEventListener('mouseup', () => {{
    const sel = window.getSelection();
    if (!sel.rangeCount || sel.isCollapsed) {{ picker.style.display='none'; return; }}
    const r = sel.getRangeAt(0);
    if (!doc.contains(r.commonAncestorContainer)) return;
    let a = offsetOf(r.startContainer, r.startOffset);
    let b = offsetOf(r.endContainer, r.endOffset);
    if (a > b) [a,b] = [b,a];
    if (b - a < 1) {{ picker.style.display='none'; return; }}
    const rect = r.getBoundingClientRect();
    picker.innerHTML = '<div style="font-size:11px;margin:2px 4px;opacity:.8">Tag "'
      + esc(ORIGINAL.slice(a,b).slice(0,30)) + '" as:</div>'
      + TYPES.map(t=>`<button data-t="${{t}}">${{t}}</button>`).join('');
    picker.style.left = (window.scrollX + rect.left) + 'px';
    picker.style.top  = (window.scrollY + rect.bottom + 4) + 'px';
    picker.style.display = 'block';
    picker.dataset.a = a; picker.dataset.b = b;
  }});

  picker.addEventListener('click', e => {{
    const btn = e.target.closest('button'); if (!btn) return;
    state.spans.push({{start:+picker.dataset.a, end:+picker.dataset.b,
      type:btn.dataset.t, user:true, kept:false}});
    picker.style.display = 'none';
    window.getSelection().removeAllRanges();
    render();
  }});
  document.addEventListener('mousedown', e => {{
    if (!picker.contains(e.target) && !e.target.closest('.ent')) picker.style.display='none';
  }});

  function buildOutput() {{
    const {{spanTok}} = computeTokens();
    const act = state.spans.filter(s=>!s.kept).slice().sort((a,b)=>a.start-b.start);
    let out='', pos=0;
    for (const s of act) {{
      if (s.start < pos) continue;
      out += ORIGINAL.slice(pos, s.start) + (spanTok.get(s) || '');
      pos = s.end;
    }}
    return out + ORIGINAL.slice(pos);
  }}

  document.getElementById('toktoggle').onclick = (e) => {{
    document.body.classList.toggle('showtok');
    e.target.classList.toggle('on', document.body.classList.contains('showtok'));
  }};
  document.getElementById('copy').onclick = async () => {{
    const txt = buildOutput();
    document.getElementById('out').textContent = txt;
    document.getElementById('outwrap').hidden = false;
    try {{ await navigator.clipboard.writeText(txt);
      const b=document.getElementById('copy'); b.textContent='Copied ✓';
      setTimeout(()=>b.textContent='Copy sanitized',1500);
    }} catch(e) {{}}
  }};
  render();
</script>
</body></html>"""
