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
                       title: str = "blotch review") -> str:
    """Return a standalone interactive review/tagging page with a mapping table."""

    result = sanitize(text, policy, use_spacy=use_spacy)
    auto_spans = []
    for start, end, replacement in result.edit_spans:
        parsed = parse_token(replacement)
        etype = parsed[0] if parsed else "REDACT"
        # carry the pipeline's token so co-reference (same entity -> same token,
        # via resolution + propagation) is preserved in the page, instead of being
        # re-derived by exact surface value.
        auto_spans.append({"start": start, "end": end, "type": etype,
                           "token": replacement})

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
  <h1>blotch review</h1>
  <span><span class="count" id="mcount">0</span> to mask · policy <strong>{policy}</strong></span>
  <span id="kept-note" class="kept-note"></span>
  <span class="spacer"></span>
  <label>Mode
    <select id="mode" title="how to censor">
      <option value="semantic" selected>Semantic tokens (reversible)</option>
      <option value="synthetic">Synthetic substitution (realistic fakes)</option>
      <option value="generalize">Generalize (less specific)</option>
      <option value="total">Total redaction ([REDACTED])</option>
      <option value="blackout">Blackout (████)</option>
    </select></label>
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
    <h3 id="maptitle">Mapping — token → original <span id="mapn" style="color:#888;font-weight:400"></span></h3>
    <div id="revnote" style="font-size:12px;margin-bottom:6px"></div>
    <table><thead><tr><th id="thtok">Token</th><th>Original</th><th>Type</th></tr></thead>
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

  const norm = v => v.trim().toLowerCase().replace(/\\s+/g,' ');
  function mode() {{ return document.getElementById('mode').value; }}
  const REVERSIBLE = {{semantic:1, synthetic:1}};

  // --- synthetic substitution: realistic fakes, consistent per (type,value) ---
  const F1 = ['Daniel','Sarah','Michael','Laura','Thomas','Anna','David','Emma',
    'Peter','Julia','Mark','Nina','Paul','Lena','Simon','Clara','Jonas','Mia'];
  const F2 = ['Weber','Klein','Fischer','Wagner','Becker','Schulz','Hoffmann',
    'Koch','Bauer','Richter','Wolf','Neumann','Schwarz','Braun','Krause','Lang'];
  const CITIES = ['Springfield','Riverton','Fairview','Greenville','Millbrook','Oakdale'];
  const ORGS = ['Acme Ltd','Globex Corp','Initech','Umbrella Group','Meridian AG','Vertex Co'];
  function fakeFor(type, n) {{
    switch (type) {{
      case 'PERSON': return F1[n % F1.length] + ' ' + F2[(n*7) % F2.length];
      case 'EMAIL': return (F1[n % F1.length] + '.' + F2[(n*7) % F2.length]).toLowerCase() + '@example.com';
      case 'PHONE': return '+1 555 ' + String(1000 + n).padStart(4,'0');
      case 'LOCATION': return CITIES[n % CITIES.length];
      case 'ADDRESS': return (10 + n) + ' Maple Street';
      case 'ORGANIZATION': return ORGS[n % ORGS.length];
      case 'DATE': case 'DOB': return '01 January 2000';
      case 'IBAN': return 'DE00 0000 0000 0000 0000 ' + String(n%100).padStart(2,'0');
      case 'CREDIT_CARD': return '4000 0000 0000 ' + String(n%10000).padStart(4,'0');
      case 'IP': return '10.0.0.' + (1 + n % 254);
      case 'CRYPTO': return '0x' + (n+1).toString(16).padStart(40,'0');
      default: return type.replace(/_/g,'') + '-' + String(1000 + n);
    }}
  }}
  const GEN = {{PERSON:'a person', ORGANIZATION:'an organisation', LOCATION:'a place',
    ADDRESS:'an address', EMAIL:'an email', PHONE:'a phone number', IBAN:'a bank account',
    CREDIT_CARD:'a card number', IP:'an IP address', GOV_ID:'an ID', PATIENT_ID:'a patient ID',
    CASE_ID:'a case number', ACCOUNT_ID:'an account', CRYPTO:'a wallet'}};
  function generalizeFor(type, val) {{
    if (type === 'DATE' || type === 'DOB') {{
      const y = (val.match(/\\b(?:19|20)\\d\\d\\b/) || [])[0];
      return y ? y : '[a date]';
    }}
    return '[' + (GEN[type] || type.toLowerCase()) + ']';
  }}

  // Assign a token per active (non-kept) span. Auto spans keep the pipeline's
  // token (co-reference preserved: same entity -> same token). User tags reuse an
  // existing token for the same (type,value) or get a fresh one. In "total" /
  // "blackout" mode the value is not recoverable, so the mapping is not reversible.
  // Every span belongs to an ENTITY: for a detected span that is the pipeline's
  // token (co-reference from resolution + propagation); for a user tag it is
  // (type, normalised value). Keying replacements by entity keeps the same person
  // -> the same token/fake in every mode.
  function entityKey(s, val) {{
    return (!s.user && s.token) ? ('AUTO|' + s.token) : (s.type + '|' + norm(val));
  }}

  function computeTokens() {{
    const act = state.spans.filter(s=>!s.kept).slice().sort((a,b)=>a.start-b.start);
    const m = mode();
    const counters={{}}, map={{}}, rows=[], spanTok=new Map(), seenRow={{}};
    // pre-seed per-type counters from the pipeline's token indices (semantic)
    if (m === 'semantic') for (const s of state.spans) {{
      if (s.kept || s.user || !s.token) continue;
      const mm = /_(\\d+)\\]\\]$/.exec(s.token);
      if (mm) counters[s.type] = Math.max(counters[s.type]||0, +mm[1]);
    }}
    let pos=-1;
    for (const s of act) {{
      if (s.start < pos) {{ spanTok.set(s,null); continue; }}
      const val = ORIGINAL.slice(s.start, s.end);
      let tok;
      if (m === 'total' || s.type === 'REDACT') tok = '[REDACTED]';
      else if (m === 'blackout') tok = '█'.repeat(Math.min(val.replace(/\\s/g,'').length||1, 16));
      else if (m === 'generalize') tok = generalizeFor(s.type, val);
      else {{
        const ek = entityKey(s, val);
        if (map[ek]) tok = map[ek];                       // same entity -> same replacement
        else if (m === 'semantic' && !s.user && s.token) tok = map[ek] = s.token;
        else {{
          counters[s.type] = (counters[s.type]||0) + 1;
          tok = (m === 'synthetic') ? fakeFor(s.type, counters[s.type]-1)
                                    : ('[[' + s.type + '_' + pad(counters[s.type]) + ']]');
          map[ek] = tok;
        }}
      }}
      spanTok.set(s, tok);
      const dk = REVERSIBLE[m] ? tok : (tok + '|' + norm(val));
      if (!seenRow[dk]) {{ seenRow[dk]=1; rows.push({{token: tok, value: val, type: s.type}}); }}
      pos = s.end;
    }}
    return {{spanTok, rows, reversible: !!REVERSIBLE[m]}};
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
    // reversibility note per mode
    const rev = !!REVERSIBLE[mode()];
    document.getElementById('thtok').textContent = rev ? 'Replacement' : 'Becomes';
    document.getElementById('maptitle').firstChild.textContent =
      rev ? 'Mapping — replacement → original ' : 'Removed values (not reversible) ';
    document.getElementById('revnote').innerHTML = rev
      ? '<span style="color:#1e7d33">Reversible</span> — restore the original later with this mapping.'
      : '<span style="color:#9a031e">Not reversible</span> — the originals cannot be recovered.';
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

  document.getElementById('mode').onchange = render;
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
