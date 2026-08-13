# -*- coding: utf-8 -*-
"""Render self-contained, interactive HTML teaching modules from the content dicts.

One HTML file per protocol (frame explorer + all sections), plus an index page.
No external dependencies, no browser storage — safe as a persisted artifact.
"""
import html, json, os
from scapy.all import rdpcap, Raw
from content_dnp3 import DNP3
from content_mqtt import MQTT

PCAP_DIR = "/root/icsnpp_kit/pcaps"
OUT_DIR = "/root/icsnpp_kit/modules"
os.makedirs(OUT_DIR, exist_ok=True)

SEV = {"info": "#2563eb", "warn": "#b45309", "critical": "#dc2626"}
SEV_LABEL = {"info": "NOTE", "warn": "CAUTION", "critical": "CRITICAL"}


def e(x):
    return html.escape(str(x), quote=True)


def hexdump(b):
    out = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append(f"{i:04x}  {hx:<47}  {asc}")
    return "\n".join(out)


def frame_hex_map(pcap_path):
    m = {}
    try:
        pkts = rdpcap(pcap_path)
    except Exception:
        return m
    t0 = float(pkts[0].time) if len(pkts) else 0.0
    for idx, p in enumerate(pkts, start=1):
        info = {"t": f"{float(p.time) - t0:.3f}"}
        if Raw in p:
            info["hex"] = hexdump(bytes(p[Raw].load))
        m[idx] = info
    return m


def render_frames_json(mod, hexmap):
    frames = []
    for f in mod["frames"]:
        g = dict(f)
        info = hexmap.get(f["n"], {})
        g["hex"] = info.get("hex", "")
        if info.get("t") is not None:      # exact time from the pcap
            g["t"] = info["t"]
        frames.append(g)
    return json.dumps(frames, ensure_ascii=False)


def sec_card(s):
    sev = s["severity"]
    color = SEV.get(sev, "#334155")
    parts = [f'<div class="seccard" style="border-left-color:{color}">']
    parts.append(f'<div class="sech"><span class="sevpill" style="background:{color}">{e(sev.upper())}</span>'
                 f'<span class="secid">{e(s["id"])}</span><b>{e(s["title"])}</b></div>')
    if s.get("frames"):
        fr = ", ".join(f'<a href="#" class="framelink" data-f="{n}">frame&nbsp;{n}</a>' for n in s["frames"])
        parts.append(f'<div class="secmeta">Seen in: {fr}</div>')
    parts.append(f'<p><b>Risk.</b> {e(s["risk"])}</p>')
    parts.append(f'<p><b>Real-world.</b> {e(s["realworld"])}</p>')
    if s.get("attack"):
        parts.append(f'<p class="attk">{e(s["attack"])}</p>')
    parts.append(f'<p><b>Control.</b> {e(s["control"])}</p>')
    parts.append('</div>')
    return "".join(parts)


def render_module(mod, accent, accent2):
    hexmap = frame_hex_map(os.path.join(PCAP_DIR, mod["pcap"]))
    frames_json = render_frames_json(mod, hexmap)

    # Overview
    ov = "".join(f"<p>{md_inline(p)}</p>" for p in mod["overview"])
    objs = "".join(f"<li>{md_inline(o)}</li>" for o in mod["objectives"])

    # Industry
    sect_ind = [f'<p>{md_inline(mod["industry"]["intro"])}</p>', '<div class="grid2">']
    for name, det in mod["industry"]["sectors"]:
        sect_ind.append(f'<div class="tile"><h4>{e(name)}</h4><p>{md_inline(det)}</p></div>')
    sect_ind.append('</div><h4>Typical use cases</h4><ul>')
    sect_ind += [f'<li>{md_inline(u)}</li>' for u in mod["industry"]["use_cases"]]
    sect_ind.append('</ul>')

    # Anatomy
    sect_an = [f'<p>{md_inline(mod["anatomy"]["intro"])}</p>']
    for name, det, diagram in mod["anatomy"]["layers"]:
        sect_an.append(f'<div class="layer"><h4>{e(name)}</h4><p>{md_inline(det)}</p>'
                       f'<pre class="wire">{e(diagram)}</pre></div>')
    sect_an.append('<h4>Function / packet types you will see</h4>'
                   '<table class="ft"><tr><th>Code</th><th>Name</th><th>Meaning</th></tr>')
    for code, name, mean in mod["anatomy"]["funcs"]:
        sect_an.append(f'<tr><td class="mono">{e(code)}</td><td><b>{e(name)}</b></td><td>{e(mean)}</td></tr>')
    sect_an.append('</table>')

    # Capture / topology
    topo = "".join(f'<tr><td><b>{e(r[0])}</b></td><td class="mono">{e(r[1])}</td><td>{e(r[2])}</td></tr>'
                   for r in mod["capture"]["topology"])

    # Security
    sec = "".join(sec_card(s) for s in mod["security"])

    # Lab
    lab = [f'<p>{md_inline(mod["lab"]["intro"])}</p>']
    for i, ex in enumerate(mod["lab"]["exercises"], 1):
        steps = "".join(f"<li>{md_inline(st)}</li>" for st in ex["steps"])
        lab.append(
            f'<div class="ex"><h4>Exercise {i}. {e(ex["title"])}</h4><ol>{steps}</ol>'
            f'<p class="q"><b>Question.</b> {e(ex["question"])}</p>'
            f'<details><summary>Show answer</summary><p>{e(ex["answer"])}</p></details></div>')

    # Personas
    per = ['<p class="muted">This module is framed around real O*NET occupational personas — the subject-matter '
           'voices that shaped it and the people whose work it maps to (see the split below: skills you practice vs. who this protects).</p>']
    for p in mod["personas"]:
        per.append(
            f'<div class="persona"><div class="pcode">{e(p["code"])}</div>'
            f'<div class="pbody"><h4>{e(p["title"])} <span class="ptag">{e(p["tag"])}</span></h4>'
            f'<p class="pvoice">“{e(p["voice"])}”</p><p>{md_inline(p["relevance"])}</p></div></div>')
    oa = mod["onet_alignment"]
    align_practice = "".join(
        f'<tr><td>{md_inline(skill)}</td><td class="mono">{e(code)}</td><td>{e(work)}</td></tr>'
        for skill, code, work in oa["practice"])
    align_context = "".join(
        f'<tr><td><b>{e(occ)}</b></td><td class="mono">{e(code)}</td><td>{e(why)}</td></tr>'
        for occ, code, why in oa["context"])

    # callouts (scope / OT-reality) at top of Overview; extras (deep-dives) after Security
    tone_color = {"scope": "#dc2626", "reality": "#b45309", "note": "#2563eb"}
    callouts_html = "".join(
        f'<div class="bigcallout" style="border-left-color:{tone_color.get(c.get("tone","note"),"#2563eb")}">'
        f'<h4>{e(c["title"])}</h4>{md_block(c["body"])}</div>'
        for c in mod.get("callouts", []))
    extras_html = "".join(
        f'<div class="card"><h4 style="margin-top:0">{e(x["title"])}</h4>{md_block(x["body"])}</div>'
        for x in mod.get("extras", []))

    # References
    refs = "".join(f'<li><a href="{e(u)}" target="_blank" rel="noopener">{e(l)}</a></li>'
                   for l, u in mod["references"])

    return PAGE.format(
        title=e(mod["title"]), protocol=e(mod["protocol"]), subtitle=e(mod["subtitle"]),
        port=e(mod["port"]), spec=e(mod["spec"]), level=e(mod["level"]),
        pcap=e(mod["pcap"]), stats=e(mod["capture"]["stats"]),
        accent=accent, accent2=accent2,
        overview=ov, objectives=objs,
        industry="".join(sect_ind), anatomy="".join(sect_an),
        scenario=md_inline(mod["capture"]["scenario"]), topo=topo,
        security=sec, extras=extras_html, callouts=callouts_html,
        lab="".join(lab), personas="".join(per),
        align_practice=align_practice, align_context=align_context, refs=refs,
        frames_json=frames_json, other=("mqtt_module.html" if mod["id"] == "dnp3" else "dnp3_module.html"),
        other_name=("MQTT" if mod["id"] == "dnp3" else "DNP3"),
    )


def md_inline(s):
    """Minimal inline markdown: **bold** and `code`, with HTML-escape."""
    s = e(s)
    import re
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


def md_block(s):
    """Render a small markdown string: blank-line-separated paragraphs and '- ' bullet lists."""
    import re
    out = []
    for b in re.split(r"\n\n+", s.strip()):
        lines = [ln for ln in b.split("\n") if ln.strip()]
        if lines and all(ln.strip().startswith("- ") for ln in lines):
            out.append("<ul>" + "".join(f"<li>{md_inline(ln.strip()[2:])}</li>" for ln in lines) + "</ul>")
        else:
            out.append(f"<p>{md_inline(b)}</p>")
    return "".join(out)


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--accent:{accent};--accent2:{accent2};--ink:#1e293b;--mut:#475569;--line:#e2e8f0;--bg:#f1f5f9;--card:#fff;}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:var(--ink);background:var(--bg);line-height:1.55;font-size:15.5px}}
a{{color:var(--accent)}}
header{{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;padding:26px 22px 18px}}
header .kick{{font-size:12px;letter-spacing:.14em;text-transform:uppercase;opacity:.9}}
header h1{{margin:.15em 0 .1em;font-size:26px}}
header .sub{{opacity:.95;margin:0 0 12px}}
header .meta{{display:flex;flex-wrap:wrap;gap:8px}}
header .chip{{background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);
padding:3px 10px;border-radius:20px;font-size:12.5px}}
nav{{position:sticky;top:0;z-index:20;background:#0f172a;display:flex;flex-wrap:wrap;gap:2px;padding:0 8px}}
nav button{{background:none;border:0;color:#cbd5e1;padding:12px 13px;font-size:13.5px;cursor:pointer;
border-bottom:3px solid transparent;font-weight:600}}
nav button:hover{{color:#fff}}
nav button.on{{color:#fff;border-bottom-color:var(--accent)}}
main{{max-width:1080px;margin:0 auto;padding:22px 18px 60px}}
section{{display:none;animation:f .2s ease}}
section.on{{display:block}}
@keyframes f{{from{{opacity:0;transform:translateY(4px)}}to{{opacity:1}}}}
h2{{font-size:21px;border-bottom:2px solid var(--line);padding-bottom:6px;margin-top:8px}}
h4{{margin:.9em 0 .35em;font-size:15.5px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0;
box-shadow:0 1px 2px rgba(15,23,42,.04)}}
.muted{{color:var(--mut)}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:10px 0}}
.tile{{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.tile h4{{margin:.1em 0 .3em;color:var(--accent)}}
.mono,.wire,pre,code{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
code{{background:#eef2ff;padding:1px 5px;border-radius:4px;font-size:.92em}}
.wire{{background:#0f172a;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:12.5px;overflow-x:auto}}
table{{border-collapse:collapse;width:100%;margin:8px 0;font-size:14px}}
th,td{{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}}
th{{background:#f8fafc}}
.ft td.mono{{white-space:nowrap;color:var(--accent);font-weight:700}}
/* frame explorer */
.explorer{{display:grid;grid-template-columns:330px 1fr;gap:14px}}
.flist{{max-height:70vh;overflow:auto;border:1px solid var(--line);border-radius:10px;background:#fff}}
.frow{{display:flex;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer;font-size:13px}}
.frow:hover{{background:#f8fafc}}
.frow.sel{{background:#eef2ff;border-left:3px solid var(--accent)}}
.frow.anom{{background:#fef2f2}}
.frow.anom.sel{{background:#fee2e2}}
.fn{{font-weight:700;color:var(--mut);min-width:26px}}
.dir{{color:var(--accent2);font-weight:700}}
.dot{{width:9px;height:9px;border-radius:50%;flex:0 0 auto}}
.fsum{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.detail{{border:1px solid var(--line);border-radius:10px;background:#fff;padding:16px 18px;min-height:60vh}}
.detail h3{{margin:.1em 0}}
.pathline{{color:var(--mut);font-size:13px;margin-bottom:8px}}
.kv{{width:100%;margin:8px 0}}
.kv td:first-child{{width:38%;color:var(--mut);font-weight:600}}
.callout{{border-left:4px solid;padding:9px 12px;border-radius:6px;margin:10px 0;font-size:14px}}
.teach{{background:#f0f9ff;border-color:#0ea5e9;padding:9px 12px;border-radius:6px;margin:10px 0;font-size:14px}}
.filterbar{{display:flex;gap:8px;align-items:center;margin:8px 0}}
.filterbar code{{flex:1}}
.copy{{border:1px solid var(--line);background:#fff;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12.5px}}
.copy:hover{{background:#f1f5f9}}
.hex{{background:#0f172a;color:#cbd5e1;padding:10px 12px;border-radius:8px;font-size:11.8px;overflow-x:auto;white-space:pre}}
.toolbar{{display:flex;gap:12px;align-items:center;margin-bottom:10px;font-size:13.5px;flex-wrap:wrap}}
.legend{{display:flex;gap:12px;font-size:12px;color:var(--mut);flex-wrap:wrap}}
.legend span{{display:inline-flex;gap:5px;align-items:center}}
.seccard{{background:#fff;border:1px solid var(--line);border-left-width:5px;border-radius:10px;padding:12px 16px;margin:12px 0}}
.sech{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.sevpill{{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}}
.secid{{font-weight:700;color:var(--mut)}}
.secmeta{{font-size:13px;color:var(--mut);margin:4px 0}}
.attk{{font-size:13px;color:#7c2d12;background:#fff7ed;border:1px solid #fed7aa;padding:5px 9px;border-radius:6px;display:inline-block}}
.ex{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:12px 0}}
.ex .q{{background:#f8fafc;padding:7px 10px;border-radius:6px}}
details summary{{cursor:pointer;color:var(--accent);font-weight:600}}
.persona{{display:flex;gap:12px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}}
.pcode{{font-family:ui-monospace,monospace;font-weight:700;color:#fff;background:var(--accent);border-radius:8px;
padding:8px 10px;height:fit-content;font-size:12.5px;white-space:nowrap}}
.pbody h4{{margin:.1em 0 .2em}}
.ptag{{font-size:11px;background:#eef2ff;color:var(--accent);padding:2px 8px;border-radius:20px;font-weight:600}}
.pvoice{{font-style:italic;color:#334155;margin:.2em 0 .4em}}
.foot{{color:var(--mut);font-size:12.5px;border-top:1px solid var(--line);margin-top:26px;padding-top:12px}}
.switch{{margin-left:auto}}
.xbadge{{background:#dc2626;color:#fff;font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px}}
.bigcallout{{background:#fff;border:1px solid var(--line);border-left:5px solid #2563eb;border-radius:10px;padding:12px 16px;margin:12px 0}}
.bigcallout h4{{margin:.1em 0 .4em}}
.sevtag{{font:700 10px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.04em;padding:2px 5px;border-radius:4px;flex:0 0 auto;min-width:54px;text-align:center}}
.sev-norm{{color:#475569;background:#f1f5f9;border:1px solid #e2e8f0}}
.sev-note{{color:#1e40af;background:#dbeafe}}
.sev-caution{{color:#9a3412;background:#ffedd5}}
.sev-crit{{color:#991b1b;background:#fee2e2}}
.frow:focus-visible{{outline:2px solid var(--accent);outline-offset:-2px}}
kbd{{font:600 11px ui-monospace,monospace;background:#f1f5f9;border:1px solid #cbd5e1;border-bottom-width:2px;border-radius:4px;padding:0 4px}}
@media(max-width:820px){{.grid2{{grid-template-columns:1fr}}.explorer{{grid-template-columns:1fr}}}}
</style></head>
<body>
<header>
  <div class="kick">ICS / OT Protocol Analysis Lab Kit &nbsp;·&nbsp; {protocol} Module</div>
  <h1>{title}</h1>
  <p class="sub">{subtitle}</p>
  <div class="meta">
    <span class="chip">Port {port}</span>
    <span class="chip">{spec}</span>
    <span class="chip">Capture: {pcap}</span>
    <span class="chip">{level}</span>
  </div>
</header>
<nav id="nav">
  <button class="on" data-t="overview">Overview</button>
  <button data-t="industry">Industry &amp; Use Cases</button>
  <button data-t="anatomy">Protocol Anatomy</button>
  <button data-t="explorer">Frame Explorer</button>
  <button data-t="security">Security &amp; Controls</button>
  <button data-t="lab">Hands-On Lab</button>
  <button data-t="onet">O*NET &amp; Careers</button>
  <button data-t="refs">References</button>
</nav>
<main>
  <section class="on" id="overview">
    {callouts}
    <h2>What this module is</h2>
    <div class="card">{overview}</div>
    <h2>Learning objectives</h2>
    <div class="card"><ul>{objectives}</ul></div>
    <h2>The capture at a glance</h2>
    <div class="card"><p>{scenario}</p>
      <table><tr><th>Host / role</th><th>Address</th><th>Notes</th></tr>{topo}</table>
      <p class="muted" style="margin-top:8px">{stats}</p>
      <p>Jump to the <a href="#" class="gotab" data-t="explorer">Frame Explorer</a> to walk the capture packet by packet.</p>
    </div>
  </section>

  <section id="industry"><h2>Where {protocol} lives</h2><div class="card">{industry}</div></section>

  <section id="anatomy"><h2>Protocol anatomy</h2><div class="card">{anatomy}</div></section>

  <section id="explorer">
    <h2>Frame-by-frame explorer</h2>
    <div class="toolbar">
      <label><input type="checkbox" id="anomOnly"> Show anomalies only</label>
      <span class="legend">
        <span><span class="dot" style="background:#94a3b8"></span>normal</span>
        <span><span class="dot" style="background:#2563eb"></span>note</span>
        <span><span class="dot" style="background:#d97706"></span>caution</span>
        <span><span class="dot" style="background:#dc2626"></span>critical / anomaly</span>
      </span>
    </div>
    <p id="fx-hint" class="muted" style="margin-top:-4px;font-size:13px">Click a frame, or press <kbd>↑</kbd>/<kbd>↓</kbd> (or <kbd>Home</kbd>/<kbd>End</kbd>) to move and <kbd>Enter</kbd>/<kbd>Space</kbd> to open it. Each row carries a severity word — <b>OK</b>, <b>NOTE</b>, <b>CAUTION</b>, <b>CRIT</b> — as well as a color. Numbers match Wireshark exactly — open {pcap} alongside this page.</p>
    <div class="explorer">
      <div class="flist" id="flist" role="listbox" aria-label="Capture frames — arrow keys to move, Enter or Space to open" aria-describedby="fx-hint"></div>
      <div class="detail" id="detail" role="region" aria-label="Selected frame detail" aria-live="polite" aria-atomic="true" tabindex="-1"></div>
    </div>
  </section>

  <section id="security"><h2>Security risks &amp; controls</h2>
    <p class="muted">Each finding ties specific frames to a real-world case and a concrete control. Frame links jump to the explorer.</p>
    {security}
    {extras}</section>

  <section id="lab"><h2>Hands-on lab</h2><div class="card">{lab}</div></section>

  <section id="onet"><h2>O*NET personas &amp; career pathways</h2>
    <div class="card">{personas}</div>
    <h2>What you practice &rarr; who does this work</h2>
    <div class="card">
      <p class="muted">These occupations do packet and detection analysis (or implement the controls) as their actual job — the skills this kit rehearses.</p>
      <table><tr><th>Skill you practice in this kit</th><th>O*NET</th><th>The real work it maps to</th></tr>{align_practice}</table>
    </div>
    <h2>Context: who this protects</h2>
    <div class="card">
      <p class="muted">These roles operate, maintain, design, or authored the systems under analysis — beneficiaries and design authorities, not skills the learner performs here.</p>
      <table><tr><th>Occupation</th><th>O*NET</th><th>Why they are in the room</th></tr>{align_context}</table>
    </div>
  </section>

  <section id="refs"><h2>References &amp; sources</h2><div class="card"><ul>{refs}</ul>
    <p class="foot">Companion module: <a href="{other}">{other_name} module</a>. All frame numbers, field values, and CRCs verified with tshark and CISA ICSNPP/Zeek. This is a curated teaching capture — synthetic but protocol-valid.</p>
  </div></section>
</main>

<script>
const FRAMES = {frames_json};
const SEV = {{"info":"#2563eb","warn":"#b45309","critical":"#dc2626"}};
const SEVL = {{"info":"NOTE","warn":"CAUTION","critical":"CRITICAL"}};
function dotColor(f){{ if(f.anomaly) return "#dc2626"; if(f.security) return SEV[f.security.level]||"#94a3b8"; return "#94a3b8"; }}
function esc(s){{return (s||"").replace(/[&<>"]/g,c=>({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}}[c]));}}

let sel = 0;
const flist = document.getElementById('flist');
function sevToken(f){{
  if(f.anomaly) return {{t:"CRIT", cls:"crit"}};
  if(f.security) return ({{info:{{t:"NOTE",cls:"note"}},warn:{{t:"CAUTION",cls:"caution"}},critical:{{t:"CRIT",cls:"crit"}}}})[f.security.level] || {{t:"OK",cls:"norm"}};
  return {{t:"OK", cls:"norm"}};
}}
function buildList(){{
  const only = document.getElementById('anomOnly').checked;
  flist.innerHTML='';
  FRAMES.forEach((f,i)=>{{
    if(only && !f.anomaly) return;
    const tok = sevToken(f);
    const row = document.createElement('div');
    row.className = 'frow'+(i===sel?' sel':'')+(f.anomaly?' anom':'');
    row.id = 'frow-'+i; row.dataset.i = i;
    row.setAttribute('role','option');
    row.setAttribute('aria-selected', i===sel ? 'true':'false');
    row.tabIndex = (i===sel ? 0 : -1);
    row.setAttribute('aria-label', `Frame ${{f.n}}, ${{f.src}} to ${{f.dst}}, ${{f.layer}}. ${{f.anomaly?'Anomaly. ':''}}Severity ${{tok.t}}. ${{(f.summary||'').replace(/^⚠\s*/,'')}}`);
    row.innerHTML = `<span class="fn">${{f.n}}</span>`+
      `<span class="dot" style="background:${{dotColor(f)}}" aria-hidden="true"></span>`+
      `<span class="sevtag sev-${{tok.cls}}">${{tok.t}}</span>`+
      `<span class="fsum">${{esc(f.summary)}}</span>`;
    row.addEventListener('click', ()=>selectRow(i,true));
    flist.appendChild(row);
  }});
}}
function selectRow(i, focus){{ sel=i; render(); const row=document.getElementById('frow-'+i); if(row&&focus) row.focus(); }}
function render(){{
  document.querySelectorAll('.frow').forEach(r=>{{const on=(+r.dataset.i===sel);r.classList.toggle('sel',on);r.setAttribute('aria-selected',on?'true':'false');r.tabIndex=on?0:-1;}});
  const rr=document.querySelector('.frow.sel'); if(rr) rr.scrollIntoView({{block:'nearest'}});
  const f = FRAMES[sel];
  const kv = (f.fields||[]).map(x=>`<tr><td>${{esc(x[0])}}</td><td>${{esc(x[1])}}</td></tr>`).join('');
  let sec='';
  if(f.security){{const c=SEV[f.security.level];sec=`<div class="callout" style="border-color:${{c}};background:${{c}}12">
     <b style="color:${{c}}">${{SEVL[f.security.level]}}.</b> ${{esc(f.security.note)}}</div>`;}}
  const anom = f.anomaly?` <span class="xbadge">ANOMALY</span>`:'';
  const hex = f.hex?`<h4>Application-layer bytes</h4><div class="hex">${{esc(f.hex)}}</div>`:'';
  document.getElementById('detail').innerHTML = `
    <h3>Frame ${{f.n}} &nbsp;<span style="font-weight:400;color:#64748b">t=${{f.t}}s · ${{esc(f.layer)}}</span>${{anom}}</h3>
    <div class="pathline">${{esc(f.src)}} &nbsp;→&nbsp; ${{esc(f.dst)}} &nbsp;·&nbsp; ${{esc(f.summary)}}</div>
    <p>${{esc(f.plain)}}</p>
    <table class="kv">${{kv}}</table>
    <div class="teach"><b>Why it matters.</b> ${{esc(f.teach)}}</div>
    ${{sec}}
    <div class="filterbar"><code>${{esc(f.filter)}}</code>
      <button class="copy" onclick="cp(this,'${{esc(f.filter).replace(/'/g,"\\'")}}')">Copy filter</button></div>
    ${{hex}}`;
}}
function cp(btn,txt){{ const t=btn.textContent;
  navigator.clipboard&&navigator.clipboard.writeText(txt).then(()=>{{btn.textContent='Copied ✓';setTimeout(()=>btn.textContent=t,1200);}},()=>{{btn.textContent='Copy manually';}});
}}
document.getElementById('anomOnly').onchange=()=>{{sel=0;buildList();render();}};
// tabs
function show(t){{
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
  document.querySelectorAll('main section').forEach(s=>s.classList.toggle('on',s.id===t));
  window.scrollTo({{top:0,behavior:'instant'}});
}}
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>show(b.dataset.t));
document.querySelectorAll('.gotab').forEach(a=>a.onclick=ev=>{{ev.preventDefault();show(a.dataset.t);}});
// frame links from security section
document.querySelectorAll('.framelink').forEach(a=>a.onclick=ev=>{{ev.preventDefault();
  const n=+a.dataset.f; const i=FRAMES.findIndex(x=>x.n===n); if(i>=0){{document.getElementById('anomOnly').checked=false;sel=i;buildList();render();show('explorer');}}
}});
flist.addEventListener('keydown', ev=>{{
  const vis = [...flist.querySelectorAll('.frow')].map(r=>+r.dataset.i);
  const pos = vis.indexOf(sel);
  if(ev.key==='ArrowDown'){{ev.preventDefault(); if(pos<vis.length-1) selectRow(vis[pos+1],true);}}
  else if(ev.key==='ArrowUp'){{ev.preventDefault(); if(pos>0) selectRow(vis[pos-1],true);}}
  else if(ev.key==='Home'){{ev.preventDefault(); selectRow(vis[0],true);}}
  else if(ev.key==='End'){{ev.preventDefault(); selectRow(vis[vis.length-1],true);}}
  else if(ev.key==='Enter'||ev.key===' '){{ev.preventDefault(); selectRow(sel,true);}}
}});
buildList(); render();
</script>
</body></html>"""


def build_index():
    idx = INDEX
    with open(os.path.join(OUT_DIR, "index.html"), "w") as f:
        f.write(idx)


INDEX = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>ICS/OT Protocol Analysis Lab Kit</title>
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#1e293b;background:#f1f5f9;line-height:1.55}
header{background:linear-gradient(135deg,#3730a3,#0f766e);color:#fff;padding:40px 24px}
header h1{margin:0 0 6px;font-size:28px}
main{max-width:900px;margin:0 auto;padding:24px 18px 60px}
.mods{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:18px 0}
.mod{display:block;text-decoration:none;color:inherit;background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:20px;box-shadow:0 1px 2px rgba(15,23,42,.05)}
.mod:hover{box-shadow:0 6px 18px rgba(15,23,42,.10);transform:translateY(-2px);transition:.15s}
.mod h2{margin:.1em 0}
.badge{display:inline-block;font-size:12px;font-weight:700;color:#fff;padding:3px 10px;border-radius:20px}
.d{background:#b45309}.m{background:#0f766e}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px 20px;margin:14px 0}
code{background:#eef2ff;padding:1px 5px;border-radius:4px;font-family:ui-monospace,monospace}
ul{margin:.3em 0}
.muted{color:#64748b}
@media(max-width:720px){.mods{grid-template-columns:1fr}}
</style></head><body>
<header><h1>ICS / OT Protocol Analysis Lab Kit</h1>
<p>Hands-on packet analysis for DNP3 &amp; MQTT — built with CISA ICSNPP, Wireshark, and Zeek. Intermediate level.</p></header>
<main>
<div class="mods">
  <a class="mod" href="dnp3_module.html"><span class="badge d">DNP3</span>
    <h2>DNP3 — Substation SCADA</h2>
    <p class="muted">Master/outstation polling &amp; control on TCP/20000, a supervised breaker close, and an unauthenticated command-injection attack — frame by frame.</p></a>
  <a class="mod" href="mqtt_module.html"><span class="badge m">MQTT</span>
    <h2>MQTT — IIoT Telemetry</h2>
    <p class="muted">Publish/subscribe telemetry on TCP/1883, broker fan-out, and an anonymous eavesdrop-and-inject intrusion — frame by frame.</p></a>
</div>
<div class="card"><h3>What's in the kit</h3>
<ul>
<li>Two verified teaching captures: <code>dnp3_substation.pcap</code> and <code>mqtt_iot_telemetry.pcap</code>.</li>
<li>Two interactive modules (this HTML) plus Word, PDF, and Markdown versions.</li>
<li>A runnable Docker lab: Mosquitto broker, a Python DNP3 outstation/master, tcpreplay, and Zeek + CISA ICSNPP parsers.</li>
<li>Student worksheets, instructor answer keys, and real Zeek/ICSNPP reference logs.</li>
</ul>
<p class="muted">Open a module, read the Overview, then work the Frame Explorer with the matching .pcap open in Wireshark.</p></div>
</main></body></html>"""


if __name__ == "__main__":
    with open(os.path.join(OUT_DIR, "dnp3_module.html"), "w") as f:
        f.write(render_module(DNP3, "#b45309", "#7c2d12"))
    with open(os.path.join(OUT_DIR, "mqtt_module.html"), "w") as f:
        f.write(render_module(MQTT, "#0f766e", "#134e4a"))
    build_index()
    print("HTML modules written to", OUT_DIR)
    for fn in ("index.html", "dnp3_module.html", "mqtt_module.html"):
        p = os.path.join(OUT_DIR, fn)
        print(" ", fn, os.path.getsize(p), "bytes")
