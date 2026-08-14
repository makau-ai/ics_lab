# -*- coding: utf-8 -*-
"""Render self-contained, interactive HTML teaching modules from the content dicts.

One HTML file per protocol (frame explorer + all sections), plus an index page.
No external dependencies, no CDN, system fonts only — safe as a persisted artifact.

Visual system: "First Light" — the same dark-first token palette, fluid type scale,
protocol leitmotifs (DNP3 amber / MQTT teal), purposeful motion and reduced-motion
twins, glossy terminal cards and light/dark theme toggle used by the curriculum hub.
"""
import html, json, os
from scapy.all import rdpcap, Raw
from content_dnp3 import DNP3
from content_mqtt import MQTT

PCAP_DIR = "/root/icsnpp_kit/pcaps"
OUT_DIR = "/root/icsnpp_kit/modules"
os.makedirs(OUT_DIR, exist_ok=True)

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


def packet_lens_svg(cls=""):
    """The reusable 'Packet Lens' glyph — a magnifier over a small topology (First Light)."""
    klass = ("lens " + cls).strip()
    return (
        '<svg class="' + klass + '" viewBox="0 0 26 26" fill="none" aria-hidden="true" focusable="false">'
        '<circle cx="11.5" cy="11.5" r="8.4" stroke="currentColor" stroke-width="1.4" opacity=".55"/>'
        '<line x1="17.6" y1="17.6" x2="22.4" y2="22.4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" opacity=".75"/>'
        '<path d="M11.5 11.5 L7.4 8.2 M11.5 11.5 L15.6 8.2 M11.5 11.5 L8.6 15.4" stroke="currentColor" stroke-width="1" opacity=".45"/>'
        '<circle cx="11.5" cy="11.5" r="1.9" fill="currentColor"/>'
        '<circle cx="7.4" cy="8.2" r="1.25" fill="currentColor" opacity=".85"/>'
        '<circle cx="15.6" cy="8.2" r="1.25" fill="currentColor" opacity=".85"/>'
        '<circle cx="8.6" cy="15.4" r="1.6" fill="currentColor"/>'
        '</svg>'
    )


def sec_card(s):
    sev = s["severity"]                       # info | warn | critical
    label = SEV_LABEL.get(sev, sev.upper())
    parts = [f'<div class="seccard s-{e(sev)}">']
    parts.append(f'<div class="sech"><span class="sevpill">{label}</span>'
                 f'<span class="secid">{e(s["id"])}</span><b class="sectitle">{e(s["title"])}</b></div>')
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


def render_module(mod):
    proto = mod["id"]                          # 'dnp3' | 'mqtt'
    proto_up = mod["protocol"]                 # 'DNP3' | 'MQTT'
    accent_word = "Amber" if proto == "dnp3" else "Teal"

    hexmap = frame_hex_map(os.path.join(PCAP_DIR, mod["pcap"]))
    frames_json = render_frames_json(mod, hexmap)

    # Title with a First Light gradient flourish on the protocol acronym
    title = mod["title"]
    if " — " in title:
        head, tail = title.split(" — ", 1)
        h1 = f'<span class="fl">{e(head)}</span> &mdash; {e(tail)}'
    else:
        h1 = e(title)

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
            f'<div class="ex"><h4 class="exh">Exercise {i}. {e(ex["title"])}</h4><ol>{steps}</ol>'
            f'<p class="q"><b>Question.</b> {e(ex["question"])}</p>'
            f'<details><summary>Show answer</summary><p>{e(ex["answer"])}</p></details></div>')

    # Personas
    per = ['<p class="muted">This module is framed around real O*NET occupational personas — the subject-matter '
           'voices that shaped it and the people whose work it maps to (see the split below: skills you practice vs. who this protects).</p>']
    for p in mod["personas"]:
        per.append(
            f'<div class="persona"><div class="pcode">{e(p["code"])}</div>'
            f'<div class="pbody"><h4 class="ph">{e(p["title"])} <span class="ptag">{e(p["tag"])}</span></h4>'
            f'<p class="pvoice">&ldquo;{e(p["voice"])}&rdquo;</p><p>{md_inline(p["relevance"])}</p></div></div>')
    oa = mod["onet_alignment"]
    align_practice = "".join(
        f'<tr><td>{md_inline(skill)}</td><td class="mono">{e(code)}</td><td>{e(work)}</td></tr>'
        for skill, code, work in oa["practice"])
    align_context = "".join(
        f'<tr><td><b>{e(occ)}</b></td><td class="mono">{e(code)}</td><td>{e(why)}</td></tr>'
        for occ, code, why in oa["context"])

    # callouts (scope / OT-reality) at top of Overview; extras (deep-dives) after Security
    callouts_html = "".join(
        f'<div class="bigcallout b-{e(c.get("tone", "note"))}"><h4 class="bch">{e(c["title"])}</h4>{md_block(c["body"])}</div>'
        for c in mod.get("callouts", []))
    extras_html = "".join(
        f'<div class="card"><h3 class="cardh">{e(x["title"])}</h3>{md_block(x["body"])}</div>'
        for x in mod.get("extras", []))

    # References
    refs = "".join(f'<li><a href="{e(u)}" target="_blank" rel="noopener">{e(l)}</a></li>'
                   for l, u in mod["references"])

    repl = {
        "__PROTO_UP__": e(proto_up),
        "__PROTO__": e(proto),
        "__ACCENT_WORD__": accent_word,
        "__LENS__": packet_lens_svg("klens-svg"),
        "__H1__": h1,
        "__SUBTITLE__": e(mod["subtitle"]),
        "__PORT__": e(mod["port"]),
        "__SPEC__": e(mod["spec"]),
        "__PCAP__": e(mod["pcap"]),
        "__LEVEL__": e(mod["level"]),
        "__STATS__": e(mod["capture"]["stats"]),
        "__OVERVIEW__": ov,
        "__OBJECTIVES__": objs,
        "__CALLOUTS__": callouts_html,
        "__INDUSTRY__": "".join(sect_ind),
        "__ANATOMY__": "".join(sect_an),
        "__SCENARIO__": md_inline(mod["capture"]["scenario"]),
        "__TOPO__": topo,
        "__SECURITY__": sec,
        "__EXTRAS__": extras_html,
        "__LAB__": "".join(lab),
        "__PERSONAS__": "".join(per),
        "__ALIGN_PRACTICE__": align_practice,
        "__ALIGN_CONTEXT__": align_context,
        "__REFS__": refs,
        "__FRAMES_JSON__": frames_json,
        "__OTHER_HREF__": ("mqtt_module.html" if proto == "dnp3" else "dnp3_module.html"),
        "__OTHER_NAME__": ("MQTT" if proto == "dnp3" else "DNP3"),
    }
    page = PAGE
    for k in sorted(repl, key=len, reverse=True):   # longer tokens first (e.g. __PROTO_UP__ before __PROTO__)
        page = page.replace(k, repl[k])
    return page


PAGE = r"""<!DOCTYPE html>
<html lang="en" data-proto="__PROTO__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>__PROTO_UP__ Module — First Light</title>
<style>
/* ============================ FIRST LIGHT — module token system ============================ */
:root{
  color-scheme:dark;
  --bg:#0a0e1a; --bg-raise:#111725; --card:#131a2b; --card-2:#1a2336;
  --line:#232e49; --line-soft:#1b2440;
  --ink:#e8edf7; --mut:#9aa7bd; --faint:#64748b;
  --link:#a5b4fc; --accent-glow:#818cf8;
  --dnp3:#f59e0b; --dnp3-deep:#b45309; --mqtt:#2dd4bf; --mqtt-deep:#0f766e;
  --ghost:#f87171; --ghost-deep:#dc2626; --ok:#34d399; --ok-deep:#16a34a;
  /* semantic severity — light-on-dark tints */
  --sev-ok:#aab6cc; --sev-ok-bg:rgba(148,163,184,.16); --sev-ok-bd:rgba(148,163,184,.32);
  --sev-note:#7dd3fc; --sev-note-bg:rgba(56,189,248,.15); --sev-note-bd:rgba(56,189,248,.38);
  --sev-caution:#fcd34d; --sev-caution-bg:rgba(245,158,11,.16); --sev-caution-bd:rgba(245,158,11,.42);
  --sev-crit:#fca5a5; --sev-crit-bg:rgba(248,113,113,.16); --sev-crit-bd:rgba(248,113,113,.42);
  /* fluid modular type scale (~1.22) */
  --step--1:clamp(.78rem,.75rem + .18vw,.86rem);
  --step-0:clamp(.95rem,.9rem + .25vw,1.05rem);
  --step-1:clamp(1.06rem,1rem + .35vw,1.2rem);
  --step-2:clamp(1.2rem,1.1rem + .6vw,1.45rem);
  --step-3:clamp(1.4rem,1.25rem + .9vw,1.8rem);
  --step-4:clamp(1.7rem,1.4rem + 1.4vw,2.25rem);
  --step-6:clamp(1.95rem,1.4rem + 2.6vw,3rem);
  --spring:cubic-bezier(.34,1.56,.64,1);
  --ease:cubic-bezier(.4,0,.2,1);
}
html[data-theme="light"]{
  color-scheme:light;
  --bg:#f1f5f9; --bg-raise:#e9eef5; --card:#ffffff; --card-2:#f8fafc;
  --line:#e2e8f0; --line-soft:#eef2f7;
  --ink:#1e293b; --mut:#475569; --faint:#94a3b8;
  --link:#4f46e5; --accent-glow:#6366f1;
  --dnp3:#b45309; --dnp3-deep:#92400e; --mqtt:#0f766e; --mqtt-deep:#0d5c56;
  --ghost:#dc2626; --ghost-deep:#b91c1c; --ok:#16a34a; --ok-deep:#15803d;
  --sev-ok:#475569; --sev-ok-bg:#f1f5f9; --sev-ok-bd:#cbd5e1;
  --sev-note:#0369a1; --sev-note-bg:#e0f2fe; --sev-note-bd:#7dd3fc;
  --sev-caution:#9a3412; --sev-caution-bg:#ffedd5; --sev-caution-bd:#fdba74;
  --sev-crit:#b91c1c; --sev-crit-bg:#fee2e2; --sev-crit-bd:#fca5a5;
}
@media(prefers-color-scheme:light){
  :root:not([data-theme]){
    color-scheme:light;
    --bg:#f1f5f9; --bg-raise:#e9eef5; --card:#ffffff; --card-2:#f8fafc;
    --line:#e2e8f0; --line-soft:#eef2f7;
    --ink:#1e293b; --mut:#475569; --faint:#94a3b8;
    --link:#4f46e5; --accent-glow:#6366f1;
    --dnp3:#b45309; --dnp3-deep:#92400e; --mqtt:#0f766e; --mqtt-deep:#0d5c56;
    --ghost:#dc2626; --ghost-deep:#b91c1c; --ok:#16a34a; --ok-deep:#15803d;
    --sev-ok:#475569; --sev-ok-bg:#f1f5f9; --sev-ok-bd:#cbd5e1;
    --sev-note:#0369a1; --sev-note-bg:#e0f2fe; --sev-note-bd:#7dd3fc;
    --sev-caution:#9a3412; --sev-caution-bg:#ffedd5; --sev-caution-bd:#fdba74;
    --sev-crit:#b91c1c; --sev-crit-bg:#fee2e2; --sev-crit-bd:#fca5a5;
  }
}
/* protocol accent — theme-aware (rides the --dnp3 / --mqtt twins); bright variant is for the always-dark hero */
html[data-proto="dnp3"]{--accent:var(--dnp3); --accent2:var(--dnp3-deep); --accent-bright:#fbbf24;
  --glow:rgba(245,158,11,.12); --flgrad:linear-gradient(100deg,#fcd34d,#fb923c 55%,#f472b6)}
html[data-proto="mqtt"]{--accent:var(--mqtt); --accent2:var(--mqtt-deep); --accent-bright:#5eead4;
  --glow:rgba(45,212,191,.12); --flgrad:linear-gradient(100deg,#5eead4,#2dd4bf 50%,#38bdf8)}

*{box-sizing:border-box}
[hidden]{display:none !important}
html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--ink);background:var(--bg);line-height:1.6;font-size:var(--step-0);
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(72% 55% at 50% 0%,var(--glow),transparent 70%)}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent-glow);outline-offset:2px;border-radius:4px}
.lens{width:1em;height:1em;display:inline-block;vertical-align:-.15em;flex:0 0 auto}
h2{font-size:var(--step-3);letter-spacing:-.01em;margin:.6em 0 .5em;display:flex;align-items:center;gap:.55em;line-height:1.2}
h2::before{content:"";width:18px;height:3px;border-radius:3px;flex:0 0 auto;
  background:linear-gradient(90deg,var(--accent),var(--accent2))}
h3{font-size:var(--step-1);letter-spacing:-.01em}
h4{margin:1.4em 0 .5em;font-size:var(--step--1);color:var(--mut);text-transform:uppercase;letter-spacing:.11em;font-weight:800}
p{margin:.62em 0}
b{color:var(--ink)}
ul,ol{margin:.4em 0;padding-left:1.35em}
li{margin:.3em 0}
li::marker{color:var(--accent)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:color-mix(in srgb,var(--accent) 13%,transparent);color:var(--ink);
  padding:.05em .4em;border-radius:5px;font-size:.88em;border:1px solid color-mix(in srgb,var(--accent) 24%,transparent)}
.muted{color:var(--mut)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

/* ================================ HERO — the signal field ============================ */
.hero{position:relative;overflow:hidden;isolation:isolate;color:#e8edf7;
  padding:clamp(1.5rem,1rem + 3vw,2.8rem) clamp(1.1rem,.6rem + 2vw,2.4rem) clamp(1.3rem,1rem + 2vw,2rem)}
.herobg{position:absolute;inset:0;z-index:0;
  background:
    radial-gradient(120% 92% at 84% 4%,color-mix(in srgb,var(--accent-bright) 24%,transparent),transparent 56%),
    radial-gradient(90% 80% at 8% 0%,rgba(124,58,237,.16),transparent 55%),
    linear-gradient(160deg,#0b1020 0%,#0a0e1a 55%,#080b14 100%)}
#constellation{position:absolute;inset:0;width:100%;height:100%;z-index:1;display:block}
.heroinner{position:relative;z-index:3;max-width:1100px;margin:0 auto}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:clamp(.9rem,3vw,1.7rem);flex-wrap:wrap}
.kick{font-size:var(--step--1);letter-spacing:.2em;text-transform:uppercase;color:#aeb9d6;font-weight:700;
  display:inline-flex;align-items:center;gap:.6em}
.kick .klens{width:1.15em;height:1.15em;color:var(--accent-bright);opacity:.95}
.herotools{display:flex;gap:8px;flex-shrink:0;flex-wrap:wrap}
.htbtn{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.07);
  border:1px solid rgba(255,255,255,.16);color:#e8edf7;border-radius:10px;padding:7px 12px;
  font-size:var(--step--1);cursor:pointer;font-weight:600;text-decoration:none;
  transition:background .2s var(--ease),transform .2s var(--ease)}
.htbtn:hover{background:rgba(255,255,255,.15);text-decoration:none}
.htbtn:active{transform:translateY(1px)}
.hero h1{margin:.05em 0 .3em;font-size:var(--step-6);line-height:1.06;letter-spacing:-.02em;font-weight:800;
  max-width:24ch;text-wrap:balance;text-shadow:0 2px 26px rgba(8,11,20,.55)}
.hero h1 .fl{background:var(--flgrad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.hero .sub{color:#c9d3e6;margin:0 0 1.15em;max-width:66ch;font-size:var(--step-1);line-height:1.55;
  text-shadow:0 2px 22px rgba(8,11,20,.5)}
.meta{display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;align-items:center;gap:7px;font-size:var(--step--1);font-weight:600;color:#dbe4f5;
  background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.13);border-radius:20px;padding:5px 12px}
.chip.lead{color:#fff}
.chip.lead::before{content:"";width:9px;height:9px;border-radius:50%;background:var(--accent-bright);
  box-shadow:0 0 10px var(--accent-bright)}

/* ================================ NAV — tab bar ============================ */
nav{position:sticky;top:0;z-index:30;background:color-mix(in srgb,var(--bg-raise) 90%,transparent);
  -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);
  display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;padding:0 max(10px,calc((100% - 1100px)/2))}
nav::-webkit-scrollbar{display:none}
nav button{background:none;border:0;color:var(--mut);padding:13px 14px;font-size:var(--step--1);cursor:pointer;
  border-bottom:2px solid transparent;font-weight:700;white-space:nowrap;font-family:inherit;transition:color .2s var(--ease)}
nav button:hover{color:var(--ink)}
nav button.on{color:var(--ink);border-bottom-color:var(--accent)}

main{max-width:1100px;margin:0 auto;padding:clamp(1.1rem,2vw,1.7rem) clamp(1rem,2vw,1.6rem) 72px}
section{display:none}
section.on{display:block;animation:secin .28s var(--ease)}
@keyframes secin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* ================================ CARDS & content ============================ */
.card{background:linear-gradient(180deg,var(--card),var(--bg-raise));border:1px solid var(--line);border-radius:16px;
  padding:clamp(1rem,2vw,1.35rem) clamp(1.05rem,2vw,1.5rem);margin:14px 0;position:relative;overflow:hidden}
.cardh{margin:.1em 0 .5em;color:var(--ink)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0}
.tile{background:var(--card-2);border:1px solid var(--line);border-radius:12px;padding:12px 15px}
.tile h4{margin:.1em 0 .35em;color:var(--accent);text-transform:none;letter-spacing:0;font-size:var(--step-0);font-weight:800}
.layer{margin:14px 0}
.layer h4{color:var(--accent);text-transform:none;letter-spacing:0;font-size:var(--step-0);font-weight:800}
.wire{background:#080d18;color:#cbd5e1;padding:11px 14px;border-radius:10px;font-size:var(--step--1);overflow-x:auto;
  border:1px solid var(--line-soft);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;line-height:1.5;
  box-shadow:0 6px 22px -14px rgba(0,0,0,.7)}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:var(--step--1)}
th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top}
th{background:var(--card-2);font-weight:700;color:var(--ink)}
.ft td.mono{white-space:nowrap;color:var(--accent);font-weight:700}
a.framelink{color:var(--accent);font-weight:700}

/* big callouts (scope / OT reality / note) */
.bigcallout{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:12px;
  padding:13px 17px;margin:13px 0}
.bigcallout.b-scope{border-left-color:var(--ghost)}
.bigcallout.b-reality{border-left-color:var(--accent)}
.bigcallout.b-note{border-left-color:var(--sev-note)}
.bigcallout .bch{margin:.1em 0 .45em;color:var(--ink);font-size:var(--step-1);text-transform:none;letter-spacing:-.01em;font-weight:800}

/* security cards */
.seccard{background:var(--card);border:1px solid var(--line);border-left-width:5px;border-radius:12px;padding:13px 17px;margin:13px 0}
.seccard.s-info{border-left-color:var(--sev-note)}
.seccard.s-warn,.seccard.s-high{border-left-color:var(--sev-caution)}
.seccard.s-critical{border-left-color:var(--ghost)}
.sech{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.sech .sectitle{font-size:var(--step-0)}
.sevpill{font-size:10px;font-weight:800;letter-spacing:.06em;padding:3px 9px;border-radius:20px;border:1px solid;
  color:var(--sev-ok);background:var(--sev-ok-bg);border-color:var(--sev-ok-bd)}
.s-info .sevpill{color:var(--sev-note);background:var(--sev-note-bg);border-color:var(--sev-note-bd)}
.s-warn .sevpill,.s-high .sevpill{color:var(--sev-caution);background:var(--sev-caution-bg);border-color:var(--sev-caution-bd)}
.s-critical .sevpill{color:var(--sev-crit);background:var(--sev-crit-bg);border-color:var(--sev-crit-bd)}
.secid{font-weight:800;color:var(--mut);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--step--1)}
.secmeta{font-size:var(--step--1);color:var(--mut);margin:6px 0}
.attk{font-size:var(--step--1);color:var(--sev-caution);background:var(--sev-caution-bg);
  border:1px solid var(--sev-caution-bd);padding:6px 11px;border-radius:8px;display:inline-block;margin:8px 0}

/* lab */
.ex{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 17px;margin:13px 0}
.ex .exh{margin:.1em 0 .5em;color:var(--accent);text-transform:none;letter-spacing:0;font-size:var(--step-1);font-weight:800}
.ex .q{background:var(--card-2);border:1px solid var(--line);padding:9px 12px;border-radius:9px}
details{margin:.5em 0}
details summary{cursor:pointer;color:var(--accent);font-weight:700}
details[open] summary{margin-bottom:.4em}

/* personas */
.persona{display:flex;gap:13px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 15px;margin:11px 0}
.pcode{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-weight:800;color:#0a0e1a;
  background:linear-gradient(140deg,var(--accent-bright),var(--accent));border-radius:9px;padding:8px 11px;
  height:fit-content;font-size:var(--step--1);white-space:nowrap}
.pbody .ph{margin:.1em 0 .25em;text-transform:none;letter-spacing:0;font-size:var(--step-0);color:var(--ink);font-weight:800}
.ptag{font-size:10px;font-weight:700;background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent);
  padding:2px 9px;border-radius:20px;border:1px solid color-mix(in srgb,var(--accent) 28%,transparent);
  margin-left:6px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.pvoice{font-style:italic;color:var(--ink);margin:.25em 0 .45em}

.foot{color:var(--faint);font-size:var(--step--1);border-top:1px solid var(--line);margin-top:26px;padding-top:14px}
.foot a{color:var(--link);font-weight:600;white-space:nowrap}

/* ================================ FRAME EXPLORER ============================ */
.toolbar{display:flex;gap:15px;align-items:center;margin:12px 0 4px;font-size:var(--step--1);flex-wrap:wrap;color:var(--mut)}
.toolbar label{display:inline-flex;align-items:center;gap:7px;cursor:pointer;color:var(--ink);font-weight:600}
.toolbar input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px}
.legend{display:flex;gap:13px;flex-wrap:wrap}
.legend span{display:inline-flex;gap:6px;align-items:center}
.dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.fx-hint{color:var(--mut);font-size:var(--step--1);margin:6px 0 12px}
.fx-hint b{color:var(--ink)}
kbd{font:600 11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--card-2);border:1px solid var(--line);
  border-bottom-width:2px;border-radius:4px;padding:0 5px;color:var(--ink)}
.explorer{display:grid;grid-template-columns:340px 1fr;gap:15px}
.flist{max-height:74vh;overflow:auto;border:1px solid var(--line);border-radius:14px;background:var(--card);scrollbar-width:thin}
.frow{display:flex;gap:9px;align-items:center;padding:9px 12px;border-bottom:1px solid var(--line-soft);cursor:pointer;
  font-size:var(--step--1);border-left:3px solid transparent;transition:background .15s var(--ease)}
.frow:last-child{border-bottom:0}
.frow:hover{background:color-mix(in srgb,var(--accent) 8%,transparent)}
.frow.sel{background:color-mix(in srgb,var(--accent) 15%,transparent);border-left-color:var(--accent)}
.frow.anom{background:color-mix(in srgb,var(--ghost) 9%,transparent)}
.frow.anom.sel{background:color-mix(in srgb,var(--ghost) 19%,transparent);border-left-color:var(--ghost)}
.frow:focus-visible{outline:2px solid var(--accent-glow);outline-offset:-2px}
.fn{font-weight:800;color:var(--mut);min-width:26px;font-variant-numeric:tabular-nums}
.sevtag{font:800 10px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.04em;padding:3px 6px;
  border-radius:5px;flex:0 0 auto;min-width:56px;text-align:center;border:1px solid}
.sevtag.sev-norm{color:var(--sev-ok);background:var(--sev-ok-bg);border-color:var(--sev-ok-bd)}
.sevtag.sev-note{color:var(--sev-note);background:var(--sev-note-bg);border-color:var(--sev-note-bd)}
.sevtag.sev-caution{color:var(--sev-caution);background:var(--sev-caution-bg);border-color:var(--sev-caution-bd)}
.sevtag.sev-crit{color:var(--sev-crit);background:var(--sev-crit-bg);border-color:var(--sev-crit-bd)}
.fsum{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink)}
.detail{border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--card),var(--bg-raise));
  padding:16px 19px;min-height:62vh}
.detail h3{margin:.1em 0}
.fmeta{font-weight:400;color:var(--faint);font-size:.8em}
.pathline{color:var(--mut);font-size:var(--step--1);margin:7px 0 10px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.kv{width:100%;margin:10px 0}
.kv td:first-child{width:38%;color:var(--mut);font-weight:600}
.teach{background:color-mix(in srgb,var(--accent) 10%,var(--card-2));border:1px solid color-mix(in srgb,var(--accent) 26%,var(--line));
  border-left:3px solid var(--accent);padding:10px 13px;border-radius:9px;margin:11px 0;font-size:var(--step--1)}
.teach b{color:var(--accent)}
.fcallout{border-left:3px solid;padding:10px 13px;border-radius:9px;margin:11px 0;font-size:var(--step--1)}
.fcallout.c-note{border-color:var(--sev-note);background:var(--sev-note-bg)}
.fcallout.c-note b{color:var(--sev-note)}
.fcallout.c-caution{border-color:var(--sev-caution);background:var(--sev-caution-bg)}
.fcallout.c-caution b{color:var(--sev-caution)}
.fcallout.c-crit{border-color:var(--sev-crit);background:var(--sev-crit-bg)}
.fcallout.c-crit b{color:var(--sev-crit)}
.xbadge{background:var(--ghost-deep);color:#fff;font-size:10px;font-weight:800;padding:2px 7px;border-radius:10px;letter-spacing:.04em}
.filterbar{display:flex;gap:9px;align-items:center;margin:12px 0}
.filterbar code{flex:1;background:#080d18;border-color:var(--line-soft);color:#93c5fd;padding:9px 12px;border-radius:8px}
.copy{border:1px solid var(--line);background:var(--card-2);color:var(--ink);border-radius:8px;padding:7px 13px;cursor:pointer;
  font-size:var(--step--1);font-weight:600;font-family:inherit;transition:all .2s var(--ease);flex:0 0 auto}
.copy:hover{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--card-2))}
.hex{background:#080d18;color:#9fb2cd;padding:11px 13px;border-radius:10px;font-size:11.8px;overflow-x:auto;white-space:pre;
  border:1px solid var(--line-soft);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;line-height:1.5;
  box-shadow:0 6px 22px -14px rgba(0,0,0,.7)}

/* ================================ responsive ============================ */
@media(max-width:820px){
  .grid2{grid-template-columns:1fr}
  .explorer{grid-template-columns:1fr}
  .flist{max-height:52vh}
  .detail{min-height:auto}
}

/* ============================ reduced motion — static twins ============================ */
@media(prefers-reduced-motion:reduce){
  *{animation:none !important;transition:none !important;scroll-behavior:auto !important}
}
</style></head>
<body>
<header class="hero" id="hero">
  <div class="herobg" aria-hidden="true"></div>
  <canvas id="constellation" aria-hidden="true"></canvas>
  <div class="heroinner">
    <div class="topbar">
      <div class="kick"><span class="klens">__LENS__</span>ICS &middot; OT Signal Field &nbsp;&middot;&nbsp; __PROTO_UP__ Module</div>
      <div class="herotools">
        <a class="htbtn" href="../curriculum/index.html" title="Back to the First Light hub">&#9204; First Light hub</a>
        <a class="htbtn" href="__OTHER_HREF__" title="Companion protocol module">__OTHER_NAME__ module &#9205;</a>
        <button class="htbtn" id="themebtn" type="button" aria-pressed="false" aria-label="Toggle light and dark theme">
          <span id="theme-ic" aria-hidden="true">&#9680;</span><span id="theme-tx">Dark</span></button>
      </div>
    </div>
    <h1>__H1__</h1>
    <p class="sub">__SUBTITLE__</p>
    <div class="meta">
      <span class="chip lead">__ACCENT_WORD__ &middot; __PROTO_UP__</span>
      <span class="chip">Port __PORT__</span>
      <span class="chip">__SPEC__</span>
      <span class="chip">Capture &middot; __PCAP__</span>
      <span class="chip">__LEVEL__</span>
    </div>
  </div>
</header>
<nav id="nav" aria-label="Module sections">
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
    __CALLOUTS__
    <h2>What this module is</h2>
    <div class="card">__OVERVIEW__</div>
    <h2>Learning objectives</h2>
    <div class="card"><ul>__OBJECTIVES__</ul></div>
    <h2>The capture at a glance</h2>
    <div class="card"><p>__SCENARIO__</p>
      <table><tr><th>Host / role</th><th>Address</th><th>Notes</th></tr>__TOPO__</table>
      <p class="muted" style="margin-top:8px">__STATS__</p>
      <p>Jump to the <a href="#" class="gotab" data-t="explorer">Frame Explorer</a> to walk the capture packet by packet.</p>
    </div>
  </section>

  <section id="industry"><h2>Where __PROTO_UP__ lives</h2><div class="card">__INDUSTRY__</div></section>

  <section id="anatomy"><h2>Protocol anatomy</h2><div class="card">__ANATOMY__</div></section>

  <section id="explorer">
    <h2>Frame-by-frame explorer</h2>
    <div class="toolbar">
      <label><input type="checkbox" id="anomOnly"> Show anomalies only</label>
      <span class="legend">
        <span><span class="dot" style="background:#64748b"></span>normal</span>
        <span><span class="dot" style="background:#38bdf8"></span>note</span>
        <span><span class="dot" style="background:#f59e0b"></span>caution</span>
        <span><span class="dot" style="background:#f87171"></span>critical / anomaly</span>
      </span>
    </div>
    <p id="fx-hint" class="fx-hint">Click a frame, or press <kbd>&uarr;</kbd>/<kbd>&darr;</kbd> (or <kbd>Home</kbd>/<kbd>End</kbd>) to move and <kbd>Enter</kbd>/<kbd>Space</kbd> to open it. Each row carries a severity word &mdash; <b>OK</b>, <b>NOTE</b>, <b>CAUTION</b>, <b>CRIT</b> &mdash; as well as a color. Numbers match Wireshark exactly &mdash; open __PCAP__ alongside this page.</p>
    <div class="explorer">
      <div class="flist" id="flist" role="listbox" aria-label="Capture frames — arrow keys to move, Enter or Space to open" aria-describedby="fx-hint"></div>
      <div class="detail" id="detail" role="region" aria-label="Selected frame detail" aria-live="polite" aria-atomic="true" tabindex="-1"></div>
    </div>
  </section>

  <section id="security"><h2>Security risks &amp; controls</h2>
    <p class="muted">Each finding ties specific frames to a real-world case and a concrete control. Frame links jump to the explorer.</p>
    __SECURITY__
    __EXTRAS__</section>

  <section id="lab"><h2>Hands-on lab</h2><div class="card">__LAB__</div></section>

  <section id="onet"><h2>O*NET personas &amp; career pathways</h2>
    <div class="card">__PERSONAS__</div>
    <h2>What you practice &rarr; who does this work</h2>
    <div class="card">
      <p class="muted">These occupations do packet and detection analysis (or implement the controls) as their actual job &mdash; the skills this kit rehearses.</p>
      <table><tr><th>Skill you practice in this kit</th><th>O*NET</th><th>The real work it maps to</th></tr>__ALIGN_PRACTICE__</table>
    </div>
    <h2>Context: who this protects</h2>
    <div class="card">
      <p class="muted">These roles operate, maintain, design, or authored the systems under analysis &mdash; beneficiaries and design authorities, not skills the learner performs here.</p>
      <table><tr><th>Occupation</th><th>O*NET</th><th>Why they are in the room</th></tr>__ALIGN_CONTEXT__</table>
    </div>
  </section>

  <section id="refs"><h2>References &amp; sources</h2><div class="card"><ul>__REFS__</ul>
    <p class="foot">Companion module: <a href="__OTHER_HREF__">__OTHER_NAME__ module</a> &middot; <a href="../curriculum/index.html">First Light hub</a>. All frame numbers, field values, and CRCs verified with tshark and CISA ICSNPP/Zeek. This is a curated teaching capture &mdash; synthetic but protocol-valid.</p>
  </div></section>
</main>

<script>
const FRAMES = __FRAMES_JSON__;
const SEV = {"info":"#38bdf8","warn":"#f59e0b","critical":"#f87171"};
const SEVL = {"info":"NOTE","warn":"CAUTION","critical":"CRITICAL"};
const CMAP = {"info":"note","warn":"caution","critical":"crit"};
function dotColor(f){ if(f.anomaly) return "#f87171"; if(f.security) return SEV[f.security.level]||"#64748b"; return "#64748b"; }
function esc(s){return (s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

let sel = 0;
const flist = document.getElementById('flist');
function sevToken(f){
  if(f.anomaly) return {t:"CRIT", cls:"crit"};
  if(f.security) return ({info:{t:"NOTE",cls:"note"},warn:{t:"CAUTION",cls:"caution"},critical:{t:"CRIT",cls:"crit"}})[f.security.level] || {t:"OK",cls:"norm"};
  return {t:"OK", cls:"norm"};
}
function buildList(){
  const only = document.getElementById('anomOnly').checked;
  flist.innerHTML='';
  FRAMES.forEach((f,i)=>{
    if(only && !f.anomaly) return;
    const tok = sevToken(f);
    const row = document.createElement('div');
    row.className = 'frow'+(i===sel?' sel':'')+(f.anomaly?' anom':'');
    row.id = 'frow-'+i; row.dataset.i = i;
    row.setAttribute('role','option');
    row.setAttribute('aria-selected', i===sel ? 'true':'false');
    row.tabIndex = (i===sel ? 0 : -1);
    row.setAttribute('aria-label', `Frame ${f.n}, ${f.src} to ${f.dst}, ${f.layer}. ${f.anomaly?'Anomaly. ':''}Severity ${tok.t}. ${(f.summary||'').replace(/^⚠\s*/,'')}`);
    row.innerHTML = `<span class="fn">${f.n}</span>`+
      `<span class="dot" style="background:${dotColor(f)}" aria-hidden="true"></span>`+
      `<span class="sevtag sev-${tok.cls}">${tok.t}</span>`+
      `<span class="fsum">${esc(f.summary)}</span>`;
    row.addEventListener('click', ()=>selectRow(i,true));
    flist.appendChild(row);
  });
}
function selectRow(i, focus){ sel=i; render(); const row=document.getElementById('frow-'+i); if(row&&focus) row.focus(); }
function render(){
  document.querySelectorAll('.frow').forEach(r=>{const on=(+r.dataset.i===sel);r.classList.toggle('sel',on);r.setAttribute('aria-selected',on?'true':'false');r.tabIndex=on?0:-1;});
  const rr=document.querySelector('.frow.sel'); if(rr) rr.scrollIntoView({block:'nearest'});
  const f = FRAMES[sel];
  const kv = (f.fields||[]).map(x=>`<tr><td>${esc(x[0])}</td><td>${esc(x[1])}</td></tr>`).join('');
  let sec='';
  if(f.security){const lc=CMAP[f.security.level]||'note';sec=`<div class="fcallout c-${lc}"><b>${SEVL[f.security.level]}.</b> ${esc(f.security.note)}</div>`;}
  const anom = f.anomaly?` <span class="xbadge">ANOMALY</span>`:'';
  const hex = f.hex?`<h4>Application-layer bytes</h4><div class="hex">${esc(f.hex)}</div>`:'';
  document.getElementById('detail').innerHTML = `
    <h3>Frame ${f.n} &nbsp;<span class="fmeta">t=${f.t}s · ${esc(f.layer)}</span>${anom}</h3>
    <div class="pathline">${esc(f.src)} &nbsp;&rarr;&nbsp; ${esc(f.dst)} &nbsp;&middot;&nbsp; ${esc(f.summary)}</div>
    <p>${esc(f.plain)}</p>
    <table class="kv">${kv}</table>
    <div class="teach"><b>Why it matters.</b> ${esc(f.teach)}</div>
    ${sec}
    <div class="filterbar"><code>${esc(f.filter)}</code>
      <button class="copy" onclick="cp(this,'${esc(f.filter).replace(/'/g,"\\'")}')">Copy filter</button></div>
    ${hex}`;
}
function cp(btn,txt){ const t=btn.textContent;
  navigator.clipboard&&navigator.clipboard.writeText(txt).then(()=>{btn.textContent='Copied ✓';setTimeout(()=>btn.textContent=t,1200);},()=>{btn.textContent='Copy manually';});
}
document.getElementById('anomOnly').onchange=()=>{sel=0;buildList();render();};
// tabs
function show(t){
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
  document.querySelectorAll('main section').forEach(s=>s.classList.toggle('on',s.id===t));
  window.scrollTo({top:0,behavior:'instant'});
}
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>show(b.dataset.t));
document.querySelectorAll('.gotab').forEach(a=>a.onclick=ev=>{ev.preventDefault();show(a.dataset.t);});
// frame links from the security section
document.querySelectorAll('.framelink').forEach(a=>a.onclick=ev=>{ev.preventDefault();
  const n=+a.dataset.f; const i=FRAMES.findIndex(x=>x.n===n); if(i>=0){document.getElementById('anomOnly').checked=false;sel=i;buildList();render();show('explorer');}
});
flist.addEventListener('keydown', ev=>{
  const vis = [...flist.querySelectorAll('.frow')].map(r=>+r.dataset.i);
  const pos = vis.indexOf(sel);
  if(ev.key==='ArrowDown'){ev.preventDefault(); if(pos<vis.length-1) selectRow(vis[pos+1],true);}
  else if(ev.key==='ArrowUp'){ev.preventDefault(); if(pos>0) selectRow(vis[pos-1],true);}
  else if(ev.key==='Home'){ev.preventDefault(); selectRow(vis[0],true);}
  else if(ev.key==='End'){ev.preventDefault(); selectRow(vis[vis.length-1],true);}
  else if(ev.key==='Enter'||ev.key===' '){ev.preventDefault(); selectRow(sel,true);}
});
buildList(); render();

/* ============ theme: OS preference wins until the user overrides (persisted, shared with the hub) ============ */
(function(){
  try{
    var TK = "icskit.path.theme.v1";
    var btn = document.getElementById("themebtn");
    var ic = document.getElementById("theme-ic"), tx = document.getElementById("theme-tx");
    function stored(){ try{ return localStorage.getItem(TK); }catch(e){ return null; } }
    function osLight(){ try{ return window.matchMedia("(prefers-color-scheme: light)").matches; }catch(e){ return false; } }
    function effective(){ var s = stored(); if(s==="light"||s==="dark") return s; return osLight()?"light":"dark"; }
    function paint(){
      var s = stored();
      if(s==="light"||s==="dark"){ document.documentElement.setAttribute("data-theme", s); }
      else{ document.documentElement.removeAttribute("data-theme"); }
      var eff = effective();
      if(ic) ic.textContent = eff==="light" ? "◑" : "◐";
      if(tx) tx.textContent = eff==="light" ? "Light" : "Dark";
      if(btn) btn.setAttribute("aria-pressed", eff==="light" ? "true":"false");
    }
    if(btn) btn.addEventListener("click", function(){
      var next = effective()==="light" ? "dark" : "light";
      try{ localStorage.setItem(TK, next); }catch(e){}
      paint();
    });
    try{ window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", paint); }catch(e){}
    paint();
  }catch(e){}
})();

/* ============ living hero: the conversation constellation (single rAF, DPR, paused, reduced-motion still) ============ */
(function(){
  try{
    var cv = document.getElementById("constellation");
    if(!cv || !cv.getContext) return;
    var ctx = cv.getContext("2d");
    var RM=false; try{ RM = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }catch(e){}
    var proto = document.documentElement.getAttribute("data-proto") || "dnp3";
    var AC = proto==="mqtt" ? "#2dd4bf" : "#f59e0b";
    var GH = "#f87171";
    var W=0,H=0,DPR=1, running=false, onscreen=true, raf=0, last=0;
    var nodes=[], links=[], parts=[];

    function build(){
      if(proto==="mqtt"){
        nodes = [
          {id:"broker", x:.70, y:.44, r:6.5, c:AC, hub:1},
          {id:"s1", x:.87, y:.22, r:3.4, c:AC},
          {id:"s2", x:.91, y:.5, r:3.4, c:AC},
          {id:"s3", x:.82, y:.72, r:3.4, c:AC},
          {id:"s4", x:.6, y:.22, r:3.0, c:AC},
          {id:"ghost", x:.45, y:.72, r:5, c:GH, ghost:1}
        ];
        links = [
          {a:"broker",b:"s1",c:AC},{a:"broker",b:"s2",c:AC},{a:"broker",b:"s3",c:AC},{a:"broker",b:"s4",c:AC},
          {a:"ghost",b:"broker",c:GH,rogue:1}
        ];
      } else {
        nodes = [
          {id:"master", x:.6, y:.3, r:6, c:AC, hub:1},
          {id:"outst", x:.81, y:.58, r:5.5, c:AC},
          {id:"rtu2", x:.66, y:.76, r:3.4, c:AC},
          {id:"rtu3", x:.91, y:.32, r:3.4, c:AC},
          {id:"ghost", x:.45, y:.68, r:5, c:GH, ghost:1}
        ];
        links = [
          {a:"master",b:"outst",c:AC},{a:"master",b:"rtu3",c:AC},{a:"outst",b:"rtu2",c:AC},
          {a:"ghost",b:"outst",c:GH,rogue:1}
        ];
      }
      parts = [];
    }
    function N(id){ for(var i=0;i<nodes.length;i++) if(nodes[i].id===id) return nodes[i]; return null; }
    function resize(){
      var r = cv.getBoundingClientRect();
      DPR = Math.min(window.devicePixelRatio||1, 2);
      W = Math.max(1, r.width); H = Math.max(1, r.height);
      cv.width = Math.round(W*DPR); cv.height = Math.round(H*DPR);
      ctx.setTransform(DPR,0,0,DPR,0,0);
    }
    function px(n){ return {x:n.x*W, y:n.y*H}; }
    function spawn(){
      if(parts.length > 34) return;
      var l = links[(Math.random()*links.length)|0];
      parts.push({l:l, t:Math.random()*0.15, sp:0.10+Math.random()*0.16, rogue:l.rogue?1:0});
    }
    function glow(p, r, col, a){
      var g = ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,r*3.4);
      g.addColorStop(0, col); g.addColorStop(1, "rgba(0,0,0,0)");
      ctx.globalAlpha = a; ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(p.x,p.y,r*3.4,0,6.2832); ctx.fill(); ctx.globalAlpha=1;
    }
    function frame(ts){
      if(!running){ return; }
      var dt = last ? Math.min(0.05,(ts-last)/1000) : 0.016; last = ts;
      ctx.clearRect(0,0,W,H);
      links.forEach(function(l){
        var a=px(N(l.a)), b=px(N(l.b));
        ctx.strokeStyle = l.c; ctx.globalAlpha = l.rogue?0.13:0.17; ctx.lineWidth = 1;
        if(l.rogue){ ctx.setLineDash([3,5]); } else { ctx.setLineDash([]); }
        ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
      });
      ctx.setLineDash([]); ctx.globalAlpha=1;
      nodes.forEach(function(n){
        var p=px(n);
        var jx = n.ghost ? Math.sin(ts/230)*2.2 : 0;
        var jy = n.ghost ? Math.cos(ts/190)*1.6 : 0;
        var pp = {x:p.x+jx, y:p.y+jy};
        glow(pp, n.r, n.c, n.ghost ? (0.5+0.3*Math.abs(Math.sin(ts/300))) : (n.hub?0.5:0.34));
        ctx.fillStyle = n.c; ctx.beginPath(); ctx.arc(pp.x,pp.y,n.r,0,6.2832); ctx.fill();
        if(n.hub){ ctx.strokeStyle=n.c; ctx.globalAlpha=.5; ctx.lineWidth=1.4;
          ctx.beginPath(); ctx.arc(pp.x,pp.y,n.r+4,0,6.2832); ctx.stroke(); ctx.globalAlpha=1; }
      });
      for(var i=parts.length-1;i>=0;i--){
        var pt=parts[i]; pt.t += pt.sp*dt* (pt.rogue? (0.7+0.6*Math.abs(Math.sin(ts/160))) : 1);
        if(pt.t>=1){ parts.splice(i,1); continue; }
        var a=px(N(pt.l.a)), b=px(N(pt.l.b));
        var x=a.x+(b.x-a.x)*pt.t, y=a.y+(b.y-a.y)*pt.t;
        var jj = pt.rogue ? Math.sin(pt.t*30)*1.5 : 0;
        glow({x:x,y:y+jj}, 2.4, pt.l.c, 0.9);
        ctx.fillStyle="#fff"; ctx.globalAlpha=.85; ctx.beginPath(); ctx.arc(x,y+jj,1.5,0,6.2832); ctx.fill(); ctx.globalAlpha=1;
      }
      if(Math.random()<0.4) spawn();
      raf = requestAnimationFrame(frame);
    }
    function still(){
      resize(); ctx.clearRect(0,0,W,H);
      links.forEach(function(l){ var a=px(N(l.a)),b=px(N(l.b));
        ctx.strokeStyle=l.c; ctx.globalAlpha=l.rogue?0.13:0.17; ctx.lineWidth=1;
        if(l.rogue) ctx.setLineDash([3,5]); else ctx.setLineDash([]);
        ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
      });
      ctx.setLineDash([]); ctx.globalAlpha=1;
      nodes.forEach(function(n){ var p=px(n); glow(p,n.r,n.c,n.hub?0.5:(n.ghost?0.6:0.34));
        ctx.fillStyle=n.c; ctx.beginPath(); ctx.arc(p.x,p.y,n.r,0,6.2832); ctx.fill(); });
      links.forEach(function(l,idx){ var a=px(N(l.a)),b=px(N(l.b)); var t=0.35+(idx%3)*0.12;
        var x=a.x+(b.x-a.x)*t,y=a.y+(b.y-a.y)*t; glow({x:x,y:y},2.2,l.c,0.8);
        ctx.fillStyle="#fff"; ctx.beginPath(); ctx.arc(x,y,1.4,0,6.2832); ctx.fill(); });
    }
    function start(){ if(running) return; if(RM||document.hidden||!onscreen){ return; } running=true; last=0; raf=requestAnimationFrame(frame); }
    function stop(){ running=false; if(raf) cancelAnimationFrame(raf); raf=0; }

    build(); resize();
    if(RM){ still(); }
    else{
      try{
        var io = new IntersectionObserver(function(en){ onscreen = en[0].isIntersecting; if(onscreen) start(); else stop(); }, {threshold:0.02});
        io.observe(cv);
      }catch(e){ onscreen=true; }
      document.addEventListener("visibilitychange", function(){ if(document.hidden) stop(); else start(); });
      var rt=0; window.addEventListener("resize", function(){ clearTimeout(rt); rt=setTimeout(function(){ resize(); if(!running && !RM) still(); }, 150); }, {passive:true});
      start();
      setTimeout(function(){ if(!running) still(); }, 400);
    }
  }catch(e){ /* canvas failure never breaks the page — the CSS gradient remains */ }
})();
</script>
</body></html>"""


def build_index():
    with open(os.path.join(OUT_DIR, "index.html"), "w") as f:
        f.write(INDEX)


INDEX = r"""<!DOCTYPE html><html lang="en" data-proto="hub"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>ICS/OT Protocol Analysis Lab Kit — Modules</title>
<style>
:root{
  color-scheme:dark;
  --bg:#0a0e1a; --bg-raise:#111725; --card:#131a2b; --line:#232e49;
  --ink:#e8edf7; --mut:#9aa7bd; --faint:#64748b; --link:#a5b4fc; --accent-glow:#818cf8;
  --dnp3:#f59e0b; --mqtt:#2dd4bf;
  --step--1:clamp(.78rem,.75rem + .18vw,.86rem);
  --step-0:clamp(.95rem,.9rem + .25vw,1.05rem);
  --step-2:clamp(1.2rem,1.1rem + .6vw,1.45rem);
  --step-4:clamp(1.7rem,1.4rem + 1.4vw,2.25rem);
  --ease:cubic-bezier(.4,0,.2,1);
}
html[data-theme="light"]{color-scheme:light;--bg:#f1f5f9;--bg-raise:#e9eef5;--card:#fff;--line:#e2e8f0;
  --ink:#1e293b;--mut:#475569;--faint:#94a3b8;--link:#4f46e5;--accent-glow:#6366f1;--dnp3:#b45309;--mqtt:#0f766e}
@media(prefers-color-scheme:light){:root:not([data-theme]){color-scheme:light;--bg:#f1f5f9;--bg-raise:#e9eef5;--card:#fff;--line:#e2e8f0;
  --ink:#1e293b;--mut:#475569;--faint:#94a3b8;--link:#4f46e5;--accent-glow:#6366f1;--dnp3:#b45309;--mqtt:#0f766e}}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--ink);background:var(--bg);line-height:1.6;font-size:var(--step-0);-webkit-font-smoothing:antialiased}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent-glow);outline-offset:2px;border-radius:4px}
.hero{position:relative;overflow:hidden;color:#e8edf7;padding:clamp(2rem,4vw,3.4rem) clamp(1.1rem,2vw,2.4rem)}
.hero::before{content:"";position:absolute;inset:0;z-index:0;background:
  radial-gradient(120% 90% at 82% 4%,rgba(245,158,11,.16),transparent 55%),
  radial-gradient(90% 80% at 8% 0%,rgba(45,212,191,.14),transparent 55%),
  linear-gradient(160deg,#0b1020,#0a0e1a 55%,#080b14)}
.heroinner{position:relative;z-index:1;max-width:960px;margin:0 auto}
.kick{font-size:var(--step--1);letter-spacing:.2em;text-transform:uppercase;color:#aeb9d6;font-weight:700}
.hero h1{margin:.15em 0 .3em;font-size:var(--step-4);line-height:1.08;letter-spacing:-.02em;font-weight:800;max-width:22ch}
.hero p{color:#c9d3e6;margin:0;max-width:64ch;font-size:var(--step-0)}
.themebtn{position:absolute;top:clamp(1rem,2vw,1.6rem);right:clamp(1rem,2vw,1.6rem);z-index:2;
  display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);
  color:#e8edf7;border-radius:10px;padding:7px 12px;font-size:var(--step--1);cursor:pointer;font-weight:600}
.themebtn:hover{background:rgba(255,255,255,.16)}
main{max-width:960px;margin:0 auto;padding:24px 18px 64px}
.mods{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:18px 0}
.mod{display:block;text-decoration:none;color:inherit;background:linear-gradient(180deg,var(--card),var(--bg-raise));
  border:1px solid var(--line);border-radius:16px;padding:20px 22px;position:relative;overflow:hidden;
  transition:transform .18s var(--ease),border-color .18s var(--ease),box-shadow .18s var(--ease)}
.mod::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px}
.mod.dnp3::before{background:linear-gradient(180deg,var(--dnp3),#b45309)}
.mod.mqtt::before{background:linear-gradient(180deg,var(--mqtt),#0f766e)}
.mod:hover{transform:translateY(-2px);border-color:var(--accent-glow);box-shadow:0 14px 34px -18px rgba(0,0,0,.7);text-decoration:none}
.mod h2{margin:.35em 0 .2em;font-size:var(--step-2)}
.mod .muted{color:var(--mut)}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:800;letter-spacing:.05em;
  padding:4px 11px;border-radius:20px;border:1px solid}
.badge::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 9px currentColor}
.badge.d{color:var(--dnp3);background:color-mix(in srgb,var(--dnp3) 15%,transparent);border-color:color-mix(in srgb,var(--dnp3) 32%,transparent)}
.badge.m{color:var(--mqtt);background:color-mix(in srgb,var(--mqtt) 15%,transparent);border-color:color-mix(in srgb,var(--mqtt) 32%,transparent)}
.card{background:linear-gradient(180deg,var(--card),var(--bg-raise));border:1px solid var(--line);border-radius:16px;padding:18px 22px;margin:14px 0}
.card h3{margin:.1em 0 .5em}
code{background:color-mix(in srgb,var(--accent-glow) 14%,transparent);border:1px solid color-mix(in srgb,var(--accent-glow) 24%,transparent);
  padding:1px 6px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}
ul{margin:.4em 0;padding-left:1.3em}li{margin:.3em 0}li::marker{color:var(--accent-glow)}
.muted{color:var(--mut)}
.foot{color:var(--faint);font-size:var(--step--1);margin-top:8px}
.foot a{color:var(--link);font-weight:600}
@media(max-width:720px){.mods{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){*{animation:none !important;transition:none !important}}
</style></head><body>
<header class="hero">
  <button class="themebtn" id="themebtn" type="button" aria-pressed="false" aria-label="Toggle light and dark theme">
    <span id="theme-ic" aria-hidden="true">&#9680;</span><span id="theme-tx">Dark</span></button>
  <div class="heroinner">
    <div class="kick">ICS &middot; OT Signal Field</div>
    <h1>Protocol Analysis Lab Kit &mdash; Modules</h1>
    <p>Hands-on packet analysis for DNP3 &amp; MQTT &mdash; built with CISA ICSNPP, Wireshark, and Zeek. Part of the <a href="../curriculum/index.html" style="color:#c7d2fe">First Light</a> curriculum.</p>
  </div>
</header>
<main>
<div class="mods">
  <a class="mod dnp3" href="dnp3_module.html"><span class="badge d">DNP3</span>
    <h2>DNP3 &mdash; Substation SCADA</h2>
    <p class="muted">Master/outstation polling &amp; control on TCP/20000, a supervised breaker close, and an unauthenticated command-injection attack &mdash; frame by frame.</p></a>
  <a class="mod mqtt" href="mqtt_module.html"><span class="badge m">MQTT</span>
    <h2>MQTT &mdash; IIoT Telemetry</h2>
    <p class="muted">Publish/subscribe telemetry on TCP/1883, broker fan-out, and an anonymous eavesdrop-and-inject intrusion &mdash; frame by frame.</p></a>
</div>
<div class="card"><h3>What's in the kit</h3>
<ul>
<li>Two verified teaching captures: <code>dnp3_substation.pcap</code> and <code>mqtt_iot_telemetry.pcap</code>.</li>
<li>Two interactive modules (this HTML) plus Word, PDF, and Markdown versions.</li>
<li>A runnable Docker lab: Mosquitto broker, a Python DNP3 outstation/master, tcpreplay, and Zeek + CISA ICSNPP parsers.</li>
<li>Student worksheets, instructor answer keys, and real Zeek/ICSNPP reference logs.</li>
</ul>
<p class="muted">Open a module, read the Overview, then work the Frame Explorer with the matching .pcap open in Wireshark.</p>
<p class="foot">Return to the <a href="../curriculum/index.html">First Light hub</a>.</p></div>
</main>
<script>
(function(){ try{
  var TK="icskit.path.theme.v1", btn=document.getElementById("themebtn");
  var ic=document.getElementById("theme-ic"), tx=document.getElementById("theme-tx");
  function stored(){ try{ return localStorage.getItem(TK); }catch(e){ return null; } }
  function osLight(){ try{ return window.matchMedia("(prefers-color-scheme: light)").matches; }catch(e){ return false; } }
  function effective(){ var s=stored(); if(s==="light"||s==="dark") return s; return osLight()?"light":"dark"; }
  function paint(){ var s=stored();
    if(s==="light"||s==="dark"){ document.documentElement.setAttribute("data-theme", s); } else { document.documentElement.removeAttribute("data-theme"); }
    var eff=effective(); if(ic) ic.textContent=eff==="light"?"◑":"◐"; if(tx) tx.textContent=eff==="light"?"Light":"Dark";
    if(btn) btn.setAttribute("aria-pressed", eff==="light"?"true":"false"); }
  if(btn) btn.addEventListener("click", function(){ var n=effective()==="light"?"dark":"light"; try{ localStorage.setItem(TK,n);}catch(e){} paint(); });
  try{ window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", paint); }catch(e){}
  paint();
}catch(e){} })();
</script>
</body></html>"""


if __name__ == "__main__":
    with open(os.path.join(OUT_DIR, "dnp3_module.html"), "w") as f:
        f.write(render_module(DNP3))
    with open(os.path.join(OUT_DIR, "mqtt_module.html"), "w") as f:
        f.write(render_module(MQTT))
    build_index()
    print("HTML modules written to", OUT_DIR)
    for fn in ("index.html", "dnp3_module.html", "mqtt_module.html"):
        p = os.path.join(OUT_DIR, fn)
        print(" ", fn, os.path.getsize(p), "bytes")
