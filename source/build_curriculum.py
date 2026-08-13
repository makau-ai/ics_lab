# -*- coding: utf-8 -*-
"""Render the leveled curriculum (content_levels.LEVELS) into student-facing outputs.

Produces:
  curriculum/index.html   — self-contained interactive Levels hub (progress tracking,
                            expandable cards, copyable commands, checkpoint reveals).
  curriculum/LEVEL_n.md   — one Markdown file per level.
  CURRICULUM.md           — a single combined walkthrough (kit root).

No external dependencies; safe to open from file://. Progress is stored in localStorage
inside a try/catch so the page still works where storage is unavailable.
"""
import html
import os
import re

from content_levels import LEVELS

KIT = "/root/icsnpp_kit"
OUT_HTML_DIR = os.path.join(KIT, "curriculum")
os.makedirs(OUT_HTML_DIR, exist_ok=True)

ACCENT = "#4f46e5"    # indigo — the "learning path" identity (distinct from DNP3 amber / MQTT teal)
ACCENT2 = "#7c3aed"   # violet

DIFF_CLASS = {
    "Start here": "d-start",
    "Introductory": "d-intro",
    "Intermediate": "d-inter",
    "Advanced": "d-adv",
    "UIUC-level capstone": "d-cap",
}


def e(x):
    return html.escape(str(x), quote=True)


def md_inline(s):
    """Minimal inline markdown → HTML: **bold** and `code`, escaped."""
    s = e(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


# ---------------------------------------------------------------- HTML rendering
def step_html(st):
    kind = st.get("kind", "note")
    if kind == "cmd":
        cmd = e(st["text"])
        exp = st.get("expect")
        exp_html = ""
        if exp:
            exp_html = (f'<div class="expect"><span class="explabel">Expected</span>'
                        f'<pre class="expbody">{e(exp)}</pre></div>')
        return (
            '<div class="step cmd">'
            '<div class="cmdbar"><span class="kind kind-cmd">Terminal</span>'
            '<button class="copy" type="button" onclick="cpPre(this)">Copy</button></div>'
            f'<pre class="term">{cmd}</pre>{exp_html}</div>'
        )
    if kind == "gui":
        return (f'<div class="step gui"><span class="kind kind-gui">In Wireshark</span>'
                f'<div class="steptext">{md_inline(st["text"])}</div></div>')
    # note
    return (f'<div class="step note"><span class="kind kind-note">Note</span>'
            f'<div class="steptext">{md_inline(st["text"])}</div></div>')


def checkpoint_html(cp):
    return (
        '<details class="cp"><summary><span class="cpq">'
        f'{md_inline(cp["q"])}</span></summary>'
        f'<div class="cpa">{md_inline(cp["a"])}</div></details>'
    )


def level_html(lv):
    n = lv["n"]
    dcls = DIFF_CLASS.get(lv["difficulty"], "d-intro")
    is_mp = lv.get("is_mp")
    objectives = "".join(f"<li>{md_inline(o)}</li>" for o in lv["objectives"])
    background = "".join(f"<p>{md_inline(b)}</p>" for b in lv["background"])
    steps = "".join(step_html(s) for s in lv["steps"])
    checks = "".join(checkpoint_html(c) for c in lv["checkpoints"])
    open_attr = " open" if n == 0 else ""
    mpclass = " mp" if is_mp else ""

    # capstone gets a launch link to the MP handout
    mp_launch = ""
    if is_mp:
        mp_launch = (
            '<div class="mplaunch">'
            '<b>This is the capstone.</b> The full handout, the two evidence captures, the answer '
            'template, the self-check autograder, and the report rubric are in the '
            '<code>mp/</code> folder. Start with <a href="../mp/README.md">mp/README.md</a>.'
            '</div>'
        )

    return f"""
<section class="lvl{mpclass}" id="level-{n}">
  <div class="lvlhead">
    <div class="lvlnum" aria-hidden="true">{n}</div>
    <div class="lvlmeta">
      <div class="lvltitle">Level {n} — {e(lv['title'])}
        <span class="dbadge {dcls}">{e(lv['difficulty'])}</span>
        <span class="mins">~{e(lv['minutes'])} min</span>
      </div>
      <div class="lvlsub">{e(lv['subtitle'])}</div>
    </div>
    <label class="donebox" title="Mark this level complete">
      <input type="checkbox" class="donechk" data-level="{n}"><span>Done</span>
    </label>
  </div>
  <div class="lvlgoal"><span class="goallabel">Goal</span> {md_inline(lv['goal'])}</div>
  {mp_launch}
  <details class="lvlbody"{open_attr}>
    <summary><span class="openlabel">Open this level</span><span class="closelabel">Hide this level</span></summary>
    <div class="lvlinner">
      <h4>What you'll be able to do</h4>
      <ul class="obj">{objectives}</ul>
      <p class="prereq"><b>Prerequisite:</b> {md_inline(lv['prereq'])}</p>
      <h4>Background</h4>
      <div class="bg">{background}</div>
      <h4>Do this</h4>
      <div class="steps">{steps}</div>
      <h4>Check yourself</h4>
      <div class="checks">{checks}</div>
      <div class="levelup"><span class="lulabel">Level up</span> {md_inline(lv['levelup'])}</div>
    </div>
  </details>
</section>"""


def build_hub():
    cards = "".join(level_html(lv) for lv in LEVELS)
    # mini-nav dots
    nav = "".join(
        f'<a href="#level-{lv["n"]}" class="navdot" data-level="{lv["n"]}" '
        f'title="Level {lv["n"]}: {e(lv["title"])}"><span class="nd-n">{lv["n"]}</span>'
        f'<span class="nd-t">{e(lv["title"])}</span></a>'
        for lv in LEVELS
    )
    total = len(LEVELS)
    page = HUB_TEMPLATE
    page = page.replace("__ACCENT__", ACCENT).replace("__ACCENT2__", ACCENT2)
    page = page.replace("__CARDS__", cards)
    page = page.replace("__NAV__", nav)
    page = page.replace("__TOTAL__", str(total))
    with open(os.path.join(OUT_HTML_DIR, "index.html"), "w") as f:
        f.write(page)


HUB_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Learning Path — DNP3 &amp; MQTT Packet Analysis</title>
<style>
:root{--accent:__ACCENT__;--accent2:__ACCENT2__;--ink:#1e293b;--mut:#475569;--line:#e2e8f0;--bg:#f1f5f9;--card:#fff;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:var(--ink);background:var(--bg);line-height:1.55;font-size:15.5px}
a{color:var(--accent)}
header{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;padding:30px 22px 22px}
header .kick{font-size:12px;letter-spacing:.14em;text-transform:uppercase;opacity:.9}
header h1{margin:.15em 0 .12em;font-size:27px}
header .sub{opacity:.96;margin:0 0 14px;max-width:70ch}
.progwrap{background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);border-radius:12px;
padding:12px 14px;max-width:560px}
.progrow{display:flex;justify-content:space-between;align-items:center;font-size:13px;margin-bottom:7px}
.progbar{height:10px;background:rgba(255,255,255,.25);border-radius:20px;overflow:hidden}
.progfill{height:100%;width:0;background:#fff;border-radius:20px;transition:width .3s ease}
.reset{background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.4);color:#fff;border-radius:8px;
padding:3px 10px;font-size:12px;cursor:pointer}
.reset:hover{background:rgba(255,255,255,.28)}
.layout{max-width:1080px;margin:0 auto;padding:20px 18px 70px;display:grid;grid-template-columns:210px 1fr;gap:22px}
/* left rail nav */
.rail{position:sticky;top:16px;align-self:start;max-height:92vh;overflow:auto}
.railh{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin:2px 0 8px 6px}
.navdot{display:flex;gap:9px;align-items:center;text-decoration:none;color:var(--ink);padding:7px 8px;
border-radius:9px;margin-bottom:2px}
.navdot:hover{background:#eef2ff}
.navdot .nd-n{flex:0 0 auto;width:23px;height:23px;border-radius:50%;background:#e2e8f0;color:var(--mut);
font-weight:700;font-size:12.5px;display:flex;align-items:center;justify-content:center}
.navdot.done .nd-n{background:#16a34a;color:#fff}
.navdot .nd-t{font-size:12.5px;color:var(--mut);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.navdot.active{background:#eef2ff}
.navdot.active .nd-t{color:var(--ink);font-weight:600}
main{min-width:0}
.intro{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--accent);
border-radius:12px;padding:14px 18px;margin:0 0 18px}
.intro h2{margin:.1em 0 .3em;font-size:18px}
.intro p{margin:.4em 0}
.pathline{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:10px 0 2px;font-size:12.5px;color:var(--mut)}
.pathline .pl{background:#eef2ff;border:1px solid #e0e7ff;color:var(--accent);border-radius:20px;padding:2px 9px;font-weight:600}
.pathline .arr{color:#94a3b8}
/* level card */
.lvl{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:0;margin:0 0 16px;
box-shadow:0 1px 2px rgba(15,23,42,.05);overflow:hidden}
.lvl.done{border-color:#bbf7d0}
.lvl.mp{border-color:#ddd6fe;box-shadow:0 3px 16px rgba(124,58,237,.12)}
.lvlhead{display:flex;gap:14px;align-items:center;padding:15px 18px 12px}
.lvlnum{flex:0 0 auto;width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));
color:#fff;font-weight:800;font-size:19px;display:flex;align-items:center;justify-content:center}
.lvl.done .lvlnum{background:linear-gradient(135deg,#16a34a,#15803d)}
.lvlmeta{flex:1;min-width:0}
.lvltitle{font-size:17px;font-weight:700;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.lvlsub{color:var(--mut);font-size:13.5px;margin-top:1px}
.dbadge{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px}
.d-start{background:#e0f2fe;color:#0369a1}.d-intro{background:#dcfce7;color:#15803d}
.d-inter{background:#fef9c3;color:#a16207}.d-adv{background:#ffedd5;color:#9a3412}
.d-cap{background:#ede9fe;color:#6d28d9}
.mins{font-size:12px;color:var(--mut);font-weight:600}
.donebox{flex:0 0 auto;display:flex;gap:6px;align-items:center;font-size:13px;color:var(--mut);
cursor:pointer;user-select:none;border:1px solid var(--line);border-radius:20px;padding:5px 11px}
.donebox:hover{background:#f8fafc}
.donebox input{accent-color:#16a34a;width:15px;height:15px}
.lvl.done .donebox{color:#15803d;border-color:#bbf7d0;background:#f0fdf4}
.lvlgoal{margin:0 18px 12px;background:#f8fafc;border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:14.5px}
.goallabel{font-size:10.5px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:var(--accent);
margin-right:7px}
.mplaunch{margin:0 18px 12px;background:#f5f3ff;border:1px solid #ddd6fe;border-radius:9px;padding:10px 13px;font-size:14px}
.lvlbody{margin:0 0 4px;border-top:1px solid var(--line)}
.lvlbody>summary{cursor:pointer;list-style:none;padding:11px 18px;font-weight:600;color:var(--accent);font-size:14px;
display:flex;align-items:center;gap:8px}
.lvlbody>summary::-webkit-details-marker{display:none}
.lvlbody>summary::before{content:"▸";display:inline-block;transition:transform .15s}
.lvlbody[open]>summary::before{transform:rotate(90deg)}
.lvlbody .closelabel{display:none}.lvlbody[open] .openlabel{display:none}.lvlbody[open] .closelabel{display:inline}
.lvlinner{padding:2px 18px 18px}
h4{margin:1.1em 0 .4em;font-size:14px;color:#334155;text-transform:uppercase;letter-spacing:.03em;font-weight:800}
.obj{margin:.2em 0;padding-left:1.2em}
.obj li{margin:.2em 0}
.prereq{font-size:13.5px;color:var(--mut);background:#f8fafc;border-radius:7px;padding:6px 10px}
.bg p{margin:.5em 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#eef2ff;padding:1px 5px;border-radius:4px;font-size:.9em}
/* steps */
.step{margin:9px 0;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.step.cmd{border-color:#1e293b}
.cmdbar{display:flex;align-items:center;justify-content:space-between;background:#1e293b;padding:5px 10px}
.kind{font-size:10.5px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;padding:2px 8px;border-radius:20px}
.kind-cmd{background:#334155;color:#e2e8f0}
.copy{border:1px solid #475569;background:#0f172a;color:#e2e8f0;border-radius:6px;padding:2px 10px;cursor:pointer;font-size:12px}
.copy:hover{background:#1e293b}
.term{margin:0;background:#0f172a;color:#e2e8f0;padding:11px 13px;font-size:12.9px;overflow-x:auto;white-space:pre;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;line-height:1.5}
.expect{background:#f8fafc;border-top:1px dashed var(--line);padding:8px 12px}
.explabel{font-size:10px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:#16a34a}
.expbody{margin:5px 0 0;white-space:pre-wrap;font-size:12.6px;color:#334155;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.step.gui,.step.note{display:flex;gap:11px;align-items:flex-start;padding:10px 13px;background:#fff}
.step.gui{background:#eff6ff}.step.note{background:#fffbeb}
.kind-gui{background:#dbeafe;color:#1d4ed8;flex:0 0 auto;margin-top:1px}
.kind-note{background:#fef3c7;color:#92400e;flex:0 0 auto;margin-top:1px}
.steptext{flex:1}
/* checkpoints */
.cp{border:1px solid var(--line);border-radius:9px;margin:7px 0;background:#fff}
.cp>summary{cursor:pointer;padding:9px 12px;list-style:none;font-size:14px;display:flex;gap:8px;align-items:flex-start}
.cp>summary::-webkit-details-marker{display:none}
.cp>summary::before{content:"?";flex:0 0 auto;width:19px;height:19px;border-radius:50%;background:var(--accent);
color:#fff;font-weight:800;font-size:12px;display:flex;align-items:center;justify-content:center;margin-top:1px}
.cp[open]>summary::before{content:"✓";background:#16a34a}
.cpq{font-weight:600}
.cpa{padding:2px 12px 11px 40px;color:#334155;font-size:14px}
.levelup{margin-top:14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:9px;padding:9px 12px;font-size:14px}
.lulabel{font-size:10.5px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:#15803d;margin-right:7px}
.footer{max-width:1080px;margin:0 auto;padding:0 18px 50px;color:var(--mut);font-size:12.8px}
.footer a{white-space:nowrap}
.jump{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:0 0 18px}
.jump h3{margin:.1em 0 .5em;font-size:15px}
.jump .links{display:flex;flex-wrap:wrap;gap:9px}
.jump .links a{text-decoration:none;background:#eef2ff;border:1px solid #e0e7ff;border-radius:9px;padding:7px 12px;
font-size:13.5px;color:var(--accent);font-weight:600}
.jump .links a:hover{background:#e0e7ff}
@media(max-width:820px){.layout{grid-template-columns:1fr}.rail{position:static;max-height:none;
display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px}.railh{width:100%}.navdot .nd-t{display:none}
.navdot{padding:6px}}
</style></head>
<body>
<header>
  <div class="kick">ICS / OT Protocol Analysis Lab Kit &nbsp;·&nbsp; Learning Path</div>
  <h1>DNP3 &amp; MQTT — from first packet to a UIUC-style Machine Problem</h1>
  <p class="sub">Seven levels, in order. Start by watching live traffic, learn who is talking, then what they say,
  then open the packets byte by byte — and finish by catching an intruder you've never seen. Everything auto-starts
  in this Codespace; you just work the levels.</p>
  <div class="progwrap">
    <div class="progrow"><span id="progtext">0 of __TOTAL__ levels complete</span>
      <button class="reset" id="resetbtn" type="button">Reset progress</button></div>
    <div class="progbar"><div class="progfill" id="progfill"></div></div>
  </div>
</header>

<div class="layout">
  <aside class="rail" aria-label="Level navigation">
    <div class="railh">Levels</div>
    __NAV__
  </aside>
  <main>
    <div class="intro">
      <h2>How this path works</h2>
      <p>Each level builds on the one before it. Read the <b>Goal</b>, expand the level, and run the commands in
      the terminal (a <span class="kind kind-cmd" style="text-transform:uppercase">Terminal</span> block copies with one click) or follow the
      <span class="kind kind-gui" style="text-transform:uppercase">In&nbsp;Wireshark</span> steps on the noVNC desktop. Tick <b>Done</b> as you finish — your
      progress is saved in this browser. The last level is a graded-style capstone.</p>
      <div class="pathline">
        <span class="pl">tooling</span><span class="arr">→</span>
        <span class="pl">endpoints</span><span class="arr">→</span>
        <span class="pl">message types</span><span class="arr">→</span>
        <span class="pl">inside the packet</span><span class="arr">→</span>
        <span class="pl">find the attack</span><span class="arr">→</span>
        <span class="pl">detection</span><span class="arr">→</span>
        <span class="pl">Machine Problem</span>
      </div>
    </div>

    <div class="jump">
      <h3>Reference material (open in a second tab as you go)</h3>
      <div class="links">
        <a href="../modules/dnp3_module.html">DNP3 module — frame explorer</a>
        <a href="../modules/mqtt_module.html">MQTT module — frame explorer</a>
        <a href="../mp/README.md">Machine Problem handout</a>
        <a href="../LAB_GUIDE.md">Lab guide</a>
      </div>
    </div>

    __CARDS__
  </main>
</div>
<div class="footer">
  <p>All commands and expected outputs on this page were verified with tshark 4.2 against the shipped captures
  (<code>pcaps/dnp3_substation.pcap</code>, <code>pcaps/mqtt_iot_telemetry.pcap</code>). Progress tracking uses this
  browser's local storage only — nothing leaves your machine. See <code>FORMAL_VERIFICATION.md</code> for the full
  verification record and <code>EXTERNAL_CAPTURES.md</code> for additional government/university captures you can
  practice on.</p>
</div>

<script>
(function(){
  var KEY = "icskit.path.progress.v1";
  var TOTAL = __TOTAL__;
  var done = new Set();
  function load(){
    try{ var raw = localStorage.getItem(KEY); if(raw){ JSON.parse(raw).forEach(function(n){done.add(+n);}); } }
    catch(e){ /* storage unavailable — run without persistence */ }
  }
  function save(){
    try{ localStorage.setItem(KEY, JSON.stringify([].concat(Array.from(done)))); }
    catch(e){ /* ignore */ }
  }
  function apply(){
    document.querySelectorAll('.donechk').forEach(function(chk){
      var n = +chk.dataset.level, on = done.has(n);
      chk.checked = on;
      var card = document.getElementById('level-'+n); if(card) card.classList.toggle('done', on);
      var dot = document.querySelector('.navdot[data-level="'+n+'"]'); if(dot) dot.classList.toggle('done', on);
    });
    var c = done.size, pct = TOTAL? Math.round(c/TOTAL*100):0;
    var fill = document.getElementById('progfill'); if(fill) fill.style.width = pct+'%';
    var t = document.getElementById('progtext'); if(t) t.textContent = c+' of '+TOTAL+' levels complete';
  }
  load();
  document.querySelectorAll('.donechk').forEach(function(chk){
    chk.addEventListener('change', function(){
      var n = +chk.dataset.level;
      if(chk.checked) done.add(n); else done.delete(n);
      save(); apply();
    });
  });
  var rb = document.getElementById('resetbtn');
  if(rb) rb.addEventListener('click', function(){ done.clear(); save(); apply(); });
  apply();

  // active-level highlight in the rail
  var cards = [].slice.call(document.querySelectorAll('.lvl'));
  function onScroll(){
    var y = window.scrollY + 140, cur = null;
    cards.forEach(function(c){ if(c.offsetTop <= y) cur = c.id; });
    document.querySelectorAll('.navdot').forEach(function(d){
      d.classList.toggle('active', d.getAttribute('href') === '#'+cur);
    });
  }
  window.addEventListener('scroll', onScroll, {passive:true}); onScroll();
})();

function cpPre(btn){
  var pre = btn.closest('.step').querySelector('pre.term');
  if(!pre) return;
  var txt = pre.textContent, orig = btn.textContent;
  function ok(){ btn.textContent = 'Copied ✓'; setTimeout(function(){ btn.textContent = orig; }, 1200); }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(ok, function(){ btn.textContent = 'Select & copy'; });
  } else {
    var r = document.createRange(); r.selectNodeContents(pre);
    var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); ok();
  }
}
</script>
</body></html>"""


# ---------------------------------------------------------------- Markdown rendering
def level_md(lv):
    n = lv["n"]
    L = []
    L.append(f"# Level {n} — {lv['title']}")
    L.append("")
    L.append(f"*{lv['subtitle']}*")
    L.append("")
    L.append(f"**Difficulty:** {lv['difficulty']} &nbsp;·&nbsp; **Time:** ~{lv['minutes']} min &nbsp;·&nbsp; "
             f"**Prerequisite:** {lv['prereq']}")
    L.append("")
    L.append(f"**Goal.** {lv['goal']}")
    L.append("")
    L.append("## What you'll be able to do")
    L.append("")
    for o in lv["objectives"]:
        L.append(f"- {o}")
    L.append("")
    L.append("## Background")
    L.append("")
    for b in lv["background"]:
        L.append(b)
        L.append("")
    L.append("## Do this")
    L.append("")
    for st in lv["steps"]:
        kind = st.get("kind", "note")
        if kind == "cmd":
            L.append("```bash")
            L.append(st["text"])
            L.append("```")
            if st.get("expect"):
                L.append(f"> **Expected:** {st['expect']}")
            L.append("")
        elif kind == "gui":
            L.append(f"- **In Wireshark:** {st['text']}")
        else:
            L.append(f"- **Note:** {st['text']}")
    L.append("")
    L.append("## Check yourself")
    L.append("")
    for i, c in enumerate(lv["checkpoints"], 1):
        L.append(f"{i}. **{c['q']}**")
        L.append(f"   <details><summary>answer</summary>{c['a']}</details>")
        L.append("")
    if lv.get("is_mp"):
        L.append("> **Capstone.** The handout, evidence captures, answer template, autograder, and rubric are in "
                 "the `mp/` folder — start with `mp/README.md`.")
        L.append("")
    L.append(f"**Level up:** {lv['levelup']}")
    L.append("")
    return "\n".join(L)


def build_markdown():
    # per-level files
    for lv in LEVELS:
        with open(os.path.join(OUT_HTML_DIR, f"LEVEL_{lv['n']}.md"), "w") as f:
            f.write(level_md(lv))
    # combined
    C = []
    C.append("# ICS/OT Protocol Analysis — Leveled Learning Path")
    C.append("")
    C.append("From first packet to a UIUC-style Machine Problem. Work the levels in order. Every command and "
             "expected output here was verified with tshark against the shipped captures "
             "(`pcaps/dnp3_substation.pcap`, `pcaps/mqtt_iot_telemetry.pcap`).")
    C.append("")
    C.append("**The arc:** tooling → endpoints → message types → inside the packet → find the attack → "
             "detection → Machine Problem.")
    C.append("")
    C.append("| Level | Title | Difficulty | Time |")
    C.append("|---|---|---|---|")
    for lv in LEVELS:
        C.append(f"| {lv['n']} | [{lv['title']}](#level-{lv['n']}) | {lv['difficulty']} | ~{lv['minutes']} min |")
    C.append("")
    C.append("> Prefer a clickable, progress-tracking version? Open `curriculum/index.html` "
             "(auto-opens in the Codespace).")
    C.append("")
    C.append("---")
    C.append("")
    for lv in LEVELS:
        C.append(f'<a id="level-{lv["n"]}"></a>')
        C.append("")
        C.append(level_md(lv))
        C.append("")
        C.append("---")
        C.append("")
    with open(os.path.join(KIT, "CURRICULUM.md"), "w") as f:
        f.write("\n".join(C))


if __name__ == "__main__":
    build_hub()
    build_markdown()
    print("curriculum hub :", os.path.join(OUT_HTML_DIR, "index.html"),
          os.path.getsize(os.path.join(OUT_HTML_DIR, "index.html")), "bytes")
    for lv in LEVELS:
        p = os.path.join(OUT_HTML_DIR, f"LEVEL_{lv['n']}.md")
        print("  level md      :", p, os.path.getsize(p), "bytes")
    print("combined       :", os.path.join(KIT, "CURRICULUM.md"),
          os.path.getsize(os.path.join(KIT, "CURRICULUM.md")), "bytes")
