# -*- coding: utf-8 -*-
"""Render the leveled curriculum (content_levels.LEVELS) into student-facing outputs.

Produces:
  curriculum/index.html   — "FIRST LIGHT — The Signal Descent": a self-contained,
                            dark-first interactive Levels hub (progress tracking,
                            expandable stations, copyable commands, checkpoint reveals,
                            a living signal-field hero, a climb spine, a case file, and
                            a hardcoded exploded-packet specimen at Level 3).
  curriculum/LEVEL_n.md   — one Markdown file per level.
  CURRICULUM.md           — a single combined walkthrough (kit root).

No external dependencies (stdlib only); safe to open from file://. Progress is stored in
localStorage inside a try/catch so the page still works where storage is unavailable, and
every interactive flourish degrades to a working static page with JS off / reduced motion.
"""
import html
import json
import os
import re

from content_levels import LEVELS, type_tokens, split_cmd

KIT = "/root/icsnpp_kit"
OUT_HTML_DIR = os.path.join(KIT, "curriculum")
os.makedirs(OUT_HTML_DIR, exist_ok=True)

ACCENT = "#4f46e5"    # indigo — the "learning path" identity (distinct from DNP3 amber / MQTT teal)
ACCENT2 = "#7c3aed"   # violet

# Powers-of-ten descent altitudes (fallbacks; a level may override with lv["zoom"]).
ZOOM = ["NETWORK", "CONVERSATION", "MESSAGE", "FIELD", "BYTE", "THREAT", "MASTERY"]
# Color-script emotional beats per level (fallbacks; a level may override with lv["beat"]).
BEATS = ["dawn", "morning", "morning", "trough", "threat", "resolve", "summit"]

DIFF_CLASS = {
    "Start here": "d-start",
    "Introductory": "d-intro",
    "Intermediate": "d-inter",
    "Advanced": "d-adv",
    "University-level capstone": "d-cap",
}
# Shape glyph so difficulty is never conveyed by colour alone (AA + colour-blind safe).
DIFF_SHAPE = {
    "Start here": "●",              # ●
    "Introductory": "◆",            # ◆
    "Intermediate": "▲",            # ▲
    "Advanced": "★",                # ★
    "University-level capstone": "✦",  # ✦
}

COLDOPEN = ("Something is on the wire that should not be. You cannot see it yet — it hides "
            "inside traffic that looks perfectly ordinary. Descend through seven altitudes, "
            "from the whole network down to a single byte, and by the end you will not just "
            "see it. You will catch it.")

# Just-in-time glossary. Terms are wrapped in prose as keyboard-accessible <dfn> tokens.
GLOSSARY = {
    "CROB": "Control Relay Output Block — DNP3 group 12 variation 1, the object that actually moves a breaker or relay (trip / close).",
    "IIN": "Internal Indications — a two-byte status field in a DNP3 response reporting outstation state (restart, class events, errors).",
    "QoS": "Quality of Service — the MQTT delivery guarantee: 0 (at most once), 1 (at least once), or 2 (exactly once).",
    "retain": "The MQTT retain flag — the broker keeps the last retained message on a topic and hands it to every new subscriber.",
    "outstation": "The DNP3 field device (RTU / IED) that answers a master — it holds the points and executes the controls.",
    "master": "The DNP3 controlling station (SCADA / control center) that polls outstations and issues controls. 'Master' and 'outstation' are the IEEE 1815 (DNP3) role names, retained here for technical accuracy — DNP3 never uses 'slave'.",
    "unsolicited response": "A DNP3 response (function 130) the outstation sends on its own, without being polled — report-by-exception.",
    "link address": "The 16-bit DNP3 data-link source / destination address — a number inside the frame, not the IP address, and trivial to forge.",
    "function code": "The DNP3 application-layer verb: READ (1), SELECT (3), OPERATE (4), DIRECT_OPERATE (5), COLD_RESTART (13), RESPONSE (129).",
    "SELECT-before-OPERATE": "The DNP3 safety handshake: a control must be SELECTed, confirmed, then OPERATEd — a lone OPERATE / DIRECT_OPERATE is suspect.",
}


def e(x):
    return html.escape(str(x), quote=True)


def md_inline(s):
    """Minimal inline markdown → HTML: **bold** and `code`, escaped."""
    s = e(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


def beat_for(lv):
    return lv.get("beat") or (BEATS[lv["n"]] if lv["n"] < len(BEATS) else "morning")


def zoom_for(lv):
    return lv.get("zoom") or (ZOOM[lv["n"]] if lv["n"] < len(ZOOM) else "SIGNAL")


# ---------------------------------------------------------------- inline SVG craft
def packet_lens_svg(state="benign", cls=""):
    """The reusable 'Packet Lens' glyph — a magnifier over a small topology.

    benign: a broker star with quiet satellites. ghost: one node red, pulsing off-rhythm
    (via a CSS class so prefers-reduced-motion silences it — no SMIL)."""
    klass = ("lens " + cls).strip()
    ghost = state == "ghost"
    rogue_fill = "var(--ghost)" if ghost else "currentColor"
    rogue_cls = ' class="lensghost"' if ghost else ""
    return (
        '<svg class="' + klass + '" viewBox="0 0 26 26" fill="none" aria-hidden="true" focusable="false">'
        '<circle cx="11.5" cy="11.5" r="8.4" stroke="currentColor" stroke-width="1.4" opacity=".55"/>'
        '<line x1="17.6" y1="17.6" x2="22.4" y2="22.4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" opacity=".75"/>'
        '<path d="M11.5 11.5 L7.4 8.2 M11.5 11.5 L15.6 8.2 M11.5 11.5 L8.6 15.4" stroke="currentColor" stroke-width="1" opacity=".45"/>'
        '<circle cx="11.5" cy="11.5" r="1.9" fill="currentColor"/>'
        '<circle cx="7.4" cy="8.2" r="1.25" fill="currentColor" opacity=".85"/>'
        '<circle cx="15.6" cy="8.2" r="1.25" fill="currentColor" opacity=".85"/>'
        '<circle' + rogue_cls + ' cx="8.6" cy="15.4" r="1.6" fill="' + rogue_fill + '"/>'
        '</svg>'
    )


def station_signature_svg(n):
    """A small distinct 'resolution signature' per station, drawn from its own arc."""
    head = '<svg class="sig" viewBox="0 0 32 32" fill="none" aria-hidden="true" focusable="false">'
    tail = '</svg>'
    if n == 0:   # live dots
        body = ('<circle cx="8" cy="16" r="2.4" fill="currentColor" opacity=".55"/>'
                '<circle cx="16" cy="16" r="2.9" fill="currentColor" opacity=".85"/>'
                '<circle cx="24" cy="16" r="2.2" fill="currentColor" opacity=".4"/>')
    elif n == 1:  # endpoint graph / star
        body = ('<line x1="16" y1="16" x2="7" y2="9" stroke="currentColor" stroke-width="1.2" opacity=".55"/>'
                '<line x1="16" y1="16" x2="25" y2="9" stroke="currentColor" stroke-width="1.2" opacity=".55"/>'
                '<line x1="16" y1="16" x2="10" y2="25" stroke="currentColor" stroke-width="1.2" opacity=".55"/>'
                '<line x1="16" y1="16" x2="24" y2="24" stroke="currentColor" stroke-width="1.2" opacity=".55"/>'
                '<circle cx="16" cy="16" r="3.1" fill="currentColor"/>'
                '<circle cx="7" cy="9" r="1.8" fill="currentColor" opacity=".8"/>'
                '<circle cx="25" cy="9" r="1.8" fill="currentColor" opacity=".8"/>'
                '<circle cx="10" cy="25" r="1.8" fill="currentColor" opacity=".8"/>'
                '<circle cx="24" cy="24" r="1.8" fill="currentColor" opacity=".8"/>')
    elif n == 2:  # message tally
        body = ''.join('<rect x="%d" y="%d" width="2.4" height="%d" rx="1.2" fill="currentColor" opacity="%s"/>'
                       % (7 + i * 4, 22 - h, h, op)
                       for i, (h, op) in enumerate([(6, ".5"), (11, ".7"), (8, ".6"), (14, ".9"), (5, ".45")]))
    elif n == 3:  # byte / field grid
        cells = []
        for r in range(3):
            for c in range(3):
                op = ".9" if (r == 1 and c == 1) else ".4"
                cells.append('<rect x="%d" y="%d" width="6" height="6" rx="1.4" fill="currentColor" opacity="%s"/>'
                             % (7 + c * 8, 7 + r * 8, op))
        body = ''.join(cells)
    elif n == 4:  # anomaly flare
        body = ('<path d="M16 5 L18 14 L27 16 L18 18 L16 27 L14 18 L5 16 L14 14 Z" fill="currentColor" opacity=".85"/>'
                '<circle cx="16" cy="16" r="2.1" fill="var(--ghost)"/>')
    elif n == 5:  # detection funnel
        body = ('<path d="M6 8 H26 L18.5 17 V25 L13.5 22 V17 Z" fill="currentColor" opacity=".7"/>'
                '<circle cx="16" cy="27" r="1.8" fill="var(--ok)"/>')
    else:        # summit seal
        body = ('<path d="M16 4 L20 12 L28 13 L22 19 L23.5 27 L16 23 L8.5 27 L10 19 L4 13 L12 12 Z" '
                'fill="currentColor" opacity=".9"/>'
                '<path d="M13 16 L15.3 18.4 L19.5 13.6" stroke="var(--bg)" stroke-width="1.8" '
                'stroke-linecap="round" stroke-linejoin="round" fill="none"/>')
    return head + body + tail


def exploded_frame_html():
    """A hardcoded, self-contained exploded view of the DNP3 rogue-trip frame (frame 27).

    Hardcoded from verified content (no scapy, no pcap read): the tell is that the DNP3
    link source claims 100 (the master) while the IP source is 10.20.0.66 (the ghost).
    Interactive via CSS :hover/:focus on each labelled byte-chip; fully labelled and static
    under prefers-reduced-motion. The module Frame Explorers remain the full byte-level tool."""

    def chip(hexb, field, note, tell=""):
        tattr = ' data-tell="1"' if tell else ''
        tellmark = ('<span class="xtell">' + tell + '</span>') if tell else ''
        return ('<span class="xchip"' + tattr + ' tabindex="0">'
                '<span class="xhex">' + hexb + '</span>'
                '<span class="xlab"><b>' + field + '</b>' + note + tellmark + '</span></span>')

    net = (
        '<div class="xlayer" data-layer="net"><span class="xtag">Network · IP / TCP</span><div class="xrow">'
        + chip('0a 14 00 42', 'ip.src', ' = 10.20.0.66', 'the ghost')
        + chip('0a 14 00 14', 'ip.dst', ' = 10.20.0.20 (outstation)')
        + chip('4e 20', 'tcp.dstport', ' = 20000 (DNP3)')
        + '</div></div>'
    )
    dl = (
        '<div class="xlayer" data-layer="dl"><span class="xtag">DNP3 · Data-link</span><div class="xrow">'
        + chip('05 64', 'start', ' = 0x0564')
        + chip('16', 'len', ' = 22 bytes')
        + chip('c4', 'ctl', ' DIR·PRM')
        + chip('04 00', 'dnp3.dst', ' link = 4 (outstation)')
        + chip('64 00', 'dnp3.src', ' link = 100', 'forged to the master')
        + chip('47 8b', 'crc', ' data-link')
        + '</div></div>'
    )
    tr = (
        '<div class="xlayer" data-layer="tr"><span class="xtag">DNP3 · Transport</span><div class="xrow">'
        + chip('c1', 'transport', ' FIR·FIN·seq')
        + '</div></div>'
    )
    app = (
        '<div class="xlayer" data-layer="app"><span class="xtag">DNP3 · Application</span><div class="xrow">'
        + chip('c3', 'app.ctl', ' FIR·FIN·seq')
        + chip('05', 'dnp3.al.func', ' = DIRECT_OPERATE (5)')
        + chip('0c 01', 'object', ' = CROB, group 12 var 1')
        + chip('17 01 00', 'qualifier', ' 1 object, index 0')
        + chip('41', 'dnp3.ctl.trip', ' = TRIP + Pulse On', 'the breaker command')
        + chip('e8 03 00 00', 'on-time', ' = 1000 ms')
        + chip('00 00 00 00', 'off-time', ' = 0 ms')
        + chip('00', 'status', ' requested')
        + '</div></div>'
    )
    tell = (
        '<div class="xtellbox">'
        '<span class="xtellhead">' + packet_lens_svg("ghost", "xtelllens")
        + 'Two sources, one lie</span>'
        '<p>The IP header says the trip came from <code>10.20.0.66</code>. The DNP3 '
        '<b>link address</b> inside the very same frame claims <code>100</code> — the master. '
        'DNP3 authenticates neither, so the outstation obeys. That single contradiction — '
        '<code>ip.src</code> vs <code>dnp3.src</code> — is the whole case.</p>'
        '</div>'
    )
    return (
        '<figure class="specimen" aria-label="Exploded view of DNP3 frame 27, the rogue trip">'
        '<figcaption><span class="spec-k">Hero specimen</span> Frame 27 · the rogue DIRECT_OPERATE trip'
        '<span class="spec-hint">Hover or focus any byte-chip to light it. This is a fixed teaching '
        'diagram — the module <a href="../modules/dnp3_module.html">Frame Explorer</a> is the full byte-level tool.</span>'
        '</figcaption>'
        '<div class="xstack">' + net + dl + tr + app + '</div>'
        + tell +
        '</figure>'
    )


# ---------------------------------------------------------------- HTML rendering
def _cmd_context(cmd):
    tool = ""
    for line in cmd.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        tool = s.split()[0]
        break
    m = re.search(r"([\w./-]+\.pcap)", cmd)
    pcap = m.group(1).split("/")[-1] if m else ""
    if tool and pcap:
        return tool + " · " + pcap
    return tool or pcap or "shell"


def _cmd_proto(cmd):
    c = cmd.lower()
    d = ("dnp3" in c) or ("20000" in c)
    m = ("mqtt" in c) or ("1883" in c)
    if d and not m:
        return "dnp3"
    if m and not d:
        return "mqtt"
    return "neutral"


def step_html(st, tok=None):
    """Render one step as a Read / Do / Check card.

    note  -> READ   (background context; badge 'READ')
    gui   -> DO · CLICK (a Wireshark click; badge 'DO · CLICK')
    cmd   -> DO · TYPE  (a terminal step; the student types the short token `tok`
             — it prints the real command and runs it — then a CHECK reveal).
    """
    kind = st.get("kind", "note")
    if kind == "cmd":
        cmd = e(st["text"])
        proto = _cmd_proto(st["text"])
        ctx = e(_cmd_context(st["text"]))
        ptag = {"dnp3": "DNP3", "mqtt": "MQTT", "neutral": ""}[proto]
        ptag_html = ('<span class="ptag ptag-' + proto + '">' + ptag + '</span>') if ptag else ""

        # The token affordance: the short handle the student TYPES to run the real
        # command below (no copy-paste). Degrades gracefully if a token is absent.
        typerun_html = ""
        if tok:
            typerun_html = (
                '<div class="typerun">'
                '<span class="tr-badge">DO · TYPE</span>'
                '<span class="tr-lead">⌨ Type</span>'
                '<code class="tr-tok">' + e(tok) + '</code>'
                '<span class="tr-hint">— prints the real command &amp; runs it</span>'
                '</div>'
            )

        cons = st.get("consequence")
        cons_html = ""
        if cons:
            cons_html = ('<div class="consequence"><span class="cq-ic" aria-hidden="true">⚡</span>'
                         '<span>' + md_inline(cons) + '</span></div>')
        exp = st.get("expect")
        exp_html = ""
        if exp:
            exp_html = (
                '<details class="reveal"><summary><span class="rv-ic" aria-hidden="true"></span>'
                '<span class="rv-label"><span class="rv-badge">CHECK</span> Predict, then reveal the expected output</span>'
                '<span class="rv-hint">what will this print?</span></summary>'
                '<div class="expect"><span class="explabel">Expected output</span>'
                '<pre class="expbody">' + e(exp) + '</pre></div></details>'
            )
        return (
            '<div class="step cmd cmd-' + proto + '">'
            + typerun_html +
            '<div class="termwrap">'
            '<div class="titlebar"><span class="tdots" aria-hidden="true"><i></i><i></i><i></i></span>'
            '<span class="tctx">' + ctx + '</span>' + ptag_html +
            '<button class="copy" type="button" onclick="cpPre(this)">Copy</button></div>'
            '<pre class="term">' + cmd + '</pre></div>'
            + cons_html + exp_html + '</div>'
        )
    if kind == "gui":
        return ('<div class="step gui"><span class="kind kind-gui">DO · CLICK</span>'
                '<div class="steptext">' + md_inline(st["text"]) + '</div></div>')
    return ('<div class="step note"><span class="kind kind-read">READ</span>'
            '<div class="steptext">' + md_inline(st["text"]) + '</div></div>')


def checkpoint_html(cp):
    quiz = ""
    opts = cp.get("options")
    if opts:
        correct = cp.get("correct", 0)
        btns = "".join(
            '<button type="button" class="cpopt" data-i="%d">%s</button>' % (i, md_inline(o))
            for i, o in enumerate(opts)
        )
        quiz = ('<div class="cpquiz" data-correct="%d" role="group" aria-label="Predict the answer">%s'
                '<span class="cpquiz-fb" aria-live="polite"></span></div>' % (correct, btns))
    return (
        '<details class="cp"><summary><span class="cpq">'
        + md_inline(cp["q"]) + '</span>'
        + quiz +
        '<span class="cphint">Predict &middot; then reveal</span></summary>'
        '<div class="cpa">' + md_inline(cp["a"]) + '</div></details>'
    )


def level_html(lv):
    n = lv["n"]
    dcls = DIFF_CLASS.get(lv["difficulty"], "d-intro")
    dshape = DIFF_SHAPE.get(lv["difficulty"], "◆")
    is_mp = lv.get("is_mp")
    beat = beat_for(lv)
    zoom = zoom_for(lv)
    objectives = "".join("<li>" + md_inline(o) + "</li>" for o in lv["objectives"])
    background = "".join("<p>" + md_inline(b) + "</p>" for b in lv["background"])
    toks = type_tokens(lv)
    steps = "".join(step_html(s, toks.get(i)) for i, s in enumerate(lv["steps"]))
    checks = "".join(checkpoint_html(c) for c in lv["checkpoints"])
    open_attr = " open" if n == 0 else ""
    mpclass = " mp" if is_mp else ""

    specimen = exploded_frame_html() if n == 3 else ""

    storybeat = lv.get("storybeat")
    story_html = ""
    if storybeat:
        story_html = (
            '<div class="storybeat"><span class="sb-lens">' + packet_lens_svg("benign", "sb-glyph")
            + '</span><div class="sb-body"><span class="sb-k">Next descent</span>'
            + '<p>' + md_inline(storybeat) + '</p></div></div>'
        )

    teaser = lv.get("teaser") or lv.get("subtitle", "")
    teaser_html = ('<div class="frostteaser"><span class="ft-k">Locked in the descent</span>'
                   '<p>' + md_inline(teaser) + '</p>'
                   '<span class="ft-open">Curious? Open it anyway →</span></div>')

    mp_launch = ""
    if is_mp:
        mp_launch = (
            '<div class="mplaunch">'
            '<b>This is the capstone.</b> The full handout, the two evidence captures, the answer '
            'template, the self-check autograder, and the report rubric are in the '
            '<code>mp/</code> folder. Start with <a href="../mp/README.md">mp/README.md</a>.'
            '</div>'
        )

    return (
        '\n<section class="lvl' + mpclass + '" id="level-' + str(n) + '" data-beat="' + beat + '"'
        + ' data-level="' + str(n) + '">'
        '<div class="lvledge" aria-hidden="true"></div>'
        '<div class="lvlhead">'
        '<div class="lvlnum" aria-hidden="true"><span class="ln-n">' + str(n) + '</span>'
        '<span class="ln-check">' + station_signature_svg(n) + '</span></div>'
        '<div class="lvlmeta">'
        '<div class="lvlalt">' + e(zoom) + '<span class="lvlalt-dot" aria-hidden="true"></span>'
        '<span class="lvlalt-sig">' + station_signature_svg(n) + '</span></div>'
        '<div class="lvltitle">Level ' + str(n) + ' — ' + e(lv['title']) +
        '<span class="dbadge ' + dcls + '"><span class="dsh" aria-hidden="true">' + dshape + '</span>'
        + e(lv['difficulty']) + '</span>'
        '<span class="mins">~' + e(lv['minutes']) + ' min</span></div>'
        '<div class="lvlsub">' + e(lv['subtitle']) + '</div>'
        '</div>'
        '<label class="donebox" title="Mark this level complete">'
        '<input type="checkbox" class="donechk" data-level="' + str(n) + '"><span>Done</span></label>'
        '</div>'
        '<div class="lvlgoal"><span class="goallabel">Goal</span> ' + md_inline(lv['goal']) + '</div>'
        + teaser_html + mp_launch +
        '<details class="lvlbody"' + open_attr + '>'
        '<summary><span class="openlabel">Open this level</span>'
        '<span class="closelabel">Hide this level</span></summary>'
        '<div class="lvlinner">'
        '<h4>What you\'ll be able to do</h4>'
        '<ul class="obj">' + objectives + '</ul>'
        '<p class="prereq"><b>Prerequisite:</b> ' + md_inline(lv['prereq']) + '</p>'
        '<h4>Background</h4>'
        '<div class="bg">' + background + '</div>'
        + specimen +
        '<h4>Do this</h4>'
        '<div class="steps">' + steps + '</div>'
        '<h4>Check yourself</h4>'
        '<div class="checks">' + checks + '</div>'
        '<div class="levelup"><span class="lulabel">Level up</span> ' + md_inline(lv['levelup']) + '</div>'
        + story_html +
        '</div></details>'
        '</section>'
    )


TWIN_PANEL = r"""
<section class="jump" style="margin-top:26px;border-color:color-mix(in srgb,var(--ok) 30%,var(--line))" aria-label="Advanced tier: the digital twin">
  <h3 style="color:var(--ok);letter-spacing:.08em">&#9733; Beyond the descent &mdash; the digital twin</h3>
  <p style="color:var(--mut);margin:.2em 0 .7em;font-size:var(--step-0);line-height:1.55">
    The seven levels train the <em>eye</em> on a clean loopback capture. The <strong>digital twin</strong> is where you
    prove it on a living plant: a closed-loop <strong>OpenPLC</strong> controller driving a simulated wet-well, fronted by
    a <strong>DNP3</strong> outstation and an <strong>MQTT</strong> telemetry path, across <strong>five segmented
    IEC-62443 zones</strong> with an nftables conduit firewall &mdash; and every packet still readable in Wireshark.
    Grounded in INL CyOTE incident patterns, MITRE <strong>CWE-1358</strong> ICS weaknesses, and
    <strong>Cyber-Informed Engineering</strong>.
  </p>
  <div class="pathline" style="margin:.2em 0 .8em">
    <span class="pl">5 zones</span><span class="arr">&rarr;</span>
    <span class="pl">OpenPLC logic</span><span class="arr">&rarr;</span>
    <span class="pl">DNP3 + MQTT on the wire</span><span class="arr">&rarr;</span>
    <span class="pl" style="color:var(--ghost)">inject the attack</span><span class="arr">&rarr;</span>
    <span class="pl" style="color:var(--ok)">harden it out</span>
  </div>
  <div style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--card-2);border:1px solid var(--line);border-radius:10px;padding:11px 14px;font-size:.88rem;color:var(--ink);overflow-x:auto;margin:.2em 0 .7em">
    <span style="color:var(--faint)">$</span> bash lab/twin/launch-twin.sh<br>
    <span style="color:var(--faint)">$</span> bash lab/twin/launch-twin.sh <span style="color:var(--ghost)">--attack</span>&nbsp;&nbsp;&nbsp;<span style="color:var(--faint)"># adversary foothold, then inject</span><br>
    <span style="color:var(--faint)">$</span> bash lab/twin/launch-twin.sh <span style="color:var(--ok)">--hardened</span>&nbsp;<span style="color:var(--faint)"># same attack, refused</span>
  </div>
  <p style="color:var(--faint);font-size:var(--step--1);margin:.2em 0 .7em">
    Objective: hold the Sanitary-Sewer-Overflow <strong style="color:var(--mut)">spill counter at 0</strong> under full
    DNP3 + MQTT write access. Doors once it boots: OpenPLC <code>:8088</code> &middot; HMI <code>:1881</code> &middot;
    Wireshark <code>:3000</code> (the Learning Path stays on <code>:8080</code>).
  </p>
  <div class="links">
    <a href="../lab/twin/README.md">Twin guide</a>
    <a href="../design/DIGITAL_TWIN_ARCHITECTURE.md">Architecture</a>
    <a href="../design/WEAKNESS_ANALYSIS.md">CWE-1358 weaknesses</a>
    <a href="../design/CIE_HARDENING.md">CIE hardening</a>
    <a href="../projects/README.md">Forward&rarr;reverse projects</a>
  </div>
</section>
"""


def build_hub():
    cards = "".join(level_html(lv) for lv in LEVELS) + TWIN_PANEL
    total = len(LEVELS)
    # The Machine Problem is the ignite target — find it by flag, not by position, so an
    # advanced level appended after it (e.g. Level 7) doesn't steal the capstone glow.
    mp_level = next((lv["n"] for lv in LEVELS if lv.get("is_mp")), total - 1)

    nav = ""
    for lv in LEVELS:
        n = lv["n"]
        nav += (
            '<a href="#level-' + str(n) + '" class="navdot" data-level="' + str(n) + '"'
            ' data-beat="' + beat_for(lv) + '" title="Level ' + str(n) + ': ' + e(lv["title"]) + '">'
            '<span class="nd-rail" aria-hidden="true"><span class="nd-node">'
            '<span class="nd-check">✓</span></span></span>'
            '<span class="nd-body">'
            '<span class="nd-alt">' + e(zoom_for(lv)) + '</span>'
            '<span class="nd-line"><span class="nd-n">' + str(n) + '</span>'
            '<span class="nd-t">' + e(lv["title"]) + '</span></span>'
            '</span></a>'
        )

    casefile = [
        {"n": lv["n"], "zoom": zoom_for(lv), "title": lv["title"], "evidence": lv.get("evidence", "")}
        for lv in LEVELS
    ]
    glossary_json = json.dumps(GLOSSARY).replace("</", "<\\/")
    casefile_json = json.dumps(casefile).replace("</", "<\\/")

    page = HUB_TEMPLATE
    page = page.replace("__ACCENT__", ACCENT).replace("__ACCENT2__", ACCENT2)
    page = page.replace("__CARDS__", cards)
    page = page.replace("__NAV__", nav)
    page = page.replace("__TOTAL__", str(total))
    page = page.replace("__MP_LEVEL__", str(mp_level))
    page = page.replace("__COLDOPEN__", e(COLDOPEN))
    page = page.replace("__GLOSSARY_JSON__", glossary_json)
    page = page.replace("__CASEFILE_JSON__", casefile_json)
    page = page.replace("__LENS_KICK__", packet_lens_svg("benign", "klens-svg"))
    page = page.replace("__LENS_CASE__", packet_lens_svg("ghost", "cf-glyph"))
    page = page.replace("__LENS_COLD__", packet_lens_svg("ghost", "co-lens-svg"))
    with open(os.path.join(OUT_HTML_DIR, "index.html"), "w") as f:
        f.write(page)


HUB_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>First Light — DNP3 &amp; MQTT Signal Descent</title>
<style>
/* ============================ FIRST LIGHT — token system ============================ */
:root{
  color-scheme:dark;
  --accent:__ACCENT__; --accent2:__ACCENT2__;
  --bg:#0a0e1a; --bg-raise:#111725; --card:#131a2b; --card-2:#1a2336;
  --line:#232e49; --line-soft:#1b2440;
  --ink:#e8edf7; --mut:#9aa7bd; --faint:#64748b;
  --link:#a5b4fc; --accent-glow:#818cf8;
  --dnp3:#f59e0b; --dnp3-deep:#b45309; --mqtt:#2dd4bf; --mqtt-deep:#0f766e;
  --ghost:#f87171; --ghost-deep:#dc2626; --ok:#34d399; --ok-deep:#16a34a;
  --now:#818cf8; --now-soft:rgba(129,140,248,.14); --edge:var(--accent-glow);
  --dawn:0;
  /* fluid modular type scale (~1.22) */
  --step--1:clamp(.78rem,.75rem + .18vw,.86rem);
  --step-0:clamp(.95rem,.9rem + .25vw,1.05rem);
  --step-1:clamp(1.06rem,1rem + .35vw,1.2rem);
  --step-2:clamp(1.2rem,1.1rem + .6vw,1.45rem);
  --step-3:clamp(1.4rem,1.25rem + .9vw,1.8rem);
  --step-4:clamp(1.7rem,1.4rem + 1.4vw,2.25rem);
  --step-6:clamp(1.95rem,1.4rem + 2.6vw,3rem);
  --space:clamp(.9rem,.7rem + .6vw,1.2rem);
  --spring:cubic-bezier(.34,1.56,.64,1);
  --ease:cubic-bezier(.4,0,.2,1);
  --spinefill:0%;
}
html[data-theme="light"]{
  color-scheme:light;
  --bg:#f1f5f9; --bg-raise:#e9eef5; --card:#ffffff; --card-2:#f8fafc;
  --line:#e2e8f0; --line-soft:#eef2f7;
  --ink:#1e293b; --mut:#475569; --faint:#94a3b8;
  --link:#4f46e5; --accent-glow:#6366f1;
  --dnp3:#b45309; --dnp3-deep:#92400e; --mqtt:#0f766e; --mqtt-deep:#0d5c56;
  --ghost:#dc2626; --ghost-deep:#b91c1c; --ok:#16a34a; --ok-deep:#15803d;
  --now:#6366f1; --now-soft:rgba(99,102,241,.10);
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
    --now:#6366f1; --now-soft:rgba(99,102,241,.10);
  }
}
/* color-script beats — one ambient glow + one active accent temperature (never the base bg) */
body[data-beat="dawn"]   {--now:#818cf8; --now-soft:rgba(129,140,248,.15)}
body[data-beat="morning"]{--now:#38bdf8; --now-soft:rgba(56,189,248,.12)}
body[data-beat="trough"] {--now:#f59e0b; --now-soft:rgba(245,158,11,.13)}
body[data-beat="threat"] {--now:#f87171; --now-soft:rgba(248,113,113,.14)}
body[data-beat="resolve"]{--now:#a78bfa; --now-soft:rgba(167,139,250,.14)}
body[data-beat="summit"] {--now:#fbbf24; --now-soft:rgba(251,191,36,.16)}
/* per-station edge colour (independent of the active ambient beat) */
.lvl[data-beat="dawn"],.navdot[data-beat="dawn"]      {--edge:var(--accent-glow)}
.lvl[data-beat="morning"],.navdot[data-beat="morning"]{--edge:var(--mqtt)}
.lvl[data-beat="trough"],.navdot[data-beat="trough"]  {--edge:var(--dnp3)}
.lvl[data-beat="threat"],.navdot[data-beat="threat"]  {--edge:var(--ghost)}
.lvl[data-beat="resolve"],.navdot[data-beat="resolve"]{--edge:#a78bfa}
.lvl[data-beat="summit"],.navdot[data-beat="summit"]  {--edge:#fbbf24}

*{box-sizing:border-box}
[hidden]{display:none !important}
.lens{width:1em;height:1em;display:inline-block;vertical-align:-.15em;flex:0 0 auto}
.htbtn .lens{width:1.05em;height:1.05em}
html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--ink);background:var(--bg);line-height:1.6;font-size:var(--step-0);
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(70% 55% at 50% 16%,var(--now-soft),transparent 72%);
  transition:background .8s ease}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent-glow);outline-offset:2px;border-radius:4px}
h4{margin:1.5em 0 .5em;font-size:var(--step--1);color:var(--mut);text-transform:uppercase;
  letter-spacing:.11em;font-weight:800}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:color-mix(in srgb,var(--now) 12%,transparent);color:var(--ink);
  padding:.05em .4em;border-radius:5px;font-size:.88em;border:1px solid color-mix(in srgb,var(--now) 20%,transparent)}

/* ================================ HERO — the signal field ============================ */
.hero{position:relative;overflow:hidden;isolation:isolate;color:#e8edf7;
  padding:clamp(1.6rem,1rem + 3vw,3.2rem) clamp(1.1rem,.6rem + 2vw,2.4rem) clamp(1.4rem,1rem + 2vw,2.4rem)}
.herobg{position:absolute;inset:0;z-index:0;
  background:
    radial-gradient(120% 90% at 80% 8%,rgba(37,99,235,.20),transparent 55%),
    radial-gradient(90% 80% at 12% 4%,rgba(124,58,237,.18),transparent 55%),
    linear-gradient(160deg,#0b1020 0%,#0a0e1a 55%,#080b14 100%)}
#constellation{position:absolute;inset:0;width:100%;height:100%;z-index:1;display:block}
.herosky{position:absolute;inset:0;z-index:2;pointer-events:none;transition:opacity .8s ease,background .8s ease;
  background:linear-gradient(to top,
    rgba(251,191,36,calc(.30*var(--dawn))) 0%,
    rgba(248,150,90,calc(.16*var(--dawn))) 26%,
    rgba(236,120,170,calc(.08*var(--dawn))) 48%,
    transparent 72%)}
.heroinner{position:relative;z-index:3;max-width:1120px;margin:0 auto}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:clamp(1rem,3vw,2.2rem)}
.kick{font-size:var(--step--1);letter-spacing:.22em;text-transform:uppercase;color:#aeb9d6;font-weight:700;
  display:inline-flex;align-items:center;gap:.6em}
.kick .klens{width:1.15em;height:1.15em;color:#c7d2fe;opacity:.95}
.herotools{display:flex;gap:8px;flex-shrink:0}
.htbtn{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.07);
  border:1px solid rgba(255,255,255,.16);color:#e8edf7;border-radius:10px;padding:7px 12px;
  font-size:var(--step--1);cursor:pointer;font-weight:600;transition:background .2s var(--ease),transform .2s var(--ease)}
.htbtn:hover{background:rgba(255,255,255,.14)}
.htbtn:active{transform:translateY(1px)}
.hero h1{margin:.1em 0 .35em;font-size:var(--step-6);line-height:1.05;letter-spacing:-.02em;font-weight:800;
  max-width:20ch;text-wrap:balance}
.hero h1 .fl{background:linear-gradient(100deg,#fcd34d,#fb923c 45%,#f472b6);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.hero .sub{color:#c3cde0;margin:0 0 1.2em;max-width:60ch;font-size:var(--step-1);line-height:1.55}
.legend{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 1.3em}
.lg{display:inline-flex;align-items:center;gap:7px;font-size:var(--step--1);font-weight:600;color:#dbe4f5;
  background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:20px;padding:4px 11px}
.lg::before{content:"";width:9px;height:9px;border-radius:50%;box-shadow:0 0 10px currentColor}
.lg-dnp3{color:#f59e0b}.lg-mqtt{color:#2dd4bf}.lg-ghost{color:#f87171}
.lg span{color:#dbe4f5}
.progwrap{background:rgba(10,14,26,.5);border:1px solid rgba(255,255,255,.14);border-radius:14px;
  padding:14px 16px;max-width:600px;backdrop-filter:blur(6px)}
.progrow{display:flex;justify-content:space-between;align-items:center;font-size:var(--step--1);margin-bottom:9px}
#progtext{font-weight:600;color:#e8edf7}
.progbar{height:8px;background:rgba(255,255,255,.12);border-radius:20px;overflow:hidden;position:relative}
.progfill{height:100%;width:0;border-radius:20px;transition:width .6s var(--spring);
  background:linear-gradient(90deg,#6366f1,#818cf8 60%,#fbbf24);box-shadow:0 0 14px rgba(129,140,248,.6)}
.reset{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.2);color:#e8edf7;border-radius:9px;
  padding:5px 12px;font-size:var(--step--1);cursor:pointer;font-weight:600;transition:background .2s var(--ease)}
.reset:hover{background:rgba(255,255,255,.18)}
.enter{display:inline-flex;align-items:center;gap:8px;margin-top:1.3em;color:#e8edf7;font-weight:700;
  font-size:var(--step-0);border:1px solid rgba(255,255,255,.22);border-radius:30px;padding:9px 20px;
  transition:gap .25s var(--spring),background .2s var(--ease)}
.enter:hover{gap:14px;background:rgba(255,255,255,.08);text-decoration:none}
.enter .ea{transition:transform .5s var(--spring)}
.enter:hover .ea{transform:translateY(3px)}

/* welcome-back banner */
.welcome{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 18px;
  background:linear-gradient(120deg,color-mix(in srgb,var(--now) 14%,var(--card)),var(--card));
  border:1px solid var(--line);border-left:3px solid var(--now);border-radius:14px;padding:12px 16px;
  animation:rise .5s var(--spring) both}
.welcome b{color:var(--ink)}
.welcome .wgo{margin-left:auto;background:var(--now);color:#0a0e1a;border:none;border-radius:9px;
  padding:7px 15px;font-weight:700;cursor:pointer;font-size:var(--step--1)}
.welcome .wx{background:none;border:none;color:var(--mut);cursor:pointer;font-size:1.1em;padding:2px 6px}

/* ================================ LAYOUT ============================ */
.layout{max-width:1120px;margin:0 auto;padding:clamp(1.2rem,2vw,2rem) clamp(1rem,2vw,1.6rem) 80px;
  display:grid;grid-template-columns:248px 1fr;gap:clamp(1.2rem,2.4vw,2.4rem)}
main{min-width:0}

/* ================================ THE CLIMB — spine ============================ */
.rail{position:sticky;top:14px;align-self:start;max-height:calc(100vh - 28px);overflow:auto;
  padding-right:4px;scrollbar-width:thin}
.railh{font-size:var(--step--1);letter-spacing:.2em;text-transform:uppercase;color:var(--mut);
  font-weight:800;margin:6px 0 14px 2px;display:flex;align-items:center;gap:8px}
.railh::before{content:"";width:14px;height:1px;background:var(--now)}
.spine{position:relative;padding-left:4px}
.spine::before{content:"";position:absolute;left:16px;top:14px;bottom:14px;width:2px;
  background:var(--line);border-radius:2px}
.spinefill{position:absolute;left:16px;top:14px;width:2px;height:var(--spinefill);border-radius:2px;
  background:linear-gradient(180deg,#6366f1,#818cf8 50%,var(--dnp3));
  box-shadow:0 0 10px rgba(129,140,248,.5);transition:height .6s var(--spring);max-height:calc(100% - 28px)}
.navdot{display:flex;gap:12px;align-items:flex-start;text-decoration:none;color:var(--ink);
  padding:9px 8px 9px 0;border-radius:11px;position:relative;transition:background .2s var(--ease)}
.navdot:hover{background:color-mix(in srgb,var(--now) 8%,transparent);text-decoration:none}
.nd-rail{flex:0 0 34px;display:flex;justify-content:center;padding-top:2px;position:relative;z-index:1}
.nd-node{width:15px;height:15px;border-radius:50%;background:var(--bg-raise);
  border:2px solid var(--line);display:flex;align-items:center;justify-content:center;
  transition:all .35s var(--spring);position:relative}
.nd-check{font-size:9px;font-weight:900;color:#0a0e1a;opacity:0;transform:scale(.4);transition:all .3s var(--spring)}
.navdot .nd-body{flex:1;min-width:0}
.nd-alt{display:block;font-size:9.5px;letter-spacing:.16em;font-weight:800;color:var(--faint);
  text-transform:uppercase;margin-bottom:1px}
.nd-line{display:flex;gap:7px;align-items:baseline}
.nd-n{flex:0 0 auto;font-weight:800;font-size:var(--step--1);color:var(--mut);font-variant-numeric:tabular-nums}
.nd-t{font-size:var(--step--1);color:var(--mut);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* states */
.navdot.active .nd-node{border-color:var(--now);box-shadow:0 0 0 4px color-mix(in srgb,var(--now) 22%,transparent),0 0 14px var(--now)}
.navdot.active .nd-alt{color:var(--now)}
.navdot.active .nd-t{color:var(--ink);font-weight:700}
.navdot.active .nd-n{color:var(--ink)}
.navdot.done .nd-node{background:var(--edge);border-color:var(--edge);box-shadow:0 0 12px color-mix(in srgb,var(--edge) 60%,transparent)}
.navdot.done .nd-check{opacity:1;transform:scale(1)}
.navdot.done .nd-alt{color:color-mix(in srgb,var(--edge) 70%,var(--mut))}
.navdot[data-reachable="0"]{opacity:.5}
.navdot[data-reachable="0"] .nd-node{border-style:dashed}
.navdot.justdone .nd-node{animation:nodepop .6s var(--spring)}
@keyframes nodepop{0%{transform:scale(.6)}55%{transform:scale(1.35)}100%{transform:scale(1)}}
.spine.flow .spinefill{animation:flowpulse .7s var(--ease)}
@keyframes flowpulse{0%{filter:brightness(1)}40%{filter:brightness(1.9)}100%{filter:brightness(1)}}

/* ================================ INTRO + jump ============================ */
.intro{background:var(--card);border:1px solid var(--line);border-radius:16px;
  padding:clamp(1rem,2vw,1.4rem) clamp(1.1rem,2vw,1.5rem);margin:0 0 18px;position:relative;overflow:hidden}
.intro::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
  background:linear-gradient(180deg,var(--accent-glow),var(--mqtt))}
.intro h2{margin:.1em 0 .35em;font-size:var(--step-2);letter-spacing:-.01em}
.intro p{margin:.5em 0;color:var(--mut)}
.intro p b{color:var(--ink)}
.pathline{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:14px 0 2px}
.pathline .pl{background:color-mix(in srgb,var(--now) 12%,transparent);
  border:1px solid color-mix(in srgb,var(--now) 26%,transparent);color:var(--ink);
  border-radius:20px;padding:3px 11px;font-weight:600;font-size:var(--step--1)}
.pathline .arr{color:var(--faint)}
.inlinekind{font-size:.72em;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:20px;
  background:color-mix(in srgb,var(--now) 16%,transparent);color:var(--ink)}
.jump{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;margin:0 0 20px}
.jump h3{margin:.1em 0 .6em;font-size:var(--step-0);color:var(--mut);text-transform:uppercase;letter-spacing:.08em;font-weight:800}
.jump .links{display:flex;flex-wrap:wrap;gap:9px}
.jump .links a{display:inline-flex;align-items:center;gap:8px;background:var(--card-2);
  border:1px solid var(--line);border-radius:11px;padding:9px 13px;font-size:var(--step--1);
  color:var(--ink);font-weight:600;transition:border-color .2s var(--ease),transform .2s var(--ease)}
.jump .links a:hover{border-color:var(--now);transform:translateY(-1px);text-decoration:none}
.jump .links a::before{content:"";width:7px;height:7px;border-radius:2px;background:var(--now);flex:0 0 auto}

/* ================================ STATION / lit vitrine ============================ */
.lvl{background:linear-gradient(180deg,var(--card),var(--bg-raise));border:1px solid var(--line);
  border-radius:18px;padding:0;margin:0 0 clamp(1rem,2vw,1.5rem);position:relative;overflow:hidden;
  transition:border-color .3s var(--ease),box-shadow .3s var(--ease),transform .3s var(--ease),opacity .4s var(--ease)}
.lvl::before{content:"";position:absolute;inset:0;pointer-events:none;border-radius:18px;
  background:radial-gradient(120% 60% at 0% 0%,color-mix(in srgb,var(--edge) 9%,transparent),transparent 55%);opacity:.9}
.lvledge{position:absolute;left:0;top:0;bottom:0;width:4px;z-index:2;
  background:linear-gradient(180deg,var(--edge),color-mix(in srgb,var(--edge) 30%,transparent));
  box-shadow:0 0 16px color-mix(in srgb,var(--edge) 45%,transparent)}
.lvl.done{border-color:color-mix(in srgb,var(--ok) 45%,var(--line))}
.lvl.mp{border-color:color-mix(in srgb,#fbbf24 32%,var(--line))}
.lvl.frosted{opacity:.62}
.lvl.frosted .lvlbody{filter:saturate(.7)}
/* opening a frosted station rewards curiosity: it lifts out of the frost */
.lvl.frosted:has(.lvlbody[open]){opacity:1}
.lvl.frosted:has(.lvlbody[open]) .lvlbody{filter:none}
.lvl.frosted:has(.lvlbody[open]) .frostteaser{display:none}
.lvl.reveal-in{animation:rise .5s var(--spring) both}
.lvlhead{display:flex;gap:15px;align-items:flex-start;padding:clamp(1rem,2vw,1.35rem) clamp(1rem,2vw,1.5rem) 12px 22px;position:relative;z-index:1}
.lvlnum{flex:0 0 auto;width:52px;height:52px;border-radius:15px;position:relative;
  background:linear-gradient(140deg,color-mix(in srgb,var(--edge) 26%,var(--card-2)),var(--card-2));
  border:1px solid color-mix(in srgb,var(--edge) 40%,var(--line));
  display:flex;align-items:center;justify-content:center;color:var(--ink);overflow:hidden}
.ln-n{font-weight:800;font-size:var(--step-3);font-variant-numeric:tabular-nums;transition:opacity .4s var(--spring),transform .4s var(--spring)}
.ln-check{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  opacity:0;transform:scale(.4) rotate(-20deg);transition:opacity .4s var(--spring),transform .5s var(--spring);color:var(--ok)}
.ln-check .sig{width:26px;height:26px}
.lvl.done .ln-n{opacity:0;transform:scale(.5)}
.lvl.done .ln-check{opacity:1;transform:scale(1) rotate(0)}
.lvl.done .lvlnum{background:linear-gradient(140deg,color-mix(in srgb,var(--ok) 24%,var(--card-2)),var(--card-2));
  border-color:color-mix(in srgb,var(--ok) 45%,var(--line))}
.lvlmeta{flex:1;min-width:0}
.lvlalt{display:flex;align-items:center;gap:8px;font-size:10.5px;letter-spacing:.2em;font-weight:800;
  text-transform:uppercase;color:var(--edge);margin-bottom:3px}
.lvlalt-dot{width:4px;height:4px;border-radius:50%;background:currentColor;opacity:.6}
.lvlalt-sig{margin-left:auto;width:22px;height:22px;color:var(--edge);opacity:.85}
.lvlalt-sig .sig{width:22px;height:22px}
.lvltitle{font-size:var(--step-2);font-weight:800;letter-spacing:-.01em;display:flex;gap:9px;align-items:center;flex-wrap:wrap;line-height:1.2}
.lvlsub{color:var(--mut);font-size:var(--step--1);margin-top:3px}
.dbadge{font-size:10.5px;font-weight:800;padding:3px 10px;border-radius:20px;display:inline-flex;align-items:center;gap:5px;letter-spacing:.02em}
.dbadge .dsh{font-size:.85em;line-height:1}
.d-start{background:color-mix(in srgb,#38bdf8 20%,transparent);color:#7dd3fc;border:1px solid color-mix(in srgb,#38bdf8 32%,transparent)}
.d-intro{background:color-mix(in srgb,var(--ok) 18%,transparent);color:#6ee7b7;border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.d-inter{background:color-mix(in srgb,var(--dnp3) 20%,transparent);color:#fcd34d;border:1px solid color-mix(in srgb,var(--dnp3) 32%,transparent)}
.d-adv{background:color-mix(in srgb,#fb923c 20%,transparent);color:#fdba74;border:1px solid color-mix(in srgb,#fb923c 32%,transparent)}
.d-cap{background:color-mix(in srgb,var(--accent2) 26%,transparent);color:#c4b5fd;border:1px solid color-mix(in srgb,var(--accent2) 38%,transparent)}
html[data-theme="light"] .d-start{color:#0369a1}html[data-theme="light"] .d-intro{color:#15803d}
html[data-theme="light"] .d-inter{color:#a16207}html[data-theme="light"] .d-adv{color:#9a3412}
html[data-theme="light"] .d-cap{color:#6d28d9}
@media(prefers-color-scheme:light){:root:not([data-theme]) .d-start{color:#0369a1}
  :root:not([data-theme]) .d-intro{color:#15803d}:root:not([data-theme]) .d-inter{color:#a16207}
  :root:not([data-theme]) .d-adv{color:#9a3412}:root:not([data-theme]) .d-cap{color:#6d28d9}}
.mins{font-size:var(--step--1);color:var(--faint);font-weight:600}
.donebox{flex:0 0 auto;display:flex;gap:7px;align-items:center;font-size:var(--step--1);color:var(--mut);
  cursor:pointer;user-select:none;border:1px solid var(--line);border-radius:22px;padding:6px 13px;
  background:var(--card-2);transition:all .25s var(--ease)}
.donebox:hover{border-color:var(--ok);color:var(--ink)}
.donebox input{accent-color:var(--ok-deep);width:15px;height:15px}
.lvl.done .donebox{color:#6ee7b7;border-color:color-mix(in srgb,var(--ok) 45%,var(--line));
  background:color-mix(in srgb,var(--ok) 12%,var(--card-2))}
html[data-theme="light"] .lvl.done .donebox{color:#15803d}
.lvlgoal{margin:0 22px 12px;background:var(--card-2);border:1px solid var(--line);border-radius:11px;
  padding:11px 14px;font-size:var(--step-0);position:relative;z-index:1}
.goallabel{font-size:9.5px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--now);margin-right:9px}
.mplaunch{margin:0 22px 12px;background:color-mix(in srgb,#fbbf24 10%,var(--card-2));
  border:1px solid color-mix(in srgb,#fbbf24 30%,var(--line));border-radius:11px;padding:11px 14px;font-size:var(--step--1);position:relative;z-index:1}
.mplaunch b{color:var(--ink)}
.frostteaser{display:none;margin:0 22px 14px;padding:11px 14px;border:1px dashed var(--line);border-radius:11px;
  background:color-mix(in srgb,var(--now) 5%,var(--card-2));position:relative;z-index:1}
.lvl.frosted .frostteaser{display:block}
.ft-k{font-size:9.5px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
.frostteaser p{margin:4px 0 6px;color:var(--mut);font-size:var(--step--1)}
.ft-open{font-size:var(--step--1);color:var(--now);font-weight:700}

.lvlbody{margin:0;border-top:1px solid var(--line);position:relative;z-index:1}
.lvlbody>summary{cursor:pointer;list-style:none;padding:13px 22px;font-weight:700;color:var(--now);
  font-size:var(--step--1);display:flex;align-items:center;gap:9px;letter-spacing:.02em;transition:color .2s var(--ease)}
.lvlbody>summary::-webkit-details-marker{display:none}
.lvlbody>summary::before{content:"";width:16px;height:16px;flex:0 0 auto;
  border:2px solid currentColor;border-radius:5px;position:relative;transition:transform .3s var(--spring)}
.lvlbody>summary::after{content:"";position:absolute;left:29px;width:6px;height:6px;
  border-right:2px solid var(--now);border-bottom:2px solid var(--now);
  transform:rotate(45deg) translateY(-2px);transition:transform .3s var(--spring)}
.lvlbody[open]>summary::after{transform:rotate(225deg) translateY(0)}
.lvlbody .closelabel{display:none}.lvlbody[open] .openlabel{display:none}.lvlbody[open] .closelabel{display:inline}
.lvlinner{padding:2px 22px 22px;animation:bodyin .45s var(--ease)}
@keyframes bodyin{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.obj{margin:.3em 0;padding-left:1.3em}
.obj li{margin:.35em 0;color:var(--mut)}
.obj li::marker{color:var(--now)}
.prereq{font-size:var(--step--1);color:var(--mut);background:var(--card-2);border:1px solid var(--line);
  border-radius:9px;padding:8px 12px}
.prereq b{color:var(--ink)}
.bg{max-width:66ch}
.bg p{margin:.6em 0;color:var(--mut)}

/* ================================ TERMINAL — live instrument ============================ */
.step{margin:11px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--card-2)}
.step.cmd{border-color:var(--line-soft);background:transparent}
.termwrap{border-radius:12px 12px 0 0;overflow:hidden;border:1px solid #0b1120;position:relative;
  box-shadow:0 8px 30px -12px rgba(0,0,0,.6)}
.termwrap::before{content:"";position:absolute;left:0;right:0;top:0;height:2px;z-index:2;background:var(--now)}
.cmd-dnp3 .termwrap::before{background:linear-gradient(90deg,var(--dnp3),var(--dnp3-deep))}
.cmd-mqtt .termwrap::before{background:linear-gradient(90deg,var(--mqtt),var(--mqtt-deep))}
.cmd-neutral .termwrap::before{background:linear-gradient(90deg,var(--accent-glow),var(--accent))}
.titlebar{display:flex;align-items:center;gap:10px;background:#0c1322;padding:8px 12px;border-bottom:1px solid #0b1120}
.tdots{display:flex;gap:6px;flex:0 0 auto}
.tdots i{width:11px;height:11px;border-radius:50%;background:#334155;display:block}
.tdots i:nth-child(1){background:#ef4444aa}.tdots i:nth-child(2){background:#f59e0baa}.tdots i:nth-child(3){background:#22c55eaa}
.tctx{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--step--1);color:#9aa7bd;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ptag{margin-left:auto;font-size:9.5px;font-weight:800;letter-spacing:.08em;padding:2px 8px;border-radius:20px}
.ptag-dnp3{background:color-mix(in srgb,var(--dnp3) 22%,#0c1322);color:#fcd34d}
.ptag-mqtt{background:color-mix(in srgb,var(--mqtt) 22%,#0c1322);color:#5eead4}
.copy{margin-left:8px;border:1px solid #334155;background:#0b1120;color:#cbd5e1;border-radius:8px;
  padding:4px 12px;cursor:pointer;font-size:var(--step--1);font-weight:600;transition:all .2s var(--ease);flex:0 0 auto}
.copy:hover{background:#1e293b;border-color:#475569}
.copy.ok{background:color-mix(in srgb,var(--ok) 25%,#0b1120);border-color:var(--ok);color:#bbf7d0}
.term{margin:0;background:#080d18;color:#e2e8f0;padding:13px 15px;font-size:var(--step--1);overflow-x:auto;white-space:pre;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;line-height:1.6}
.consequence{display:flex;gap:9px;align-items:center;margin:9px 0 0;padding:9px 13px;border-radius:11px;
  background:color-mix(in srgb,var(--dnp3) 12%,var(--card-2));border:1px solid color-mix(in srgb,var(--dnp3) 30%,var(--line));
  font-size:var(--step--1);color:var(--ink)}
.cq-ic{color:var(--dnp3);font-size:1.1em;flex:0 0 auto}
.reveal{margin:9px 0 0;border:1px solid var(--line);border-radius:11px;background:var(--card-2);overflow:hidden}
.reveal>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:9px;padding:9px 13px;font-size:var(--step--1);font-weight:600;color:var(--ok)}
.reveal>summary::-webkit-details-marker{display:none}
.rv-ic{width:15px;height:15px;flex:0 0 auto;border-radius:50%;border:2px solid currentColor;position:relative}
.rv-ic::after{content:"";position:absolute;left:3.5px;top:1px;width:4px;height:7px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(40deg)}
.reveal[open] .rv-label::after{content:" \2014 revealed"}
.rv-hint{margin-left:auto;color:var(--faint);font-weight:500;font-style:italic}
.reveal[open] .rv-hint{display:none}
.expect{background:#080d18;border-top:1px solid var(--line-soft);padding:10px 14px;animation:expfade .5s var(--ease)}
@keyframes expfade{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.explabel{font-size:9.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--ok)}
.expbody{margin:6px 0 0;white-space:pre-wrap;font-size:var(--step--1);color:#b6c2d6;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;line-height:1.55}
.expbody .cursor{display:inline-block;width:.6em;height:1.05em;vertical-align:-.18em;background:var(--ok);
  margin-left:1px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
/* DO · TYPE affordance — the short token the student types to run the command below */
.typerun{display:flex;align-items:center;flex-wrap:wrap;gap:9px;margin:0 0 9px;padding:8px 13px;border-radius:11px;
  background:color-mix(in srgb,var(--accent) 12%,var(--card-2));border:1px solid color-mix(in srgb,var(--accent) 34%,var(--line))}
.tr-badge{font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:20px;flex:0 0 auto;
  background:color-mix(in srgb,var(--accent) 28%,transparent);color:var(--accent-glow)}
html[data-theme="light"] .tr-badge{color:var(--accent)}
.tr-lead{font-weight:700;color:var(--ink);font-size:var(--step--1)}
.tr-tok{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-weight:800;font-size:1.05em;letter-spacing:.03em;
  background:var(--ink);color:var(--bg);padding:2px 13px;border-radius:8px}
.tr-hint{color:var(--faint);font-size:var(--step--1)}
/* CHECK badge inside the expected-output reveal summary */
.rv-badge{display:inline-block;font-size:9px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;padding:2px 7px;border-radius:20px;margin-right:7px;
  background:color-mix(in srgb,var(--ok) 22%,transparent);color:var(--ok)}
.step.gui,.step.note{display:flex;gap:12px;align-items:flex-start;padding:11px 14px}
.step.gui{background:color-mix(in srgb,#38bdf8 8%,var(--card-2))}
.step.note{background:color-mix(in srgb,var(--mut) 7%,var(--card-2))}
.kind{font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:20px;flex:0 0 auto;margin-top:1px}
.kind-gui{background:color-mix(in srgb,#38bdf8 22%,transparent);color:#7dd3fc}
.kind-note{background:color-mix(in srgb,var(--dnp3) 22%,transparent);color:#fcd34d}
.kind-read{background:color-mix(in srgb,var(--mut) 20%,transparent);color:var(--mut)}
html[data-theme="light"] .kind-gui{color:#1d4ed8}html[data-theme="light"] .kind-note{color:#92400e}
html[data-theme="light"] .kind-read{color:#475569}
.steptext{flex:1;color:var(--mut)}
.steptext b{color:var(--ink)}

/* ================================ CHECKPOINT — evidence card ============================ */
.checks{display:grid;gap:9px}
.cp{border:1px solid var(--line);border-radius:12px;background:var(--card-2);transition:border-color .25s var(--ease)}
.cp:hover{border-color:color-mix(in srgb,var(--now) 40%,var(--line))}
.cp>summary{cursor:pointer;padding:11px 14px;list-style:none;font-size:var(--step-0);display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}
.cp>summary::-webkit-details-marker{display:none}
.cp>summary::before{content:"?";flex:0 0 auto;width:22px;height:22px;border-radius:50%;
  background:color-mix(in srgb,var(--now) 22%,transparent);color:var(--now);font-weight:800;font-size:13px;
  display:flex;align-items:center;justify-content:center;margin-top:1px;border:1px solid color-mix(in srgb,var(--now) 40%,transparent);transition:all .3s var(--spring)}
.cp[open]>summary::before{content:"\2713";background:var(--ok);color:#062e17;border-color:var(--ok)}
.cpq{font-weight:600;flex:1;min-width:60%;color:var(--ink)}
.cphint{font-size:var(--step--1);color:var(--faint);font-style:italic;width:100%;padding-left:32px}
.cp[open] .cphint{display:none}
.cpquiz{width:100%;padding-left:32px;display:grid;gap:6px;margin-top:2px}
.cpopt{text-align:left;background:var(--card);border:1px solid var(--line);color:var(--ink);
  border-radius:9px;padding:8px 12px;font-size:var(--step--1);cursor:pointer;font-family:inherit;
  transition:all .18s var(--ease);position:relative}
.cpopt:hover{border-color:var(--now);background:color-mix(in srgb,var(--now) 8%,var(--card))}
.cpopt.right{border-color:var(--ok);background:color-mix(in srgb,var(--ok) 16%,var(--card));color:var(--ink)}
.cpopt.right::after{content:"\2713";float:right;color:var(--ok);font-weight:900}
.cpopt.wrong{border-color:var(--ghost);background:color-mix(in srgb,var(--ghost) 14%,var(--card))}
.cpopt.wrong::after{content:"\2717";float:right;color:var(--ghost);font-weight:900}
.cpopt:disabled{cursor:default}
.cpquiz-fb{font-size:var(--step--1);font-weight:700;min-height:1em}
.cpquiz-fb.ok{color:var(--ok)}.cpquiz-fb.no{color:var(--ghost)}
.cpa{padding:2px 14px 13px 46px;color:var(--mut);font-size:var(--step-0);animation:expfade .4s var(--ease)}

/* ================================ LEVEL-UP + storybeat ============================ */
.levelup{margin-top:16px;background:color-mix(in srgb,var(--ok) 10%,var(--card-2));
  border:1px solid color-mix(in srgb,var(--ok) 26%,var(--line));border-radius:12px;padding:11px 14px;font-size:var(--step-0)}
.lulabel{font-size:9.5px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--ok);margin-right:9px}
.storybeat{margin-top:14px;display:flex;gap:14px;align-items:flex-start;padding:16px 18px;border-radius:14px;
  background:linear-gradient(120deg,color-mix(in srgb,var(--now) 12%,var(--card)),var(--card));
  border:1px solid color-mix(in srgb,var(--now) 26%,var(--line));position:relative;overflow:hidden}
.storybeat::before{content:"";position:absolute;right:-40px;top:-40px;width:160px;height:160px;border-radius:50%;
  background:radial-gradient(circle,color-mix(in srgb,var(--now) 22%,transparent),transparent 70%)}
.sb-lens{flex:0 0 auto;width:34px;height:34px;color:var(--now);position:relative;z-index:1}
.sb-glyph{width:34px;height:34px}
.sb-body{position:relative;z-index:1}
.sb-k{font-size:9.5px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:var(--now)}
.storybeat p{margin:3px 0 0;color:var(--ink);font-size:var(--step-0);line-height:1.55;max-width:60ch;font-style:italic}

/* ================================ HERO SPECIMEN — exploded frame 27 ============================ */
.specimen{margin:16px 0 2px;padding:0;border:1px solid color-mix(in srgb,var(--dnp3) 30%,var(--line));
  border-radius:16px;background:linear-gradient(180deg,#0c1322,#0a0f1c);overflow:hidden;position:relative}
.specimen figcaption{padding:13px 16px;border-bottom:1px solid var(--line-soft);color:#cbd5e1;font-size:var(--step-0);font-weight:700}
.spec-k{display:inline-block;font-size:9.5px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;
  color:var(--dnp3);background:color-mix(in srgb,var(--dnp3) 16%,transparent);border-radius:6px;padding:2px 8px;margin-right:9px}
.spec-hint{display:block;font-weight:400;font-size:var(--step--1);color:#8b98af;margin-top:5px}
.spec-hint a{color:var(--dnp3)}
.xstack{padding:16px;display:grid;gap:12px}
.xlayer{position:relative;padding:11px 13px 13px;border-radius:12px;background:rgba(255,255,255,.02);
  border:1px solid rgba(255,255,255,.06);margin-left:calc(var(--xo,0)*14px)}
.xlayer[data-layer="net"]{--xo:0}.xlayer[data-layer="dl"]{--xo:1}
.xlayer[data-layer="tr"]{--xo:2}.xlayer[data-layer="app"]{--xo:3}
.xlayer::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;background:#334155}
.xlayer[data-layer="net"]::before{background:#64748b}
.xlayer[data-layer="dl"]::before{background:var(--dnp3)}
.xlayer[data-layer="tr"]::before{background:#818cf8}
.xlayer[data-layer="app"]::before{background:var(--dnp3-deep)}
.xtag{font-size:9.5px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8;display:block;margin-bottom:8px}
.xrow{display:flex;flex-wrap:wrap;gap:8px}
.xchip{display:flex;flex-direction:column;gap:3px;padding:7px 10px;border-radius:9px;background:#0b1120;
  border:1px solid #22304d;cursor:default;transition:transform .2s var(--spring),box-shadow .2s var(--ease),border-color .2s var(--ease);outline:none}
.xchip:hover,.xchip:focus-visible{transform:translateY(-3px);border-color:#3b82f6;box-shadow:0 8px 20px -8px rgba(59,130,246,.5)}
.xhex{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--step--1);color:#93c5fd;letter-spacing:.05em}
.xlab{font-size:10.5px;color:#8b98af;line-height:1.35}
.xlab b{color:#e2e8f0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-weight:600}
.xchip[data-tell="1"]{border-color:var(--ghost);background:color-mix(in srgb,var(--ghost) 12%,#0b1120)}
.xchip[data-tell="1"] .xhex{color:#fca5a5}
.xchip[data-tell="1"]:hover,.xchip[data-tell="1"]:focus-visible{box-shadow:0 8px 22px -8px color-mix(in srgb,var(--ghost) 60%,transparent);border-color:var(--ghost)}
.xtell{display:block;margin-top:3px;font-size:9.5px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:var(--ghost)}
.xtellbox{margin:0 16px 16px;padding:13px 15px;border-radius:12px;
  background:color-mix(in srgb,var(--ghost) 10%,#0b1120);border:1px solid color-mix(in srgb,var(--ghost) 34%,transparent)}
.xtellhead{display:flex;align-items:center;gap:9px;font-weight:800;color:#fca5a5;font-size:var(--step-0);margin-bottom:5px}
.xtelllens{width:22px;height:22px;color:var(--ghost)}
.xtellbox p{margin:0;color:#c3cde0;font-size:var(--step--1);line-height:1.55}
.xtellbox code{background:color-mix(in srgb,var(--ghost) 16%,transparent);border-color:color-mix(in srgb,var(--ghost) 30%,transparent);color:#fecaca}

/* ================================ glossary <dfn> tokens ============================ */
.dfn{border-bottom:1px dashed color-mix(in srgb,var(--now) 55%,var(--faint));cursor:help;position:relative;
  color:inherit;font-style:inherit;background:none;border-left:0;border-right:0;border-top:0;padding:0;font:inherit}
.dfn:focus-visible{outline:2px solid var(--accent-glow);outline-offset:2px}
.dfntip{position:absolute;left:0;bottom:calc(100% + 8px);z-index:40;width:min(280px,72vw);
  background:var(--bg-raise);color:var(--ink);border:1px solid var(--now);border-radius:10px;padding:9px 12px;
  font-size:var(--step--1);font-style:normal;line-height:1.45;font-weight:400;letter-spacing:normal;text-transform:none;
  box-shadow:0 12px 34px -10px rgba(0,0,0,.6);opacity:0;visibility:hidden;transform:translateY(4px);
  transition:opacity .18s var(--ease),transform .18s var(--ease);pointer-events:none}
.dfntip::before{content:"";position:absolute;left:16px;top:100%;border:6px solid transparent;border-top-color:var(--now)}
.dfn:hover .dfntip,.dfn:focus .dfntip,.dfn:focus-within .dfntip{opacity:1;visibility:visible;transform:none}

/* ================================ footer ============================ */
.footer{max-width:1120px;margin:0 auto;padding:0 clamp(1rem,2vw,1.6rem) 60px;color:var(--faint);font-size:var(--step--1)}
.footer code{color:var(--mut)}
.footer a{white-space:nowrap}

/* ================================ CASE FILE drawer ============================ */
.casefile{position:fixed;top:0;right:0;bottom:0;width:min(400px,92vw);z-index:80;
  background:var(--bg-raise);border-left:1px solid var(--line);box-shadow:-20px 0 60px -20px rgba(0,0,0,.6);
  transform:translateX(100%);transition:transform .4s var(--ease);display:flex;flex-direction:column}
.casefile.open{transform:none}
.cf-head{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--line)}
.cf-head b{font-size:var(--step-1);color:var(--ink)}
.cf-head .cf-k{display:block;font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ghost);font-weight:800;margin-bottom:2px}
.cf-close{background:none;border:1px solid var(--line);color:var(--mut);border-radius:9px;width:32px;height:32px;cursor:pointer;font-size:1.1em}
.cf-close:hover{border-color:var(--now);color:var(--ink)}
.cf-body{overflow:auto;padding:16px 18px;flex:1}
.cf-body h3{font-size:var(--step--1);text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin:18px 0 10px}
.cf-body h3:first-child{margin-top:0}
#cf-evlist{list-style:none;margin:0;padding:0;display:grid;gap:9px;counter-reset:ev}
#cf-evlist li{position:relative;padding:11px 13px 11px 40px;background:var(--card);border:1px solid var(--line);
  border-left:3px solid var(--ghost);border-radius:10px;font-size:var(--step--1);color:var(--mut);animation:rise .4s var(--spring) both}
#cf-evlist li b{color:var(--ink)}
#cf-evlist li::before{counter-increment:ev;content:counter(ev);position:absolute;left:11px;top:11px;width:20px;height:20px;
  border-radius:50%;background:color-mix(in srgb,var(--ghost) 20%,transparent);color:var(--ghost);font-weight:800;
  font-size:11px;display:flex;align-items:center;justify-content:center}
#cf-evempty{color:var(--faint);font-size:var(--step--1);font-style:italic}
#cf-nblist{margin:0;display:grid;gap:8px}
#cf-nblist .nb{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:9px 12px}
#cf-nblist dt{font-weight:800;color:var(--now);font-size:var(--step--1);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
#cf-nblist dd{margin:3px 0 0;color:var(--mut);font-size:var(--step--1);line-height:1.45}
.scrim{position:fixed;inset:0;z-index:70;background:rgba(4,7,15,.55);backdrop-filter:blur(2px);opacity:0;visibility:hidden;transition:opacity .3s ease}
.scrim.on{opacity:1;visibility:visible}

/* ================================ command palette ============================ */
.palette{position:fixed;inset:0;z-index:100;display:flex;align-items:flex-start;justify-content:center;padding-top:12vh}
.pal-backdrop{position:absolute;inset:0;background:rgba(4,7,15,.6);backdrop-filter:blur(3px)}
.pal-box{position:relative;width:min(560px,92vw);background:var(--bg-raise);border:1px solid var(--line);
  border-radius:16px;box-shadow:0 30px 80px -20px rgba(0,0,0,.7);overflow:hidden;animation:rise .28s var(--spring)}
#pal-input{width:100%;border:none;border-bottom:1px solid var(--line);background:transparent;color:var(--ink);
  font-size:var(--step-1);padding:16px 18px;outline:none;font-family:inherit}
#pal-input::placeholder{color:var(--faint)}
#pal-list{list-style:none;margin:0;padding:8px;max-height:52vh;overflow:auto}
#pal-list li{padding:10px 13px;border-radius:10px;cursor:pointer;display:flex;align-items:center;gap:11px;font-size:var(--step-0);color:var(--mut)}
#pal-list li .pk{font-size:9.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);
  margin-left:auto;border:1px solid var(--line);border-radius:5px;padding:2px 6px}
#pal-list li .pico{width:20px;text-align:center;color:var(--now);flex:0 0 auto}
#pal-list li b{color:var(--ink);font-weight:600}
#pal-list li.sel,#pal-list li:hover{background:color-mix(in srgb,var(--now) 14%,transparent)}
#pal-list li.sel b,#pal-list li:hover b{color:var(--ink)}

/* ================================ cold open ============================ */
.coldopen{position:fixed;inset:0;z-index:120;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(80% 60% at 50% 40%,#0d1426,#070a12);padding:24px;animation:cofade .6s ease}
@keyframes cofade{from{opacity:0}to{opacity:1}}
.co-inner{max-width:620px;text-align:center;animation:rise .7s var(--spring)}
.co-lens{width:64px;height:64px;color:var(--ghost);margin:0 auto 22px}
.co-lens .lens{width:64px;height:64px}
.co-text{font-size:var(--step-3);line-height:1.5;color:#e8edf7;font-weight:600;letter-spacing:-.01em;margin:0 0 28px;text-wrap:balance}
.co-actions{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.co-enter{background:linear-gradient(100deg,#6366f1,#818cf8);color:#0a0e1a;border:none;border-radius:30px;
  padding:12px 28px;font-size:var(--step-0);font-weight:800;cursor:pointer;transition:transform .2s var(--spring),box-shadow .2s var(--ease);box-shadow:0 0 30px -6px rgba(129,140,248,.6)}
.co-enter:hover{transform:translateY(-2px)}
.co-skip{background:none;border:1px solid rgba(255,255,255,.2);color:#aeb9d6;border-radius:30px;padding:12px 22px;font-size:var(--step--1);cursor:pointer}
.co-skip:hover{background:rgba(255,255,255,.06)}

@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes ghostpulse{0%,100%{opacity:1}50%{opacity:.3}}
.lensghost{animation:ghostpulse 1.7s ease-in-out infinite}

/* capstone ignite */
.lvl.mp.ignited{border-color:color-mix(in srgb,#fbbf24 55%,var(--line));
  box-shadow:0 0 40px -10px rgba(251,191,36,.5)}
.lvl.mp.ignited .lvledge{background:linear-gradient(180deg,#fde68a,#fbbf24);box-shadow:0 0 26px rgba(251,191,36,.7)}

/* ============================ responsive ============================ */
@media(max-width:860px){
  .layout{grid-template-columns:1fr}
  .rail{position:static;max-height:none;top:0;margin-bottom:6px}
  .railh{margin-bottom:8px}
  .spine{display:flex;flex-wrap:wrap;gap:5px;padding-left:0}
  .spine::before,.spinefill{display:none}
  .navdot{padding:6px 9px;border:1px solid var(--line);border-radius:20px;background:var(--card)}
  .navdot .nd-rail{flex:0 0 auto}
  .nd-node{width:12px;height:12px}
  .nd-alt{display:none}
  .nd-t{display:none}
  .nd-line{gap:0}
}
@media(max-width:520px){
  .topbar{flex-direction:column}
  .herotools{align-self:flex-end}
}

/* ============================ reduced motion — considered static twins ============================ */
@media(prefers-reduced-motion:reduce){
  *{animation:none !important;transition:none !important;scroll-behavior:auto !important}
  .lensghost{opacity:1}
  .expbody .cursor{display:none}
  /* the exploded frame still explodes into a labelled diagram; the spine still shows filled
     waypoints; the constellation freezes to a still starfield (handled in JS) */
}
</style></head>
<body>
<header class="hero" id="hero">
  <div class="herobg" aria-hidden="true"></div>
  <canvas id="constellation" aria-hidden="true"></canvas>
  <div class="herosky" aria-hidden="true"></div>
  <div class="heroinner">
    <div class="topbar">
      <div class="kick"><span class="klens">__LENS_KICK__</span>First Light &nbsp;&middot;&nbsp; The Signal Descent</div>
      <div class="herotools">
        <button class="htbtn" id="casebtn" type="button" aria-haspopup="dialog">__LENS_CASE__ Case File</button>
        <button class="htbtn" id="themebtn" type="button" aria-label="Toggle light and dark theme">
          <span id="theme-ic" aria-hidden="true">◐</span><span id="theme-tx">Theme</span></button>
      </div>
    </div>
    <h1>DNP3 &amp; MQTT &mdash; <span class="fl">First Light</span>: from first packet to catching an intruder</h1>
    <p class="sub">A network is a conversation you can watch &mdash; and something in this one moves wrong.
      Descend seven altitudes, from the whole network down to a single byte, and learn to see the ghost on the wire.</p>
    <div class="legend">
      <span class="lg lg-dnp3"><span>Amber &middot; DNP3 substation</span></span>
      <span class="lg lg-mqtt"><span>Teal &middot; MQTT telemetry</span></span>
      <span class="lg lg-ghost"><span>Red &middot; the rogue .66</span></span>
    </div>
    <div class="progwrap">
      <div class="progrow"><span id="progtext" aria-live="polite">0 of __TOTAL__ levels complete</span>
        <button class="reset" id="resetbtn" type="button">Reset progress</button></div>
      <div class="progbar"><div class="progfill" id="progfill"></div></div>
    </div>
    <a class="enter" href="#level-0">Begin the descent <span class="ea" aria-hidden="true">↓</span></a>
  </div>
</header>

<div class="layout">
  <aside class="rail" aria-label="The climb — level navigation">
    <div class="railh">The Climb</div>
    <div class="spine">
      <span class="spinefill" aria-hidden="true"></span>
      __NAV__
    </div>
  </aside>
  <main>
    <div class="welcome" id="welcome" hidden>
      <span id="welcome-txt"></span>
      <button class="wgo" id="welcome-go" type="button">Continue</button>
      <button class="wx" id="welcome-x" type="button" aria-label="Dismiss">✕</button>
    </div>

    <div class="intro">
      <h2>How the descent works</h2>
      <p>Seven stations, one continuous zoom. Read the <b>Goal</b>, open a station, and work its steps — each one is
      one of three kinds. A <span class="inlinekind">READ</span> step is background: read it and move on. A
      <span class="inlinekind">DO&nbsp;·&nbsp;CLICK</span> step is a click to make in Wireshark on the noVNC desktop.
      A <span class="inlinekind">DO&nbsp;·&nbsp;TYPE</span> step shows a short handle like <code>l1</code> that you just
      <b>type</b> in the terminal — it prints the real command <em>and runs it</em>, so there is nothing to copy-paste
      (the terminal card's <span class="inlinekind">Copy</span> button stays as a backup, and <code>lab list</code> shows
      every handle). Each command ends in a <span class="inlinekind">CHECK</span> — the expected output: predict it, then
      reveal to self-verify. Tick <b>Done</b> and watch the sky warm from night toward first light. Your progress is saved
      in this browser; the seven-station descent ends in a graded-style capstone (Level&nbsp;6), and an advanced
      <b>Level&nbsp;7</b> then carries those exact skills onto a living digital-twin plant.</p>
      <div class="pathline">
        <span class="pl">tooling</span><span class="arr">&rarr;</span>
        <span class="pl">endpoints</span><span class="arr">&rarr;</span>
        <span class="pl">message types</span><span class="arr">&rarr;</span>
        <span class="pl">inside the packet</span><span class="arr">&rarr;</span>
        <span class="pl">find the attack</span><span class="arr">&rarr;</span>
        <span class="pl">detection</span><span class="arr">&rarr;</span>
        <span class="pl">Machine Problem</span><span class="arr">&rarr;</span>
        <span class="pl" style="color:var(--ok)">the living plant</span>
      </div>
    </div>

    <div class="jump">
      <h3>Reference material (open in a second tab as you go)</h3>
      <div class="links">
        <a href="../modules/dnp3_module.html">DNP3 module &mdash; frame explorer</a>
        <a href="../modules/mqtt_module.html">MQTT module &mdash; frame explorer</a>
        <a href="../mp/README.md">Machine Problem handout</a>
        <a href="../LAB_GUIDE.md">Lab guide</a>
      </div>
    </div>

    __CARDS__
  </main>
</div>
<div class="footer">
  <p>All commands and expected outputs on this page were verified with tshark 4.2 against the shipped captures
  (<code>pcaps/dnp3_substation.pcap</code>, <code>pcaps/mqtt_iot_telemetry.pcap</code>). The exploded specimen is a
  fixed teaching diagram of frame&nbsp;27; the module Frame Explorers remain the full byte-level tool. Progress
  tracking uses this browser's local storage only &mdash; nothing leaves your machine. See
  <code>FORMAL_VERIFICATION.md</code> for the full verification record and <code>EXTERNAL_CAPTURES.md</code> for
  additional government / university captures you can practice on.</p>
</div>

<aside class="casefile" id="casefile" hidden aria-label="Case file: the rogue .66" role="dialog" aria-modal="false">
  <div class="cf-head"><div><span class="cf-k">Dossier</span><b>The Ghost &mdash; .66</b></div>
    <button class="cf-close" id="cf-close" type="button" aria-label="Close case file">✕</button></div>
  <div class="cf-body">
    <h3>Evidence &mdash; collected on Done</h3>
    <ol id="cf-evlist"></ol>
    <p id="cf-evempty">Mark stations <b>Done</b> to collect the evidence trail the ghost leaves behind&hellip;</p>
    <h3>Field notebook</h3>
    <dl id="cf-nblist"></dl>
  </div>
</aside>
<div class="scrim" id="scrim"></div>

<div class="palette" id="palette" hidden>
  <div class="pal-backdrop" data-palclose></div>
  <div class="pal-box" role="dialog" aria-modal="true" aria-label="Command palette">
    <input id="pal-input" type="text" placeholder="Jump to a station, toggle theme, mark done, open a module…" autocomplete="off" spellcheck="false">
    <ul id="pal-list"></ul>
  </div>
</div>

<div class="coldopen" id="coldopen" hidden>
  <div class="co-inner">
    <div class="co-lens">__LENS_COLD__</div>
    <p class="co-text">__COLDOPEN__</p>
    <div class="co-actions">
      <button class="co-enter" id="co-enter" type="button">Begin the descent ↓</button>
      <button class="co-skip" id="co-skip" type="button">Skip intro</button>
    </div>
  </div>
</div>

<script>
var GLOSSARY = __GLOSSARY_JSON__;
var CASEFILE = __CASEFILE_JSON__;

/* ============ progress core (preserved key + Set + apply + handlers + reset + scroll-spy) ============ */
(function(){
  "use strict";
  var KEY = "icskit.path.progress.v1";
  var THEMEKEY = "icskit.path.theme.v1";
  var COKEY = "icskit.path.coldopen.v1";
  var IGNITEKEY = "icskit.path.ignited.v1";
  var TOTAL = __TOTAL__;
  var done = new Set();
  var RM = false;
  try{ RM = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }catch(e){}

  function load(){
    try{ var raw = localStorage.getItem(KEY); if(raw){ JSON.parse(raw).forEach(function(n){done.add(+n);}); } }
    catch(e){}
  }
  function save(){
    try{ localStorage.setItem(KEY, JSON.stringify([].concat(Array.from(done)))); }catch(e){}
  }
  function maxDone(){ var m=-1; done.forEach(function(n){ if(n>m) m=n; }); return m; }

  function renderCase(){
    try{
      var list = document.getElementById("cf-evlist");
      var empty = document.getElementById("cf-evempty");
      if(!list) return;
      list.innerHTML = "";
      var order = Array.from(done).sort(function(a,b){return a-b;});
      order.forEach(function(n){
        var rec = CASEFILE[n]; if(!rec || !rec.evidence) return;
        var li = document.createElement("li");
        li.innerHTML = '<b>L'+rec.n+' &middot; '+rec.zoom+'</b><br>'+rec.evidence;
        list.appendChild(li);
      });
      if(empty) empty.style.display = list.children.length ? "none" : "";
    }catch(e){}
  }

  function apply(){
    var md = maxDone();
    document.querySelectorAll(".donechk").forEach(function(chk){
      var n = +chk.dataset.level, on = done.has(n);
      chk.checked = on;
      var card = document.getElementById("level-"+n);
      if(card){
        card.classList.toggle("done", on);
        var reach = n <= md+1;
        card.classList.toggle("frosted", !on && !reach);
        card.setAttribute("data-reachable", reach ? "1" : "0");
      }
      var dot = document.querySelector('.navdot[data-level="'+n+'"]');
      if(dot){
        dot.classList.toggle("done", on);
        dot.setAttribute("data-reachable", (n <= md+1) ? "1" : "0");
      }
    });
    var c = done.size, pct = TOTAL ? Math.round(c/TOTAL*100) : 0;
    var fill = document.getElementById("progfill"); if(fill) fill.style.width = pct+"%";
    var t = document.getElementById("progtext"); if(t) t.textContent = c+" of "+TOTAL+" levels complete";
    var spine = document.querySelector(".spinefill"); if(spine) spine.style.height = pct+"%";
    var hero = document.getElementById("hero"); if(hero) hero.style.setProperty("--dawn", (pct/100).toFixed(3));

    // capstone ignite when every pre-MP level is done (one-time celebratory flag; still class-applied each load)
    var MPLEVEL = __MP_LEVEL__;
    var baseDone = true; for(var i=0;i<MPLEVEL;i++){ if(!done.has(i)){ baseDone=false; break; } }
    var mp = document.getElementById("level-"+MPLEVEL);
    if(mp){
      if(baseDone){
        var wasIgnited=false; try{ wasIgnited = localStorage.getItem(IGNITEKEY)==="1"; }catch(e){}
        mp.classList.add("ignited");
        if(!wasIgnited && !RM){ try{ localStorage.setItem(IGNITEKEY,"1"); }catch(e){} }
      } else {
        mp.classList.remove("ignited");
        try{ localStorage.removeItem(IGNITEKEY); }catch(e){}
      }
    }
    renderCase();
  }

  function pulseSpine(n){
    if(RM) return;
    var dot = document.querySelector('.navdot[data-level="'+n+'"]');
    if(dot){ dot.classList.add("justdone"); setTimeout(function(){ dot.classList.remove("justdone"); }, 650); }
    var spine = document.querySelector(".spine");
    if(spine){ spine.classList.add("flow"); setTimeout(function(){ spine.classList.remove("flow"); }, 720); }
  }

  load();
  document.querySelectorAll(".donechk").forEach(function(chk){
    chk.addEventListener("change", function(){
      var n = +chk.dataset.level;
      if(chk.checked){ done.add(n); pulseSpine(n); } else { done.delete(n); }
      save(); apply();
    });
  });
  var rb = document.getElementById("resetbtn");
  if(rb) rb.addEventListener("click", function(){ done.clear(); try{localStorage.removeItem(IGNITEKEY);}catch(e){} save(); apply(); });
  apply();

  // active-station highlight in the spine (scroll-spy, unchanged contract)
  var cards = [].slice.call(document.querySelectorAll(".lvl"));
  function onScroll(){
    var y = window.scrollY + 150, cur = null;
    cards.forEach(function(c){ if(c.offsetTop <= y) cur = c.id; });
    document.querySelectorAll(".navdot").forEach(function(d){
      d.classList.toggle("active", d.getAttribute("href") === "#"+cur);
    });
  }
  window.addEventListener("scroll", onScroll, {passive:true}); onScroll();

  // expose a tiny API for the enhancement blocks below (all optional, all guarded)
  window.__FL = {
    done:done, apply:apply, save:save, TOTAL:TOTAL, RM:RM,
    frontier:function(){ for(var i=0;i<TOTAL;i++){ if(!done.has(i)) return i; } return -1; },
    markDone:function(n){ done.add(n); pulseSpine(n); save(); apply(); },
    KEYS:{THEMEKEY:THEMEKEY, COKEY:COKEY}
  };
})();

/* ============ copy (PRESERVED — copies the exact pre.term.textContent) ============ */
function cpPre(btn){
  var pre = btn.closest(".step").querySelector("pre.term");
  if(!pre) return;
  var txt = pre.textContent, orig = btn.textContent;
  function ok(){ btn.textContent = "Copied ✓"; btn.classList.add("ok");
    setTimeout(function(){ btn.textContent = orig; btn.classList.remove("ok"); }, 1200); }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(ok, function(){ btn.textContent = "Select & copy"; });
  } else {
    var r = document.createRange(); r.selectNodeContents(pre);
    var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); ok();
  }
}

/* ============ theme: OS preference wins until the user overrides (persisted) ============ */
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

/* ============ color-script beats via IntersectionObserver (no scroll thrash) ============ */
(function(){
  try{
    if(!("IntersectionObserver" in window)){ document.body.setAttribute("data-beat","dawn"); return; }
    var secs = [].slice.call(document.querySelectorAll(".lvl[data-beat]"));
    if(!secs.length) return;
    document.body.setAttribute("data-beat", secs[0].getAttribute("data-beat"));
    var vis = {};
    var io = new IntersectionObserver(function(entries){
      entries.forEach(function(en){ vis[en.target.id] = en.isIntersecting ? en.intersectionRatio : 0; });
      var best=null, br=0;
      secs.forEach(function(s){ var r=vis[s.id]||0; if(r>br){ br=r; best=s; } });
      if(best) document.body.setAttribute("data-beat", best.getAttribute("data-beat"));
    }, {rootMargin:"-30% 0px -45% 0px", threshold:[0,.25,.5,.75,1]});
    secs.forEach(function(s){ io.observe(s); });
  }catch(e){ try{ document.body.setAttribute("data-beat","dawn"); }catch(_){} }
})();

/* ============ living hero: the conversation constellation (single rAF, DPR, paused) ============ */
(function(){
  try{
    var cv = document.getElementById("constellation");
    if(!cv || !cv.getContext) return;
    var ctx = cv.getContext("2d");
    var RM=false; try{ RM = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }catch(e){}
    var W=0,H=0,DPR=1, running=false, onscreen=true, raf=0;
    var nodes=[], links=[], parts=[], last=0;

    function build(){
      // normalized layout (0..1); MQTT star on the right flank, DNP3 pair on the left, ghost centre-low
      nodes = [
        {id:"broker", x:.72, y:.42, r:6.5, c:"#2dd4bf", hub:1},
        {id:"m1", x:.86, y:.24, r:3.4, c:"#2dd4bf"},
        {id:"m2", x:.90, y:.52, r:3.4, c:"#2dd4bf"},
        {id:"m3", x:.80, y:.68, r:3.4, c:"#2dd4bf"},
        {id:"master", x:.20, y:.30, r:5.5, c:"#f59e0b"},
        {id:"outst",  x:.30, y:.66, r:5.5, c:"#f59e0b"},
        {id:"ghost",  x:.50, y:.78, r:5, c:"#f87171", ghost:1}
      ];
      links = [
        {a:"broker",b:"m1",c:"#2dd4bf"},{a:"broker",b:"m2",c:"#2dd4bf"},{a:"broker",b:"m3",c:"#2dd4bf"},
        {a:"master",b:"outst",c:"#f59e0b"},
        {a:"ghost",b:"outst",c:"#f87171",rogue:1},{a:"ghost",b:"broker",c:"#f87171",rogue:1}
      ];
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
      if(parts.length > 40) return;
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
      // links
      links.forEach(function(l){
        var a=px(N(l.a)), b=px(N(l.b));
        ctx.strokeStyle = l.c; ctx.globalAlpha = l.rogue?0.12:0.16; ctx.lineWidth = 1;
        if(l.rogue){ ctx.setLineDash([3,5]); } else { ctx.setLineDash([]); }
        ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
      });
      ctx.setLineDash([]); ctx.globalAlpha=1;
      // nodes (soft glow + core)
      nodes.forEach(function(n){
        var p=px(n);
        var jitter = n.ghost ? Math.sin(ts/230)*2.2 : 0;
        var pp = {x:p.x+jitter, y:p.y+ (n.ghost?Math.cos(ts/190)*1.6:0)};
        glow(pp, n.r, n.c, n.ghost ? (0.5+0.3*Math.abs(Math.sin(ts/300))) : (n.hub?0.5:0.34));
        ctx.fillStyle = n.c; ctx.beginPath(); ctx.arc(pp.x,pp.y,n.r,0,6.2832); ctx.fill();
        if(n.hub){ ctx.strokeStyle="rgba(45,212,191,.5)"; ctx.lineWidth=1.4;
          ctx.beginPath(); ctx.arc(pp.x,pp.y,n.r+4,0,6.2832); ctx.stroke(); }
      });
      // particles
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
      // reduced-motion / paused static frame: nodes + links + a few frozen packets
      resize(); ctx.clearRect(0,0,W,H);
      links.forEach(function(l){ var a=px(N(l.a)),b=px(N(l.b));
        ctx.strokeStyle=l.c; ctx.globalAlpha=l.rogue?0.12:0.16; ctx.lineWidth=1;
        if(l.rogue) ctx.setLineDash([3,5]); else ctx.setLineDash([]);
        ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
      });
      ctx.setLineDash([]); ctx.globalAlpha=1;
      nodes.forEach(function(n){ var p=px(n); glow(p,n.r,n.c,n.hub?0.5:(n.ghost?0.6:0.34));
        ctx.fillStyle=n.c; ctx.beginPath(); ctx.arc(p.x,p.y,n.r,0,6.2832); ctx.fill(); });
      // a few static packets mid-link
      links.forEach(function(l,idx){ var a=px(N(l.a)),b=px(N(l.b)); var t=0.35+0.1*idx%0.6;
        var x=a.x+(b.x-a.x)*t,y=a.y+(b.y-a.y)*t; glow({x:x,y:y},2.2,l.c,0.8);
        ctx.fillStyle="#fff"; ctx.beginPath(); ctx.arc(x,y,1.4,0,6.2832); ctx.fill(); });
    }
    function start(){ if(running) return; if(RM||document.hidden||!onscreen){ return; } running=true; last=0; raf=requestAnimationFrame(frame); }
    function stop(){ running=false; if(raf) cancelAnimationFrame(raf); raf=0; }

    build(); resize();
    if(RM){ still(); }
    else{
      var io = null;
      try{
        io = new IntersectionObserver(function(en){ onscreen = en[0].isIntersecting; if(onscreen) start(); else stop(); }, {threshold:0.02});
        io.observe(cv);
      }catch(e){ onscreen=true; }
      document.addEventListener("visibilitychange", function(){ if(document.hidden) stop(); else start(); });
      var rt=0; window.addEventListener("resize", function(){ clearTimeout(rt); rt=setTimeout(function(){ resize(); if(!running && !RM) still(); }, 150); }, {passive:true});
      start();
      // if it never started (e.g. offscreen), still paint a static frame so the hero is never blank
      setTimeout(function(){ if(!running) still(); }, 400);
    }
  }catch(e){ /* canvas failure never breaks the page — the CSS gradient remains */ }
})();

/* ============ predict-then-reveal terminal: typewriter on a CLONE (never touches pre.term) ============ */
(function(){
  try{
    var RM=false; try{ RM = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }catch(e){}
    if(RM) return; // reduced motion: the <details> simply reveals the real expected block, no typing
    document.querySelectorAll(".reveal").forEach(function(d){
      d.addEventListener("toggle", function(){
        if(!d.open || d.dataset.typed) return;
        var real = d.querySelector(".expbody"); if(!real) return;
        d.dataset.typed = "1";
        var full = real.textContent;              // read only — never write pre.term
        real.dataset.final = full;
        real.textContent = "";
        var cur = document.createElement("span"); cur.className="cursor"; real.appendChild(cur);
        var i=0, n=full.length, step=Math.max(1, Math.round(n/90));
        (function type(){
          if(i>=n){ real.textContent = full; return; }
          i = Math.min(n, i+step);
          real.textContent = full.slice(0,i);
          real.appendChild(cur);
          setTimeout(type, 16);
        })();
      });
    });
  }catch(e){}
})();

/* ============ checkpoint quiz: mark right/wrong before the <details> reveal ============ */
(function(){
  try{
    document.querySelectorAll(".cpquiz").forEach(function(q){
      var correct = +q.getAttribute("data-correct");
      var fb = q.querySelector(".cpquiz-fb");
      var opts = [].slice.call(q.querySelectorAll(".cpopt"));
      opts.forEach(function(b){
        b.addEventListener("click", function(ev){
          ev.preventDefault(); ev.stopPropagation();       // don't toggle the <details>
          if(q.dataset.answered) return;
          q.dataset.answered = "1";
          var i = +b.dataset.i;
          opts.forEach(function(o){ o.disabled = true; });
          opts[correct].classList.add("right");
          if(i===correct){ if(fb){ fb.textContent="Correct — now open the card to confirm."; fb.className="cpquiz-fb ok"; } }
          else{ b.classList.add("wrong"); if(fb){ fb.textContent="Not quite — the highlighted answer is right."; fb.className="cpquiz-fb no"; } }
          var det = q.closest("details.cp"); if(det){ setTimeout(function(){ det.open = true; }, 550); }
        });
      });
    });
  }catch(e){}
})();

/* ============ glossary <dfn> tokens (walk prose text nodes; keyboard + Esc dismiss) ============ */
(function(){
  try{
    var terms = Object.keys(GLOSSARY).sort(function(a,b){ return b.length-a.length; });
    if(!terms.length) return;
    var sel = ".bg, .lvlgoal, .storybeat p, .levelup, .obj li, .prereq";
    var containers = [].slice.call(document.querySelectorAll(sel));
    function esc(s){ return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"); }
    var seen = {};
    terms.forEach(function(term){
      var re = new RegExp("\\b"+esc(term)+"\\b", "i");
      for(var ci=0; ci<containers.length; ci++){
        var root = containers[ci];
        var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
        var tn, hit=null;
        while((tn = walker.nextNode())){
          var p = tn.parentNode;
          if(!p) continue;
          var tag = p.nodeName.toLowerCase();
          if(tag==="code"||tag==="pre"||tag==="a"||tag==="button"||p.classList.contains("dfn")) continue;
          if(re.test(tn.nodeValue)){ hit = tn; break; }
        }
        if(hit){
          var m = hit.nodeValue.match(re);
          var idx = m.index;
          var before = hit.nodeValue.slice(0, idx);
          var matched = hit.nodeValue.slice(idx, idx+m[0].length);
          var after = hit.nodeValue.slice(idx+m[0].length);
          var span = document.createElement("span");
          span.className = "dfn"; span.tabIndex = 0; span.setAttribute("role","button");
          span.setAttribute("aria-label", "Definition of "+term);
          span.textContent = matched;
          var tip = document.createElement("span");
          tip.className = "dfntip"; tip.setAttribute("role","tooltip");
          tip.textContent = GLOSSARY[term];
          span.appendChild(tip);
          var frag = document.createDocumentFragment();
          if(before) frag.appendChild(document.createTextNode(before));
          frag.appendChild(span);
          if(after) frag.appendChild(document.createTextNode(after));
          hit.parentNode.replaceChild(frag, hit);
          break; // one wrap per term keeps prose calm
        }
      }
    });
    document.addEventListener("keydown", function(ev){
      if(ev.key==="Escape"){ var a=document.activeElement; if(a && a.classList && a.classList.contains("dfn")) a.blur(); }
    });
  }catch(e){}
})();

/* ============ field notebook render (glossary → drawer) ============ */
(function(){
  try{
    var dl = document.getElementById("cf-nblist"); if(!dl) return;
    Object.keys(GLOSSARY).forEach(function(k){
      var wrap = document.createElement("div"); wrap.className="nb";
      var dt = document.createElement("dt"); dt.textContent = k;
      var dd = document.createElement("dd"); dd.textContent = GLOSSARY[k];
      wrap.appendChild(dt); wrap.appendChild(dd); dl.appendChild(wrap);
    });
  }catch(e){}
})();

/* ============ case file drawer open/close ============ */
(function(){
  try{
    var panel = document.getElementById("casefile");
    var scrim = document.getElementById("scrim");
    var openb = document.getElementById("casebtn");
    var closeb = document.getElementById("cf-close");
    if(!panel) return;
    function open(){ panel.hidden=false; requestAnimationFrame(function(){ panel.classList.add("open"); }); if(scrim) scrim.classList.add("on"); if(closeb) closeb.focus(); }
    function close(){ panel.classList.remove("open"); if(scrim) scrim.classList.remove("on"); setTimeout(function(){ panel.hidden=true; }, 380); if(openb) openb.focus(); }
    if(openb) openb.addEventListener("click", open);
    if(closeb) closeb.addEventListener("click", close);
    if(scrim) scrim.addEventListener("click", close);
    document.addEventListener("keydown", function(ev){ if(ev.key==="Escape" && panel.classList.contains("open")) close(); });
    window.__FL_openCase = open;
  }catch(e){}
})();

/* ============ welcome back → continue to frontier ============ */
(function(){
  try{
    var api = window.__FL; if(!api) return;
    var f = api.frontier();
    var banner = document.getElementById("welcome");
    if(!banner) return;
    if(api.done.size>0 && f>0){
      var txt = document.getElementById("welcome-txt");
      if(txt) txt.innerHTML = "Welcome back. Your sight reaches <b>Level "+(f-1)+"</b> — continue the descent to <b>Level "+f+"</b>.";
      banner.hidden = false;
      var go = document.getElementById("welcome-go");
      var x = document.getElementById("welcome-x");
      function goto(){
        var el = document.getElementById("level-"+f);
        if(el){ el.scrollIntoView({behavior: api.RM?"auto":"smooth", block:"start"});
          var body = el.querySelector(".lvlbody"); if(body) body.open = true;
          if(!api.RM){ el.classList.add("reveal-in"); setTimeout(function(){ el.classList.remove("reveal-in"); }, 700); }
        }
        banner.hidden = true;
      }
      if(go) go.addEventListener("click", goto);
      if(x) x.addEventListener("click", function(){ banner.hidden = true; });
    }
  }catch(e){}
})();

/* ============ cold-open (first visit only; skippable; instant under reduced motion) ============ */
(function(){
  try{
    var CK = "icskit.path.coldopen.v1";
    var seen=false; try{ seen = localStorage.getItem(CK)==="1"; }catch(e){}
    var co = document.getElementById("coldopen"); if(!co) return;
    if(seen){ co.parentNode && co.parentNode.removeChild(co); return; }
    co.hidden = false;
    var RM=false; try{ RM = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }catch(e){}
    if(RM) co.style.animation = "none";
    function dismiss(goDescend){
      try{ localStorage.setItem(CK,"1"); }catch(e){}
      co.style.opacity="0"; co.style.transition = RM?"none":"opacity .4s ease";
      setTimeout(function(){ co.parentNode && co.parentNode.removeChild(co); }, RM?0:420);
      if(goDescend){ var l0=document.getElementById("level-0"); if(l0) l0.scrollIntoView({behavior:RM?"auto":"smooth"}); }
    }
    var en=document.getElementById("co-enter"), sk=document.getElementById("co-skip");
    if(en) en.addEventListener("click", function(){ dismiss(true); });
    if(sk) sk.addEventListener("click", function(){ dismiss(false); });
    document.addEventListener("keydown", function h(ev){ if(ev.key==="Escape"||ev.key==="Enter"){ dismiss(ev.key==="Enter"); document.removeEventListener("keydown",h); } });
    if(en && !RM) en.focus();
  }catch(e){}
})();

/* ============ command palette (Cmd/Ctrl-K or "/") ============ */
(function(){
  try{
    var api = window.__FL;
    var pal = document.getElementById("palette");
    var input = document.getElementById("pal-input");
    var list = document.getElementById("pal-list");
    if(!pal||!input||!list) return;
    var actions = [];
    document.querySelectorAll(".lvl[data-level]").forEach(function(s){
      var n=+s.getAttribute("data-level");
      var alt = s.querySelector(".lvlalt"); var title = s.querySelector(".lvltitle");
      var label = (alt?alt.textContent.trim():"") + " — " + (title?title.textContent.replace(/\s+/g," ").trim():("Level "+n));
      actions.push({ico:"◉", name:"Jump: "+label, key:"L"+n, run:function(){ jump(n); }});
    });
    actions.push({ico:"◐", name:"Toggle light / dark theme", key:"THEME", run:function(){ var b=document.getElementById("themebtn"); if(b) b.click(); }});
    actions.push({ico:"✓", name:"Mark my current frontier Done", key:"DONE", run:function(){ if(api){ var f=api.frontier(); if(f>=0) api.markDone(f); } }});
    actions.push({ico:"↺", name:"Reset all progress", key:"RESET", run:function(){ var r=document.getElementById("resetbtn"); if(r) r.click(); }});
    actions.push({ico:"⌗", name:"Open the Case File", key:"CASE", run:function(){ if(window.__FL_openCase) window.__FL_openCase(); }});
    actions.push({ico:"→", name:"Open DNP3 module (frame explorer)", key:"DNP3", run:function(){ location.href="../modules/dnp3_module.html"; }});
    actions.push({ico:"→", name:"Open MQTT module (frame explorer)", key:"MQTT", run:function(){ location.href="../modules/mqtt_module.html"; }});
    actions.push({ico:"→", name:"Open the Machine Problem handout", key:"MP", run:function(){ location.href="../mp/README.md"; }});
    actions.push({ico:"→", name:"Open the Lab guide", key:"LAB", run:function(){ location.href="../LAB_GUIDE.md"; }});

    var sel=0, filtered=actions.slice();
    function jump(n){ var el=document.getElementById("level-"+n); if(el){ el.scrollIntoView({behavior:(api&&api.RM)?"auto":"smooth",block:"start"}); var b=el.querySelector(".lvlbody"); if(b) b.open=true; } }
    function render(){
      list.innerHTML="";
      filtered.forEach(function(a,i){
        var li=document.createElement("li"); if(i===sel) li.className="sel";
        li.innerHTML='<span class="pico">'+a.ico+'</span><b>'+a.name+'</b><span class="pk">'+a.key+'</span>';
        li.addEventListener("click", function(){ close(); a.run(); });
        li.addEventListener("mousemove", function(){ sel=i; hi(); });
        list.appendChild(li);
      });
    }
    function hi(){ [].slice.call(list.children).forEach(function(li,i){ li.classList.toggle("sel", i===sel); }); }
    function filter(){ var q=input.value.toLowerCase().trim();
      filtered = q ? actions.filter(function(a){ return a.name.toLowerCase().indexOf(q)>=0 || a.key.toLowerCase().indexOf(q)>=0; }) : actions.slice();
      sel=0; render();
    }
    function open(){ pal.hidden=false; input.value=""; filter(); setTimeout(function(){ input.focus(); },10); }
    function close(){ pal.hidden=true; }
    input.addEventListener("input", filter);
    input.addEventListener("keydown", function(ev){
      if(ev.key==="ArrowDown"){ ev.preventDefault(); sel=Math.min(filtered.length-1,sel+1); hi(); scroll(); }
      else if(ev.key==="ArrowUp"){ ev.preventDefault(); sel=Math.max(0,sel-1); hi(); scroll(); }
      else if(ev.key==="Enter"){ ev.preventDefault(); if(filtered[sel]){ close(); filtered[sel].run(); } }
      else if(ev.key==="Escape"){ close(); }
    });
    function scroll(){ var li=list.children[sel]; if(li) li.scrollIntoView({block:"nearest"}); }
    pal.querySelector("[data-palclose]").addEventListener("click", close);
    document.addEventListener("keydown", function(ev){
      var typing = /^(input|textarea|select)$/i.test((ev.target&&ev.target.nodeName)||"") || (ev.target&&ev.target.isContentEditable);
      if((ev.key==="k"||ev.key==="K") && (ev.metaKey||ev.ctrlKey)){ ev.preventDefault(); pal.hidden?open():close(); }
      else if(ev.key==="/" && !typing && pal.hidden){ ev.preventDefault(); open(); }
    });
  }catch(e){}
})();
</script>
</body></html>"""


# ---------------------------------------------------------------- Markdown rendering (unchanged)
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
    toks = type_tokens(lv)
    for i, st in enumerate(lv["steps"]):
        kind = st.get("kind", "note")
        if kind == "cmd":
            tok = toks.get(i, "")
            _gist, command = split_cmd(st["text"])
            # Collapse a multi-line command to one runnable line (sequential ';') for the
            # inline 'runs' phrase; the individual commands stay runnable.
            oneline = " ; ".join(ln.strip() for ln in command.splitlines() if ln.strip())
            L.append(f"**⌨ Type:** `{tok}`  — runs `{oneline}`")
            if st.get("expect"):
                L.append("")
                L.append(f"> **Check (expected):** {st['expect']}")
            L.append("")
        elif kind == "gui":
            L.append(f"- **Do · Click.** {st['text']}")
            L.append("")
        else:
            L.append(f"- **Read.** {st['text']}")
            L.append("")
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
    C.append("From first packet to a university-style Machine Problem. Work the levels in order. Every command and "
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
