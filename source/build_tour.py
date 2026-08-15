# -*- coding: utf-8 -*-
"""Generate curriculum/tour.html — the narrated, multilingual Guided Tour.

Reads build/tour_data.json (assembled from the persona-workflow outputs) and
emits a single self-contained HTML file: a full-screen guided tour that steps
through every lab section, narrates each step aloud via the browser Web Speech
API in a runtime-selectable language, shows synced closed captions, an animated
SVG scene of the real-world OT process, and the real command + real captured
output for each demonstration.

No external dependencies, no build-time network, stdlib only. The page works from
file://, from the Codespace :8080 server, or as a saved artifact. Voice narration
degrades gracefully to captions-only where Web Speech is unavailable; every
animation respects prefers-reduced-motion.

tour_data.json contract:
{
  "langs":   [ {"code","name","native","bcp47","rtl"?}, ... ],   # 'en' first
  "ui":      { "en": {..strings..}, "es": {...}, ... },
  "sections":[
     { "id","n","title": {lang:str},
       "onet": {"code","title":{lang:str},"why":{lang:str}},
       "realWorld": {lang:str},
       "svg": "<svg...>",
       "steps": [
          {"type":"intro",    "narration": {lang:str}},
          {"type":"demo",     "command":str, "output":str, "narration": {lang:str}},
          {"type":"takeaway", "narration": {lang:str}}
       ]
     }, ...
  ],
  "levelHref": "index.html"   # link back into the Learning Path (optional)
}
"""
import json
import os

KIT = "/root/icsnpp_kit"
DATA = os.path.join(KIT, "build", "tour_data.json")
OUT = os.path.join(KIT, "curriculum", "tour.html")

TEMPLATE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Guided Tour · First Light — ICS/OT Protocol Analysis</title>
<meta name="description" content="A narrated, multilingual guided tour of the First Light ICS/OT protocol-analysis lab: real DNP3 + MQTT commands, real captured output, animated real-world visuals, closed captions, and voice narration in your language.">
<style>
  :root{
    --bg:#0b0f17; --bg2:#111827; --panel:#0f1524; --panel2:#151d31;
    --ink:#e5e7eb; --muted:#94a3b8; --dim:#64748b; --line:#1f2937;
    --indigo:#6366f1; --violet:#7c3aed; --amber:#f59e0b; --teal:#14b8a6;
    --red:#ef4444; --green:#22c55e; --focus:#a5b4fc;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    --sans:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,"Noto Sans","Noto Sans Arabic","Noto Sans Devanagari","Noto Sans CJK SC",sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{background:radial-gradient(1200px 700px at 70% -10%, #16213b 0%, var(--bg) 55%) fixed;color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased;overflow:hidden}
  button{font-family:inherit}
  .sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
  :focus-visible{outline:3px solid var(--focus);outline-offset:2px;border-radius:8px}

  #app{position:fixed;inset:0;display:flex;flex-direction:column}

  /* ---------- start screen ---------- */
  #start{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:22px;padding:24px;text-align:center;background:radial-gradient(900px 520px at 50% 8%, #1b2745 0%, var(--bg) 60%);z-index:40}
  #start .kick{letter-spacing:.32em;text-transform:uppercase;font-size:12px;color:var(--indigo);font-weight:700}
  #start h1{margin:.1em 0 0;font-size:clamp(28px,5vw,52px);line-height:1.05;font-weight:800;background:linear-gradient(90deg,#c7d2fe,#a7f3d0);-webkit-background-clip:text;background-clip:text;color:transparent}
  #start p.sub{margin:0;color:var(--muted);max-width:640px;font-size:clamp(14px,2vw,18px)}
  .langgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;max-width:720px;width:100%}
  .langbtn{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:12px;padding:12px 10px;cursor:pointer;display:flex;flex-direction:column;gap:2px;transition:transform .12s ease,border-color .12s ease,background .12s ease}
  .langbtn:hover{transform:translateY(-2px);border-color:var(--indigo);background:var(--panel2)}
  .langbtn[aria-pressed="true"]{border-color:var(--indigo);box-shadow:0 0 0 1px var(--indigo) inset}
  .langbtn b{font-size:16px}
  .langbtn small{color:var(--muted);font-size:11px}
  .cta{display:inline-flex;align-items:center;gap:10px;background:linear-gradient(90deg,var(--indigo),var(--violet));color:#fff;border:0;border-radius:999px;padding:14px 26px;font-size:17px;font-weight:700;cursor:pointer;box-shadow:0 10px 30px -8px rgba(99,102,241,.6)}
  .cta:hover{filter:brightness(1.07)}
  .note{color:var(--dim);font-size:12px;max-width:560px}

  /* ---------- top bar ---------- */
  #bar{display:flex;align-items:center;gap:14px;padding:10px 16px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,rgba(17,24,39,.9),rgba(11,15,23,.75));backdrop-filter:blur(6px);z-index:20}
  #bar .sec{display:flex;flex-direction:column;min-width:0}
  #bar .sec .ttl{font-weight:700;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:46vw}
  #bar .sec .cnt{font-size:11px;color:var(--muted);letter-spacing:.02em}
  #prog{flex:1;height:6px;border-radius:999px;background:#1e2637;overflow:hidden;min-width:60px}
  #prog>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--indigo),var(--teal));transition:width .35s ease}
  .bar-tools{display:flex;align-items:center;gap:8px}
  select.ui,button.ui{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:9px;padding:7px 10px;font-size:13px;cursor:pointer}
  select.ui:hover,button.ui:hover{border-color:var(--indigo)}
  button.icon{width:36px;height:36px;display:inline-flex;align-items:center;justify-content:center;padding:0;font-size:15px}
  .toggle[aria-pressed="true"]{border-color:var(--teal);color:#5eead4}

  /* ---------- stage ---------- */
  #stage{flex:1;display:grid;grid-template-columns:1.35fr 1fr;gap:16px;padding:16px;min-height:0}
  #visual{position:relative;background:linear-gradient(180deg,#0c1220,#0a0e18);border:1px solid var(--line);border-radius:16px;overflow:hidden;display:flex;align-items:center;justify-content:center;min-height:0}
  #visual svg{width:100%;height:100%;display:block}
  .badge{position:absolute;top:12px;left:12px;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);background:rgba(2,6,12,.5);border:1px solid var(--line);border-radius:999px;padding:4px 10px}
  #panel{display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}
  .role{display:flex;align-items:flex-start;gap:12px}
  .role .chip{flex:0 0 auto;font-size:11px;font-weight:700;color:#0b0f17;background:linear-gradient(90deg,var(--amber),#fbbf24);border-radius:8px;padding:6px 9px;white-space:nowrap}
  .role .who b{display:block;font-size:14px}
  .role .who small{color:var(--muted)}
  .lbl{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);margin:0 0 6px}
  .rw{font-size:14.5px;line-height:1.5;color:#dbe4f0}
  .term{position:relative;background:#070b12;border:1px solid #1c2740;border-radius:12px;overflow:hidden}
  .term .top{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid #16203a;background:#0a1120}
  .term .top .dot{width:10px;height:10px;border-radius:50%}
  .term .top .d1{background:#f87171}.term .top .d2{background:#fbbf24}.term .top .d3{background:#34d399}
  .term .top .lbl{margin:0 0 0 6px}
  .term .copy{margin-inline-start:auto;background:transparent;border:1px solid #24304a;color:var(--muted);border-radius:7px;padding:3px 9px;font-size:11px;cursor:pointer}
  .term .copy:hover{color:var(--ink);border-color:var(--indigo)}
  .term pre{margin:0;padding:12px 14px;font-family:var(--mono);font-size:12.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word;color:#cfe3ff}
  .term pre.out{color:#a7f3d0;background:#060a10;border-top:1px dashed #16203a}
  .term .prompt{color:var(--teal)}

  /* ---------- captions ---------- */
  #cc{padding:14px 18px;min-height:76px;display:flex;align-items:center;justify-content:center;text-align:center;border-top:1px solid var(--line);background:linear-gradient(0deg,rgba(2,6,12,.6),transparent)}
  #cc .box{max-width:1000px;font-size:clamp(16px,2.3vw,22px);line-height:1.45;font-weight:600;letter-spacing:.005em}
  #cc .w{color:var(--muted);transition:color .08s linear}
  #cc .w.on{color:#fff}
  #cc.hidden{visibility:hidden}

  /* ---------- controls ---------- */
  #controls{display:flex;align-items:center;justify-content:center;gap:10px;padding:10px 16px 16px;flex-wrap:wrap}
  .cbtn{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:999px;height:44px;min-width:44px;padding:0 16px;display:inline-flex;align-items:center;gap:8px;font-size:14px;font-weight:600;cursor:pointer}
  .cbtn:hover{border-color:var(--indigo)}
  .cbtn.primary{background:linear-gradient(90deg,var(--indigo),var(--violet));border:0;color:#fff;padding:0 22px}
  .cbtn[disabled]{opacity:.4;cursor:not-allowed}
  #controls .grp{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px}
  #controls input[type=range]{accent-color:var(--indigo)}

  /* ---------- finish ---------- */
  #finish{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;gap:18px;text-align:center;padding:24px;background:radial-gradient(900px 520px at 50% 20%, #1b2745 0%, var(--bg) 60%);z-index:40}
  #finish h2{font-size:clamp(26px,4vw,44px);margin:0;background:linear-gradient(90deg,#fde68a,#a7f3d0);-webkit-background-clip:text;background-clip:text;color:transparent}
  #finish p{color:var(--muted);max-width:620px;margin:0;font-size:17px}

  .warn{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.4);color:#fecaca;border-radius:10px;padding:8px 12px;font-size:12.5px}
  [hidden]{display:none !important}

  @media (max-width:860px){
    #stage{grid-template-columns:1fr;grid-template-rows:minmax(200px,42%) 1fr}
    #bar .sec .ttl{max-width:40vw}
  }
  @media (prefers-reduced-motion: reduce){
    *{transition:none !important}
  }
  html[dir="rtl"] .term pre{direction:ltr;text-align:left}
</style>
</head>
<body>
<div id="app">

  <!-- ============ START ============ -->
  <section id="start" aria-label="Start the guided tour">
    <div class="kick">First Light</div>
    <h1 id="s-title">The Guided Tour</h1>
    <p class="sub" id="s-sub">A narrated walk through the whole ICS/OT protocol-analysis lab — real DNP3 and MQTT commands, real captured output, and the real-world plant behind each step. Pick your language; it narrates aloud with closed captions.</p>
    <div class="langgrid" id="langgrid" role="group" aria-label="Narration language"></div>
    <button class="cta" id="beginBtn">▶ <span id="beginLbl">Begin</span></button>
    <p class="note" id="ttsNote"></p>
  </section>

  <!-- ============ TOUR ============ -->
  <header id="bar" hidden>
    <div class="sec"><span class="ttl" id="secTitle"></span><span class="cnt" id="secCount"></span></div>
    <div id="prog" role="progressbar" aria-label="Tour progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i id="progFill"></i></div>
    <div class="bar-tools">
      <label class="sr" for="langSel">Language</label>
      <select class="ui" id="langSel" aria-label="Narration language"></select>
      <button class="ui toggle icon" id="ccToggle" aria-pressed="true" title="Closed captions" aria-label="Toggle closed captions">CC</button>
      <button class="ui icon" id="exitBtn" title="Exit tour" aria-label="Exit tour">✕</button>
    </div>
  </header>

  <main id="stage" hidden>
    <div id="visual" aria-hidden="false">
      <span class="badge" id="vBadge">Real-world scene</span>
      <div id="svgHost" role="img" aria-label="Illustration of the step"></div>
    </div>
    <aside id="panel">
      <div class="card role">
        <span class="chip" id="onetChip">O*NET</span>
        <div class="who"><b id="onetTitle"></b><small id="onetWhy"></small></div>
      </div>
      <div class="card">
        <p class="lbl" id="rwLbl">Real-world applicability</p>
        <div class="rw" id="rwText"></div>
      </div>
      <div class="term" id="demoBox" hidden>
        <div class="top"><span class="dot d1"></span><span class="dot d2"></span><span class="dot d3"></span><span class="lbl" id="cmdLbl">Real command</span><button class="copy" id="copyBtn">Copy</button></div>
        <pre id="cmdText"></pre>
        <pre class="out" id="outText"></pre>
        <div class="lbl" id="outLbl" style="padding:6px 14px 10px;border-top:1px solid #10192e">Real captured output</div>
      </div>
      <a class="cbtn" id="openLevel" style="align-self:flex-start" href="#" hidden></a>
    </aside>
  </main>

  <div id="cc" hidden><div class="box" id="ccBox"></div></div>

  <footer id="controls" hidden>
    <button class="cbtn" id="backBtn" title="Previous (Left arrow)">◀ <span id="backLbl">Back</span></button>
    <button class="cbtn primary" id="playBtn" title="Play / Pause (Space)"><span id="playIcon">⏸</span> <span id="playLbl">Pause</span></button>
    <button class="cbtn" id="nextBtn" title="Next (Right arrow)"><span id="nextLbl">Next</span> ▶</button>
    <button class="cbtn" id="replayBtn" title="Replay narration">↻ <span id="replayLbl">Replay</span></button>
    <span class="grp"><label for="rate" id="speedLbl">Speed</label><input type="range" id="rate" min="0.7" max="1.3" step="0.1" value="1"><span id="rateVal">1.0×</span></span>
    <span class="grp"><label for="voiceSel" id="voiceLbl">Voice</label><select class="ui" id="voiceSel" aria-label="Narration voice"></select></span>
    <button class="ui toggle" id="autoToggle" aria-pressed="true" title="Autoplay"><span id="autoLbl">Autoplay</span></button>
  </footer>

  <!-- ============ FINISH ============ -->
  <section id="finish" aria-label="Tour complete">
    <div class="kick" style="color:var(--amber)">✦</div>
    <h2 id="finTitle"></h2>
    <p id="finBody"></p>
    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center">
      <button class="cbtn primary" id="restartBtn"></button>
      <a class="cbtn" id="finPathLink" href="index.html"></a>
    </div>
  </section>
</div>

<script>
const TOUR = __TOUR_DATA__;

(function(){
  "use strict";
  const $ = (s,r)=> (r||document).querySelector(s);
  const langs = TOUR.langs, sections = TOUR.sections;
  const UI = TOUR.ui || {};
  const levelHref = TOUR.levelHref || "index.html";
  const synth = window.speechSynthesis;
  const ttsOK = !!synth && typeof SpeechSynthesisUtterance !== "undefined";

  // ---- flatten sections -> steps ----
  const steps = [];
  sections.forEach((sec, si)=>{
    (sec.steps||[]).forEach((st, sti)=>{
      steps.push({sec, si, st, first: sti===0});
    });
  });

  const state = { lang: "en", i: 0, playing:false, autoplay:true, rate:1, voiceURI:null, cc:true, started:false };

  // ---- i18n helpers ----
  function t(key){ const d=UI[state.lang]||{}; return d[key] || (UI.en&&UI.en[key]) || key; }
  function pick(obj){ if(!obj) return ""; return obj[state.lang] || obj.en || obj[Object.keys(obj)[0]] || ""; }
  function curLang(){ return langs.find(l=>l.code===state.lang) || langs[0]; }

  // ---- build language buttons + selects ----
  function buildLangUI(){
    const grid = $("#langgrid"); grid.innerHTML="";
    const sel = $("#langSel"); sel.innerHTML="";
    langs.forEach(l=>{
      const b=document.createElement("button");
      b.className="langbtn"; b.type="button"; b.setAttribute("aria-pressed", l.code===state.lang);
      b.innerHTML="<b>"+l.native+"</b><small>"+l.name+"</small>";
      b.onclick=()=>{ setLang(l.code); [...grid.children].forEach(c=>c.setAttribute("aria-pressed", c===b)); };
      grid.appendChild(b);
      const o=document.createElement("option"); o.value=l.code; o.textContent=l.native+" — "+l.name; sel.appendChild(o);
    });
    sel.value=state.lang;
    sel.onchange=()=> setLang(sel.value);
  }

  // ---- voices ----
  let voices=[];
  function loadVoices(){ voices = ttsOK ? (synth.getVoices()||[]) : []; buildVoiceSel(); }
  function voicesFor(bcp47){
    const base=(bcp47||"en").slice(0,2).toLowerCase();
    return voices.filter(v=> (v.lang||"").toLowerCase().replace("_","-").slice(0,2)===base);
  }
  function buildVoiceSel(){
    const sel=$("#voiceSel"); if(!sel) return; sel.innerHTML="";
    const list=voicesFor(curLang().bcp47);
    if(!list.length){ const o=document.createElement("option"); o.textContent="(default)"; sel.appendChild(o); sel.disabled=true; return; }
    sel.disabled=false;
    list.forEach(v=>{ const o=document.createElement("option"); o.value=v.voiceURI; o.textContent=v.name+" ("+v.lang+")"; sel.appendChild(o); });
    // keep chosen voice if still valid for this lang, else first
    if(!list.some(v=>v.voiceURI===state.voiceURI)) state.voiceURI=list[0].voiceURI;
    sel.value=state.voiceURI;
    sel.onchange=()=>{ state.voiceURI=sel.value; if(state.playing) speakCurrent(); };
  }
  function chosenVoice(){
    const list=voicesFor(curLang().bcp47);
    return list.find(v=>v.voiceURI===state.voiceURI) || list[0] || null;
  }

  // ---- speech ----
  let ccWords=[], boundarySupported=false;
  function stopSpeech(){ if(ttsOK){ try{synth.cancel();}catch(e){} } }
  function renderCaption(text){
    const box=$("#ccBox");
    ccWords = text.split(/(\s+)/);
    box.innerHTML="";
    ccWords.forEach(w=>{ const s=document.createElement("span"); s.className="w"; s.textContent=w; box.appendChild(s); });
    box.setAttribute("lang", curLang().bcp47);
  }
  function highlightUpTo(charIndex){
    const spans=$("#ccBox").children; let acc=0;
    for(let k=0;k<spans.length;k++){ acc+=spans[k].textContent.length; spans[k].classList.toggle("on", acc<=charIndex+ (spans[k].textContent.trim()?0:0) ? true : (acc-spans[k].textContent.length)<=charIndex); }
  }
  function speak(text){
    renderCaption(text);
    if(!ttsOK){ return; }
    stopSpeech();
    const u=new SpeechSynthesisUtterance(text);
    const v=chosenVoice(); if(v){ u.voice=v; u.lang=v.lang; } else { u.lang=curLang().bcp47; }
    u.rate=state.rate; u.pitch=1;
    u.onboundary=(e)=>{ if(e.name==="word"||e.charIndex!=null){ boundarySupported=true; highlightUpTo(e.charIndex||0);} };
    u.onend=()=>{ // mark all spoken
      [...$("#ccBox").children].forEach(s=>s.classList.add("on"));
      if(state.playing && state.autoplay){ if(state.i < steps.length-1){ go(state.i+1); } else { finish(); } }
    };
    // small delay so cancel settles (Chrome quirk)
    setTimeout(()=>{ if(state.playing){ try{ synth.speak(u); }catch(e){} } }, 60);
  }
  function speakCurrent(){ speak(pick(steps[state.i].st.narration)); }

  // ---- render a step ----
  function render(){
    const {sec, st} = steps[state.i];
    const rtl = !!curLang().rtl;
    document.documentElement.setAttribute("dir", rtl?"rtl":"ltr");
    document.documentElement.setAttribute("lang", state.lang);
    // bar
    $("#secTitle").textContent = pick(sec.title);
    const secNum = sections.indexOf(sec)+1;
    $("#secCount").textContent = fmt(t("sectionOf"), secNum, sections.length);
    const pct = Math.round(((state.i+1)/steps.length)*100);
    $("#progFill").style.width = pct+"%"; $("#prog").setAttribute("aria-valuenow", pct);
    // visual (only reset when section changes)
    if($("#svgHost").dataset.sec !== sec.id){ $("#svgHost").innerHTML = sec.svg||""; $("#svgHost").dataset.sec=sec.id; }
    // role / realworld
    $("#onetChip").textContent = sec.onet ? ("O*NET "+sec.onet.code) : "O*NET";
    $("#onetTitle").textContent = sec.onet ? pick(sec.onet.title) : "";
    $("#onetWhy").textContent = sec.onet ? pick(sec.onet.why) : "";
    $("#rwLbl").textContent = t("realWorld");
    $("#rwText").textContent = pick(sec.realWorld);
    // demo
    const demo = st.type==="demo";
    $("#demoBox").hidden = !demo;
    if(demo){
      $("#cmdLbl").textContent=t("realCommand"); $("#outLbl").textContent=t("realOutput");
      $("#cmdText").textContent = st.command; $("#outText").textContent = st.output;
    }
    // link back to level
    const a=$("#openLevel");
    a.textContent = t("openInPath"); a.href = levelHref+"#level-"+(sec.n);
    a.hidden = false;
    // labels
    applyStaticLabels();
    // captions
    $("#cc").classList.toggle("hidden", !state.cc);
    renderCaption(pick(st.narration));
    // play state icon
    setPlayIcon();
    // focus mgmt for a11y (announce section on first step)
    $("#backBtn").disabled = state.i===0;
  }

  function fmt(s,i,n){ return (s||"").replace("{i}",i).replace("{n}",n); }

  function applyStaticLabels(){
    $("#playLbl").textContent = state.playing? t("pause"): t("play");
    $("#backLbl").textContent=t("back"); $("#nextLbl").textContent=t("next"); $("#replayLbl").textContent=t("replay");
    $("#speedLbl").textContent=t("speed"); $("#voiceLbl").textContent=t("voice"); $("#autoLbl").textContent=t("autoplay");
    $("#ccToggle").title=t("captions"); $("#exitBtn").title=t("exit");
    $("#beginLbl").textContent=t("begin");
    $("#copyBtn").textContent="⧉";
  }

  // ---- navigation ----
  function go(i){
    i=Math.max(0,Math.min(steps.length-1,i));
    state.i=i; render();
    if(state.playing) speakCurrent();
  }
  function setPlayIcon(){ $("#playIcon").textContent = state.playing? "⏸":"▶"; $("#playLbl").textContent = state.playing? t("pause"): t("play"); }
  function play(){ state.playing=true; setPlayIcon(); speakCurrent(); }
  function pause(){ state.playing=false; setPlayIcon(); stopSpeech(); }
  function togglePlay(){ state.playing? pause(): play(); }

  function setLang(code){
    state.lang=code; $("#langSel").value=code;
    buildVoiceSel();
    render();
    if(state.playing) speakCurrent();
  }

  function startTour(){
    state.started=true;
    $("#start").style.display="none";
    ["#bar","#stage","#cc","#controls"].forEach(s=>$(s).hidden=false);
    go(0); play();
  }
  function finish(){
    pause();
    $("#finTitle").textContent=t("finishTitle"); $("#finBody").textContent=t("finishBody");
    $("#restartBtn").textContent=t("restart"); $("#finPathLink").textContent=t("openInPath"); $("#finPathLink").href=levelHref;
    $("#finish").style.display="flex";
  }
  function exitTour(){
    pause(); location.href=levelHref;
  }

  // ---- wire controls ----
  function wire(){
    $("#beginBtn").onclick=startTour;
    $("#playBtn").onclick=togglePlay;
    $("#nextBtn").onclick=()=>{ if(state.i<steps.length-1) go(state.i+1); else finish(); };
    $("#backBtn").onclick=()=> go(state.i-1);
    $("#replayBtn").onclick=()=>{ state.playing=true; setPlayIcon(); speakCurrent(); };
    $("#exitBtn").onclick=exitTour;
    $("#restartBtn").onclick=()=>{ $("#finish").style.display="none"; go(0); play(); };
    $("#ccToggle").onclick=()=>{ state.cc=!state.cc; $("#ccToggle").setAttribute("aria-pressed",state.cc); $("#cc").classList.toggle("hidden",!state.cc); };
    $("#autoToggle").onclick=()=>{ state.autoplay=!state.autoplay; $("#autoToggle").setAttribute("aria-pressed",state.autoplay); };
    $("#rate").oninput=(e)=>{ state.rate=parseFloat(e.target.value); $("#rateVal").textContent=state.rate.toFixed(1)+"×"; if(state.playing) speakCurrent(); };
    $("#copyBtn").onclick=()=>{ const c=steps[state.i].st.command||""; navigator.clipboard&&navigator.clipboard.writeText(c); $("#copyBtn").textContent="✓"; setTimeout(()=>$("#copyBtn").textContent="⧉",900); };
    document.addEventListener("keydown",(e)=>{
      if(!state.started) return;
      if(e.key==="ArrowRight"){ e.preventDefault(); $("#nextBtn").click(); }
      else if(e.key==="ArrowLeft"){ e.preventDefault(); go(state.i-1); }
      else if(e.key===" "){ e.preventDefault(); togglePlay(); }
      else if(e.key==="Escape"){ exitTour(); }
    });
  }

  // ---- boot ----
  function boot(){
    // static UI text
    $("#beginLbl").textContent=UI.en.begin||"Begin";
    $("#s-sub").textContent = $("#s-sub").textContent;
    $("#ttsNote").textContent = ttsOK ? "" : (UI.en.ttsUnavailable||"");
    if(!ttsOK){ const w=document.createElement("div"); w.className="warn"; w.textContent=UI.en.ttsUnavailable||""; $("#start").appendChild(w); }
    buildLangUI(); wire();
    if(ttsOK){ loadVoices(); if(synth.onvoiceschanged!==undefined){ synth.onvoiceschanged=loadVoices; } }
    // default language from URL ?lang= or browser
    const q=new URLSearchParams(location.search);
    const want=(q.get("lang")|| (navigator.language||"en").slice(0,2)).toLowerCase();
    if(langs.some(l=>l.code===want)) state.lang=want;
    [...$("#langgrid").children].forEach((c,idx)=> c.setAttribute("aria-pressed", langs[idx].code===state.lang));
    $("#langSel") && ($("#langSel").value=state.lang);
    applyStaticLabels();
    $("#rateVal").textContent="1.0×";
    if(q.get("autostart")==="1") startTour();
  }
  // Chrome sometimes needs a resume nudge to keep long queues alive
  if(ttsOK){ setInterval(()=>{ if(state.playing && synth.paused){ try{synth.resume();}catch(e){} } }, 4000); }
  boot();
})();
</script>
</body>
</html>
"""


def main():
    with open(DATA, encoding="utf-8") as f:
        tour = json.load(f)
    html = TEMPLATE.replace("__TOUR_DATA__", json.dumps(tour, ensure_ascii=False))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(html)
    print("wrote %s (%d bytes, %d sections, %d langs)" % (
        OUT, len(html), len(tour.get("sections", [])), len(tour.get("langs", []))))


if __name__ == "__main__":
    main()
