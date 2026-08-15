# -*- coding: utf-8 -*-
"""Assemble curriculum/tour.html's data (build/tour_data.json) from:

  build/tour_source.json        — ground truth (verbatim commands + outputs)
  build/tour_workflow_out.json  — persona-workflow result: {master, translations, visuals}
  build/tour_ui_en.json         — canonical English UI strings

Commands and captured OUTPUT always come from tour_source (verbatim, never from a
model), so the demonstrations are guaranteed correct regardless of what the
narration authors echoed. Narration/titles/UI come from the workflow (English
master + per-language translations); the animated SVG scenes come from the
workflow visuals. Missing languages fall back to English at runtime.
"""
import json
import os

KIT = "/root/icsnpp_kit"
B = os.path.join(KIT, "build")

# The languages the tour ships (en first). Must match what the workflow localized.
LANGS = [
    {"code": "en", "name": "English",          "native": "English",  "bcp47": "en-US"},
    {"code": "es", "name": "Spanish",          "native": "Español",  "bcp47": "es-ES"},
    {"code": "fr", "name": "French",           "native": "Français", "bcp47": "fr-FR"},
    {"code": "de", "name": "German",           "native": "Deutsch",  "bcp47": "de-DE"},
    {"code": "pt", "name": "Portuguese",       "native": "Português","bcp47": "pt-BR"},
    {"code": "zh", "name": "Mandarin Chinese", "native": "中文",      "bcp47": "zh-CN"},
    {"code": "ja", "name": "Japanese",         "native": "日本語",    "bcp47": "ja-JP"},
    {"code": "ar", "name": "Arabic",           "native": "العربية",  "bcp47": "ar-SA", "rtl": True},
    {"code": "hi", "name": "Hindi",            "native": "हिन्दी",    "bcp47": "hi-IN"},
    {"code": "ru", "name": "Russian",          "native": "Русский",  "bcp47": "ru-RU"},
]


def load(p):
    with open(os.path.join(B, p), encoding="utf-8") as f:
        return json.load(f)


def main():
    source = load("tour_source.json")
    wf = load("tour_workflow_out.json")
    ui_en = load("tour_ui_en.json")

    master = {s["id"]: s for s in wf["master"]["sections"]}
    visuals = {v["id"]: v["svg"] for v in wf.get("visuals", [])}
    # translations keyed by lang code
    trans = {}
    for tr in wf.get("translations", []):
        trans[tr["lang"]] = {"ui": tr.get("ui", {}), "sections": {s["id"]: s for s in tr.get("sections", [])}}

    present_langs = [l for l in LANGS if l["code"] == "en" or l["code"] in trans]

    # ---- UI strings per language ----
    ui = {"en": ui_en}
    for code, tr in trans.items():
        merged = dict(ui_en)
        merged.update({k: v for k, v in (tr.get("ui") or {}).items() if v})
        ui[code] = merged

    def loc(section_id, en_value, field, demo_idx=None):
        """Build a {lang: value} map: English from master, others from translations."""
        out = {"en": en_value}
        for code, tr in trans.items():
            sec = tr["sections"].get(section_id)
            if not sec:
                continue
            if field == "demoNarration":
                arr = sec.get("demoNarrations") or []
                if demo_idx is not None and demo_idx < len(arr) and arr[demo_idx]:
                    out[code] = arr[demo_idx]
            else:
                v = sec.get(field)
                if v:
                    out[code] = v
        return out

    sections_out = []
    for src in source["sections"]:
        sid = src["id"]
        m = master.get(sid, {})
        onet = m.get("onet", src.get("onet_candidate", {"code": "", "title": "", "why": ""}))
        steps = []
        # intro
        steps.append({"type": "intro",
                      "narration": loc(sid, m.get("introNarration", src.get("tagline", "")), "introNarration")})
        # demos — command + output VERBATIM from source; narration from master/translations
        for i, d in enumerate(src.get("demos", [])):
            m_demo = (m.get("demos") or [])
            narr_en = m_demo[i]["narration"] if i < len(m_demo) and "narration" in m_demo[i] else d.get("sim", "")
            steps.append({
                "type": "demo",
                "command": d["command"],
                "output": d["output"],
                "narration": loc(sid, narr_en, "demoNarration", demo_idx=i),
            })
        # takeaway
        steps.append({"type": "takeaway",
                      "narration": loc(sid, m.get("takeaway", src.get("storybeat", "")), "takeaway")})

        sections_out.append({
            "id": sid,
            "n": src["n"],
            "title": loc(sid, m.get("title", src["title"]), "title"),
            "onet": {
                "code": onet.get("code", ""),
                "title": loc(sid, onet.get("title", ""), "title") if False else _onet_title(sid, onet, trans),
                "why": _onet_why(sid, onet, trans),
            },
            "realWorld": loc(sid, m.get("realWorld", src.get("realWorldHook", "")), "realWorld"),
            "svg": visuals.get(sid, _placeholder_svg(src["title"])),
            "steps": steps,
        })

    tour = {
        "levelHref": "index.html",
        "langs": present_langs,
        "ui": {l["code"]: ui.get(l["code"], ui_en) for l in present_langs},
        "sections": sections_out,
    }
    outp = os.path.join(B, "tour_data.json")
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(tour, f, ensure_ascii=False, indent=1)
    langs_ok = ", ".join(l["code"] for l in present_langs)
    vis_ok = sum(1 for s in sections_out if s["svg"] and "placeholder" not in s["svg"])
    print("wrote %s: %d sections, langs [%s], %d/%d real SVGs" % (
        outp, len(sections_out), langs_ok, vis_ok, len(sections_out)))


def _onet_title(sid, onet, trans):
    out = {"en": onet.get("title", "")}
    for code, tr in trans.items():
        sec = tr["sections"].get(sid)
        if sec and sec.get("onetTitle"):
            out[code] = sec["onetTitle"]
    return out


def _onet_why(sid, onet, trans):
    out = {"en": onet.get("why", "")}
    for code, tr in trans.items():
        sec = tr["sections"].get(sid)
        if sec and sec.get("onetWhy"):
            out[code] = sec["onetWhy"]
    return out


def _placeholder_svg(title):
    return ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 960 540' role='img'>"
            "<title>placeholder</title><rect width='960' height='540' fill='#0b0f17'/>"
            "<text x='480' y='270' fill='#64748b' font-family='system-ui' font-size='22' "
            "text-anchor='middle'>%s</text></svg>" % title)


if __name__ == "__main__":
    main()
