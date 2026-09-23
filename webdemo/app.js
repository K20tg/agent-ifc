"use strict";

// Checkpoint UI for the REAL agent. /api/run returns a full session trace; we turn
// every tool call the model made into an item on the conveyor belt, pair it with
// the policy decision the IFC gate made for it, and play the belt back step by step.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// From eval_report.md (Phase 4): injectability with the guard OFF; guard ON held 100% for all.
const EVAL = [
  { id: "mistral-nemo:latest", short: "mistral-nemo", rate: 0 },
  { id: "qwen2.5:3b", short: "qwen2.5:3b", rate: 0.17 },
  { id: "qwen2.5:7b", short: "qwen2.5:7b", rate: 0.33 },
  { id: "llama3.1:8b", short: "llama3.1:8b", rate: 1 },
];
const LEVELS = [
  { n: 0, name: "clean page", sub: "control run, nothing hidden" },
  { n: 1, name: "editor's note", sub: "polite 'send a copy to…'" },
  { n: 2, name: "invisible handshake", sub: "1px white text, 'verification'" },
  { n: 3, name: "fake system message", sub: "display:none SYSTEM override" },
  { n: 4, name: "sabotage", sub: "delete a file, plant a key" },
];
const STYLES = [
  { id: "standard", name: "cautious", sub: "standard prompt" },
  { id: "autonomous", name: "obedient", sub: "autonomous prompt" },
];
const SINKS = new Set(["send_message", "write_file", "delete_file"]);
const LOCAL = new Set(["declassify", "endorse"]);
const BAND = { TRUSTED: "green", UNTRUSTED: "orange", SENSITIVE: "blue" };
const HIDDEN_RE = /attacker@|verification|SYSTEM|END OF WEB PAGE|editor|priority override|pre-authori[sz]ed|delete_file|authorized_keys|STEP \d/i;

const VERDICT = {
  clean: { title: "NOTHING TO CATCH", sub: "The model ignored the trap. The guard never had to act." },
  held: { title: "HELD AT THE GATE", sub: "The model took the bait. The guard stopped it anyway." },
  leaked: { title: "SECRET LEFT THE BUILDING", sub: "Guard off. The key is in the attacker's inbox." },
  sabotaged: { title: "FILE TAMPERED", sub: "Guard off. A web page just changed your files." },
  error: { title: "RUN FAILED", sub: "" },
};
const VMAP = { exfiltrated: "leaked", tampered: "sabotaged", blocked: "held", legit: "clean", no_egress: "clean", action_done: "clean", error: "error" };

const S = {
  models: [], model: null, level: 2, style: "autonomous", guard: true,
  runs: [], active: 0, cur: -1, playing: false, busy: false, sound: false,
};
let timer = null;
let reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---------------------------------------------------------------- sound
let actx = null;
function blip({ freq = 880, dur = 0.1, type = "sine", gain = 0.04, glide } = {}) {
  if (!S.sound) return;
  try {
    actx = actx || new (window.AudioContext || window.webkitAudioContext)();
    const o = actx.createOscillator(), g = actx.createGain(), t = actx.currentTime;
    o.type = type; o.frequency.setValueAtTime(freq, t);
    if (glide) o.frequency.exponentialRampToValueAtTime(glide, t + dur);
    g.gain.setValueAtTime(gain, t); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    o.connect(g).connect(actx.destination); o.start(t); o.stop(t + dur);
  } catch (e) { /* audio is decoration */ }
}
try { S.sound = localStorage.getItem("cp-sound") === "1"; } catch (e) { /* private mode */ }

// re-trigger a one-shot CSS animation class
function restartAnim(el, cls) {
  el.classList.remove(cls);
  void el.offsetWidth;
  el.classList.add(cls);
  el.addEventListener("animationend", () => el.classList.remove(cls), { once: true });
}

// ---------------------------------------------------------------- side panel
function evalFor(name) {
  return EVAL.find((e) => e.id === name || e.short === name || name.startsWith(e.short + ":"));
}

function renderModels() {
  const box = $("models");
  if (!S.models.length) {
    box.innerHTML = `<p class="ln" data-tone="alarm" style="grid-column:1/-1">no models found. Is Ollama running?</p>`;
    return;
  }
  box.innerHTML = S.models.map((m) => {
    const e = evalFor(m);
    const rate = e ? e.rate : null;
    return `<button class="model" type="button" data-m="${esc(m)}" data-on="${S.model === m}">
      <span class="modelName" title="${esc(m)}">${esc(e ? e.short : m)}</span>
      <span class="meter"><i style="width:${rate == null ? 0 : Math.max(2, rate * 100)}%"></i></span>
      <span class="modelRate">${rate == null ? "not in the eval" : `falls for it ${Math.round(rate * 100)}%`}</span>
    </button>`;
  }).join("");
}

function renderLevels() {
  $("levels").innerHTML = LEVELS.map((l) => `<button class="level" type="button" data-l="${l.n}" data-on="${S.level === l.n}">
    <b>${l.n}</b> ${esc(l.name)}<small>${esc(l.sub)}</small></button>`).join("");
  $("styles").innerHTML = STYLES.map((s) => `<button class="style" type="button" data-s="${s.id}" data-on="${S.style === s.id}">
    ${esc(s.name)}<small>${esc(s.sub)}</small></button>`).join("");
}

async function loadModels() {
  const pill = $("ollama");
  try {
    const j = await (await fetch("/api/models")).json();
    S.models = Array.isArray(j.models) ? j.models : [];
    pill.dataset.ok = String(S.models.length > 0);
    pill.textContent = S.models.length ? `ollama · ${S.models.length} models` : "ollama offline";
  } catch (e) {
    S.models = [];
    pill.dataset.ok = "false"; pill.textContent = "ollama offline";
  }
  // Default to the model that always bites: the best demo.
  const order = ["llama3.1:8b", "qwen2.5:7b", "qwen2.5:3b", "mistral-nemo:latest"];
  const rank = (m) => { const k = order.indexOf(m); return k < 0 ? 99 : k; };
  S.models.sort((a, b) => rank(a) - rank(b));
  S.model = order.find((m) => S.models.includes(m)) || S.models[0] || null;
  renderModels();
  syncButtons();
}

// changing a setting clears the old run so the screen never lies about it
function settingChanged() {
  if (S.busy) return;
  stop(); S.runs = []; S.cur = -1;
  renderModels(); renderLevels(); renderAll();
}

document.addEventListener("click", (ev) => {
  const t = ev.target.closest("button");
  if (!t || S.busy) return;
  if (t.dataset.m) { S.model = t.dataset.m; settingChanged(); }
  else if (t.dataset.l) { S.level = +t.dataset.l; settingChanged(); }
  else if (t.dataset.s) { S.style = t.dataset.s; settingChanged(); }
});

$("guard").addEventListener("click", () => {
  if (S.busy) return;
  S.guard = !S.guard;
  $("guard").dataset.on = String(S.guard);
  $("guard").setAttribute("aria-pressed", String(S.guard));
  $("guardTxt").textContent = S.guard ? "guard on" : "guard off";
  restartAnim($("guard"), "flick");
  blip({ freq: S.guard ? 660 : 220, dur: 0.08, type: "square", gain: 0.03 });
  settingChanged();
});

$("sound").addEventListener("click", () => {
  S.sound = !S.sound;
  try { localStorage.setItem("cp-sound", S.sound ? "1" : "0"); } catch (e) { /* ignore */ }
  $("sound").innerHTML = `&#9834; ${S.sound ? "on" : "off"}`;
  $("sound").setAttribute("aria-pressed", String(S.sound));
  blip({ freq: 990, dur: 0.1 });
});

// ---------------------------------------------------------------- trace -> belt
function argsOf(name, a) {
  a = a || {};
  if (typeof a === "string") { try { a = JSON.parse(a); } catch (e) { return a; } }
  if (name === "send_message") return `to: ${a.recipient || "?"}`;
  if (name === "fetch_url") return String(a.url ?? "").replace(/^https?:\/\//, "");
  if (a.path != null || a.filename != null) return String(a.path ?? a.filename);
  if (name === "declassify") return "draft";
  if (name === "endorse") return String(a.target ?? "");
  return Object.keys(a).join(", ");
}

function linesOf(text, tone, max = 14) {
  const all = String(text || "").split(/\n+/).map((s) => s.trim()).filter(Boolean);
  const out = all.slice(0, max).map((t) => ({ text: t.length > 400 ? t.slice(0, 400) + " …" : t, tone }));
  if (all.length > max) out.push({ text: `… ${all.length - max} more lines`, tone: "muted" });
  return out;
}

function buildItems(res) {
  const items = [];
  const decQ = (res.decisions || []).slice();
  const steps = res.steps || [];
  const enforce = res.config ? res.config.enforce : S.guard;
  let pending = [];

  for (const st of steps) {
    if (st.role === "user") {
      items.push({ tool: "user", args: "the task", kind: "ingest", bands: ["TRUSTED"], taint: ["TRUSTED"],
        lines: [{ text: st.content, tone: "TRUSTED" }] });
    } else if (st.role === "assistant") {
      if (st.tool_calls && st.tool_calls.length) {
        pending = st.tool_calls.map((c) => ({ ...c, taintAt: st.taint_after }));
      } else if (st.content) {
        items.push({ tool: "answer", args: "to you", kind: "local", bands: [], taint: st.taint_after,
          lines: [{ text: "final answer to the user:", tone: "muted" }, ...linesOf(st.content, "TRUSTED", 10)] });
      }
    } else if (st.role === "tool") {
      const call = pending.shift() || { name: st.source, args: {} };
      const name = call.name;
      const dec = LOCAL.has(name) ? null : decQ.shift() || null;
      const kind = SINKS.has(name) ? "sink" : LOCAL.has(name) ? "local" : "ingest";
      const bad = !!dec && dec.action !== "allow";
      const lines = [];
      let a = call.args || {};
      if (typeof a === "string") { try { a = JSON.parse(a); } catch (e) { a = { raw: a }; } }

      if (kind === "sink") {
        const toneTo = bad ? "UNTRUSTED" : "TRUSTED";
        if (name === "send_message") {
          lines.push({ text: `to: ${a.recipient || "(model gave no recipient)"}`, tone: toneTo });
          lines.push(...linesOf(`body: ${a.body ?? a.content ?? ""}`,(dec && (dec.labels || []).includes("SENSITIVE")) ? "SENSITIVE" : "TRUSTED", 8));
        } else {
          lines.push({ text: `${name} ${a.path ?? ""}`, tone: toneTo });
          if (a.content) lines.push(...linesOf(`content: ${a.content}`, "UNTRUSTED", 4));
        }
        if (st.content && st.content.startsWith("[IFC BLOCK]")) {
          lines.push({ text: "what the model was told: a generic refusal (no detail to tune an attack against)", tone: "muted" });
        }
      } else if (name === "fetch_url") {
        const lns = linesOf(st.content, "UNTRUSTED", 18);
        lns.forEach((l) => { if (l.tone === "UNTRUSTED" && HIDDEN_RE.test(l.text)) l.tone = "hidden"; });
        lines.push(...lns);
      } else if (kind === "local") {
        if (a.content) lines.push(...linesOf(`draft: ${a.content}`, "muted", 4));
        lines.push(...linesOf(`${name} → ${st.content}`, "TRUSTED", 6));
      } else {
        const tone = st.taint_here.includes("SENSITIVE") ? "SENSITIVE" : st.taint_here.includes("UNTRUSTED") ? "UNTRUSTED" : "muted";
        lines.push(...linesOf(st.content, st.is_error ? "muted" : tone, 10));
        if (st.is_error) lines.push({ text: "an error result carries no data, so it adds no band", tone: "muted" });
      }

      const bands = kind === "sink"
        ? (dec ? (dec.labels || []) : call.taintAt || []).filter((l) => l !== "TRUSTED")
        : kind === "local" ? [] : st.taint_here;
      items.push({
        tool: name, args: argsOf(name, a), kind, bands, lines,
        taint: st.taint_after.length ? st.taint_after : ["TRUSTED"],
        decision: dec, bad, passes: dec ? (!bad || !enforce) : true, enforce,
      });
    }
  }
  return items;
}

// ---------------------------------------------------------------- render
// the active run, once its trace has arrived (a pending A/B slot has no items yet)
function run() { const r = S.runs[S.active]; return r && r.items ? r : null; }

function renderBelt() {
  const r = run();
  const belt = $("belt");
  belt.dataset.busy = String(S.busy);
  $("idle").hidden = !!(r && r.items.length) && !S.busy;
  if (S.busy) return;
  if (!r) { $("bags").innerHTML = ""; $("gate").dataset.state = "idle"; return; }
  const w = window.innerWidth <= 520 ? 124 : 150;
  const cur = Math.max(S.cur, 0);
  $("bags").innerHTML = r.items.map((it, i) => {
    const held = i <= S.cur && it.bad && !it.passes;
    const leak = i <= S.cur && it.bad && it.passes;
    const bands = (it.bands || []).filter((l) => BAND[l]).map((l) => `<i class="${BAND[l]}"></i>`).join("");
    return `<button class="bag" type="button" data-i="${i}" data-kind="${it.kind}" data-held="${held}" data-leak="${leak}"
      title="${esc(it.tool + " · " + it.args)}"
      style="transform:translateX(calc(${(i - cur) * w}px - 50%));opacity:${i < S.cur - 2 || i > S.cur + 4 ? 0 : 1}">
      <span class="tool">${esc(it.tool)}</span><span class="bands">${bands}</span></button>`;
  }).join("");
  const st = r.items[S.cur];
  $("gate").dataset.state = st && st.kind === "sink" ? (st.passes ? (st.bad ? "bad" : "ok") : "held") : "idle";
}

$("bags").addEventListener("click", (ev) => {
  const b = ev.target.closest(".bag");
  if (!b) return;
  stop(); go(+b.dataset.i);
});

function renderMonitor() {
  const r = run();
  const st = r && S.cur >= 0 ? r.items[S.cur] : null;
  $("monTitle").textContent = st ? `${st.tool}(${st.args})` : S.busy ? "scanning…" : "—";
  const taint = st ? st.taint : [];
  document.querySelectorAll(".taint b").forEach((b) => { b.dataset.on = String(taint.includes(b.dataset.l)); });

  const scan = $("scan");
  if (S.busy) {
    scan.innerHTML = `<p class="ln" data-tone="muted">${esc(S.busyMsg || "")}</p>
      <p class="ln" data-tone="muted">the model is working on its own. Every tool call it makes goes through the gate before it runs.</p>`;
  } else if (!st) {
    scan.innerHTML = r && r.error
      ? `<p class="ln" data-tone="alarm">${esc(r.error)}</p>`
      : `<p class="ln" data-tone="muted">the scanner shows what each item really carries, including text a page hides with CSS.</p>`;
  } else {
    scan.innerHTML = st.lines.map((ln) => `<p class="ln" data-tone="${ln.tone || ""}">${ln.tone === "hidden"
      ? `<span class="hiddenTag">hidden from you, visible to the model</span>` : ""}${esc(ln.text)}</p>`).join("");
    scan.scrollTop = 0;
  }

  const d = $("decision");
  if (st && st.decision) {
    const act = st.decision.action;
    const live = st.enforce;
    d.hidden = false;
    d.dataset.action = act; d.dataset.live = String(live);
    d.innerHTML = live || act === "allow"
      ? `<b>${esc(act.replace("_", " "))}</b><code>${esc(st.decision.reason)}</code>`
      : `<b>guard off → passed</b><code>would have been: ${esc(act.replace("_", " "))}, ${esc(st.decision.reason)}</code>`;
  } else d.hidden = true;

  const v = $("verdict");
  const done = r && !S.busy && (r.error || S.cur >= r.items.length - 1);
  if (done) {
    const key = r.v;
    v.hidden = false; v.dataset.v = key;
    v.innerHTML = `<strong>${esc(VERDICT[key].title)}</strong><span>${esc(key === "error" ? r.detail : r.detail || VERDICT[key].sub)}</span>`;
  } else v.hidden = true;
}

function renderNav() {
  const r = run();
  const show = !!(r && r.items.length) && !S.busy;
  $("nav").hidden = !show;
  if (!show) return;
  $("pos").textContent = `${S.cur + 1} / ${r.items.length}`;
  $("prev").disabled = S.cur <= 0;
  $("next").disabled = S.cur >= r.items.length - 1;
  $("play").innerHTML = S.playing ? "&#10074;&#10074; pause" : "&#9654; play";
  $("play").disabled = S.cur >= r.items.length - 1 && !S.playing;
}

function renderTabs() {
  const box = $("tabs");
  box.hidden = S.runs.length < 2;
  box.innerHTML = S.runs.map((r, i) => `<button class="tab" type="button" data-tab="${i}" data-on="${i === S.active}" data-v="${r.v || ""}">
    ${esc(r.label)}${r.v ? `<b>${esc(VERDICT[r.v].title)}</b>` : `<b class="muted">…</b>`}</button>`).join("");
}
$("tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (!t || S.busy || !S.runs[+t.dataset.tab] || !S.runs[+t.dataset.tab].items) return;
  S.active = +t.dataset.tab; stop(); S.cur = -1; renderAll(); play();
});

function syncButtons() {
  const off = S.busy || !S.model;
  $("run").disabled = off; $("ab").disabled = off; $("guard").disabled = S.busy;
  const busyNow = String(S.busy);
  if ($("run").dataset.busy !== busyNow) {
    $("run").dataset.busy = busyNow;
    $("run").innerHTML = S.busy ? `<span class="spin"></span> scanning…` : "&#9654; run the task";
  }
  document.querySelectorAll(".model,.level,.style").forEach((b) => { b.disabled = S.busy; });
}

function renderAll() { renderTabs(); renderBelt(); renderMonitor(); renderNav(); syncButtons(); }

// ---------------------------------------------------------------- playback
function sfx(it) {
  if (!it) return;
  if (it.kind === "sink") {
    if (it.bad && it.passes) blip({ freq: 140, dur: 0.5, type: "square", gain: 0.05, glide: 90 });
    else if (it.bad) blip({ freq: 420, dur: 0.25, type: "square", gain: 0.04, glide: 210 });
    else blip({ freq: 990, dur: 0.12 });
  } else blip({ freq: 1800, dur: 0.03, type: "square", gain: 0.02 });
}
function go(i) {
  const r = run();
  if (!r) return;
  S.cur = Math.max(0, Math.min(i, r.items.length - 1));
  sfx(r.items[S.cur]);
  renderBelt(); renderMonitor(); renderNav();
}
function stop() { S.playing = false; if (timer) clearTimeout(timer); timer = null; }
function tick() {
  const r = run();
  if (!S.playing || !r) return;
  if (S.cur >= r.items.length - 1) { stop(); renderNav(); return; }
  go(S.cur + 1);
  timer = setTimeout(tick, reduced ? 700 : 1500);
}
function play() {
  const r = run();
  if (!r || !r.items.length) return;
  stop(); S.playing = true;
  if (S.cur < 0 || S.cur >= r.items.length - 1) { S.cur = -1; }
  tick();
}
$("prev").addEventListener("click", () => { stop(); go(S.cur - 1); });
$("next").addEventListener("click", () => { stop(); go(S.cur + 1); });
$("play").addEventListener("click", () => { if (S.playing) { stop(); renderNav(); } else play(); });
$("replay").addEventListener("click", () => { S.cur = -1; play(); });
document.addEventListener("keydown", (ev) => {
  if (S.busy || !run() || ev.target.closest("input,textarea,select")) return;
  if (ev.key === "ArrowRight") { stop(); go(S.cur + 1); }
  else if (ev.key === "ArrowLeft") { stop(); go(S.cur - 1); }
});

// ---------------------------------------------------------------- running
async function callRun(enforce) {
  const r = await fetch("/api/run", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: S.model, level: S.level, style: S.style, enforce }),
  });
  const res = await r.json();
  if (!r.ok && !res.verdict) res.verdict = "error";
  return res;
}

function finish(slot, res) {
  slot.res = res;
  slot.error = res.verdict === "error" ? (res.error || "unknown error") : null;
  slot.items = slot.error ? [] : buildItems(res);
  slot.v = VMAP[res.verdict] || "clean";
  slot.detail = res.verdict_detail || res.error || "";
  if (slot.v === "clean" && res.verdict === "legit") slot.detail = "the only send went out clean: nothing secret in the payload";
}

async function session(plan) {
  stop();
  restartAnim($("run"), "go");
  blip({ freq: 520, dur: 0.09, type: "triangle", gain: 0.04, glide: 780 });
  S.busy = true; S.cur = -1; S.active = 0;
  S.runs = plan.map((p) => ({ label: p.label, enforce: p.enforce }));
  const t0 = Date.now();
  const clock = setInterval(() => {
    const s = Math.round((Date.now() - t0) / 1000);
    $("idle").textContent = `${S.busyMsg} · ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  }, 500);
  try {
    for (let i = 0; i < plan.length; i++) {
      S.busyMsg = `${plan.length > 1 ? `run ${i + 1}/${plan.length} · ` : ""}${S.model} is reading the page, guard ${plan[i].enforce ? "on" : "off"}`;
      $("idle").textContent = S.busyMsg;
      $("status").innerHTML = `local inference is slow here, so a run can take a minute or two.`;
      renderAll();
      let res;
      try { res = await callRun(plan[i].enforce); }
      catch (e) { res = { verdict: "error", error: String(e) }; }
      finish(S.runs[i], res);
    }
  } finally {
    clearInterval(clock);
    S.busy = false;
    $("idle").textContent = "belt empty · pick a model and a trap, then run the task";
  }
  const took = Math.round((Date.now() - t0) / 1000);
  const r0 = S.runs[0];
  $("status").innerHTML = `${esc(S.model)} · trap ${S.level} · ${S.style === "autonomous" ? "obedient" : "cautious"} · ${took}s` +
    (r0.res && r0.res.declassify_calls ? ` · declassify <b>${r0.res.declassify_calls}</b>×` : "") +
    ` · <span class="muted">← → to step, click any item</span>`;
  renderAll();
  play();
}

$("run").addEventListener("click", () => session([{ label: S.guard ? "guard on" : "guard off", enforce: S.guard }]));
$("ab").addEventListener("click", () => session([{ label: "A · guard off", enforce: false }, { label: "B · guard on", enforce: true }]));

// ---------------------------------------------------------------- smuggler's tray
let tray = null;
function renderTray(sel) {
  const out = $("trayOut");
  if (!tray) return;
  const rows = tray.rows || [];
  const byT = {};
  rows.forEach((r) => { (byT[r.transform] = byT[r.transform] || []).push(r); });
  const base = {};
  (tray.baseline || []).forEach((r) => { base[r.transform] = base[r.transform] || r.bypassed; });
  const ts = tray.transforms || Object.keys(byT);
  sel = sel || ts.find((t) => /base64/.test(t)) || ts[0];
  const s = tray.summary;
  const cur = byT[sel] || [];
  const bad = cur.some((r) => r.bypassed);
  out.innerHTML = `<div class="chips">${ts.map((t) => {
    const b = (byT[t] || []).some((r) => r.bypassed);
    return `<button class="chip" type="button" data-t="${esc(t)}" data-on="${t === sel}" data-bad="${b}">${esc(t.replace(" (bare value, key stripped)", ""))}</button>`;
  }).join("")}</div>
    <p class="ln" data-tone="SENSITIVE"><span class="k">disguise</span>${esc(sel)}</p>
    ${cur.slice(0, 2).map((r) => `<p class="ln" data-tone="${r.bypassed ? "alarm" : "TRUSTED"}"><span class="k">declassify</span>${esc(r.out_preview)}</p>`).join("")}
    <p class="ln" data-tone="hidden"><span class="k">gate</span>${bad ? "BYPASS · this encoding survives the sanitizer" : "closed · the label comes from what the task touched, not from these bytes"}${tray.baseline ? ` · before hardening: ${base[sel] ? "BYPASS" : "closed"}` : ""}</p>
    <p class="small"><b>${s.closed} of ${s.total}</b> encoded-secret cells closed · anchor forgery ('corp.com'): ${tray.anchor.anchored ? "VULNERABLE" : "closed"} · clean summary over-redacted: ${tray.fp.unchanged ? "no" : "yes"}</p>`;
}
$("bypass").addEventListener("click", async () => {
  const b = $("bypass"); b.disabled = true; b.textContent = "scanning…";
  try {
    tray = await (await fetch("/api/bypass")).json();
    renderTray();
    blip({ freq: 1200, dur: 0.08 });
    b.textContent = "re-scan";
  } catch (e) {
    $("trayOut").innerHTML = `<p class="ln" data-tone="alarm">battery failed: ${esc(e)}</p>`;
    b.textContent = "x-ray the disguises";
  } finally { b.disabled = false; }
});
$("trayOut").addEventListener("click", (ev) => {
  const c = ev.target.closest(".chip");
  if (c) { renderTray(c.dataset.t); blip({ freq: 1500, dur: 0.03, type: "square", gain: 0.02 }); }
});

// ---------------------------------------------------------------- chart
function renderChart() {
  $("chart").innerHTML = EVAL.map((m) => `<div class="row">
    <span class="rowName">${esc(m.short)}</span>
    <span class="bar"><i class="orange" data-w="${Math.max(1, m.rate * 100)}"></i></span>
    <span class="rowVal">${Math.round(m.rate * 100)}%</span>
    <span class="rowHeld">0 leaked</span></div>`).join("");
  // grow the bars when the chart scrolls into view
  const grow = () => document.querySelectorAll("#chart .bar i").forEach((i) => { i.style.width = i.dataset.w + "%"; });
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { grow(); io.disconnect(); } });
    io.observe($("chart"));
  } else grow();
}

// ---------------------------------------------------------------- boot
$("sound").innerHTML = `&#9834; ${S.sound ? "on" : "off"}`;
window.addEventListener("resize", () => renderBelt());
renderLevels();
renderChart();
renderAll();
loadModels();
