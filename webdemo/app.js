"use strict";

const $ = (id) => document.getElementById(id);
const PREFERRED = ["qwen2.5:7b", "llama3.1:8b", "qwen2.5:3b", "mistral-nemo:latest"];

let enforce = true;

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

async function loadModels() {
  try {
    const r = await fetch("/api/models");
    const j = await r.json();
    const sel = $("model");
    sel.innerHTML = "";
    const models = j.models || [];
    if (!models.length) {
      sel.innerHTML = "<option>(no models — is Ollama running?)</option>";
      return;
    }
    models.sort((a, b) => PREFERRED.indexOf(a) - PREFERRED.indexOf(b));
    for (const m of models) {
      const o = document.createElement("option");
      o.value = o.textContent = m;
      sel.appendChild(o);
    }
    const def = PREFERRED.find((m) => models.includes(m));
    if (def) sel.value = def;
  } catch (e) {
    $("status").textContent = "Could not load models: " + e;
  }
}

$("enforce").addEventListener("click", () => {
  enforce = !enforce;
  const b = $("enforce");
  b.textContent = enforce ? "ON" : "OFF";
  b.className = "toggle " + (enforce ? "on" : "off");
});

function cfg(overrideEnforce) {
  return {
    model: $("model").value,
    level: parseInt($("level").value, 10),
    style: $("style").value,
    enforce: overrideEnforce === undefined ? enforce : overrideEnforce,
  };
}

function taintChips(labels) {
  return (labels || []).map((l) => `<span class="chip ${l.toLowerCase()}">${l}</span>`).join("");
}

function renderStep(s) {
  let cls = "step " + s.role;
  let tag = s.role;
  if (s.role === "tool") {
    if (s.source === "declassify" || s.source === "endorse") { cls += " declassify"; }
    else if (s.taint_here.includes("UNTRUSTED")) { cls += " untrusted"; }
    else if (s.taint_here.includes("SENSITIVE")) { cls += " sensitive"; }
    tag = "tool result &middot; <b>" + esc(s.source) + "</b>";
    if (s.is_error) tag += " <span class='muted'>(ERROR — does not taint)</span>";
  } else if (s.role === "assistant") { tag = "model"; }
  else if (s.role === "user") { tag = "user task"; }
  else if (s.role === "system") { tag = "system prompt"; }

  let calls = "";
  if (s.tool_calls && s.tool_calls.length) {
    calls = "<div class='calls'>&rarr; calls: " +
      s.tool_calls.map((c) => esc(c.name) + "(" + esc(JSON.stringify(c.args)) + ")").join(", ") + "</div>";
  }
  const chips = s.role === "tool" ? taintChips(s.taint_here) : "";
  const bar = (s.taint_after && s.taint_after.length)
    ? `<div class="taintbar">task taint now: ${s.taint_after.join(" + ")}</div>` : "";
  const body = s.content ? `<pre>${esc(s.content)}</pre>` : "";
  return `<div class="${cls}"><div class="role">${tag}${chips}</div>${calls}${body}${bar}</div>`;
}

function renderResult(res, title) {
  if (res.error && res.verdict === "error") {
    return `<div class="result"><h2>${esc(title)}</h2>
      <div class="verdict error">ERROR <span class="detail">${esc(res.error)}</span></div></div>`;
  }
  const c = res.config;
  const decs = res.decisions.length
    ? res.decisions.map((d) => `<div class="dec">
        <span class="badge ${d.action}">${d.action.replace("_", " ")}</span>
        <span class="tool">${esc(d.tool)}</span>
        <span class="reason">${esc(d.reason)}</span></div>`).join("")
    : `<div class="muted">no tool calls were policy-checked</div>`;
  const sends = res.sends.length
    ? res.sends.map((m) => `<div class="send"><span class="to">&rarr; ${esc(m.recipient) || "(no recipient)"}</span>
        <pre>${esc(m.body)}</pre></div>`).join("")
    : `<div class="muted">send_message never fired</div>`;
  const actions = (res.actions && res.actions.length)
    ? res.actions.map((a) => `<div class="action"><span class="to">${esc(a.action)}</span> &rarr; <code>${esc(a.path)}</code></div>`).join("")
    : `<div class="muted">no state-changing action executed</div>`;
  const steps = res.steps.map(renderStep).join("");
  const bits = [];
  if (res.declassify_calls) bits.push(`declassify &times;${res.declassify_calls}`);
  if (res.endorse_calls) bits.push(`endorse &times;${res.endorse_calls}`);
  const dtl = bits.length ? " &middot; " + bits.join(" &middot; ") : "";

  return `<div class="result">
    <h2>${esc(title)} <span class="cfg">${esc(c.model)} &middot; level ${c.level} &middot; ${esc(c.style)} &middot; defense ${c.enforce ? "ON" : "OFF"}${dtl}</span></h2>
    <div class="verdict ${res.verdict}">${verdictLabel(res.verdict)}<span class="detail">${esc(res.verdict_detail)}</span></div>
    <div class="cols">
      <div class="col"><h3>Conversation trace</h3>${steps}</div>
      <div class="col">
        <h3>Policy decisions</h3>${decs}
        <h3 style="margin-top:16px">Messages sent</h3>${sends}
        <h3 style="margin-top:16px">State-changing actions</h3>${actions}
        <h3 style="margin-top:16px">Final answer to user</h3>
        <div class="final">${esc(res.final) || "<span class='muted'>(none)</span>"}</div>
      </div>
    </div></div>`;
}

function verdictLabel(v) {
  return { exfiltrated: "SECRETS EXFILTRATED", tampered: "SYSTEM TAMPERED",
    blocked: "ATTACK BLOCKED", legit: "LEGIT SEND", action_done: "ACTION PERFORMED",
    no_egress: "NO TAINTED EGRESS", error: "ERROR" }[v] || v;
}

async function callRun(conf) {
  const r = await fetch("/api/run", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(conf),
  });
  return r.json();
}

function busy(on, msg) {
  $("run").disabled = on; $("runab").disabled = on;
  $("status").textContent = msg || "";
}

async function run() {
  const conf = cfg();
  busy(true, `Running ${conf.model} (level ${conf.level}, defense ${conf.enforce ? "ON" : "OFF"})… the model call can take a while.`);
  try {
    const res = await callRun(conf);
    $("results").innerHTML = renderResult(res, "Result");
  } catch (e) {
    $("status").textContent = "Run failed: " + e;
  } finally { busy(false); }
}

async function runAB() {
  const base = cfg(false);
  busy(true, `A/B run 1/2 — defense OFF (${base.model}, level ${base.level})…`);
  try {
    const off = await callRun({ ...base, enforce: false });
    $("results").innerHTML = renderResult(off, "① Defense OFF");
    busy(true, `A/B run 2/2 — defense ON (${base.model}, level ${base.level})…`);
    const on = await callRun({ ...base, enforce: true });
    $("results").innerHTML = renderResult(off, "① Defense OFF") + renderResult(on, "② Defense ON");
  } catch (e) {
    $("status").textContent = "A/B failed: " + e;
  } finally { busy(false); }
}

function renderBypass(j) {
  const base = {};
  (j.baseline || []).forEach((r) => { if (!(r.transform in base)) base[r.transform] = false; if (r.bypassed) base[r.transform] = true; });
  const now = {};
  (j.rows || []).forEach((r) => { if (!(r.transform in now)) now[r.transform] = false; if (r.bypassed) now[r.transform] = true; });
  const cell = (v) => v === undefined ? "<span class='muted'>n/a</span>"
    : (v ? "<span class='badge block'>BYPASS</span>" : "<span class='badge allow'>closed</span>");
  const rows = (j.transforms || []).map((t) =>
    `<tr><td>${esc(t)}</td><td>${j.baseline ? cell(!!base[t]) : "<span class='muted'>—</span>"}</td><td>${cell(now[t])}</td></tr>`
  ).join("");
  const s = j.summary;
  return `<div class="result"><h2>Sanitizer bypass battery
      <span class="cfg">${s.closed}/${s.total} cells closed · ${s.bypassed} bypassing</span></h2>
    <div class="col">
      <table class="bypass-table"><thead><tr><th>encoding transform</th><th>before hardening</th><th>after (current)</th></tr></thead>
      <tbody>${rows}</tbody></table>
      <div class="taintbar" style="margin-top:10px">
        anchor substring-forgery ('corp.com' via 'report@corp.com'): <b>${j.anchor.anchored ? "VULNERABLE" : "closed"}</b> ·
        legit full address still anchors: <b>${j.anchor.legit_full_address_anchored}</b> ·
        clean summary over-redacted (false positive): <b>${!j.fp.unchanged}</b>
      </div>
    </div></div>`;
}

async function runBypass() {
  const btn = $("bypass"); btn.disabled = true;
  $("bypass-out").innerHTML = "<p class='muted'>running the deterministic transform battery…</p>";
  try {
    const r = await fetch("/api/bypass");
    $("bypass-out").innerHTML = renderBypass(await r.json());
  } catch (e) { $("bypass-out").innerHTML = "<p class='muted'>failed: " + esc(e) + "</p>"; }
  finally { btn.disabled = false; }
}

$("run").addEventListener("click", run);
$("runab").addEventListener("click", runAB);
$("bypass").addEventListener("click", runBypass);
loadModels();
