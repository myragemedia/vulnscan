"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const state = {
  plugins: [],
  currentScanId: null,
  runningScanId: null,
  counts: zeroCounts(),
  filter: null,
};

function zeroCounts() {
  return SEVERITIES.reduce((acc, s) => ((acc[s] = 0), acc), {});
}

// ------------------------------------------------------------------ elements
const el = (id) => document.getElementById(id);
const pluginSelect = el("pluginSelect");
const pluginDesc = el("pluginDesc");
const optionsForm = el("optionsForm");
const targetInput = el("targetInput");
const launchBtn = el("launchBtn");
const launchMsg = el("launchMsg");
const consoleEl = el("console");
const findingsEl = el("findings");
const historyList = el("historyList");
const scanContext = el("scanContext");
const findingsCount = el("findingsCount");
const cancelBtn = el("cancelBtn");
const reportBtn = el("reportBtn");

// ------------------------------------------------------------------ bootstrap
init();

async function init() {
  await loadPlugins();
  await loadHistory();
  connectWs();
  bindUi();
  setFindingsEmpty("Launch a scan to see findings here.");
}

function bindUi() {
  pluginSelect.addEventListener("change", renderOptions);
  launchBtn.addEventListener("click", launch);
  cancelBtn.addEventListener("click", cancel);
  reportBtn.addEventListener("click", exportReport);
  document.querySelectorAll(".sev").forEach((btn) =>
    btn.addEventListener("click", () => toggleFilter(btn.dataset.sev))
  );
}

// ------------------------------------------------------------------ plugins
async function loadPlugins() {
  const res = await fetch("/api/plugins");
  const data = await res.json();
  state.plugins = data.plugins;

  pluginSelect.innerHTML = "";
  for (const p of state.plugins) {
    const opt = document.createElement("option");
    opt.value = p.slug;
    opt.textContent = p.available ? p.name : `${p.name} (not installed)`;
    opt.disabled = !p.available;
    pluginSelect.appendChild(opt);
  }
  renderOptions();
}

function currentPlugin() {
  return state.plugins.find((p) => p.slug === pluginSelect.value);
}

function renderOptions() {
  const p = currentPlugin();
  pluginDesc.textContent = p ? p.description : "";
  optionsForm.innerHTML = "";
  if (!p) return;

  for (const opt of p.options_schema || []) {
    const wrap = document.createElement(opt.type === "checkbox" ? "label" : "label");
    if (opt.type === "checkbox") {
      wrap.className = "opt-check";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.dataset.key = opt.key;
      input.checked = !!opt.default;
      wrap.appendChild(input);
      wrap.appendChild(document.createTextNode(opt.label));
    } else {
      wrap.className = "field";
      const span = document.createElement("span");
      span.className = "field-label";
      span.textContent = opt.label;
      wrap.appendChild(span);

      let input;
      if (opt.type === "select") {
        input = document.createElement("select");
        for (const choice of opt.choices || []) {
          const o = document.createElement("option");
          o.value = choice;
          o.textContent = choice;
          if (choice === opt.default) o.selected = true;
          input.appendChild(o);
        }
      } else {
        input = document.createElement("input");
        input.type = opt.type === "number" ? "number" : "text";
        if (opt.default != null) input.value = opt.default;
      }
      input.dataset.key = opt.key;
      wrap.appendChild(input);
      if (opt.hint) {
        const hint = document.createElement("div");
        hint.className = "opt-hint";
        hint.textContent = opt.hint;
        wrap.appendChild(hint);
      }
    }
    optionsForm.appendChild(wrap);
  }
}

function collectOptions() {
  const options = {};
  optionsForm.querySelectorAll("[data-key]").forEach((input) => {
    if (input.type === "checkbox") options[input.dataset.key] = input.checked;
    else if (input.type === "number") options[input.dataset.key] = Number(input.value);
    else options[input.dataset.key] = input.value;
  });
  return options;
}

// ------------------------------------------------------------------ launch
async function launch() {
  const target = targetInput.value.trim();
  if (!target) {
    setLaunchMsg("Enter a target first.", "error");
    return;
  }
  const body = { plugin: pluginSelect.value, target, options: collectOptions() };
  launchBtn.disabled = true;
  setLaunchMsg("Starting …", "");

  try {
    const res = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      setLaunchMsg(data.detail || "Failed to start.", "error");
      launchBtn.disabled = false;
      return;
    }
    setLaunchMsg("", "");
    focusScan(data.id, { fresh: true, plugin: data.plugin, target: data.target });
    await loadHistory();
  } catch (err) {
    setLaunchMsg("Network error starting scan.", "error");
  } finally {
    launchBtn.disabled = false;
  }
}

async function cancel() {
  if (!state.runningScanId) return;
  await fetch(`/api/scans/${state.runningScanId}/cancel`, { method: "POST" });
}

// ------------------------------------------------------------------ websocket
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => setWs(true);
  ws.onclose = () => {
    setWs(false);
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (evt) => handleEvent(JSON.parse(evt.data));
}

function handleEvent(msg) {
  const { type, scan_id, data } = msg;

  if (type === "status" && data.status === "running") {
    state.runningScanId = scan_id;
    updateActivePill();
  }

  // Only render into the workspace for the scan currently in focus.
  if (state.currentScanId && scan_id !== state.currentScanId) {
    if (type === "status") loadHistory();
    return;
  }

  if (type === "log") appendLine(data.line);
  else if (type === "finding") addFinding(data.finding);
  else if (type === "status") applyStatus(data);
}

function applyStatus(data) {
  if (data.status === "running") {
    scanContext.textContent = `running · ${data.plugin} · ${data.target}`;
    cancelBtn.disabled = false;
  } else {
    cancelBtn.disabled = true;
    scanContext.textContent = data.status;
    if (data.counts) setCounts(data.counts);
    state.runningScanId = null;
    updateActivePill();
    loadHistory();
  }
}

// ------------------------------------------------------------------ rendering
function appendLine(text) {
  const div = document.createElement("div");
  div.className = "line";
  if (text.startsWith("$")) div.classList.add("line-cmd");
  else if (/\[\+\]|CVE-\d/i.test(text)) div.classList.add("line-hit");
  else if (/complete|cancelled|error/i.test(text)) div.classList.add("line-sys");
  div.textContent = text;
  consoleEl.appendChild(div);
  const nearBottom =
    consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 80;
  if (nearBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
}

function addFinding(f) {
  state.counts[f.severity] = (state.counts[f.severity] || 0) + 1;
  renderCounts();
  if (findingsEl.querySelector(".empty")) findingsEl.innerHTML = "";
  findingsEl.prepend(buildFindingRow(f));
  findingsCount.textContent = findingsEl.querySelectorAll(".finding").length;
}

function buildFindingRow(f) {
  const row = document.createElement("div");
  row.className = "finding";
  row.dataset.sev = f.severity;
  if (state.filter && state.filter !== f.severity) row.style.display = "none";

  const top = document.createElement("div");
  top.className = "finding-top";
  const name = document.createElement("span");
  name.className = "finding-name";
  name.textContent = f.name;
  top.appendChild(name);
  if (f.cve) {
    const cve = document.createElement("span");
    cve.className = "finding-cve";
    cve.textContent = f.cve;
    top.appendChild(cve);
  }
  row.appendChild(top);

  const meta = document.createElement("div");
  meta.className = "finding-meta";
  const bits = [f.severity.toUpperCase()];
  if (f.port) bits.push(`port ${f.port}`);
  if (f.target) bits.push(f.target);
  meta.textContent = bits.join(" · ");
  row.appendChild(meta);

  if (f.evidence) {
    const ev = document.createElement("div");
    ev.className = "finding-evidence";
    ev.textContent = f.evidence;
    row.appendChild(ev);
  }
  return row;
}

// ------------------------------------------------------------------ counts
function renderCounts() {
  for (const s of SEVERITIES) el(`c-${s}`).textContent = state.counts[s] || 0;
}
function setCounts(counts) {
  state.counts = Object.assign(zeroCounts(), counts);
  renderCounts();
}

function toggleFilter(sev) {
  state.filter = state.filter === sev ? null : sev;
  document.querySelectorAll(".sev").forEach((b) =>
    b.classList.toggle("selected", b.dataset.sev === state.filter)
  );
  findingsEl.querySelectorAll(".finding").forEach((row) => {
    row.style.display = !state.filter || row.dataset.sev === state.filter ? "" : "none";
  });
}

// ------------------------------------------------------------------ history
async function loadHistory() {
  const res = await fetch("/api/scans");
  const data = await res.json();
  historyList.innerHTML = "";
  for (const scan of data.scans) {
    const li = document.createElement("li");
    li.className = "history-item";
    if (scan.id === state.currentScanId) li.classList.add("selected");
    li.addEventListener("click", () => openScan(scan.id));

    const top = document.createElement("div");
    top.className = "history-top";
    const tool = document.createElement("span");
    tool.className = "history-tool";
    tool.textContent = pluginName(scan.plugin);
    const tag = document.createElement("span");
    tag.className = `status-tag status-${scan.status}`;
    tag.textContent = scan.status;
    top.append(tool, tag);

    const target = document.createElement("div");
    target.className = "history-target";
    target.textContent = scan.target;

    li.append(top, target);
    historyList.appendChild(li);
  }
}

function pluginName(slug) {
  const p = state.plugins.find((x) => x.slug === slug);
  return p ? p.name : slug;
}

// ------------------------------------------------------------------ focus/open
function focusScan(scanId, opts = {}) {
  state.currentScanId = scanId;
  state.counts = zeroCounts();
  renderCounts();
  consoleEl.innerHTML = "";
  findingsEl.innerHTML = "";
  findingsCount.textContent = "0";
  state.filter = null;
  document.querySelectorAll(".sev").forEach((b) => b.classList.remove("selected"));
  if (opts.fresh) {
    scanContext.textContent = `starting · ${opts.plugin} · ${opts.target}`;
  }
}

async function openScan(scanId) {
  focusScan(scanId);
  const res = await fetch(`/api/scans/${scanId}`);
  const data = await res.json();

  scanContext.textContent = `${data.scan.status} · ${pluginName(data.scan.plugin)} · ${data.scan.target}`;
  cancelBtn.disabled = data.scan.status !== "running";
  if (data.scan.status === "running") state.runningScanId = scanId;

  setCounts(data.counts);
  if (!data.findings.length) {
    setFindingsEmpty("No findings recorded for this scan.");
  } else {
    findingsEl.innerHTML = "";
    for (const f of data.findings) findingsEl.appendChild(buildFindingRow(f));
    findingsCount.textContent = data.findings.length;
  }
  appendLine(`— loaded historical scan ${scanId} —`);
  loadHistory();
}

// ------------------------------------------------------------------ report
async function exportReport() {
  const url = state.currentScanId
    ? `/api/report?scan_id=${state.currentScanId}`
    : "/api/report";
  const res = await fetch(url);
  const data = await res.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `report-${state.currentScanId || "all"}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ------------------------------------------------------------------ ui bits
function setWs(connected) {
  const pill = el("wsStatus");
  pill.classList.toggle("pill-on", connected);
  pill.classList.toggle("pill-off", !connected);
  el("wsStatusText").textContent = connected ? "live" : "offline";
}
function updateActivePill() {
  const n = state.runningScanId ? 1 : 0;
  const pill = el("activeScans");
  pill.textContent = `${n} active`;
  pill.classList.toggle("active", n > 0);
}
function setLaunchMsg(text, kind) {
  launchMsg.textContent = text;
  launchMsg.className = "launch-msg" + (kind ? " " + kind : "");
}
function setFindingsEmpty(text) {
  findingsEl.innerHTML = `<div class="empty">${text}</div>`;
}
