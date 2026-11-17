// PurrRouter front end: vanilla JS, no build step.
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ui = {
  snap: null,
  filter: localStorage.getItem("rd.filter") || "all",
  view: localStorage.getItem("rd.view") || "cards",
  sort: localStorage.getItem("rd.sort") || "ip",
  query: "",
  timer: null,
  busy: new Set(),
  labels: {},
  pendingAccess: {},   // mac → { access, until }: what we just told the router, until it reports it back
  loading: null,
  nextAt: 0,
  refreshSec: +(localStorage.getItem("rd.refresh") ?? 30),
  tab: localStorage.getItem("rd.tab") || "overview",
  pf: null,
  dhcp: null,
  wl: null,
  localIps: [],
};

const BANDS = {
  "5": { label: "5 GHz", g: "var(--g5)", emoji: "⚡" },
  "2.4": { label: "2.4 GHz", g: "var(--g24)", emoji: "🧶" },
  wired: { label: "Wired", g: "var(--gwired)", emoji: "🐭" },
  wireless: { label: "Wi-Fi", g: "linear-gradient(135deg,#38bdf8,#f472b6)", emoji: "📶" },
  unknown: { label: "Unknown", g: "var(--gunk)", emoji: "❔" },
};
const band = b => BANDS[b] ?? { label: b, g: "var(--gunk)", emoji: "❔" };

// ───────────────────────── api ─────────────────────────
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method,
    headers: { "Content-Type": "application/json", "X-PurrRouter": "1" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || data.detail || data.title || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// ───────────────────────── boot ─────────────────────────
async function boot() {
  const st = await api("/status");
  ui.localIps = st.localIps || [];
  if (!st.configured) return showSetup(st);
  showDash();
}

function showSetup(st = {}) {
  clearInterval(ui.ticker);
  $("#dash").hidden = true;
  $("#setup").hidden = false;
  const f = $("#setupForm");
  if (st.host) f.host.value = st.host;
  if (st.username) f.username.value = st.username;
  if (st.port) f.port.value = st.port;
  f.useHttps.checked = !!st.useHttps;
  f.password.focus();
}

$("#setupForm").addEventListener("submit", async e => {
  e.preventDefault();
  const f = e.target, btn = f.querySelector("button"), err = $("#setupError");
  err.hidden = true;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin">🧶</span> Connecting…`;
  try {
    await api("/setup", {
      method: "POST",
      body: {
        host: f.host.value, username: f.username.value, password: f.password.value,
        port: +f.port.value || null, useHttps: f.useHttps.checked,
      },
    });
    f.password.value = "";
    showDash();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span><i class="paw"></i> Connect</span>`;
  }
});

$("#setupForm").useHttps.addEventListener("change", e => { e.target.form.port.value = e.target.checked ? 443 : 80; });

function showDash() {
  $("#setup").hidden = true;
  $("#dash").hidden = false;
  setView(ui.view);
  $("#sort").value = ui.sort;
  $("#refreshEvery").value = String(ui.refreshSec);
  setTab(ui.tab);
  load(true);
  clearInterval(ui.ticker);
  ui.ticker = setInterval(tick, 1000);
}

// One refresh at a time; the next one is scheduled 30s after the previous one *finishes*
// (the R6350 takes several seconds to answer, so a fixed interval drifts and overlaps).
const refreshMs = () => ui.refreshSec * 1000;
function tick() {
  const el = $("#updated");
  if (!ui.snap || !el) return;
  const at = new Date(ui.snap.fetchedAt).toLocaleTimeString();
  const left = Math.max(0, Math.ceil((ui.nextAt - Date.now()) / 1000));
  el.innerHTML = ui.loading ? `<i class="paw"></i> Last sniffed ${at} · sniffing around now…`
    : ui.refreshSec === 0 ? `<i class="paw"></i> Last sniffed ${at}`
    : `<i class="paw"></i> Last sniffed ${at} · next sniff in ${left >= 60 ? `${Math.floor(left / 60)}m ${left % 60}s` : `${left}s`}`;
  if (ui.refreshSec > 0 && !ui.loading && !document.hidden && Date.now() >= ui.nextAt) load(false);
}

$("#refreshEvery").addEventListener("change", e => {
  ui.refreshSec = +e.target.value;
  localStorage.setItem("rd.refresh", ui.refreshSec);
  ui.nextAt = Date.now() + refreshMs();
  tick();
});

// ───────────────────────── load & render ─────────────────────────
async function load(force) {
  if (ui.loading) {               // already refreshing: a forced refresh waits and runs right after
    if (!force) return;
    await ui.loading.catch(() => {});
  }
  ui.loading = loadCore(force).finally(() => { ui.loading = null; ui.nextAt = Date.now() + refreshMs(); tick(); });
  return ui.loading;
}

async function loadCore(force) {
  const btn = $("#refreshBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin">🧶</span> <span class="hide-sm">Refresh</span>`;
  try {
    ui.snap = await api("/snapshot" + (force ? "?force=true" : ""));
    $("#banner").hidden = true;
    render();
  } catch (ex) {
    if (ex.status === 401 || ex.status === 409) return showSetup(await api("/status"));
    if (Date.now() < (ui.wifiRestartUntil || 0)) return; // expected: Wi-Fi is restarting; awaitWifiRestart() reports
    const b = $("#banner");
    b.textContent = `🙀 ${ex.message} Showing the last data I had.`;
    b.hidden = false;
  } finally {
    btn.innerHTML = `🧶 <span class="hide-sm">Refresh</span>`;
    btn.disabled = false;
  }
}

function render() {
  const s = ui.snap;
  if (!s) return;
  renderHeader(s);
  renderTiles(s);
  renderWan(s);
  renderWifi(s);
  renderDevices();
  if (ui.pf) renderPf(); // rules may have loaded before the device list they link to
  if (ui.dhcp) renderDhcp();
  if (ui.logs) renderLogs(); // device names in the log come from the snapshot
  updateWifiLive();
  tick();
}

function renderHeader(s) {
  const r = s.router;
  $("#routerName").textContent = `Netgear ${r.model}`;
  document.title = `PurrRouter · ${r.model}`;
  $("#routerMeta").textContent = [r.firmware && `Firmware ${r.firmware}`, s.lan.ip].filter(Boolean).join(" · ");

  const up = isUp(s);
  const pill = $("#netPill");
  pill.className = "pill" + (up === false ? " down" : "");
  pill.textContent = up === false ? "🙀 Internet down" : up ? "😺 Internet up" : "😼 Internet ?";
}

function isUp(s) {
  const l = (s.wan.linkStatus || "").toLowerCase();
  if (l) return l === "up";
  return s.wan.externalIp && s.wan.externalIp !== "0.0.0.0" ? true : null;
}

function renderTiles(s) {
  const d = s.devices;
  const n = b => d.filter(x => x.band === b).length;
  const t = s.traffic;
  const tiles = [
    { g: "var(--gbrand)", label: "Devices online", emoji: "🐈", value: d.length, sub: `${d.filter(x => isBlocked(x)).length} blocked · ${d.filter(x => x.isNew).length} new` },
    { g: "var(--g24)", label: "2.4 GHz", emoji: "🧶", value: n("2.4"), sub: "long-range prowl" },
    { g: "var(--g5)", label: "5 GHz", emoji: "⚡", value: n("5"), sub: "zoomies lane" },
    { g: "var(--gwired)", label: "Wired", emoji: "🐭", value: n("wired"), sub: "tail plugged in" },
  ];
  if (t?.enabled && (t.today.downMb != null || t.month.downMb != null)) {
    tiles.push({ g: "linear-gradient(135deg,#60a5fa,#6366f1)", label: "Today", emoji: "🐟", value: mb(t.today.downMb), sub: `↓ down · ↑ ${mb(t.today.upMb)} up` });
    tiles.push({ g: "linear-gradient(135deg,#c084fc,#db2777)", label: "This month", emoji: "🥫", value: mb(t.month.downMb), sub: `↓ down · ↑ ${mb(t.month.upMb)} up` });
  }
  $("#tiles").innerHTML = tiles.map(x => `
    <div class="tile" style="--g:${x.g}">
      <div class="label"><span>${x.label}</span><span class="emoji">${x.emoji}</span></div>
      <div class="value">${esc(x.value)}</div>
      <div class="sub">${esc(x.sub)}</div>
    </div>`).join("");
}

function renderWan(s) {
  const w = s.wan, l = s.lan;
  const rows = [
    ["Public IP", w.externalIp], ["Connection", w.connectionType], ["Gateway", w.gateway],
    ["DNS", w.dns?.replace(/[;,]\s*/g, ", ")], ["Router LAN IP", l.ip], ["Subnet", l.subnet],
    ["DHCP", l.dhcp == null ? null : l.dhcp ? "On" : "Off"],
    ["Access control", s.accessControlOn == null ? null : s.accessControlOn ? "On" : "Off"],
    ["Serial", s.router.serial], ["In service since", s.router.firstUse],
  ].filter(r => r[1]);
  $("#wanPanel").innerHTML = `
    <h3>🏡 Internet & network <span class="muted small">· home turf</span></h3>
    <dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd class="${/IP|Gateway|DNS|Subnet/.test(k) ? "mono" : ""}">${esc(v)}</dd>`).join("")}</dl>`;
}

function renderWifi(s) {
  $("#wifiPanels").innerHTML = s.wifi.map(w => {
    const b = band(w.band);
    const on = w.enabled !== false;
    return `
    <div class="glass panel wifi" style="--g:${b.g}">
      <div class="stripe"></div>
      <h3><span class="band-tag">${b.label}</span> ${on ? "" : `<span class="badge blk">off</span>`}</h3>
      <div class="ssid">${esc(w.ssid || "(hidden)")}</div>
      <dl class="kv">
        ${w.channel ? `<dt>Channel</dt><dd>${esc(w.channel)}</dd>` : ""}
        ${w.mode ? `<dt>Mode</dt><dd>${esc(w.mode)}</dd>` : ""}
        ${w.security ? `<dt>Security</dt><dd>${esc(w.security)}</dd>` : ""}
        <dt>Clients</dt><dd>${s.devices.filter(d => d.band === w.band).length}</dd>
      </dl>
      <div class="pw">
        <span class="mono" id="pw-${w.band.replace(".", "")}">••••••••••</span>
        <span>
          <button class="btn sm" data-reveal="${w.band}">😼 Peek</button>
        </span>
      </div>
      ${w.guestEnabled == null ? "" : `
      <div class="guest">
        <span>🛋️ Guest network <span class="muted small">· for visiting cats</span></span>
        <label class="switch"><input type="checkbox" data-guest="${w.band}" ${w.guestEnabled ? "checked" : ""}><span></span></label>
      </div>`}
    </div>`;
  }).join("");
}

// ───────────────────────── devices ─────────────────────────
// The router can take a refresh or two to report a block/allow we just made, so show the new state right away.
function accessOf(d) {
  const p = ui.pendingAccess[d.mac];
  if (!p) return d.access;
  if ((d.access || "").toLowerCase() === p.access.toLowerCase() || Date.now() > p.until) {
    delete ui.pendingAccess[d.mac];
    return d.access;
  }
  return p.access;
}
const isBlocked = d => (accessOf(d) || "").toLowerCase() === "block";

function deviceIcon(d) {
  const n = `${d.nickname || ""} ${d.name || ""} ${d.model || ""}`.toLowerCase();
  const rules = [
    [/xbox|playstation|ps[45]|nintendo|steamdeck|steam-deck/, "🎮"],
    [/roku|tv\b|chromecast|fire.?tv|firestick|shield|appletv|apple-tv|vizio|bravia/, "📺"],
    [/lifx|hue|bulb|light|wiz|lamp/, "💡"],
    [/ecobee|thermostat|nest(?!.?mini)|honeywell/, "🌡️"],
    [/blink|ring|cam|arlo|wyze|eufy|doorbell/, "📷"],
    [/\bhs1\d\d|kasa|plug|outlet|wemo|smartthings|tapo/, "🔌"],
    [/echo|alexa|google.?home|nest.?mini|homepod|sonos|speaker/, "🔊"],
    [/printer|epson|canon|brother|officejet|laserjet/, "🖨️"],
    [/watch/, "⌚"],
    [/ipad|tablet|tab\b|galaxy-tab|kindle/, "📖"],
    [/pixel|galaxy|iphone|phone|android|oneplus|moto|sm-/, "📱"],
    [/laptop|macbook|book|thinkpad|surface/, "💻"],
    [/desktop|pc\b|-pc|windows|tower|imac|mac-mini/, "🖥️"],
    [/nas|synology|qnap|server|plex|pi\b|raspberry/, "🗄️"],
  ];
  for (const [rx, e] of rules) if (rx.test(n)) return e;
  if (d.privateMac) return "📱"; // randomized MACs are almost always phones/tablets
  return "🐱";
}

function signalBars(sig) {
  if (sig == null) return "";
  const n = sig >= 75 ? 4 : sig >= 50 ? 3 : sig >= 25 ? 2 : 1;
  return `<span class="signal" title="Signal ${sig}%">${[1, 2, 3, 4].map(i => `<i class="${i <= n ? "on" : ""}"></i>`).join("")}</span>`;
}

function filtered() {
  const q = ui.query.trim().toLowerCase();
  let list = ui.snap.devices.filter(d => {
    if (ui.filter === "blocked") return isBlocked(d);
    if (ui.filter === "new") return d.isNew;
    if (ui.filter !== "all" && d.band !== ui.filter) return false;
    return true;
  });
  if (q) list = list.filter(d => [labelFor(d), d.name, d.ip, d.mac, d.ssid, d.model].some(v => (v || "").toLowerCase().includes(q)));
  const name = d => (d.name || labelFor(d) || "~").toLowerCase();
  const ip = d => (d.ip || "999").split(".").map(x => x.padStart(3, "0")).join(".");
  const sorters = {
    ip: (a, b) => ip(a).localeCompare(ip(b)),
    name: (a, b) => name(a).localeCompare(name(b)),
    signal: (a, b) => (b.signal ?? -1) - (a.signal ?? -1),
    band: (a, b) => a.band.localeCompare(b.band) || ip(a).localeCompare(ip(b)),
  };
  return list.sort(sorters[ui.sort] || sorters.ip);
}

function renderDevices() {
  const all = ui.snap.devices;
  $("#devCount").textContent = all.length;

  const counts = { all: all.length, "5": 0, "2.4": 0, wired: 0, blocked: 0, new: 0 };
  for (const d of all) { counts[d.band] = (counts[d.band] || 0) + 1; if (isBlocked(d)) counts.blocked++; if (d.isNew) counts.new++; }
  const chips = [
    ["all", "All", "var(--gbrand)"], ["2.4", "🧶 2.4 GHz", "var(--g24)"], ["5", "⚡ 5 GHz", "var(--g5)"],
    ["wired", "🐭 Wired", "var(--gwired)"], ["blocked", "⛔ Blocked", "linear-gradient(135deg,#fb7185,#e11d48)"],
    ["new", "🐈 New", "linear-gradient(135deg,#f472b6,#a855f7)"],
  ].filter(([k]) => k === "all" || counts[k] > 0 || ui.filter === k);
  $("#chips").innerHTML = chips.map(([k, label, g]) =>
    `<button class="chip ${ui.filter === k ? "on" : ""}" style="--g:${g}" data-filter="${k}">${label}<span class="n">${counts[k] || 0}</span></button>`).join("");

  const fresh = all.filter(d => d.isNew);
  const nb = $("#newBar");
  nb.hidden = fresh.length === 0;
  nb.innerHTML = fresh.length ? `<span>🐈 <b>${fresh.length} new device${fresh.length > 1 ? "s" : ""}</b> wandered in since you last looked. Make sure you recognize ${fresh.length > 1 ? "them" : "it"}.</span>
    <button class="btn sm" id="ackAll">😺 I know ${fresh.length > 1 ? "them" : "it"}</button>` : "";

  const list = filtered();
  $("#devList").innerHTML = list.length ? list.map(deviceCard).join("") : `<div class="empty">🙀 No devices match. Not a whisker in sight.</div>`;
}

function deviceCard(d, i) {
  const b = band(d.band);
  const blocked = isBlocked(d);
  const title = d.name || "Unknown device";
  const label = labelFor(d);
  const badges = [
    `<span class="badge band">${b.label}</span>`,
    d.isNew ? `<span class="badge new">NEW KITTEN</span>` : "",
    blocked ? `<span class="badge blk">⛔ blocked</span>` : "",
    isThisPc(d) ? `<span class="badge ok" title="The computer PurrRouter is running on">💻 this PC</span>` : "",
    d.privateMac ? `<span class="badge" title="This device uses a randomized (private) MAC address">🎭 private MAC</span>` : "",
    reservationFor(d.mac) ? `<span class="badge" title="Reserved address: ${esc(reservationFor(d.mac).ip)}">🧺 reserved</span>` : "",
    d.ssid ? `<span class="badge">${esc(d.ssid)}</span>` : "",
  ].join("");
  const busy = ui.busy.has(d.mac);
  const canBlock = d.access != null;

  return `
  <article class="dev ${blocked ? "blocked" : ""}" style="--g:${b.g}; animation-delay:${Math.min(i * 25, 400)}ms" data-mac="${esc(d.mac)}">
    <i class="ears" aria-hidden="true"></i>
    <div class="dev-top">
      <div class="icon">${deviceIcon(d)}</div>
      <div class="dev-name">
        <div class="n"><span title="${esc(label ? `${title} — ${label}` : title)}">${esc(title)}</span><button class="edit" data-edit="${esc(d.mac)}" title="${label ? "Edit label" : "Add a label"}">🏷️</button></div>
        <div class="orig ${label ? "label" : ""}">${esc(label || d.model || "")}</div>
      </div>
    </div>
    <div>
      <div class="ip">${esc(d.ip || "—")}</div>
      <div class="mac"><span>${esc(d.mac)}</span><button class="copy" data-copy="${esc(d.mac)}" title="Copy MAC">📋</button></div>
    </div>
    <div class="badges">${badges}</div>
    <div class="dev-foot">
      <span class="sig-wrap">${signalBars(d.signal)}<span class="sig-text" title="Signal: how strongly the router hears this device. Link: the top speed the connection could carry right now, not actual usage.">${[
        d.signal != null ? `${d.signal}% signal` : "",
        d.linkRate ? `link ${esc(d.linkRate)} Mbps` : "",
      ].filter(Boolean).join(" · ")}</span></span>
      ${canBlock ? `<button class="btn sm ${blocked ? "" : "ghost"}" data-access="${esc(d.mac)}" data-allow="${blocked}" ${busy ? "disabled" : ""}>
        ${busy ? `<span class="spin">🧶</span>` : blocked ? "✅ Allow" : "⛔ Block"}</button>` : ""}
    </div>
  </article>`;
}

// ───────────────────────── interactions ─────────────────────────
document.addEventListener("click", async e => {
  const t = e.target.closest("button, [data-filter]");
  if (!t) return;

  if (t.dataset.filter) { ui.filter = t.dataset.filter; localStorage.setItem("rd.filter", ui.filter); renderDevices(); }
  else if (t.dataset.view) setView(t.dataset.view);
  else if (t.dataset.copy) { await navigator.clipboard.writeText(t.dataset.copy); toast(`📋 Pawed ${t.dataset.copy} onto your clipboard 😺`, "ok"); }
  else if (t.dataset.edit) editNickname(t.dataset.edit);
  else if (t.dataset.access) toggleAccess(t.dataset.access, t.dataset.allow === "true");
  else if (t.dataset.reveal) revealPassword(t, t.dataset.reveal);
  else if (t.id === "ackAll") acknowledgeAll();
  else if (t.id === "refreshBtn") load(true);
  else if (t.id === "settingsBtn") openSettings();
  else if (t.id === "rebootBtn") reboot();
  else if (t.dataset.tab) setTab(t.dataset.tab);
  else if (t.id === "pfReload") loadPf();
  else if (t.id === "pfAdd") pfEdit(null);
  else if (t.dataset.pfEdit) pfEdit(+t.dataset.pfEdit);
  else if (t.dataset.pfDel) pfDelete(+t.dataset.pfDel);
  else if (t.id === "rsvReload") loadDhcp();
  else if (t.id === "wlReload") loadWifi();
  else if (t.id === "stReload") loadLogsStatus();
  else if (t.dataset.logFilter) { ui.logFilter = t.dataset.logFilter; renderLogs(); }
  else if (t.dataset.wlPeek) peekWifiPw(t);
  else if (t.id === "rsvAdd") rsvEdit(null);
  else if (t.dataset.rsvEdit) rsvEdit(+t.dataset.rsvEdit);
  else if (t.dataset.rsvDel) rsvDelete(+t.dataset.rsvDel);
});

document.addEventListener("change", async e => {
  const t = e.target;
  if (t.dataset.guest) {
    const want = t.checked;
    const ok = await confirmBox(`${want ? "Turn on" : "Turn off"} ${band(t.dataset.guest).label} guest network?`,
      want ? "Uses whatever guest SSID and password are set on the router." : "Anyone on the guest network will be disconnected.", want ? "Turn on" : "Turn off");
    if (!ok) { t.checked = !want; return; }
    t.disabled = true;
    try { await api(`/wifi/${t.dataset.guest}/guest`, { method: "POST", body: { enabled: want } }); toast(`Guest network ${want ? "on: visitors welcome 🛋️" : "off: visitors shooed 🐈"}`, "ok"); load(true); }
    catch (ex) { t.checked = !want; toast(ex.message, "bad"); }
    finally { t.disabled = false; }
  }
});

$("#search").addEventListener("input", e => { ui.query = e.target.value; renderDevices(); });
$("#sort").addEventListener("change", e => { ui.sort = e.target.value; localStorage.setItem("rd.sort", ui.sort); renderDevices(); });

function setView(v) {
  ui.view = v;
  localStorage.setItem("rd.view", v);
  $("#devList").classList.toggle("list", v === "list");
  for (const b of document.querySelectorAll("#viewSeg button")) b.classList.toggle("on", b.dataset.view === v);
}

async function toggleAccess(mac, allow) {
  const d = ui.snap.devices.find(x => x.mac === mac);
  const name = labelFor(d) || d?.name || mac;
  if (!allow && !(await confirmBox(`Block ${name}?`, "It'll be shooed off your network until you allow it again.", "⛔ Block", true))) return;
  ui.busy.add(mac); renderDevices();
  try {
    await api(`/devices/${encodeURIComponent(mac)}/access`, { method: "POST", body: { allow } });
    toast(`${name} ${allow ? "let back in 😺" : "shooed off the network ⛔"}`, "ok");
    ui.busy.delete(mac);
    ui.pendingAccess[mac] = { access: allow ? "Allow" : "Block", until: Date.now() + 120000 };
    renderDevices();
    renderTiles(ui.snap);
    load(true);
  } catch (ex) { toast(ex.message, "bad"); ui.busy.delete(mac); renderDevices(); }
}

async function editNickname(mac) {
  const d = ui.snap.devices.find(x => x.mac === mac);
  const name = await promptBox("🏷️ Give this device a name tag", `${d?.name || "Unknown device"} · ${mac}`, labelFor(d) || "");
  if (name === null) return;
  await api(`/devices/${encodeURIComponent(mac)}/nickname`, { method: "POST", body: { name } });
  // An auto-refresh may have swapped ui.snap while the dialog was open, so keep the label in an overlay too.
  ui.labels[mac] = name.trim() || null;
  renderDevices();
  toast(name.trim() ? `Name tag on: “${name.trim()}” 🏷️` : "Name tag removed", "ok");
}

function labelFor(d) {
  if (!d) return null;
  return Object.hasOwn(ui.labels, d.mac) ? ui.labels[d.mac] : d.nickname;
}

async function acknowledgeAll() {
  const macs = ui.snap.devices.filter(d => d.isNew).map(d => d.mac);
  await api("/devices/acknowledge", { method: "POST", body: { macs } });
  for (const d of ui.snap.devices) d.isNew = false;
  if (ui.filter === "new") ui.filter = "all";
  render();
}

async function revealPassword(btn, b) {
  const el = $(`#pw-${b.replace(".", "")}`);
  if (btn.dataset.shown) {
    el.textContent = "••••••••••"; btn.textContent = "😼 Peek"; delete btn.dataset.shown; return;
  }
  try {
    const { password } = await api(`/wifi/${b}/password`);
    el.textContent = password || "(none)";
    btn.textContent = "🙈 Hide"; btn.dataset.shown = "1";
    if (password) {
      const c = document.createElement("button");
      c.className = "copy"; c.textContent = " 📋"; c.title = "Copy password";
      c.onclick = ev => { ev.stopPropagation(); navigator.clipboard.writeText(password); toast("📋 Wi-Fi password pawed onto your clipboard 😺", "ok"); };
      el.append(c);
    }
  } catch (ex) { toast(ex.message, "bad"); }
}

async function reboot() {
  if (!(await confirmBox("Reboot the router?", "Cat nap time: everything drops offline for a minute or two while it restarts.", "😴 Reboot", true))) return;
  try { await api("/reboot", { method: "POST" }); toast("Router is cat-napping… I'll keep checking back. 😴", "ok"); }
  catch (ex) { toast(ex.message, "bad"); }
}

async function openSettings() {
  const st = await api("/status");
  const choice = await modal(`
    <h3>😺 Settings</h3>
    <p>Connected to <b class="mono">${esc(st.host)}:${esc(st.port)}</b> as <b>${esc(st.username)}</b>${st.useHttps ? " over HTTPS" : ""}.</p>
    <div class="actions">
      <button class="btn ghost" value="cancel">Close</button>
      <button class="btn danger" value="forget">Sign out & forget password</button>
    </div>`);
  if (choice === "forget") { await api("/forget", { method: "POST" }); showSetup(st); }
}

// ───────────────────────── tabs ─────────────────────────
function setTab(tab) {
  ui.tab = tab;
  localStorage.setItem("rd.tab", tab);
  for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("on", b.dataset.tab === tab);
  for (const p of document.querySelectorAll(".tabpane")) p.hidden = p.dataset.pane !== tab;
  if (tab === "ports" && !ui.pf) loadPf();
  if (tab === "dhcp" && !ui.dhcp) loadDhcp();
  if (tab === "wifi" && !ui.wl) loadWifi();
  if (tab === "logs" && !ui.logs) loadLogsStatus();
}

// ───────────────────────── port forwarding ─────────────────────────
const PROTOS = { BOTH: "TCP + UDP", TCP: "TCP", UDP: "UDP" };
const prettyPorts = r => (r || "").split(",").map(x => { const [a, b] = x.split("-"); return a === b || !b ? a : `${a}–${b}`; }).join(", ");
const deviceByIp = ip => ui.snap?.devices.find(d => d.ip === ip);

async function loadPf() {
  $("#pfList").innerHTML = `<div class="empty"><span class="spin">🧶</span> Pawing at the router…</div>`;
  try { ui.pf = await api("/portforwards"); renderPf(); fillProtocols(); }
  catch (ex) { $("#pfList").innerHTML = `<div class="empty">🙀 ${esc(ex.message)}</div>`; }
}

// The list page doesn't show protocols, and reading one rule's details takes the router ~6 s (todo=edit).
// The server remembers protocols it has read, so this only fetches the missing ones: one at a time, never two
// loops at once, and paused while a dialog is open so an Edit/Save never waits behind a queue of reads.
const pfSame = (a, b) => a.name === b.name && a.ip === b.ip && a.externalPorts === b.externalPorts && a.internalPorts === b.internalPorts;
let pfFilling = null;
function fillProtocols() {
  pfFilling ??= (async () => {
    const failed = new Set();
    try {
      for (;;) {
        if ($("#modal").open) return; // resumed by the dialog's close handler below
        const r = (ui.pf || []).find(x => !x.protocol && !failed.has(x));
        if (!r) return;
        try {
          const d = await api(`/portforwards/${r.number}`);
          if (pfSame(d, r) && d.protocol) r.protocol = d.protocol; else failed.add(r);
        } catch { failed.add(r); }
        if (ui.tab === "ports") renderPf();
      }
    } finally { pfFilling = null; }
  })();
}
$("#modal").addEventListener("close", () => { if (ui.pf) fillProtocols(); });

function renderPf() {
  const list = ui.pf || [];
  $("#pfCount").textContent = list.length;
  $("#pfList").innerHTML = list.length ? list.map((r, i) => {
    const d = deviceByIp(r.ip);
    const g = d ? band(d.band).g : "var(--gunk)";
    const who = d ? `${deviceIcon(d)} ${esc(d.name || "Unknown device")}${labelFor(d) ? ` <span class="pf-label">${esc(labelFor(d))}</span>` : ""}` : "👻 No device online with this IP";
    const sameIn = r.externalPorts === r.internalPorts;
    return `
    <article class="pf" style="--g:${g}; animation-delay:${i * 40}ms">
      <div class="pf-name"><span class="pf-num">#${r.number}</span> ${esc(r.name)} ${r.protocol ? `<span class="badge">${PROTOS[r.protocol] || r.protocol}</span>` : ""}</div>
      <div class="pf-flow">
        <span class="pf-port" title="Port on your public IP">🌍 ${esc(prettyPorts(r.externalPorts))}</span>
        <span class="pf-arrow" title="forwarded to"><i class="paw"></i>➜</span>
        <span class="pf-port in" title="Port on the device">${esc(prettyPorts(r.internalPorts))}${sameIn ? "" : " (internal)"}</span>
      </div>
      <div class="pf-dev"><span>${who}</span><span class="mono muted">${esc(r.ip)}</span></div>
      <div class="pf-actions">
        <button class="btn sm ghost" data-pf-edit="${r.number}">✏️ Edit</button>
        <button class="btn sm ghost" data-pf-del="${r.number}">🗑 Delete</button>
      </div>
    </article>`;
  }).join("") : `<div class="empty">No port forwarding rules. Every cat flap is shut tight. 🐈‍⬛🔒</div>`;
}

let pfEditTicket = 0;
async function pfEdit(number) {
  // Open instantly from the list row; only the protocol may still need the router's slow (~6 s) editor read.
  let rule = { name: "", protocol: "BOTH", externalPorts: "", internalPorts: "", ip: "" };
  const row = number == null ? null : ui.pf?.find(x => x.number === number);
  if (number != null) {
    if (!row) return toast("That rule isn't in the list anymore. Hit Reload and try again.", "bad");
    rule = { ...row };
  }
  const ticket = ++pfEditTicket;
  const needProto = number != null && !rule.protocol;
  const same = !rule.internalPorts || rule.internalPorts === rule.externalPorts;
  const devices = [...(ui.snap?.devices || [])].filter(d => d.ip)
    .sort((a, b) => (labelFor(a) || a.name || "~").localeCompare(labelFor(b) || b.name || "~"));
  const known = devices.some(d => d.ip === rule.ip);
  const dlg = $("#modal"), form = $("#modalForm");
  form.innerHTML = `
    <h3>${number == null ? `<i class="paw"></i> New port forwarding rule` : `✏️ Edit rule #${number}`}</h3>
    <label>Name <input id="pfName" maxlength="30" value="${esc(rule.name)}" placeholder="e.g. Minecraft server" required></label>
    <div class="row">
      <label>Protocol
        <select id="pfProto" ${needProto ? "disabled" : ""}>${needProto ? `<option value="">🧶 Reading from router…</option>` : protoOptions(rule.protocol)}</select>
      </label>
      <label>External port(s) <input id="pfExt" class="mono" value="${esc(prettyPorts(rule.externalPorts).replace(/–/g, "-"))}" placeholder="8080 or 5000-5010"></label>
    </div>
    <label class="check"><input type="checkbox" id="pfSame" ${same ? "checked" : ""}> Same port(s) on the device</label>
    <label id="pfInWrap" ${same ? "hidden" : ""}>Internal port(s) <input id="pfIn" class="mono" value="${same ? "" : esc(prettyPorts(rule.internalPorts).replace(/–/g, "-"))}" placeholder="80"></label>
    <label>Send to device
      <select id="pfDev">
        <option value="">— pick a device —</option>
        ${devices.map(d => `<option value="${esc(d.ip)}" ${d.ip === rule.ip ? "selected" : ""}>${deviceIcon(d)} ${esc(d.name || "Unknown")}${labelFor(d) ? ` (${esc(labelFor(d))})` : ""} · ${esc(d.ip)}</option>`).join("")}
        <option value="other" ${rule.ip && !known ? "selected" : ""}>✍️ Other IP address…</option>
      </select>
    </label>
    <label id="pfIpWrap" ${rule.ip && !known ? "" : "hidden"}>IP address <input id="pfIp" class="mono" value="${esc(known ? "" : rule.ip)}" placeholder="192.168.1.50"></label>
    <p id="pfErr" class="error" hidden></p>
    <div class="actions">
      <button type="button" class="btn ghost" id="pfCancel">Cancel</button>
      <button type="submit" class="btn primary" id="pfSave" ${needProto ? "disabled" : ""}>${number == null ? "Add rule" : "Save changes"}</button>
    </div>`;
  dlg.showModal();
  $("#pfName").focus();
  if (needProto) pfLoadProtocol(number, row, ticket);
  $("#pfSame").onchange = e => { $("#pfInWrap").hidden = e.target.checked; };
  $("#pfDev").onchange = e => { $("#pfIpWrap").hidden = e.target.value !== "other"; };
  $("#pfCancel").onclick = () => dlg.close("cancel");

  form.onsubmit = async ev => {
    ev.preventDefault();
    const err = $("#pfErr"), btn = $("#pfSave");
    err.hidden = true;
    const dev = $("#pfDev").value;
    const body = {
      name: $("#pfName").value, protocol: $("#pfProto").value,
      externalPorts: $("#pfExt").value,
      internalPorts: $("#pfSame").checked ? "" : $("#pfIn").value,
      ip: dev === "other" ? $("#pfIp").value : dev,
    };
    btn.disabled = true; btn.innerHTML = `<span class="spin">🧶</span> Saving…`;
    try {
      ui.pf = await api(number == null ? "/portforwards" : `/portforwards/${number}`, { method: number == null ? "POST" : "PUT", body });
      dlg.close("saved");
      renderPf();
      fillProtocols();
      toast(number == null ? `Cat flap “${body.name.trim()}” installed 🚪🐈` : `Rule “${body.name.trim()}” saved 😺`, "ok");
    } catch (ex) {
      err.textContent = ex.message; err.hidden = false;
      btn.disabled = false; btn.textContent = number == null ? "Add rule" : "Save changes";
    }
  };
  dlg.addEventListener("close", () => { form.onsubmit = null; }, { once: true });
}

const protoOptions = sel => Object.entries(PROTOS).map(([k, v]) => `<option value="${k}" ${sel === k ? "selected" : ""}>${v}</option>`).join("");

// Fills in the edit dialog's protocol once the router answers (if the same dialog is still open).
async function pfLoadProtocol(number, row, ticket) {
  const stillOpen = () => ticket === pfEditTicket && $("#modal").open;
  const fail = msg => { if (stillOpen()) { $("#pfErr").textContent = msg; $("#pfErr").hidden = false; $("#pfProto").innerHTML = `<option value="">—</option>`; } };
  let d;
  try { d = await api(`/portforwards/${number}`); }
  catch (ex) { return fail(ex.message); }
  if (!pfSame(d, row)) return fail("This rule changed on the router since the list loaded. Close this and hit Reload.");
  if (!d.protocol) return fail("Couldn't read this rule's protocol from the router.");
  row.protocol = d.protocol;
  if (ui.tab === "ports") renderPf();
  if (!stillOpen()) return;
  const sel = $("#pfProto");
  sel.innerHTML = protoOptions(d.protocol);
  sel.disabled = false;
  $("#pfSave").disabled = false;
}

async function pfDelete(number) {
  const r = ui.pf?.find(x => x.number === number);
  if (!r) return;
  if (!(await confirmBox(`Delete “${r.name}”?`, `Ports ${prettyPorts(r.externalPorts)} will stop reaching ${r.ip}.`, "🗑 Delete", true))) return;
  try {
    ui.pf = await api(`/portforwards/${number}`, { method: "DELETE" });
    renderPf();
    fillProtocols();
    toast(`Rule “${r.name}” deleted: flap sealed 🔒`, "ok");
  } catch (ex) { toast(ex.message, "bad"); }
}

// ───────────────────────── DHCP reservations ─────────────────────────
const macKey = m => (m || "").toUpperCase().replace(/[^0-9A-F]/g, "");
const deviceByMac = mac => ui.snap?.devices.find(d => macKey(d.mac) === macKey(mac));
const reservationFor = mac => ui.dhcp?.reservations.find(r => macKey(r.mac) === macKey(mac));
const ipSort = ip => (ip || "999").split(".").map(x => x.padStart(3, "0")).join(".");

async function loadDhcp() {
  $("#rsvList").innerHTML = `<div class="empty"><span class="spin">🧶</span> Counting the cat baskets…</div>`;
  try { ui.dhcp = await api("/dhcp"); renderDhcp(); if (ui.snap) renderDevices(); }
  catch (ex) { $("#rsvList").innerHTML = `<div class="empty">🙀 ${esc(ex.message)}</div>`; }
}

function renderDhcp() {
  const d = ui.dhcp;
  if (!d) return;
  const list = d.reservations;
  $("#rsvCount").textContent = list.length;
  $("#rsvInfo").innerHTML = [
    `<span class="pill ${d.enabled === false ? "down" : ""}">${d.enabled === false ? "🙀 DHCP server off" : "😺 DHCP server on"}</span>`,
    d.poolStart && d.poolEnd ? `<span class="rsv-pool">Automatic addresses: <b class="mono">${esc(d.poolStart)}</b> – <b class="mono">${esc(d.poolEnd)}</b></span>` : "",
    d.enabled === false ? `<span class="muted small">With the router's DHCP server off, reservations have no effect.</span>` : "",
  ].join("");
  $("#rsvList").innerHTML = list.length ? [...list].sort((a, b) => ipSort(a.ip).localeCompare(ipSort(b.ip))).map((r, i) => {
    const dev = deviceByMac(r.mac);
    const g = dev ? band(dev.band).g : "var(--gunk)";
    const who = dev
      ? `${deviceIcon(dev)} ${esc(labelFor(dev) || dev.name || "Unknown device")}`
      : `💤 Not online right now`;
    const where = !dev ? "" : dev.ip === r.ip
      ? `<span class="badge ok">😺 using it</span>`
      : `<span class="badge warn" title="The device is online but hasn't picked up its reserved address yet">online at ${esc(dev.ip || "?")}</span>`;
    return `
    <article class="pf rsv" style="--g:${g}; animation-delay:${i * 30}ms">
      <div class="pf-name"><span class="pf-num">#${r.number}</span> ${esc(r.name)}</div>
      <div class="pf-flow"><span class="pf-port" title="Reserved address">🧺 ${esc(r.ip)}</span></div>
      <div class="pf-dev"><span>${who} ${where}</span><span class="mono muted">${esc(r.mac)} <button class="copy" data-copy="${esc(r.mac)}" title="Copy MAC">📋</button></span></div>
      <div class="pf-actions">
        <button class="btn sm ghost" data-rsv-edit="${r.number}">✏️ Edit</button>
        <button class="btn sm ghost" data-rsv-del="${r.number}">🗑 Delete</button>
      </div>
    </article>`;
  }).join("") : `<div class="empty">No reservations yet. Every cat is sleeping wherever it lands. 🐈💤</div>`;
}

// Router names: printable ASCII, max 20, no quotes/backslashes (they'd break the router's own page).
const routerName = s => (s || "").replace(/[^\x20-\x7E]|["\\]/g, "").trim().slice(0, 20);

function rsvEdit(number) {
  const row = number == null ? null : ui.dhcp?.reservations.find(r => r.number === number);
  if (number != null && !row) return toast("That reservation isn't in the list anymore. Hit Reload and try again.", "bad");
  const rule = row ? { ...row } : { name: "", mac: "", ip: "" };
  const devices = [...(ui.snap?.devices || [])].filter(d => d.mac)
    .sort((a, b) => (labelFor(a) || a.name || "~").localeCompare(labelFor(b) || b.name || "~"));
  const picked = row ? devices.find(d => macKey(d.mac) === macKey(row.mac)) : null;
  const dlg = $("#modal"), form = $("#modalForm");
  form.innerHTML = `
    <h3>${row ? `✏️ Edit reservation #${row.number}` : "🧺 Reserve an address"}</h3>
    <label>Device
      <select id="rsvDev">
        <option value="">— pick a device —</option>
        ${devices.map(d => {
          const taken = reservationFor(d.mac);
          const self = row && macKey(d.mac) === macKey(row.mac);
          return `<option value="${esc(d.mac)}" ${picked === d ? "selected" : ""} ${taken && !self ? "disabled" : ""}>${deviceIcon(d)} ${esc(labelFor(d) || d.name || "Unknown")} · ${esc(d.ip || "no IP")}${taken && !self ? " · already reserved" : ""}</option>`;
        }).join("")}
        <option value="other" ${row && !picked ? "selected" : ""}>✍️ Enter a MAC address…</option>
      </select>
    </label>
    <label id="rsvMacWrap" ${row && !picked ? "" : "hidden"}>MAC address <input id="rsvMac" class="mono" value="${esc(rule.mac)}" placeholder="44:61:32:2A:48:F6" maxlength="17"></label>
    <div class="row">
      <label>Name on the router <input id="rsvName" maxlength="20" value="${esc(rule.name)}" placeholder="e.g. LIVING-ROOM-TV" required></label>
      <label>Reserved IP <input id="rsvIp" class="mono" value="${esc(rule.ip)}" placeholder="192.168.1.50" required></label>
    </div>
    <p class="muted small" id="rsvHint"></p>
    <p id="rsvErr" class="error" hidden></p>
    <div class="actions">
      <button type="button" class="btn ghost" id="rsvCancel">Cancel</button>
      <button type="submit" class="btn primary" id="rsvSave">${row ? "Save changes" : "Reserve it"}</button>
    </div>`;
  dlg.showModal();
  $("#rsvDev").focus();

  const hint = () => {
    const ip = $("#rsvIp").value.trim(), d = ui.dhcp;
    const owner = ui.snap?.devices.find(x => x.ip === ip && macKey(x.mac) !== macKey(currentMac()));
    $("#rsvHint").textContent = owner ? `⚠ ${labelFor(owner) || owner.name || "Another device"} is using ${ip} right now.`
      : d?.poolStart ? `Tip: the router hands out ${d.poolStart} – ${d.poolEnd} automatically.` : "";
  };
  const currentMac = () => $("#rsvDev").value === "other" ? $("#rsvMac").value : $("#rsvDev").value;
  $("#rsvDev").onchange = e => {
    const v = e.target.value;
    $("#rsvMacWrap").hidden = v !== "other";
    const d = devices.find(x => x.mac === v);
    if (d) {
      if (!row || !$("#rsvName").value) $("#rsvName").value = routerName(labelFor(d) || (d.name !== "Unknown device" ? d.name : "") || "");
      if (!row || !$("#rsvIp").value) $("#rsvIp").value = d.ip || "";
    }
    hint();
  };
  $("#rsvIp").oninput = hint;
  hint();
  $("#rsvCancel").onclick = () => dlg.close("cancel");

  form.onsubmit = async ev => {
    ev.preventDefault();
    const err = $("#rsvErr"), btn = $("#rsvSave");
    err.hidden = true;
    const body = { name: $("#rsvName").value, mac: currentMac(), ip: $("#rsvIp").value, originalMac: row?.mac };
    if (!body.mac) { err.textContent = "Pick a device or enter its MAC address."; err.hidden = false; return; }
    btn.disabled = true; btn.innerHTML = `<span class="spin">🧶</span> Saving…`;
    try {
      ui.dhcp = await api(row ? `/dhcp/reservations/${row.number}` : "/dhcp/reservations", { method: row ? "PUT" : "POST", body });
      dlg.close("saved");
      renderDhcp(); renderDevices();
      toast(row ? `Reservation “${body.name.trim()}” saved 😺` : `${body.ip.trim()} is now ${body.name.trim()}'s basket 🧺`, "ok");
    } catch (ex) {
      err.textContent = ex.message; err.hidden = false;
      btn.disabled = false; btn.textContent = row ? "Save changes" : "Reserve it";
    }
  };
  dlg.addEventListener("close", () => { form.onsubmit = null; }, { once: true });
}

async function rsvDelete(number) {
  const r = ui.dhcp?.reservations.find(x => x.number === number);
  if (!r) return;
  if (!(await confirmBox(`Remove ${r.name}'s reservation?`, `${r.ip} will no longer be held for ${r.mac}.`, "🗑 Remove", true))) return;
  try {
    ui.dhcp = await api(`/dhcp/reservations/${number}?mac=${encodeURIComponent(r.mac)}`, { method: "DELETE" });
    renderDhcp(); renderDevices();
    toast(`Reservation for ${r.name} removed: basket's up for grabs 🧺`, "ok");
  } catch (ex) { toast(ex.message, "bad"); }
}

// ───────────────────────── Wi-Fi settings ─────────────────────────
const isThisPc = d => !!d?.ip && ui.localIps.includes(d.ip);
const thisPc = () => ui.snap?.devices.find(isThisPc);
const bandKey = bn => bn === "2.4" ? "b24" : "b5";
// Measured on the R6350 (Windows WLAN log): any Wi-Fi Apply drops BOTH bands; this PC was back after ~20 s.
const WIFI_RESTART_MS = 90_000;

async function loadWifi() {
  $("#wlForm").innerHTML = `<div class="empty"><span class="spin">🧶</span> Sniffing the airwaves…</div>`;
  try { ui.wl = await api("/wifi/settings"); renderWifiSettings(); }
  catch (ex) { $("#wlForm").innerHTML = `<div class="empty">🙀 ${esc(ex.message)}</div>`; }
}

function renderWifiSettings() {
  const s = ui.wl;
  if (!s) return;
  const pc = thisPc();
  $("#wlForm").innerHTML = s.bands.map(b => {
    const k = b.band.replace(".", "");
    const bb = band(b.band);
    const clients = ui.snap ? ui.snap.devices.filter(d => d.band === b.band).length : null;
    return `
    <div class="glass panel wifi wl-card" id="wlCard${k}" style="--g:${bb.g}">
      <div class="stripe"></div>
      <h3><span class="band-tag">${bb.label}</span> ${b.radioOn ? "" : `<span class="badge blk">radio off</span>`}
        <span class="badge wl-pc" title="The computer PurrRouter is running on" ${pc?.band === b.band ? "" : "hidden"}>💻 this PC</span>
        <span class="badge warn wl-unsaved" hidden>✏️ unsaved</span></h3>
      <label data-wl-field="ssid">Network name (SSID) <input id="wlSsid${k}" maxlength="32" value="${esc(b.ssid)}" required></label>
      <label data-wl-field="password">Password <span class="pw-row"><input id="wlPw${k}" type="password" maxlength="64" placeholder="•••••••• (unchanged)" autocomplete="new-password">
        <button type="button" class="btn sm" data-wl-peek="${k}">😼 Peek</button></span></label>
      <div class="row">
        <label data-wl-field="channel">Channel <select id="wlCh${k}">${(b.channelOptions.length ? b.channelOptions : [b.channel]).map(c =>
          `<option value="${c}" ${c === b.channel ? "selected" : ""}>${c === "0" ? "Auto 🎲" : c}</option>`).join("")}</select>
          <span class="wl-was small">saved: ${b.channel === "0" ? "Auto" : esc(b.channel)}</span></label>
        <label class="check wl-bc" data-wl-field="broadcast"><input type="checkbox" id="wlBc${k}" ${b.broadcast ? "checked" : ""}> Broadcast name</label>
      </div>
      <dl class="kv">
        <dt>Mode</dt><dd>${esc(b.mode)}</dd>
        <dt>Security</dt><dd>${esc(b.security)}</dd>
        <dt>Cats on it now</dt><dd class="wl-clients">${clients ?? "—"}</dd>
      </dl>
    </div>`;
  }).join("") + `
    <div class="wl-actions">
      <span class="muted small" id="wlHint">Leave the password empty to keep the current one. With broadcast off the network still works, but devices must type its name to join.</span>
      <span class="wl-buttons">
        <button type="button" class="btn ghost" id="wlDiscard" hidden>↩ Discard changes</button>
        <button type="submit" class="btn primary" id="wlSave" disabled><i class="paw"></i> Save Wi-Fi settings</button>
      </span>
    </div>`;
  const form = $("#wlForm");
  form.onsubmit = saveWifi;
  form.oninput = form.onchange = markWifiDirty;
  $("#wlDiscard").onclick = () => { renderWifiSettings(); toast("Changes discarded. Back to what the router has. 😺", "ok"); };
  markWifiDirty();
}

// Device counts + "this PC" badge come from the snapshot, which may arrive after (or refresh under) the form:
// update just those, never re-render, so unsaved edits survive.
function updateWifiLive() {
  const pc = thisPc();
  for (const b of ui.wl?.bands || []) {
    const card = $(`#wlCard${b.band.replace(".", "")}`);
    if (!card || !ui.snap) continue;
    card.querySelector(".wl-clients").textContent = ui.snap.devices.filter(d => d.band === b.band).length;
    card.querySelector(".wl-pc").hidden = pc?.band !== b.band;
  }
}

// What's different from what the router reported, per band: { b24: {channel: "6"}, ... }.
function wifiChanges() {
  const body = {}, changed = [];
  for (const b of ui.wl?.bands || []) {
    const k = b.band.replace(".", ""), c = {};
    const ssidEl = $(`#wlSsid${k}`), pwEl = $(`#wlPw${k}`), chEl = $(`#wlCh${k}`), bcEl = $(`#wlBc${k}`);
    if (!ssidEl) continue;
    if (ssidEl.value !== b.ssid) c.ssid = ssidEl.value;
    if (pwEl.value && pwEl.value !== pwEl.dataset.current) c.password = pwEl.value;
    if (chEl.value !== b.channel) c.channel = chEl.value;
    if (bcEl.checked !== b.broadcast) c.broadcast = bcEl.checked;
    if (Object.keys(c).length) { body[bandKey(b.band)] = c; changed.push(b.band); }
  }
  return { body, changed };
}

// Make unsaved edits impossible to miss: highlighted fields, "unsaved" badge per band, a dot on the tab, Save/Discard.
function markWifiDirty() {
  const { body } = wifiChanges();
  let any = false;
  for (const b of ui.wl?.bands || []) {
    const k = b.band.replace(".", ""), c = body[bandKey(b.band)] || {}, card = $(`#wlCard${k}`);
    if (!card) continue;
    for (const f of ["ssid", "password", "channel", "broadcast"])
      card.querySelector(`[data-wl-field="${f}"]`)?.classList.toggle("dirty", c[f] !== undefined);
    const dirty = Object.keys(c).length > 0;
    card.classList.toggle("dirty", dirty);
    card.querySelector(".wl-unsaved").hidden = !dirty;
    any ||= dirty;
  }
  ui.wlDirty = any;
  if ($("#wlSave")) { $("#wlSave").disabled = !any; $("#wlDiscard").hidden = !any; }
  if ($("#wlHint")) $("#wlHint").innerHTML = any
    ? `<b class="wl-dirty-note">✏️ Unsaved changes.</b> Nothing has been sent to the router yet. Save to apply them, or discard.`
    : "Leave the password empty to keep the current one. With broadcast off the network still works, but devices must type its name to join.";
  document.querySelector('#tabs button[data-tab="wifi"]')?.classList.toggle("dirty", any);
}

async function peekWifiPw(btn) {
  const k = btn.dataset.wlPeek, input = $(`#wlPw${k}`);
  if (input.type === "text") { input.type = "password"; btn.textContent = "😼 Peek"; return; }
  if (!input.value) {
    try { input.value = (await api(`/wifi/${k === "24" ? "2.4" : "5"}/password`)).password || ""; input.dataset.current = input.value; }
    catch (ex) { return toast(ex.message, "bad"); }
  }
  input.type = "text"; btn.textContent = "🙈 Hide";
  markWifiDirty();
}

async function saveWifi(ev) {
  ev.preventDefault();
  const { body, changed } = wifiChanges();
  if (!changed.length) return toast("Nothing changed. The cats are content. 😺", "ok");
  const pc = thisPc();
  const pcOnWifi = pc && pc.band !== "wired";
  const pcCreds = pcOnWifi && body[bandKey(pc.band)] && (body[bandKey(pc.band)].ssid != null || body[bandKey(pc.band)].password);
  const lines = changed.map(bn => {
    const c = body[bandKey(bn)];
    return `${band(bn).label}: ${[c.ssid != null && `name → “${c.ssid}”`, c.password && "new password", c.channel && `channel → ${c.channel === "0" ? "Auto" : c.channel}`,
      c.broadcast != null && (c.broadcast ? "broadcast the name" : "hide the name")].filter(Boolean).join(", ")}`;
  });
  const ok = await confirmBox("Save Wi-Fi settings?",
    `${lines.join(" · ")}. The router restarts BOTH Wi-Fi bands for any change, so every wireless device drops off for about 20 seconds.` +
    (pcOnWifi ? ` That includes this PC (on ${band(pc.band).label})${pcCreds ? ", which must then rejoin with the new name/password" : ""}.` : ""),
    "📶 Save", true);
  if (!ok) return;
  const btn = $("#wlSave");
  btn.disabled = true; btn.innerHTML = `<span class="spin">🧶</span> Saving… (the router takes a moment)`;
  try {
    ui.wl = await api("/wifi/settings", { method: "PUT", body });
    renderWifiSettings();
    toast("Saved! The router is restarting its Wi-Fi. Cats will be back in about 20 seconds. 😺", "ok");
    awaitWifiRestart();
  } catch (ex) {
    toast(ex.message, "bad");
    btn.disabled = false; btn.innerHTML = `<i class="paw"></i> Save Wi-Fi settings`;
  }
}

// After a Wi-Fi Apply the network is briefly gone (this PC too, if it's on Wi-Fi): say so instead of erroring,
// and refresh once the router answers again.
async function awaitWifiRestart() {
  ui.wifiRestartUntil = Date.now() + WIFI_RESTART_MS;
  const b = $("#banner");
  b.textContent = "📶 The router is restarting its Wi-Fi after your change. Waiting for it to come back…";
  b.hidden = false;
  await new Promise(r => setTimeout(r, 15000));
  while (Date.now() < ui.wifiRestartUntil) {
    try {
      ui.snap = await api("/snapshot?force=true");
      ui.wifiRestartUntil = 0;
      b.hidden = true;
      render();
      return toast("Wi-Fi is back. Every cat found its way home. 🐈", "ok");
    } catch { await new Promise(r => setTimeout(r, 5000)); }
  }
  ui.wifiRestartUntil = 0;
  b.textContent = "🙀 The router still isn't answering 90 seconds after the Wi-Fi change. Check this PC's network connection.";
}

// ───────────────────────── logs & status (read-only) ─────────────────────────
ui.logFilter = "all";
const LOG_STYLE = {
  "Access Control": ["🚪", "var(--g5)"], "LAN access from remote": ["🌍", "var(--g24)"], "admin login": ["🔑", "var(--gbrand)"],
  "Internet connected": ["😺", "var(--gwired)"], "Internet disconnected": ["🙀", "linear-gradient(135deg,#fb7185,#e11d48)"],
  DHCP: ["🧺", "var(--gwired)"], "Time synchronized with NTP server": ["⏰", "var(--gunk)"],
};
const logStyle = cat => LOG_STYLE[cat] || (cat.startsWith("DHCP") ? LOG_STYLE.DHCP : ["🐾", "var(--gunk)"]);
const logCat = cat => cat.startsWith("DHCP") ? "DHCP" : cat || "Other";
const isRoutine = e => e.category === "Access Control" && /is allowed to acces/.test(e.message);

// "86:30:46" (hours:min:sec) → "3d 14h 30m"
function fmtUp(s) {
  const m = /^(\d+):(\d+):(\d+)$/.exec(s || "");
  if (!m) return s || "—";
  const h = +m[1], d = Math.floor(h / 24);
  return [d && `${d}d`, `${h % 24}h`, `${+m[2]}m`].filter(Boolean).join(" ");
}
const fmtRate = v => v == null ? "—" : v >= 1e6 ? (v / 1e6).toFixed(1) + " M" : v >= 1e3 ? (v / 1e3).toFixed(1) + " k" : String(v);
const fmtCount = v => v == null ? "—" : v.toLocaleString();

async function loadLogsStatus() {
  $("#stPorts").innerHTML = $("#logList").innerHTML = `<div class="empty"><span class="spin">🧶</span> Reading the cat's diary…</div>`;
  const [st, logs] = await Promise.allSettled([api("/router-status"), api("/logs")]);
  if (st.status === "fulfilled") { ui.rstatus = st.value; renderStatus(); }
  else $("#stPorts").innerHTML = `<div class="empty">🙀 ${esc(st.reason.message)}</div>`;
  if (logs.status === "fulfilled") { ui.logs = logs.value; renderLogs(); }
  else $("#logList").innerHTML = `<div class="empty">🙀 ${esc(logs.reason.message)}</div>`;
}

function renderStatus() {
  const s = ui.rstatus, wan = s.ports.find(p => p.port === "WAN"), c = s.connection || {};
  const tiles = [
    { g: "var(--gbrand)", label: "Router awake for", emoji: "😼", value: fmtUp(s.systemUpTime), sub: "since its last nap (reboot)" },
    { g: "var(--g24)", label: "Internet link up for", emoji: "🌍", value: fmtUp(wan?.upTime), sub: wan ? `WAN ${wan.status}` : "" },
    c["Lease Expires"] && { g: "var(--g5)", label: "IP lease renews in", emoji: "⏳", value: c["Lease Expires"].replace(/(\d+) days?,\s*/, (_, d) => +d ? `${d}d ` : "").replace(/ hrs?,\s*/, "h ").replace(/ minutes?/, "m"), sub: c["IP Address"] ? `public IP ${c["IP Address"]}` : "" },
  ].filter(Boolean);
  $("#stTiles").innerHTML = tiles.map(x => `
    <div class="tile" style="--g:${x.g}">
      <div class="label"><span>${x.label}</span><span class="emoji">${x.emoji}</span></div>
      <div class="value st-value">${esc(x.value)}</div>
      <div class="sub">${esc(x.sub)}</div>
    </div>`).join("");
  const g = p => p.port === "WAN" ? "var(--g24)" : p.port.startsWith("LAN") ? "var(--gwired)" : p.port.startsWith("2.4") ? "var(--g24)" : p.port.startsWith("5") ? "var(--g5)" : "var(--gunk)";
  const icon = p => p.port === "WAN" ? "🌍" : p.port.startsWith("LAN") ? "🐭" : "📶";
  $("#stPorts").innerHTML = s.ports.map((p, i) => {
    const down = /down/i.test(p.status);
    return `
    <article class="dev st-port ${down ? "blocked" : ""}" style="--g:${g(p)}; animation-delay:${i * 30}ms">
      <div class="dev-top"><div class="icon">${icon(p)}</div>
        <div class="dev-name"><div class="n"><span>${esc(p.port)}</span></div><div class="orig">${down ? "💤 nothing plugged in" : esc(p.status)}</div></div></div>
      ${down ? "" : `<dl class="kv">
        <dt>Now ↑ / ↓</dt><dd class="mono">${fmtRate(p.txBps)} / ${fmtRate(p.rxBps)} B/s</dd>
        <dt>Packets ↑ / ↓</dt><dd class="mono">${fmtCount(p.txPkts)} / ${fmtCount(p.rxPkts)}</dd>
        <dt>Up for</dt><dd>${esc(fmtUp(p.upTime))}</dd>
        ${p.collisions ? `<dt>Collisions</dt><dd>${fmtCount(p.collisions)}</dd>` : ""}
      </dl>`}
    </article>`;
  }).join("") + (Object.keys(c).length ? `
    <article class="dev st-port" style="--g:var(--gbrand)">
      <div class="dev-top"><div class="icon">🔌</div><div class="dev-name"><div class="n"><span>Internet connection</span></div><div class="orig">from your provider</div></div></div>
      <dl class="kv">${Object.entries(c).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="${/IP|Mask|Gateway|Server/.test(k) ? "mono" : ""}">${esc(v)}</dd>`).join("")}</dl>
    </article>` : "");
}

// Put names on MACs and IPs the log mentions, and the port-forward rule a remote hit used.
function decorateLog(msg) {
  let h = esc(msg);
  h = h.replace(/\b([0-9A-F]{2}(?::[0-9A-F]{2}){5})\b/gi, mac => {
    const d = deviceByMac(mac);
    return d ? `<b title="${esc(mac)}">${deviceIcon(d)} ${esc(labelFor(d) || d.name)}</b>` : `<span class="mono">${mac}</span>`;
  });
  h = h.replace(/\b(192\.168\.\d+\.\d+)(?::(\d+))?\b/g, (all, ip, port) => {
    const d = ui.snap?.devices.find(x => x.ip === ip);
    const rule = port && ui.pf?.find(r => r.ip === ip && (r.externalPorts.split(",").some(x => { const [a, b] = x.split("-").map(Number); return +port >= a && +port <= (b || a); })
      || r.internalPorts.split(",").some(x => { const [a, b] = x.split("-").map(Number); return +port >= a && +port <= (b || a); })));
    return `${d ? `<b title="${ip}">${deviceIcon(d)} ${esc(labelFor(d) || d.name)}</b>` : `<span class="mono">${ip}</span>`}${port ? `<span class="mono">:${port}</span>` : ""}${rule ? ` <span class="badge" title="Port forwarding rule">🚪 ${esc(rule.name)}</span>` : ""}`;
  });
  return h;
}

function renderLogs() {
  const all = ui.logs || [];
  const quiet = $("#logQuiet").checked;
  const base = all.filter(e => !(quiet && isRoutine(e)));
  const counts = {};
  for (const e of base) counts[logCat(e.category)] = (counts[logCat(e.category)] || 0) + 1;
  if (ui.logFilter !== "all" && !counts[ui.logFilter]) ui.logFilter = "all";
  $("#logChips").innerHTML = [["all", `All`, "var(--gbrand)", base.length], ...Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, `${logStyle(k)[0]} ${k}`, logStyle(k)[1], n])]
    .map(([k, label, g, n]) => `<button class="chip ${ui.logFilter === k ? "on" : ""}" style="--g:${g}" data-log-filter="${esc(k)}">${esc(label)}<span class="n">${n}</span></button>`).join("");
  const q = ($("#logSearch").value || "").trim().toLowerCase();
  const list = base.filter(e => (ui.logFilter === "all" || logCat(e.category) === ui.logFilter) && (!q || `${e.category} ${e.message}`.toLowerCase().includes(q)));
  $("#logCount").textContent = all.length;
  const hidden = all.length - base.length;
  $("#logList").innerHTML = (list.length ? list.slice(0, 400).map(e => {
    const [emo, g] = logStyle(e.category);
    const t = e.time ? new Date(e.time) : null;
    return `<div class="log-row" style="--g:${g}">
      <span class="log-time mono" title="${esc(e.time || "")}">${t ? t.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—"}</span>
      <span class="log-cat">${emo} ${esc(e.category || "Other")}</span>
      <span class="log-msg">${decorateLog(e.message)}</span>
    </div>`;
  }).join("") : `<div class="empty">🙀 Nothing matches. The diary is quiet.</div>`)
    + (hidden && quiet ? `<div class="muted small log-foot">${hidden} routine “device is allowed” entries hidden.</div>` : "");
}

$("#logSearch").addEventListener("input", () => renderLogs());
$("#logQuiet").addEventListener("change", () => renderLogs());

// ───────────────────────── modal helpers ─────────────────────────
function modal(html) {
  const dlg = $("#modal"), form = $("#modalForm");
  form.innerHTML = html;
  dlg.showModal();
  return new Promise(res => dlg.addEventListener("close", () => res(dlg.returnValue), { once: true }));
}

async function confirmBox(title, text, okLabel = "OK", danger = false) {
  const v = await modal(`<h3>${esc(title)}</h3><p>${esc(text)}</p>
    <div class="actions"><button class="btn ghost" value="no">Cancel</button>
    <button class="btn ${danger ? "danger" : "primary"}" value="yes">${esc(okLabel)}</button></div>`);
  return v === "yes";
}

async function promptBox(title, text, value) {
  const dlg = $("#modal");
  const p = modal(`<h3>${esc(title)}</h3><p class="mono small">${esc(text)}</p>
    <input id="promptIn" value="${esc(value)}" placeholder="e.g. Living room TV" maxlength="40" />
    <div class="actions"><button class="btn ghost" value="cancel">Cancel</button><button class="btn primary" value="save">Save</button></div>`);
  const input = $("#promptIn");
  input.focus(); input.select();
  input.addEventListener("keydown", ev => { if (ev.key === "Enter") { ev.preventDefault(); dlg.close("save"); } });
  const v = await p;
  return v === "save" ? input.value : null;
}

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), 3800);
}

// ───────────────────────── utils ─────────────────────────
function mb(v) {
  if (v == null) return "—";
  if (v >= 1024 * 1024) return (v / 1024 / 1024).toFixed(2) + " TB";
  if (v >= 1024) return (v / 1024).toFixed(v >= 10240 ? 0 : 1) + " GB";
  return Math.round(v) + " MB";
}

boot().catch(ex => { document.body.insertAdjacentHTML("beforeend", `<p class="error" style="margin:2rem">${esc(ex.message)}</p>`); });

// ───────────────────────── 🐾 pet the cat ─────────────────────────
// Click the logo: it wiggles and makes a tiny synthesized "mrrp" (only ever on a click, never on its own).
function meow() {
  try {
    const C = new AudioContext(), t = C.currentTime;
    const o = C.createOscillator(), f = C.createBiquadFilter(), g = C.createGain();
    o.type = "sawtooth"; f.type = "bandpass"; f.Q.value = 5;
    o.frequency.setValueAtTime(480, t); o.frequency.linearRampToValueAtTime(760, t + .16); o.frequency.linearRampToValueAtTime(430, t + .5);
    f.frequency.setValueAtTime(1100, t); f.frequency.linearRampToValueAtTime(2300, t + .18); f.frequency.linearRampToValueAtTime(900, t + .5);
    g.gain.setValueAtTime(0, t); g.gain.linearRampToValueAtTime(.22, t + .04); g.gain.linearRampToValueAtTime(.15, t + .38); g.gain.linearRampToValueAtTime(0, t + .55);
    o.connect(f).connect(g).connect(C.destination);
    o.start(t); o.stop(t + .6); o.onended = () => C.close();
  } catch { /* no audio, no problem */ }
}
for (const img of document.querySelectorAll(".pet-me")) img.addEventListener("click", e => {
  img.classList.remove("petted"); void img.offsetWidth; img.classList.add("petted");
  meow();
  const pop = document.createElement("span");
  pop.className = "purr-pop";
  pop.textContent = ["mrrp!", "purr…", "meow!", "prrrt?", "😻"][Math.floor(Math.random() * 5)];
  pop.style.left = e.clientX + "px"; pop.style.top = (e.clientY - 20) + "px";
  document.body.append(pop);
  setTimeout(() => pop.remove(), 1200);
});
