// Shared frontend helpers: API calls (session aware), HTML escaping, the header
// auth box, and role-based UI gating.

const esc = s => (s ?? "").toString().replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Transient notification. type: error (stays until dismissed) | success | info (auto-hide).
function toast(message, type = "error") {
  let box = document.getElementById("toasts");
  if (!box) {
    box = document.createElement("div");
    box.id = "toasts"; box.className = "toasts";
    document.body.appendChild(box);
  }
  const t = document.createElement("div");
  t.className = "toast " + type;
  t.innerHTML = `<span></span><button class="tx" title="dismiss">×</button>`;
  t.querySelector("span").textContent = message;        // textContent = safe, no escaping
  t.querySelector(".tx").onclick = () => t.remove();
  box.appendChild(t);
  if (type !== "error") setTimeout(() => t.remove(), 4500);
}
window.toast = toast;

// Normalize opts: `json:` auto-sets the Content-Type + serializes the body, so
// callers stop hand-rolling headers/JSON.stringify at every call site.
function _prep(opts) {
  if (opts.json === undefined) return opts;
  const { json, headers, ...rest } = opts;
  return { ...rest, headers: { "Content-Type": "application/json", ...(headers || {}) },
           body: JSON.stringify(json) };
}

// Pull a human-readable message out of a FastAPI error body (detail can be a
// string, or a list of validation errors).
function detailOf(body, fallback) {
  const d = body && body.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d) && d.length) return d.map(e => e.msg || JSON.stringify(e)).join("; ");
  return fallback;
}
window.detailOf = detailOf;

// Redirect to login on 401. Shared by api() and apiTry().
function _handle401() {
  if (!location.pathname.endsWith("/login.html")) {
    location.href = "/login.html?next=" + encodeURIComponent(location.pathname);
  }
}

async function api(path, opts = {}) {
  opts = _prep(opts);
  const res = await fetch(path, { credentials: "same-origin", ...opts });
  if (res.status === 401) { _handle401(); throw new Error("unauthorized"); }
  if (!res.ok) {
    let detail;
    try { detail = detailOf(await res.json(), res.statusText); }
    catch { detail = res.statusText; }
    toast(`${(opts.method || "GET").toUpperCase()} ${path} failed (${res.status}): ${detail}`);
    throw new Error(detail);
  }
  return res.json();
}

// Like api(), but never throws/toasts on a non-2xx — returns {ok, status, body}
// so callers can branch on status (e.g. 409) and show their own message. Still
// redirects on 401. Use for writes that need status-aware handling.
async function apiTry(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", ..._prep(opts) });
  if (res.status === 401) { _handle401(); return { ok: false, status: 401, body: null }; }
  let body = null;
  try { body = await res.json(); } catch { /* empty/204 */ }
  return { ok: res.ok, status: res.status, body };
}
window.api = api; window.apiTry = apiTry;

// Shared view helpers used across pages.
const card = (n, l) => `<div class="card"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;
const fmtDate = v => v ? new Date(v).toLocaleString() : "—";

// "Sync all connectors" — shared by the Overview and Connectors pages.
async function syncAll(btn, onDone) {
  const label = btn.textContent;
  btn.textContent = "Syncing…"; btn.disabled = true;
  try {
    const runs = await api("/api/sync", { method: "POST" });
    const errs = (runs || []).filter(r => r.status === "error");
    if (errs.length) errs.forEach(r => toast(`${r.connector} failed: ${r.error}`, "error"));
    else toast("Sync complete", "success");
  } finally {
    btn.textContent = label; btn.disabled = false; if (onDone) onDone();
  }
}
window.card = card; window.fmtDate = fmtDate; window.syncAll = syncAll;

// Render table rows into a <tbody>, with a shared empty-state fallback and an
// optional count badge. Replaces the load→map→"|| empty row" idiom repeated
// across every page.
function renderRows(tbodyId, items, rowFn, { colspan = 1, empty = "Nothing here yet.", countEl } = {}) {
  const el = document.getElementById(tbodyId);
  if (!el) return;
  el.innerHTML = items.length
    ? items.map(rowFn).join("")
    : `<tr><td colspan="${colspan}" class="muted">${esc(empty)}</td></tr>`;
  if (countEl) {
    const c = document.getElementById(countEl);
    if (c) c.textContent = items.length ? `— ${items.length}` : "";
  }
}
window.renderRows = renderRows;

// Single source of truth for the top nav (rendered into <nav id="mainnav">).
const NAV = [
  { href: "/", label: "Overview" },
  { href: "/connectors.html", label: "Connectors & Settings", gate: "security" },
  { href: "/packages.html", label: "Packages" },
  { href: "/containers.html", label: "Containers", gate: "security" },
  { href: "/status.html", label: "Status", gate: "security" },
  { href: "/users.html", label: "Users", gate: "admin" },
];

function renderNav() {
  const el = document.getElementById("mainnav");
  if (!el) return;
  const path = location.pathname;
  el.innerHTML = NAV.map(n => {
    const active = (n.href === "/" ? path === "/" : path === n.href) ? ' class="active"' : "";
    const gate = n.gate ? ` data-gate="${n.gate}"` : "";   // hidden until role allows
    return `<a href="${n.href}"${active}${gate}>${esc(n.label)}</a>`;
  }).join("");
}

// Resolves to the current user once known. Pages await this to branch on role.
let _meResolve;
window.mePromise = new Promise(r => (_meResolve = r));

function applyRoleVisibility(me) {
  const admin = me.role === "security_admin";
  const sec = me.role !== "dev";   // security_admin or security_user
  // Elements with data-gate are hidden by CSS until shown here.
  if (sec) document.querySelectorAll('[data-gate="security"]').forEach(e => e.removeAttribute("data-gate"));
  if (admin) document.querySelectorAll('[data-gate="admin"]').forEach(e => e.removeAttribute("data-gate"));
}

function _roleAllows(me, level) {
  return level === "admin" ? me.role === "security_admin"
    : level === "security" ? me.role !== "dev"
      : true;
}

// Guard a whole page: redirect non-permitted users to the overview.
window.requireRole = async (level) => {
  const me = await window.mePromise;
  if (!me) { location.href = "/login.html"; return new Promise(() => {}); }  // auth failed
  if (!_roleAllows(me, level)) { location.href = "/"; return new Promise(() => {}); }  // page unloads
  return me;
};

// Resolve the current user for page init. Returns `me` (so pages can branch on
// role for feature-gating), or null if auth failed — in which case app.js has
// already redirected, so callers should just bail.
window.initPage = async () => {
  const me = await window.mePromise;
  return me || null;
};

async function initAuthHeader() {
  renderNav();  // structure first, so applyRoleVisibility can reveal allowed links
  let me;
  // On 401, api() already redirected. On any other failure, resolve null so
  // gated pages react (and don't hang forever awaiting mePromise).
  try { me = await api("/api/auth/me"); } catch { _meResolve(null); return; }
  window.ME = me;
  _meResolve(me);
  applyRoleVisibility(me);

  const el = document.getElementById("authBox");
  if (!el) return;
  el.innerHTML = `<span class="muted" style="font-size:12px">${esc(me.username)} · ${esc(me.role)}</span>
    <button class="mini" id="logoutBtn">Log out</button>`;
  document.getElementById("logoutBtn").onclick = async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    location.href = "/login.html";
  };
}

document.addEventListener("DOMContentLoaded", initAuthHeader);
