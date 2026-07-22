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

// Display labels for enum values. The stored/API values stay lowercase (see
// connectors/enums.py); this is purely how they're shown. Acronyms are kept
// upper-case here so a naive title-caser doesn't render "SAST" as "Sast".
const LABELS = {
  // finding category
  vulnerability: "Vulnerability", cloud_posture: "Cloud Posture", sast: "SAST",
  sca: "SCA", supply_chain: "Supply Chain", secret: "Secret", iac: "IAC",
  container: "Container",
  // status (source + effective) and triage
  open: "Open", fixed: "Fixed", resolved: "Resolved", suppressed: "Suppressed",
  accepted_risk: "Accepted Risk", false_positive: "False Positive",
  snoozed: "Snoozed", active: "Active",
  // severity
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
  // asset type
  host: "Host", cloud_resource: "Cloud Resource", repository: "Repository",
  container_image: "Container Image", package: "Package", web_app: "Web App",
  unknown: "Unknown",
};
// Pretty label for an enum value; falls back to Title Case (underscores → spaces).
function pretty(v) {
  if (v == null || v === "") return v ?? "";
  const k = String(v).toLowerCase();
  return LABELS[k] || k.split(/[_\s]+/)
    .map(w => w ? w[0].toUpperCase() + w.slice(1) : w).join(" ");
}
window.pretty = pretty; window.LABELS = LABELS;

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

// ---------------- Shell (sidebar + topbar), injected once ----------------

const ICONS = {
  shield: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 2.5 4.5 5.5v6c0 4.6 3.2 7.9 7.5 9.4 4.3-1.5 7.5-4.8 7.5-9.4v-6L12 2.5Z" fill="currentColor" opacity=".9"/><path d="m8.6 12 2.3 2.3 4.5-4.6" stroke="var(--accent-ink)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  overview: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
  connectors: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h16M4 12h16M4 17h16"/><circle cx="7" cy="7" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="9" cy="17" r="1.4" fill="currentColor" stroke="none"/></svg>',
  packages: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2.5 4 6.5v9L12 21l8-5.5v-9L12 2.5Z"/><path d="M4 6.5 12 11l8-4.5M12 11v10"/></svg>',
  containers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="9" cy="8" r="3.2"/><path d="M3.5 20a5.5 5.5 0 0 1 11 0"/><path d="M16 5.2a3 3 0 0 1 0 5.6M18.5 20a5.5 5.5 0 0 0-3-4.9"/></svg>',
  status: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 13v6M9 9v10M14 5v14M19 11v8"/></svg>',
  intel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>',
  assets: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10Z"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 4.5v-2M12 21.5v-2M19.5 12h2M2.5 12h2M17.7 6.3l1.4-1.4M4.9 19.1l1.4-1.4M17.7 17.7l1.4 1.4M4.9 4.9l1.4 1.4"/><circle cx="12" cy="12" r="4"/></svg>',
  logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M15 12H4M11 8l-4 4 4 4M14 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4"/></svg>',
};

// Single source of truth for navigation, grouped for the sidebar. `key` matches
// each page's data-page; `gate` hides items until the role allows.
const NAV = [
  { title: null, items: [
    { key: "overview", href: "/", label: "Overview", icon: "overview" },
    { key: "assets", href: "/assets.html", label: "Assets", icon: "assets", gate: "security" },
  ]},
  { title: "Sources", items: [
    { key: "connectors", href: "/connectors.html", label: "Connectors", icon: "connectors", gate: "security" },
    { key: "intel", href: "/intel.html", label: "Threat Intel", icon: "intel", gate: "security" },
    { key: "packages", href: "/packages.html", label: "Packages", icon: "packages" },
    { key: "containers", href: "/containers.html", label: "Containers", icon: "containers", gate: "security" },
  ]},
  { title: "Team & System", gate: "security", items: [
    { key: "users", href: "/users.html", label: "Users", icon: "users", gate: "admin" },
    { key: "status", href: "/status.html", label: "Status", icon: "status", gate: "security" },
  ]},
];

function navLabel(key) {
  for (const g of NAV) for (const it of g.items) if (it.key === key) return it.label;
  return null;
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
// role for feature-gating), or null if auth failed — app.js already redirected.
window.initPage = async () => {
  const me = await window.mePromise;
  return me || null;
};

// Persisted light/dark toggle that overrides the OS preference in both directions.
function wireTheme(btn) {
  const root = document.documentElement;
  const saved = localStorage.getItem("vu-theme");
  if (saved) root.dataset.theme = saved;
  const cur = () => root.dataset.theme
    || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const paint = () => { btn.innerHTML = cur() === "dark" ? ICONS.moon : ICONS.sun; };
  btn.onclick = () => {
    const next = cur() === "dark" ? "light" : "dark";
    root.dataset.theme = next; localStorage.setItem("vu-theme", next); paint();
  };
  paint();
}

// Build the sidebar + topbar around the page's #view content.
function buildShell(view) {
  const pageKey = view.dataset.page || "";
  const title = view.dataset.title || navLabel(pageKey) || "VulnUnify";
  const subtitle = view.dataset.subtitle || "";

  const nav = NAV.map(group => {
    const items = group.items.map(it => {
      const active = it.key === pageKey ? " active" : "";
      const gate = it.gate ? ` data-gate="${it.gate}"` : "";
      return `<a class="nav-item${active}" href="${it.href}"${gate}>${ICONS[it.icon] || ""}` +
             `<span class="label">${esc(it.label)}</span></a>`;
    }).join("");
    const gg = group.gate ? ` data-gate="${group.gate}"` : "";
    const heading = group.title ? `<div class="nav-group"${gg}>${esc(group.title)}</div>` : "";
    return heading + items;
  }).join("");

  const shell = document.createElement("div");
  shell.className = "app";
  shell.innerHTML =
    `<aside class="sidebar">
       <div class="brand"><span class="mark" aria-hidden="true">${ICONS.shield}</span>
         <span class="name">VulnUnify</span></div>
       <nav class="nav" aria-label="Primary">${nav}</nav>
       <div class="side-user" id="sideUser"></div>
     </aside>
     <div class="main">
       <header class="topbar">
         <div class="titleblock"><h1>${esc(title)}</h1>${subtitle ? `<p id="pageSubtitle">${esc(subtitle)}</p>` : `<p id="pageSubtitle" hidden></p>`}</div>
         <div class="spacer"></div>
         <div class="topbar-actions" id="topbarActions">
           <button class="icon-btn" id="themeToggle" title="Toggle theme" aria-label="Toggle theme"></button>
         </div>
       </header>
       <div class="content" id="content"></div>
     </div>`;

  const content = shell.querySelector("#content");
  const topActions = shell.querySelector("#topbarActions");
  const themeBtn = shell.querySelector("#themeToggle");

  // Page-declared topbar buttons move ahead of the theme toggle.
  const actions = view.querySelector("[data-actions]");
  if (actions) {
    Array.from(actions.children).forEach(c => topActions.insertBefore(c, themeBtn));
    actions.remove();
  }
  while (view.firstChild) content.appendChild(view.firstChild);
  view.replaceWith(shell);
  wireTheme(themeBtn);
}

async function loadMe() {
  let me;
  // On 401, api() already redirected. On any other failure, resolve null so
  // gated pages react (and don't hang forever awaiting mePromise).
  try { me = await api("/api/auth/me"); } catch { _meResolve(null); return; }
  window.ME = me;
  _meResolve(me);
  applyRoleVisibility(me);

  const el = document.getElementById("sideUser");
  if (!el) return;
  el.innerHTML =
    `<span class="avatar">${esc(me.username.slice(0, 2).toUpperCase())}</span>
     <span class="who"><b>${esc(me.username)}</b><span>${esc(me.role)}</span></span>
     <button class="icon-btn logout" id="logoutBtn" title="Log out" aria-label="Log out">${ICONS.logout}</button>`;
  document.getElementById("logoutBtn").onclick = async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    location.href = "/login.html";
  };
}

document.addEventListener("DOMContentLoaded", () => {
  const view = document.getElementById("view");
  if (!view) return;   // e.g. the login page has no shell
  buildShell(view);
  loadMe();
});
