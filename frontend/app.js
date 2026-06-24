// Shared frontend helpers: API calls (session aware), HTML escaping, the header
// auth box, and role-based UI gating.

const esc = s => (s ?? "").toString().replace(/[&<>"]/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", ...opts });
  if (res.status === 401) {
    if (!location.pathname.endsWith("/login.html")) {
      location.href = "/login.html?next=" + encodeURIComponent(location.pathname);
    }
    throw new Error("unauthorized");
  }
  return res.json();
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

// Guard a whole page: redirect non-permitted users to the overview.
window.requireRole = async (level) => {
  const me = await window.mePromise;
  const ok = level === "admin" ? me.role === "security_admin"
    : level === "security" ? me.role !== "dev"
      : true;
  if (!ok) { location.href = "/"; return new Promise(() => {}); }  // never resolves; page unloads
  return me;
};

async function initAuthHeader() {
  let me;
  try { me = await api("/api/auth/me"); } catch { return; }  // api() handled the redirect
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
