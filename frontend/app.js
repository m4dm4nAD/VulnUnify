// Shared frontend helpers: API calls (session cookie aware), HTML escaping,
// and the header auth box (current user + log out).

const esc = s => (s ?? "").toString().replace(/[&<>"]/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", ...opts });
  if (res.status === 401) {
    // Session missing/expired -> bounce to login, remembering where we were.
    if (!location.pathname.endsWith("/login.html")) {
      location.href = "/login.html?next=" + encodeURIComponent(location.pathname);
    }
    throw new Error("unauthorized");
  }
  return res.json();
}

async function initAuthHeader() {
  const el = document.getElementById("authBox");
  if (!el) return;
  let me;
  try { me = await api("/api/auth/me"); } catch { return; }  // api() handled the redirect
  el.innerHTML = `<span class="muted" style="font-size:12px">${esc(me.username)} · ${esc(me.role)}</span>
    <button class="mini" id="logoutBtn">Log out</button>`;
  document.getElementById("logoutBtn").onclick = async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    location.href = "/login.html";
  };
}

document.addEventListener("DOMContentLoaded", initAuthHeader);
