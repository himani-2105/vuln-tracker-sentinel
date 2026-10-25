/* Core: safe templating, API client, session state, and the reusable design-system components. */
export class Safe { constructor(s) { this.s = s; } toString() { return this.s; } }
export const raw = s => new Safe(String(s ?? ""));
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ESC[c]);
const one = v => v instanceof Safe ? v.s : Array.isArray(v) ? v.map(one).join("") : esc(v);
/** html`...` escapes every interpolated value unless it is already Safe (output of another html`` call). */
export const html = (s, ...v) => { let o = s[0]; v.forEach((x, i) => { o += one(x) + s[i + 1]; }); return new Safe(o); };
export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];
export const S = { user: null, csrf: "", perms: new Set(), demo: false };
export const can = p => S.perms.has("*") || S.perms.has(p);

export class ApiError extends Error { constructor(m, status) { super(m); this.status = status; } }
export async function api(path, { method = "GET", json, form } = {}) {
  const opt = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") opt.headers["X-CSRF-Token"] = S.csrf;
  if (json !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(json); }
  if (form) opt.body = form;
  let r; try { r = await fetch(path, opt); } catch { throw new ApiError("Cannot reach the server. Check your connection.", 0); }
  let data = null; try { data = await r.json(); } catch { /* non-JSON */ }
  if (r.status === 401 && S.user) { S.user = null; window.dispatchEvent(new Event("session-expired")); }
  if (!r.ok) throw new ApiError((data && data.error) || `Request failed (${r.status})`, r.status);
  return data;
}
export const qs = o => { const p = new URLSearchParams(); Object.entries(o).forEach(([k, v]) => { if (v !== "" && v != null && v !== false) p.set(k, v === true ? "1" : v); }); const s = p.toString(); return s ? "?" + s : ""; };

/* ---------- formatting ---------- */
export const fdate = s => s ? new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—";
export const fdt = s => s ? new Date(s).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
export const ago = s => { if (!s) return "never"; const m = (Date.now() - new Date(s)) / 6e4; if (m < 1) return "just now"; if (m < 60) return Math.floor(m) + " min ago"; if (m < 1440) return Math.floor(m / 60) + " h ago"; return Math.floor(m / 1440) + " d ago"; };
export const shortId = id => "F-" + String(id).slice(0, 8).toUpperCase();
export const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
export const STATUSES = ["Open", "Triaged", "In Progress", "Fixed — Pending Verification", "Verified Resolved", "Risk Accepted", "Reopened"];

/* ---------- design-system components ---------- */
export const sev = s => html`<span class="badge sev-${String(s || "info").toLowerCase()}">${s || "—"}</span>`;
export const stBadge = s => html`<span class="badge st st-${String(s).toLowerCase().replace(/[^a-z]+/g, "-")}">${s}</span>`;
export const catBadge = r => {
  if (!r) return html`<span class="muted">—</span>`;
  const c = r.category, sc = r.score == null ? "—" : r.score.toFixed(0);
  return html`<span class="badge cat-${c.toLowerCase()}" title="${r.provisional ? "Provisional: no usable CVSS. " : ""}Confidence: ${r.confidence}">${c}${r.provisional ? "" : " · " + sc}</span>`;
};
export const dueCell = f => f.due_date ? html`<span class="${f.overdue ? "overdue" : ""}">${f.due_date}${f.overdue ? html` <small>(${-f.days_left}d late)</small>` : f.days_left != null && f.days_left <= 7 ? html` <small>(${f.days_left}d)</small>` : ""}</span>` : html`<span class="muted">—</span>`;
export const empty = (title, msg, action) => html`<div class="empty"><canvas class="hero3d sm" data-model="cube"></canvas><h3>${title}</h3><p>${msg}</p>${action || ""}</div>`;
export const errorBox = (msg, retry) => html`<div class="errbox" role="alert"><strong>Something went wrong</strong><p>${msg}</p>${retry ? html`<button class="btn" data-retry>Try again</button>` : ""}</div>`;
export const skeleton = (n = 4) => html`<div class="skeleton-wrap">${Array.from({ length: n }, () => html`<div class="skeleton"></div>`)}</div>`;
export const kpi = (label, value, sub, cls = "", href = "") => html`<${raw(href ? "a" : "div")} class="card kpi tilt ${cls}" ${raw(href ? `href="${esc(href)}"` : "")}><div class="kpi-l">${label}</div><div class="kpi-v">${value}</div><div class="kpi-s">${sub ?? ""}</div><i class="glare"></i></${raw(href ? "a" : "div")}>`;

export function toast(msg, type = "info", ms = 4200) {
  let box = $("#toasts"); const t = document.createElement("div"); t.className = `toast ${type}`; t.setAttribute("role", type === "error" ? "alert" : "status"); t.textContent = msg;
  box.appendChild(t); setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 300); }, ms);
}
let lastFocus = null;
export function modal({ title, body, actions = [], wide = false, onMount }) {
  lastFocus = document.activeElement; const root = $("#modal-root"); const w = document.createElement("div"); w.className = "overlay";
  w.innerHTML = String(html`<div class="dialog ${wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-label="${title}"><header><h2>${title}</h2><button class="icon-btn" data-x aria-label="Close">✕</button></header><div class="dlg-body">${body}</div><footer></footer></div>`);
  const foot = $("footer", w);
  const close = () => { w.remove(); document.removeEventListener("keydown", onKey); lastFocus && lastFocus.focus && lastFocus.focus(); };
  const onKey = e => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  actions.forEach(a => { const b = document.createElement("button"); b.className = "btn " + (a.cls || ""); b.textContent = a.label; b.onclick = async () => { if (a.keepOpen === undefined && !a.onClick) return close(); b.disabled = true; try { const r = await a.onClick(w, close); if (r !== false && !a.keepOpen) close(); } catch (e) { showFormError(w, e.message); } finally { b.disabled = false; } }; foot.appendChild(b); });
  if (!actions.length) foot.remove();
  w.addEventListener("click", e => { if (e.target === w || e.target.closest("[data-x]")) close(); });
  root.appendChild(w); const f = $("input,select,textarea,button.primary", w); f && f.focus(); onMount && onMount(w, close); return { el: w, close };
}
export function showFormError(root, msg) { let e = $(".form-err", root); if (!e) { e = document.createElement("div"); e.className = "form-err"; e.setAttribute("role", "alert"); $(".dlg-body", root).prepend(e); } e.textContent = msg; }
export const confirmDlg = (title, msg, label = "Confirm", cls = "danger") => new Promise(res => modal({ title, body: html`<p>${msg}</p>`, actions: [{ label: "Cancel", onClick: () => { res(false); } }, { label, cls, onClick: () => { res(true); } }] }));
export const field = (label, input, hint) => html`<label class="fld"><span>${label}</span>${input}${hint ? html`<small>${hint}</small>` : ""}</label>`;
export const sel = (name, opts, cur = "", any = "") => html`<select name="${name}">${any ? html`<option value="">${any}</option>` : ""}${opts.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o]; return html`<option value="${v}" ${raw(String(v) === String(cur) ? "selected" : "")}>${l}</option>`; })}</select>`;
export const formData = root => Object.fromEntries(new FormData($("form", root) || root).entries());

export function drawer(title, content) {
  const root = $("#drawer-root"); root.innerHTML = String(html`<div class="drawer-bg"></div><aside class="drawer" role="dialog" aria-label="${title}"><header><div class="dr-title">${title}</div><button class="icon-btn" data-x aria-label="Close">✕</button></header><div class="dr-body"></div></aside>`);
  const close = () => { root.innerHTML = ""; document.removeEventListener("keydown", k); if (location.hash.match(/^#\/vulns\/[^?]/)) history.replaceState(null, "", "#/vulns"); };
  const k = e => { if (e.key === "Escape" && !$("#modal-root .overlay")) close(); };
  document.addEventListener("keydown", k); root.onclick = e => { if (e.target.closest("[data-x]") || e.target.classList.contains("drawer-bg")) close(); };
  requestAnimationFrame(() => root.classList.add("open")); return { body: $(".dr-body", root), close, setTitle: t => $(".dr-title", root).textContent = t };
}
export function pager(p, n, total, pages, cb) {
  return html`<div class="pager"><span class="muted">${total ? `${(p - 1) * n + 1}–${Math.min(p * n, total)} of ${total}` : "0 results"}</span><span class="sp"></span>
  <label>Rows <select data-pp>${[10, 25, 50, 100].map(x => html`<option ${raw(x === n ? "selected" : "")}>${x}</option>`)}</select></label>
  <button class="btn sm" data-pg="${p - 1}" ${raw(p <= 1 ? "disabled" : "")}>‹ Prev</button><span>Page ${p} / ${pages}</span><button class="btn sm" data-pg="${p + 1}" ${raw(p >= pages ? "disabled" : "")}>Next ›</button></div>`;
}
export const debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
