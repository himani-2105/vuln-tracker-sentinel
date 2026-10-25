import { html, raw, $, $$, S, api, can, toast, debounce, sev, stBadge, ago, fdt, shortId, errorBox, formData } from "./core.js";
import { startBackground, startTilt, startHeroes } from "./fx.js";
import * as P1 from "./pages1.js"; import * as P2 from "./pages2.js";
const NAV = [["overview", "Overview", "◧"], ["vulns", "Vulnerabilities", "⚠"], ["assets", "Assets", "▣"], ["attack", "Attack Path Explorer", "⌬"], ["scans", "Scan History", "⟲"], ["remediation", "Remediation Center", "✔"], ["exceptions", "Risk Exceptions", "⏳"], ["reports", "Reports", "▤"], ["audit", "Audit Logs", "☰"], ["settings", "Settings", "⚙"]];
const PAGES = { overview: P1.overview, vulns: P1.vulns, assets: P1.assets, attack: P2.attack, scans: P2.scans, remediation: P2.remediation, exceptions: P2.exceptions, reports: P2.reports, audit: P2.audit, settings: P2.settings };
const LABEL = Object.fromEntries(NAV.map(n => [n[0], n[1]]));

function parseHash() { const h = location.hash.replace(/^#\/?/, ""), [path, q] = h.split("?"), parts = path.split("/").filter(Boolean); return { page: parts[0] || "overview", parts: parts.slice(1), query: Object.fromEntries(new URLSearchParams(q || "")) }; }
async function route() {
  if (!S.user) return; const { page, parts, query } = parseHash(), fn = PAGES[page];
  $$("#nav a").forEach(a => a.classList.toggle("on", a.dataset.page === page)); $("#drawer-root").innerHTML = ""; $("#drawer-root").classList.remove("open");
  $("#crumbs").innerHTML = String(html`<span>VulnTrack Sentinel</span> <i>/</i> <b>${LABEL[page] || "Not found"}</b>${parts[0] ? html` <i>/</i> <span>${page === "vulns" ? shortId(parts[0]) : "#" + parts[0]}</span>` : ""}`);
  document.title = `${LABEL[page] || "Not found"} · VulnTrack Sentinel`;
  if (!fn) { $("#view").innerHTML = String(errorBox("That page does not exist.")); return; }
  $("#view").classList.remove("enter"); void $("#view").offsetWidth; $("#view").classList.add("enter"); $("#view").focus({ preventScroll: true });
  try { await fn(parts, query); } catch (e) { $("#view").innerHTML = String(errorBox(e.message)); }
  document.querySelector("#main").scrollTo?.(0, 0);
}
function shell() {
  $("#login").hidden = true; $("#shell").hidden = false;
  $("#nav").innerHTML = String(html`${NAV.map(([k, l, i]) => html`<a href="#/${k}" data-page="${k}"><span class="ni">${i}</span><span class="nl">${l}</span></a>`)}`);
  $("#me").innerHTML = String(html`<button class="userbtn" data-menu aria-haspopup="true"><span class="av">${(S.user.display_name || S.user.username)[0].toUpperCase()}</span><span class="un">${S.user.display_name || S.user.username}<small>${{ admin: "Admin", analyst: "Security Analyst", owner: "Remediation Owner", auditor: "Read-only Auditor" }[S.user.role]}</small></span></button><div class="menu" id="umenu" hidden><a href="#/settings">Account & settings</a><button data-logout>Sign out</button></div>`);
  $("#demo-pill").hidden = !S.demo; startHeroes();
}
function loginScreen(msg) {
  $("#shell").hidden = true; const l = $("#login"); l.hidden = false;
  l.innerHTML = String(html`<div class="login-card tilt big"><canvas class="hero3d" data-model="shield"></canvas><h1>VulnTrack <span>Sentinel</span></h1><p class="tag">Prioritize Exposure. Verify Remediation.</p>
  <form id="lf" autocomplete="on"><label class="fld"><span>Username</span><input name="username" autocomplete="username" required autofocus></label><label class="fld"><span>Password</span><input type="password" name="password" autocomplete="current-password" required></label>
  <div class="form-err" id="lerr" ${raw(msg ? "" : "hidden")}>${msg || ""}</div><button class="btn primary wide" type="submit">Sign in</button></form><p class="muted fine">${S.demo ? "Demo mode: synthetic lab data. Credentials were printed once by <code>manage.py seed-demo</code>." : "Authorised use only. Activity is audited."}</p><i class="glare"></i></div>`);
  startHeroes(l); $("#lf").onsubmit = async e => { e.preventDefault(); const b = $("button", e.target); b.disabled = true; try { const r = await api("/api/auth/login", { method: "POST", json: formData(e.target) }); S.csrf = r.csrf; await boot(); } catch (er) { const x = $("#lerr"); x.hidden = false; x.textContent = er.message; } finally { b.disabled = false; } };
}
async function boot() {
  let me; try { me = await api("/api/auth/me"); } catch (e) { return loginScreen("Cannot reach the server."); }
  S.csrf = me.csrf; S.demo = me.demo; S.user = me.user; S.perms = new Set(me.perms);
  if (!S.user) return loginScreen(); shell(); if (!location.hash) location.hash = "#/overview"; route();
}
addEventListener("hashchange", route); window.addEventListener("session-expired", () => { toast("Session expired. Please sign in again.", "error"); loginScreen("Your session expired."); });
document.addEventListener("click", async e => {
  const t = e.target;
  if (t.closest("[data-menu]")) { const m = $("#umenu"); m.hidden = !m.hidden; return; } else if (!t.closest("#umenu")) { const m = $("#umenu"); m && (m.hidden = true); }
  if (t.closest("[data-logout]")) { try { await api("/api/auth/logout", { method: "POST" }); } catch { } S.user = null; location.hash = ""; loginScreen(); }
  if (t.closest("#bell")) { const p = $("#actpanel"); p.hidden = !p.hidden; if (!p.hidden) loadActivity(); } else if (!t.closest("#actpanel")) { const p = $("#actpanel"); p && (p.hidden = true); }
  if (t.closest("#navtoggle")) document.body.classList.toggle("nav-open");
  if (t.closest("#nav a")) document.body.classList.remove("nav-open");
  const sr = t.closest("[data-go]"); if (sr) { location.hash = sr.dataset.go; $("#sres").hidden = true; $("#gsearch").value = ""; } else if (!t.closest("#sres") && !t.closest("#gsearch")) { const s = $("#sres"); s && (s.hidden = true); }
  if (t.closest("[data-import]") && !$("#view [data-import]")) P1.importDialog(route);
});
async function loadActivity() {
  const p = $("#actpanel"); p.innerHTML = String(html`<div class="skeleton"></div>`);
  try { const a = await api("/api/activity"); p.innerHTML = String(html`<h4>Recent activity</h4>${a.history.length || a.scans.length ? html`<ul>${a.scans.map(s => html`<li><b>Scan #${s.id}</b> ${s.source_type} ${s.status}, ${s.parsed_count} findings<small>${ago(s.imported_at)}</small></li>`)}${a.history.map(h => html`<li class="click" data-go="#/vulns/${h.finding_id}"><b>${h.kind}</b>${h.to_value ? " → " + h.to_value : ""} · ${h.name.slice(0, 40)}<small>${h.actor_name || "system"} · ${ago(h.at)}</small></li>`)}</ul>` : html`<p class="muted pad">No activity yet.</p>`}`); } catch (er) { p.innerHTML = String(errorBox(er.message)); }
}
const doSearch = debounce(async q => {
  const box = $("#sres"); if (q.trim().length < 2) { box.hidden = true; return; }
  try { const r = await api("/api/search?q=" + encodeURIComponent(q)); box.innerHTML = String(r.findings.length || r.assets.length ? html`${r.findings.map(f => html`<div class="sr" data-go="#/vulns/${f.id}" tabindex="0">${sev(f.sev)} <span>${f.name.slice(0, 54)}<small>${f.host} ${f.cve || ""} · ${f.status}</small></span></div>`)}${r.assets.map(a => html`<div class="sr" data-go="#/assets/${a.id}" tabindex="0"><span class="ni">▣</span><span>${a.asset_key}<small>asset · ${a.environment}</small></span></div>`)}` : html`<p class="muted pad">No matches for “${q}”.</p>`); box.hidden = false; } catch { }
});
document.addEventListener("input", e => { if (e.target.id === "gsearch") doSearch(e.target.value); });
document.addEventListener("keydown", e => { if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && S.user) { e.preventDefault(); $("#gsearch").focus(); } if (e.key === "Enter" && e.target.classList?.contains("sr")) e.target.click(); });
startBackground(); startTilt(); boot();
