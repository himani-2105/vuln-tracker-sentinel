import { html, raw, esc, $, $$, S, can, api, qs, toast, modal, drawer, confirmDlg, field, sel, formData, showFormError, sev, stBadge, catBadge, dueCell, empty, errorBox, skeleton, kpi, pager, fdate, fdt, ago, shortId, debounce, SEV_ORDER, STATUSES } from "./core.js";
import { donut, bars, lines, bindTips, SEV_COL } from "./charts.js";
import { startHeroes } from "./fx.js";
export const view = () => $("#view");
export const render = (h, then) => { view().innerHTML = String(h); startHeroes(view()); then && then(view()); };
export const go = (hash) => { location.hash = hash; };
export const pageHead = (title, sub, model, actions = "") => html`<div class="page-head"><div><h1>${title}</h1><p class="sub">${sub}</p></div><div class="head-r"><div class="actions">${actions}</div><canvas class="hero3d" data-model="${model}"></canvas></div></div>`;
export const guard = async (fn) => { try { await fn(); } catch (e) { render(errorBox(e.message, true)); view().querySelector("[data-retry]")?.addEventListener("click", () => window.dispatchEvent(new Event("hashchange"))); } };

/* ================= Import scan dialog ================= */
export function importDialog(done) {
  modal({ title: "Import scan report", wide: true, body: html`<form class="grid2" autocomplete="off"><div class="drop" id="drop"><input type="file" name="files" id="fi" multiple accept=".xml,.csv"><p><strong>Choose Nmap XML or OpenVAS/GVM CSV/XML</strong></p><p class="muted">Max 25 MB per file. Only scan systems you are authorised to assess.</p><ul id="flist" class="muted"></ul></div>
    <div>${field("Scan coverage", html`<select name="partial"><option value="">Complete: all in-scope hosts and ports were scanned</option><option value="1">Partial / targeted: do not infer fixes from missing findings</option></select>`, "A partial scan can add or update findings but can never verify remediation.")}
    ${field("Extra hosts covered (optional)", html`<textarea name="covered_hosts" rows="2" placeholder="10.0.0.5, 10.0.0.6"></textarea>`, "CSV exports only list hosts that had findings. Name other scanned hosts so a clean result can be verified.")}
    ${field("Notes", html`<input name="notes" maxlength="200" placeholder="e.g. weekly authenticated scan">`)}</div></form><div id="imp-res"></div>`,
    actions: [{ label: "Close", onClick: () => { done && done(); } }, { label: "Upload & analyse", cls: "primary", keepOpen: true, onClick: async (w) => {
      const files = $("#fi", w).files; if (!files.length) throw new Error("Choose at least one .xml or .csv file."); const fd = new FormData();
      [...files].forEach(f => fd.append("files", f)); const f = formData(w); fd.append("partial", f.partial || ""); fd.append("covered_hosts", f.covered_hosts || ""); fd.append("notes", f.notes || "");
      $("#imp-res", w).innerHTML = String(skeleton(2)); let r; try { r = await api("/api/upload", { method: "POST", form: fd }); } catch (e) { $("#imp-res", w).innerHTML = ""; throw e; }
      $("#imp-res", w).innerHTML = String(html`<div class="okbox"><strong>Imported ${r.scans.length} scan(s).</strong>${r.scans.map(s => html`<p>Scan #${s.scan_id} (${s.status}): ${s.parsed} parsed, ${s.rejected} rejected, <b>${s.new}</b> new, <b>${s.resolved}</b> verified resolved by re-scan, ${s.reopened} reopened.</p>`)}</div>${r.errors.length ? html`<div class="errbox"><strong>Rejected</strong>${r.errors.map(e => html`<p>${e}</p>`)}</div>` : ""}`);
      toast(`Imported ${r.scans.length} scan(s)`, "success"); done && done(); return false; } }],
    onMount: w => { $("#fi", w).onchange = e => { $("#flist", w).innerHTML = String(html`${[...e.target.files].map(f => html`<li>${f.name} · ${(f.size / 1024).toFixed(0)} KB</li>`)}`); }; } });
}
const importCta = () => can("upload") ? html`<button class="btn primary" data-import>⬆ Import scan</button>` : "";

/* ================= Overview ================= */
export async function overview() {
  render(html`${pageHead("Overview", "Evidence-based exposure, verified remediation, and SLA status", "globe")}${skeleton(6)}`);
  await guard(async () => {
    const d = await api("/api/overview"), m = d.metrics, ls = m.latest_scan;
    if (d.empty) return render(html`${pageHead("Overview", "Evidence-based exposure, verified remediation, and SLA status", "globe", importCta())}
      <div class="kpis">${kpi("Open findings", 0, "no data yet")}${kpi("Critical / High", "0 / 0", "")}${kpi("Affected assets", 0, "")}${kpi("Overdue", 0, "")}${kpi("Awaiting verification", 0, "")}${kpi("Verified remediation", "—", "no fixes yet")}${kpi("Latest scan", "none", "")}${kpi("New / resolved", "0 / 0", "")}</div>
      <div class="card">${empty("No scans imported yet", "Import an Nmap XML or OpenVAS CSV/XML report to populate findings, assets, and risk scoring. Sample files are in the samples/ folder.", can("upload") ? html`<button class="btn primary" data-import>⬆ Import your first scan</button>` : html`<p class="muted">Ask a Security Analyst or Admin to import a scan.</p>`)}</div>`, v => v.onclick = e => e.target.closest("[data-import]") && importDialog(overview));
    const sevData = SEV_ORDER.map(k => ({ key: k, value: d.severity[k], color: SEV_COL[k] }));
    const envData = d.by_environment.sort((a, b) => b.open - a.open).map(e => ({ key: e.environment, value: e.open, label: `${e.open} · avg ${e.avg_score ?? "n/a"}`, tip: `${e.environment}: ${e.open} open, ${e.critical_high} critical/high, avg priority ${e.avg_score ?? "incomplete"}`, color: e.critical_high ? "#b3261e" : "#1f4e8c" }));
    const age = d.aging.map((a, i) => ({ key: a.bucket, value: a.count, color: ["#2f6fb3", "#4a86c2", "#c99a06", "#d9730d", "#b3261e"][i] }));
    const hidden = new Set(); const trendHtml = () => lines(d.trend.map(t => t.week), [{ key: "open", name: "Open backlog", color: "#0b1f3a", values: d.trend.map(t => t.open) }, { key: "new", name: "New", color: "#d9730d", values: d.trend.map(t => t.new) }, { key: "res", name: "Verified resolved", color: "#1f8a5b", values: d.trend.map(t => t.resolved) }], { hidden });
    const row = f => html`<tr data-fid="${f.id}" class="click"><td>${sev(f.sev)}</td><td class="trunc">${f.name}<br><small class="muted">${f.host} · ${f.port}</small></td><td>${catBadge(f.risk)}</td><td>${dueCell(f)}</td></tr>`;
    render(html`${pageHead("Overview", "Evidence-based exposure, verified remediation, and SLA status", "globe", importCta())}
    <div class="kpis">
      ${kpi("Open findings", m.total_open, `${m.incomplete_assessments} with incomplete risk evidence`, "", "#/vulns?status=open")}
      ${kpi("Critical / High", html`<span class="c-crit">${m.open_critical}</span> / <span class="c-high">${m.open_high}</span>`, "by CVSS severity (open)", "", "#/vulns?status=open&severity=Critical")}
      ${kpi("Affected assets", m.affected_assets, "with at least one open finding", "", "#/assets")}
      ${kpi("Overdue", m.overdue, "past SLA deadline", m.overdue ? "alert" : "", "#/vulns?status=open&overdue=1")}
      ${kpi("Awaiting verification", m.awaiting_verification, "fixed, not yet proven", "", "#/remediation")}
      ${kpi("Verified remediation", m.verified_rate == null ? "—" : m.verified_rate + "%", `${m.verified_count} verified · ${m.awaiting_verification} pending proof`, "", "#/vulns?status=Verified Resolved")}
      ${kpi("Latest complete scan", ls ? "#" + ls.id : "none", ls ? `${ls.source_type} · ${ago(ls.imported_at)}` : "only partial/failed scans so far", "", "#/scans")}
      ${kpi("Since previous scan", html`+${m.new_since_previous} / −${m.resolved_since_previous}`, "new / verified resolved", "", "#/scans")}
    </div>
    <div class="grid3">
      <section class="card tilt big"><h3>Open findings by severity</h3><p class="hint">Click a segment to filter</p>${donut(sevData, { label: "open findings" })}<i class="glare"></i></section>
      <section class="card tilt big"><h3>Risk by environment</h3><p class="hint">Open findings; red = has critical/high</p>${bars(envData, { horizontal: true })}${envData.length ? "" : html`<p class="muted">No environment data. Set asset environments on the Assets page.</p>`}<i class="glare"></i></section>
      <section class="card tilt big"><h3>Vulnerability aging</h3><p class="hint">Days since first seen (open)</p>${bars(age, { w: 340 })}<i class="glare"></i></section>
    </div>
    <section class="card tilt big"><h3>Remediation trend · 12 weeks</h3><p class="hint">Verified resolved counts only fixes proven by re-scan or independent evidence</p><div id="trend">${trendHtml()}</div><i class="glare"></i></section>
    <div class="grid2">
      <section class="card"><h3>Priority remediation queue</h3><p class="hint">Ranked by internal priority score (not CVSS). Hover badges for confidence.</p><table class="dt"><thead><tr><th>CVSS sev.</th><th>Finding</th><th>Priority</th><th>SLA</th></tr></thead><tbody>${d.queue.map(row)}</tbody></table>${d.queue.length ? "" : html`<p class="muted pad">Nothing open.</p>`}</section>
      <section class="card"><h3>Upcoming SLA deadlines</h3><p class="hint">Next 14 days</p><table class="dt"><thead><tr><th>CVSS sev.</th><th>Finding</th><th>Priority</th><th>SLA</th></tr></thead><tbody>${d.upcoming.map(row)}</tbody></table>${d.upcoming.length ? "" : html`<p class="muted pad">No deadlines in the next 14 days.</p>`}</section>
    </div>
    <section class="card"><h3>Recent scan activity</h3><table class="dt"><thead><tr><th>Scan</th><th>Source</th><th>Imported</th><th>Parsed</th><th>Rejected</th><th>Status</th></tr></thead><tbody>${d.recent_scans.map(s => html`<tr><td>#${s.id}</td><td>${s.source_type}</td><td>${fdt(s.imported_at)}</td><td>${s.parsed_count}</td><td>${s.rejected_count}</td><td><span class="badge scan-${s.status.toLowerCase()}">${s.status}</span></td></tr>`)}</tbody></table></section>`,
    v => { bindTips(v);
      v.onclick = e => { const k = e.target.closest("[data-key]")?.dataset.key, t = e.target.closest("[data-fid]"), s = e.target.closest("[data-series]");
        if (e.target.closest("[data-import]")) return importDialog(overview); if (t) return go("#/vulns/" + t.dataset.fid);
        if (s) { hidden.has(s.dataset.series) ? hidden.delete(s.dataset.series) : hidden.add(s.dataset.series); $("#trend", v).innerHTML = String(trendHtml()); return; }
        if (!k) return; const sec = e.target.closest("section").querySelector("h3").textContent;
        if (sec.startsWith("Open findings")) go(`#/vulns?status=open&severity=${k}`); else if (sec.startsWith("Risk")) go(`#/vulns?status=open&environment=${encodeURIComponent(k)}`);
        else { const b = { "0-7d": [0, 7], "8-30d": [8, 30], "31-60d": [31, 60], "61-90d": [61, 90], "90d+": [91, ""] }[k]; go(`#/vulns?age_min=${b[0]}&age_max=${b[1]}`); } };
      v.onkeydown = e => { if (e.key === "Enter") e.target.click?.(); }; });
  });
}

/* ================= Vulnerabilities ================= */
const TRANS = { "Open": ["Triaged", "In Progress", "Fixed — Pending Verification"], "Triaged": ["Open", "In Progress", "Fixed — Pending Verification"], "In Progress": ["Triaged", "Fixed — Pending Verification"], "Fixed — Pending Verification": ["Verified Resolved", "Reopened", "In Progress"], "Verified Resolved": ["Reopened"], "Risk Accepted": ["Reopened"], "Reopened": ["Triaged", "In Progress", "Fixed — Pending Verification"] };
export async function vulns(parts, query) {
  const st = { page: 1, per_page: 25, sort: "risk", dir: "desc", q: "", severity: "", status: "", asset: "", environment: "", cve: "", overdue: "", category: "", age_min: "", age_max: "", ...query };
  let assets = []; try { assets = await api("/api/assets"); } catch { }
  const cols = [["id", "ID"], ["cve", "CVE"], ["name", "Vulnerability"], ["cvss", "CVSS"], ["sev", "CVSS sev."], ["host", "Asset · service"], ["first_seen", "First / last seen"], ["risk", "Priority"], ["owner", "Owner"], ["due_date", "SLA deadline"], ["status", "Status"]];
  render(html`${pageHead("Vulnerability Intelligence", "Every finding with its evidence, explainable priority, owner, and SLA", "network", html`${can("finding.create") ? html`<button class="btn" data-new>＋ Add finding</button>` : ""}<button class="btn" data-csv>⬇ Export CSV</button>${importCta()}`)}
  <div class="kpis small" id="vk"></div>
  <section class="card"><form class="filters" id="flt">
    <input type="search" name="q" placeholder="Search ID, title, CVE, host…" value="${st.q}" aria-label="Search findings">
    ${sel("severity", SEV_ORDER, st.severity, "All severities")}${sel("status", [["open", "All open"], ...STATUSES], st.status, "Any status")}
    ${sel("environment", ["Production", "Staging", "Development", "Lab", "Unassigned"], st.environment, "All environments")}
    ${sel("asset", assets.map(a => [a.id, a.asset_key]), st.asset, "All assets")}${sel("category", ["Critical", "High", "Medium", "Low", "Incomplete"], st.category, "Any priority")}
    <input name="cve" placeholder="CVE-…" value="${st.cve}" size="14" aria-label="CVE filter"><label class="chk"><input type="checkbox" name="overdue" ${raw(st.overdue ? "checked" : "")}> Overdue</label><button type="button" class="btn ghost" data-reset>Reset</button></form>
    ${st.age_min !== "" || st.age_max !== "" ? html`<div class="chipbar"><span class="chip">Age ${st.age_min}–${st.age_max || "∞"} days <button data-clearage aria-label="Clear age filter">✕</button></span></div>` : ""}
    <div class="tw" id="tbl">${skeleton(5)}</div><div id="pg"></div></section>`);
  const root = view();
  const load = async () => {
    const r = $("#tbl", root); if (!r) return; const q = { page: st.page, per_page: st.per_page, sort: st.sort, dir: st.dir, ...Object.fromEntries(["q", "severity", "status", "asset", "environment", "cve", "category", "age_min", "age_max"].map(k => [k, st[k]])), overdue: st.overdue };
    history.replaceState(null, "", "#/vulns" + qs(Object.fromEntries(Object.entries(st).filter(([k, v]) => v && !["page", "per_page", "sort", "dir"].includes(k)))));
    let d; try { d = await api("/api/findings" + qs(q)); } catch (e) { r.innerHTML = String(errorBox(e.message, true)); return; }
    r.innerHTML = String(d.items.length ? html`<table class="dt"><thead><tr>${cols.map(([k, l]) => html`<th><button class="sortb" data-sort="${k}" aria-sort="${st.sort === k ? (st.dir === "asc" ? "ascending" : "descending") : "none"}">${l}${st.sort === k ? (st.dir === "asc" ? " ▲" : " ▼") : ""}</button></th>`)}</tr></thead><tbody>${d.items.map(f => html`<tr class="click" data-fid="${f.id}" tabindex="0">
      <td><code>${shortId(f.id)}</code></td><td>${f.cve ? f.cve.split(",")[0] : html`<span class="muted">—</span>`}${f.cve && f.cve.includes(",") ? html` <small>+${f.cve.split(",").length - 1}</small>` : ""}</td><td class="trunc" title="${f.name}">${f.name}</td>
      <td>${f.cvss_source && !f.cvss_source.startsWith("Heuristic") && f.cvss_source !== "None" ? html`<b>${f.cvss.toFixed(1)}</b><br><small class="muted">${f.cvss_source.replace(" reported", "").replace("Nmap script output", "Nmap")}</small>` : html`<span class="muted" title="${f.cvss_source}">${f.cvss_source.startsWith("Heuristic") ? "est. " + f.cvss.toFixed(1) : "n/a"}</span><br><small class="muted">${f.cvss_source.startsWith("Heuristic") ? "not CVSS" : ""}</small>`}</td>
      <td>${sev(f.sev)}</td><td>${f.host}<br><small class="muted">${f.port}${f.service ? " · " + f.service.slice(0, 24) : ""}</small></td><td><small>${fdate(f.first_seen)}<br>${fdate(f.last_seen)}</small></td><td>${catBadge(f.risk)}</td>
      <td>${f.owner_name || html`<span class="muted">unassigned</span>`}</td><td>${dueCell(f)}</td><td>${stBadge(f.status)}</td></tr>`)}</tbody></table>` : empty("No findings match", "Adjust or reset the filters, or import a scan.", html`<button class="btn" data-reset>Reset filters</button>`));
    $("#pg", root).innerHTML = String(pager(d.page, d.per_page, d.total, d.pages));
    startHeroes(r);
  };
  api("/api/overview").then(o => { const m = o.metrics; $("#vk", root).innerHTML = String(html`${kpi("Open", m.total_open, "")}${kpi("Critical open", m.open_critical, "")}${kpi("Overdue", m.overdue, "")}${kpi("Incomplete evidence", m.incomplete_assessments, "priority is provisional")}`); }).catch(() => { });
  const refresh = debounce(() => { const f = formData($("#flt", root)); Object.assign(st, { q: f.q || "", severity: f.severity || "", status: f.status || "", environment: f.environment || "", asset: f.asset || "", category: f.category || "", cve: f.cve || "", overdue: f.overdue ? "1" : "", page: 1 }); load(); }, 220);
  $("#flt", root).addEventListener("input", refresh); $("#flt", root).addEventListener("submit", e => e.preventDefault());
  root.onclick = e => { const t = e.target;
    if (t.closest("[data-import]")) return importDialog(() => load()); if (t.closest("[data-new]")) return newFindingDialog(() => load());
    if (t.closest("[data-csv]")) return void (location.href = "/api/reports/inventory.csv" + qs({ severity: st.severity, status: st.status === "open" ? "" : st.status, environment: st.environment, asset: st.asset, cve: st.cve }));
    if (t.closest("[data-reset]")) { Object.assign(st, { q: "", severity: "", status: "", asset: "", environment: "", cve: "", overdue: "", category: "", age_min: "", age_max: "", page: 1 }); return vulns(parts, {}); }
    if (t.closest("[data-clearage]")) { st.age_min = st.age_max = ""; return vulns(parts, { ...st }); }
    const s = t.closest("[data-sort]"); if (s) { const k = s.dataset.sort; st.dir = st.sort === k && st.dir === "desc" ? "asc" : "desc"; st.sort = k; return load(); }
    const p = t.closest("[data-pg]"); if (p) { st.page = +p.dataset.pg; return load(); }
    const f = t.closest("[data-fid]"); if (f) openFinding(f.dataset.fid, load); if (t.closest("[data-retry]")) load(); };
  root.onchange = e => { if (e.target.matches("[data-pp]")) { st.per_page = +e.target.value; st.page = 1; load(); } };
  root.onkeydown = e => { if (e.key === "Enter" && e.target.matches("tr[data-fid]")) openFinding(e.target.dataset.fid, load); };
  load(); if (parts[0]) openFinding(parts[0], load);
}
function newFindingDialog(done) {
  modal({ title: "Add finding manually", body: html`<form class="grid2">${field("Host / IP *", html`<input name="host" required>`)}${field("Port (e.g. 443/tcp)", html`<input name="port">`)}${field("Title *", html`<input name="name" required maxlength="300">`)}${field("CVE (optional)", html`<input name="cve" placeholder="CVE-2024-12345">`)}
    ${field("CVSS (only if you have a source)", html`<input name="cvss" type="number" min="0" max="10" step="0.1">`, "Leave blank if unknown. A blank score is shown as incomplete, never guessed.")}${field("Severity", sel("severity", SEV_ORDER, "", "Derive from CVSS"))}${field("Evidence", html`<textarea name="evidence" rows="3"></textarea>`)}${field("Suggested remediation", html`<textarea name="remediation" rows="3"></textarea>`)}</form>`,
    wide: true, actions: [{ label: "Cancel" }, { label: "Create finding", cls: "primary", onClick: async w => { const f = formData(w); await api("/api/findings", { method: "POST", json: f }); toast("Finding created", "success"); done(); } }] });
}

/* ================= Finding detail drawer ================= */
export async function openFinding(id, onChange) {
  const dr = drawer("Finding " + shortId(id), skeleton(6)); dr.body.innerHTML = String(skeleton(6)); history.replaceState(null, "", "#/vulns/" + id + (location.hash.includes("?") ? "?" + location.hash.split("?")[1] : ""));
  const draw = async (tab = "summary") => {
    let f; try { f = await api("/api/findings/" + encodeURIComponent(id)); } catch (e) { dr.body.innerHTML = String(errorBox(e.message)); return; }
    dr.setTitle(f.name.slice(0, 70)); const r = f.risk, mine = f.owner_id === S.user.id, canAct = can("finding.status") || (can("finding.status_own") && mine);
    const tabs = ["summary", "evidence", "risk", "history", "related"], T = tab;
    const body = { summary: html`<dl class="kv"><dt>Status</dt><dd>${stBadge(f.status)} ${f.verification_method ? html`<small class="muted">verified by ${f.verification_method === "rescan" ? "re-scan #" + f.verification_scan_id : "manual evidence"}</small>` : ""}</dd><dt>CVSS severity</dt><dd>${sev(f.sev)} ${f.cvss_source.startsWith("Heuristic") ? html`<small class="warn">heuristic estimate ${f.cvss.toFixed(1)}: NOT a CVSS score</small>` : f.cvss_source === "None" ? html`<small class="muted">no score</small>` : html`<b>${f.cvss.toFixed(1)}</b> <small class="muted">source: ${f.cvss_source}${f.cvss_vector ? " · vector " + f.cvss_vector : ""}</small>`}</dd>
      <dt>Internal priority</dt><dd>${catBadge(r)} <small class="muted">(${r.confidence} confidence; not a CVSS score)</small></dd><dt>Asset</dt><dd><a href="#/assets/${f.asset_id}">${f.host}</a> ${f.hostname ? "(" + f.hostname + ")" : ""} · ${f.port} ${f.service ? "· " + f.service : ""} · ${f.environment}</dd>
      <dt>Source scan</dt><dd>${f.first_scan?.id ? html`#${f.first_scan.id} ${f.first_scan.source_type} · imported ${fdt(f.first_scan.imported_at)}` : "manual entry"} <br><small class="muted">First seen ${fdt(f.first_seen)} · last seen ${fdt(f.last_seen)} · seen in ${f.scans.length} scan(s)</small></dd>
      <dt>Owner / deadline</dt><dd>${f.owner_name || "Unassigned"} · ${dueCell(f)}</dd><dt>CVE</dt><dd>${f.cve_info.length ? f.cve_info.map(c => html`<div><b>${c.cve}</b> ${c.kev ? html`<span class="badge cat-critical">In CISA KEV (imported)</span> <small>${c.kev.name}</small>` : html`<small class="muted">not in imported KEV catalogue</small>`} · <a href="${c.reference}" target="_blank" rel="noopener noreferrer">NVD lookup ↗</a></div>`) : html`<span class="muted">none reported</span>`}</dd>
      <dt>Suggested remediation</dt><dd>${f.rem}</dd>${f.description ? html`<dt>Description</dt><dd>${f.description}</dd>` : ""}<dt>OWASP</dt><dd>${f.owasp}</dd></dl>`,
      evidence: html`<p class="hint">Original scanner output, displayed as inert text.</p><pre class="evidence">${f.evidence || "(no evidence text stored)"}</pre><h4>Scans that observed this finding</h4><ul>${f.scans.map(s => html`<li>#${s.id} · ${s.source_type} · ${fdt(s.imported_at)} · ${s.status} · ${s.filename || ""}</li>`)}</ul>`,
      risk: html`<div class="riskbox"><div class="score">${r.score == null ? "—" : r.score}<small>/100 ${r.provisional ? "provisional" : ""}</small></div><div>${catBadge(r)}<p class="muted">Confidence <b>${r.confidence}</b> (${Math.round(r.confidence_ratio * 100)}% of weighted evidence available)</p></div></div>
      <h4>Why this priority</h4>${r.factors.length ? html`<ul class="fac">${r.factors.map(x => html`<li>▲ ${x}</li>`)}</ul>` : html`<p class="muted">No factors elevate risk beyond baseline.</p>`}
      <h4>Missing evidence</h4>${r.missing.length ? html`<ul class="miss">${r.missing.map(x => html`<li>? ${x}</li>`)}</ul>` : html`<p class="muted">Assessment is complete.</p>`}
      <h4>Recommended next action</h4><p class="nextact">${r.next_action}</p><h4>Component values (0–1)</h4><div class="comps">${Object.entries(r.components).map(([k, v]) => html`<div><span>${k}</span><div class="bar"><i style="width:${v * 100}%"></i></div><b>${v}</b></div>`)}</div>
      <p class="hint">Formula and limitations: docs/SCORING.md. Exploit status: <b>${f.exploit_status}</b>${f.exploit_evidence ? " · " + f.exploit_evidence : ""}</p>`,
      history: html`<ol class="timeline">${f.history.map(h => html`<li><b>${h.kind}</b> ${h.from_value || h.to_value ? html`${h.from_value || ""} → <b>${h.to_value || ""}</b>` : ""}<br><small class="muted">${fdt(h.at)} · ${h.actor_name || "system"}</small>${h.note ? html`<p>${h.note}</p>` : ""}${h.evidence_ref ? html`<small>Evidence: ${h.evidence_ref}</small>` : ""}</li>`)}</ol>${f.audit ? html`<h4>Audit events</h4><table class="dt"><tbody>${f.audit.map(a => html`<tr><td>${fdt(a.at)}</td><td>${a.actor_name}</td><td>${a.action}</td></tr>`)}</tbody></table>` : ""}`,
      related: f.related.length ? html`<table class="dt"><tbody>${f.related.map(x => html`<tr class="click" data-rel="${x.id}"><td>${sev(x.sev)}</td><td>${x.name}<br><small class="muted">${x.host} · ${x.port}</small></td><td>${stBadge(x.status)}</td><td><small>${x.reason}</small></td></tr>`)}</tbody></table>` : html`<p class="muted">No related or duplicate findings.</p>` }[T];
    const acts = [];
    if (canAct) (TRANS[f.status] || []).forEach(t => { if (t === "Verified Resolved" && !can("finding.verify")) return; acts.push(html`<button class="btn sm" data-to="${t}">${t === "Verified Resolved" ? "✔ Verify fix" : "→ " + t}</button>`); });
    if (can("finding.assign")) acts.push(html`<button class="btn sm" data-assign>Assign / deadline</button>`);
    if (can("finding.exploit")) acts.push(html`<button class="btn sm" data-exploit>Exploit evidence</button>`);
    if (can("finding.note") || (S.user.role === "owner" && mine)) acts.push(html`<button class="btn sm" data-note>＋ Note</button>`);
    if (can("exception.request") && !["Verified Resolved", "Risk Accepted"].includes(f.status) && (S.user.role !== "owner" || mine)) acts.push(html`<button class="btn sm" data-exc>Request risk exception</button>`);
    dr.body.innerHTML = String(html`<div class="tabs">${tabs.map(t => html`<button class="${t === T ? "on" : ""}" data-tab="${t}">${t}</button>`)}</div><div class="tabbody">${body}</div><div class="dr-actions">${acts}</div>`);
    dr.body.onclick = async e => { const b = e.target.closest("button,[data-rel]"); if (!b) return;
      if (b.dataset.tab) return draw(b.dataset.tab); if (b.dataset.rel) { dr.close(); return openFinding(b.dataset.rel, onChange); }
      const after = async () => { await draw(T); onChange && onChange(); };
      if (b.dataset.to) return transitionDialog(f, b.dataset.to, after); if ("assign" in b.dataset) return assignDialog(f, after); if ("exploit" in b.dataset) return exploitDialog(f, after); if ("note" in b.dataset) return noteDialog(f, after); if ("exc" in b.dataset) return exceptionDialog(f.id, after); };
  }; draw();
}
function transitionDialog(f, to, done) {
  const ver = to === "Verified Resolved", need = to.startsWith("Fixed") ? "Describe the remediation performed (min 10 chars)" : ver ? "How was the fix verified? (min 10 chars)" : (to === "Reopened" || to === "Open") ? "Reason (required)" : "Note (optional)";
  modal({ title: `${f.status} → ${to}`, body: html`<form>${ver ? html`<div class="info">Verification should rest on independent evidence (a re-scan or retest), and must be done by someone other than the person who marked it fixed. The platform also verifies automatically when a later complete scan no longer shows the finding.</div>` : ""}${field(need, html`<textarea name="note" rows="3"></textarea>`)}${ver || to.startsWith("Fixed") ? field(ver ? "Evidence reference *" : "Evidence / change reference", html`<input name="evidence" placeholder="CHG-1042, scan #12, ticket URL…">`) : ""}</form>`,
    actions: [{ label: "Cancel" }, { label: "Apply", cls: "primary", onClick: async w => { await api(`/api/findings/${encodeURIComponent(f.id)}/transition`, { method: "POST", json: { to, ...formData(w) } }); toast("Status updated", "success"); done(); } }] });
}
async function assignDialog(f, done) {
  const users = await api("/api/users"); modal({ title: "Assign owner & deadline", body: html`<form>${field("Remediation owner", sel("owner_id", users.filter(u => u.role !== "auditor").map(u => [u.id, `${u.display_name || u.username} (${u.role})`]), f.owner_id || "", "Unassigned"))}${field("Deadline (default comes from SLA policy)", html`<input type="date" name="due_date" value="${f.due_date || ""}">`)}${field("Note", html`<input name="note" maxlength="300">`)}</form>`,
    actions: [{ label: "Cancel" }, { label: "Save", cls: "primary", onClick: async w => { const x = formData(w); await api(`/api/findings/${encodeURIComponent(f.id)}/assign`, { method: "POST", json: { owner_id: x.owner_id ? +x.owner_id : null, due_date: x.due_date, note: x.note } }); toast("Assignment saved", "success"); done(); } }] });
}
function exploitDialog(f, done) {
  modal({ title: "Exploit evidence", body: html`<form><div class="info">Only record what you can reference. "Unknown" stays missing evidence; it is not treated as "safe".</div>${field("Determination", sel("status", ["Unknown", "None known", "Public exploit reference", "Exploit confirmed (evidence)"], f.exploit_status))}${field("Evidence / source", html`<textarea name="evidence" rows="3" placeholder="Advisory URL, PoC reference, lab test ID…">${f.exploit_evidence || ""}</textarea>`)}</form>`,
    actions: [{ label: "Cancel" }, { label: "Save", cls: "primary", onClick: async w => { await api(`/api/findings/${encodeURIComponent(f.id)}/exploit`, { method: "POST", json: formData(w) }); toast("Exploit status saved", "success"); done(); } }] });
}
function noteDialog(f, done) { modal({ title: "Add investigation / remediation note", body: html`<form>${field("Note", html`<textarea name="note" rows="4"></textarea>`)}${field("Evidence reference (optional)", html`<input name="evidence">`)}</form>`, actions: [{ label: "Cancel" }, { label: "Add note", cls: "primary", onClick: async w => { await api(`/api/findings/${encodeURIComponent(f.id)}/note`, { method: "POST", json: formData(w) }); toast("Note added", "success"); done(); } }] }); }
export function exceptionDialog(fid, done) {
  const d = new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);
  modal({ title: "Request risk exception", wide: true, body: html`<form class="grid2">${field("Finding ID", html`<input name="finding_id" value="${fid || ""}" ${raw(fid ? "readonly" : "")} required>`)}${field("Expires *", html`<input type="date" name="expires_at" value="${d}" required>`, "Max 365 days. Expiry forces re-review.")}${field("Business justification * (min 20 chars)", html`<textarea name="justification" rows="4"></textarea>`)}${field("Compensating controls * (min 10 chars)", html`<textarea name="compensating_controls" rows="4"></textarea>`)}</form><p class="hint">An exception records accepted risk. It never counts as a fix.</p>`,
    actions: [{ label: "Cancel" }, { label: "Submit request", cls: "primary", onClick: async w => { await api("/api/exceptions", { method: "POST", json: formData(w) }); toast("Exception submitted for approval", "success"); done && done(); } }] });
}

/* ================= Assets ================= */
export async function assets(parts) {
  if (parts[0]) return assetDetail(+parts[0]);
  render(html`${pageHead("Asset Explorer", "Inventory, ownership, and aggregated risk per asset", "cube")}${skeleton(5)}`);
  await guard(async () => {
    let rows = await api("/api/assets"), env = "", q = "";
    const draw = () => { const list = rows.filter(a => (!env || a.environment === env) && (!q || (a.asset_key + a.hostname).toLowerCase().includes(q.toLowerCase())));
      $("#atbl").innerHTML = String(list.length ? html`<table class="dt"><thead><tr><th>Asset</th><th>Hostname / IP</th><th>Environment</th><th>Owner</th><th>Criticality</th><th>Internet exposure</th><th>Last scan</th><th>Open</th><th>Highest sev.</th><th>Overall risk</th></tr></thead><tbody>${list.map(a => html`<tr class="click" data-aid="${a.id}" tabindex="0"><td><b>A-${a.id}</b></td><td>${a.hostname || "—"}<br><small class="muted">${a.ip || a.asset_key}</small></td><td>${a.environment}</td><td>${a.owner_name || html`<span class="muted">unassigned</span>`}</td><td>${a.criticality === "Unrated" ? html`<span class="muted">Unrated</span>` : a.criticality}</td><td>${a.internet_exposure === "Unknown" ? html`<span class="muted" title="Not established by data">Unknown</span>` : a.internet_exposure}</td><td>${ago(a.last_scan)}</td><td>${a.open_findings}${a.overdue ? html` <small class="c-crit">(${a.overdue} overdue)</small>` : ""}</td><td>${a.highest_severity ? sev(a.highest_severity) : "—"}</td><td><div class="meter" title="${a.overall_risk}/100"><i style="width:${a.overall_risk}%"></i></div></td></tr>`)}</tbody></table>` : empty("No assets", "Assets are created automatically when you import scans.", can("upload") ? html`<button class="btn primary" data-import>⬆ Import scan</button>` : ""));
    };
    render(html`${pageHead("Asset Explorer", "Inventory, ownership, and aggregated risk per asset", "cube", importCta())}
      <div class="kpis small">${kpi("Assets", rows.length, "")}${kpi("With open findings", rows.filter(a => a.open_findings).length, "")}${kpi("Internet-facing (established)", rows.filter(a => a.internet_exposure === "Internet-facing").length, "only counted when stated with a source")}${kpi("Criticality not set", rows.filter(a => a.criticality === "Unrated").length, "lowers risk confidence")}</div>
      <section class="card"><div class="filters"><input type="search" id="aq" placeholder="Search assets…" aria-label="Search assets">${sel("env", ["Production", "Staging", "Development", "Lab", "Unassigned"], "", "All environments")}</div><div class="tw" id="atbl"></div></section>`, v => {
      draw(); $("#aq", v).oninput = e => { q = e.target.value; draw(); }; $("select", v).onchange = e => { env = e.target.value; draw(); };
      v.onclick = e => { const r = e.target.closest("[data-aid]"); if (r) go("#/assets/" + r.dataset.aid); if (e.target.closest("[data-import]")) importDialog(() => assets([])); }; });
  });
}
async function assetDetail(id) {
  render(skeleton(6)); await guard(async () => {
    const d = await api("/api/assets/" + id), a = d.asset, users = await api("/api/users"), edit = can("asset.edit");
    render(html`${pageHead(a.hostname || a.asset_key, `Asset A-${a.id} · ${a.ip || a.asset_key}`, "cube", html`<a class="btn" href="#/assets">← All assets</a>`)}
    <div class="kpis small">${kpi("Open findings", a.open_findings, "")}${kpi("Highest severity", a.highest_severity || "—", "")}${kpi("Overall risk", a.overall_risk, "internal 0–100; not CVSS")}${kpi("Incomplete assessments", a.incomplete, "need asset context")}</div>
    <div class="grid2"><section class="card"><h3>Asset context</h3><p class="hint">Risk scoring uses only what is recorded here. Unknown values are treated as missing evidence.</p>
      <form id="af" class="fgrid">${field("Environment", sel("environment", ["Production", "Staging", "Development", "Lab", "Unassigned"], a.environment))}${field("Business criticality", sel("criticality", ["Critical", "High", "Medium", "Low", "Unrated"], a.criticality))}
      ${field("Business importance", sel("business_importance", ["Mission-critical", "Important", "Supporting", "Unrated"], a.business_importance))}${field("Internet exposure", sel("internet_exposure", ["Unknown", "Internal", "Internet-facing"], a.internet_exposure))}
      ${field("Exposure source (required if known)", html`<input name="exposure_source" value="${a.exposure_source || ""}" placeholder="external scan, firewall review…">`)}${field("Owner", sel("owner_id", users.filter(u => u.role !== "auditor").map(u => [u.id, u.display_name || u.username]), a.owner_id || "", "Unassigned"))}
      ${field("Notes", html`<textarea name="notes" rows="2">${a.notes || ""}</textarea>`)}${edit ? html`<button type="submit" class="btn primary">Save changes (audited)</button>` : html`<p class="muted">Read-only for your role.</p>`}</form></section>
      <section class="card"><h3>Scan history</h3><table class="dt"><thead><tr><th>Scan</th><th>Source</th><th>Date</th><th>Findings seen</th><th>Status</th></tr></thead><tbody>${d.scan_history.map(s => html`<tr><td>#${s.id}</td><td>${s.source_type}</td><td>${fdt(s.imported_at)}</td><td>${s.n}</td><td><span class="badge scan-${s.status.toLowerCase()}">${s.status}</span></td></tr>`)}</tbody></table></section></div>
    <section class="card"><h3>Vulnerability history & related findings (${d.findings.length})</h3>${d.findings.length ? html`<table class="dt"><thead><tr><th>CVSS sev.</th><th>Finding</th><th>Priority</th><th>First seen</th><th>Status</th></tr></thead><tbody>${d.findings.map(f => html`<tr class="click" data-fid="${f.id}"><td>${sev(f.sev)}</td><td>${f.name}<br><small class="muted">${f.port}</small></td><td>${catBadge(f.risk)}</td><td>${fdate(f.first_seen)}</td><td>${stBadge(f.status)}</td></tr>`)}</tbody></table>` : html`<p class="muted pad">No findings recorded.</p>`}</section>`, v => {
      v.onclick = e => { const r = e.target.closest("[data-fid]"); if (r) openFinding(r.dataset.fid, () => assetDetail(id)); };
      const f = $("#af", v); if (!edit) $$("input,select,textarea", f).forEach(i => i.disabled = true);
      f.onsubmit = async e => { e.preventDefault(); const x = formData(f); try { await api("/api/assets/" + id, { method: "PATCH", json: { ...x, owner_id: x.owner_id ? +x.owner_id : null } }); toast("Asset updated and audited", "success"); assetDetail(id); } catch (er) { toast(er.message, "error"); } }; });
  });
}
