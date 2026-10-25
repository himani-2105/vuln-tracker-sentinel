/* Lightweight SVG charts. No libraries. Each chart supports hover tooltips and click callbacks. */
import { html, esc, raw, $ } from "./core.js";
export const SEV_COL = { Critical: "#b3261e", High: "#d9730d", Medium: "#c99a06", Low: "#2f6fb3", Info: "#8a97a8" };
let tip; const tipEl = () => tip || (tip = Object.assign(document.body.appendChild(document.createElement("div")), { className: "chart-tip" }));
export function bindTips(root) {
  root.addEventListener("pointermove", e => { const t = e.target.closest("[data-tip]"); const el = tipEl(); if (!t) { el.style.opacity = 0; return; } el.textContent = t.dataset.tip; el.style.opacity = 1; el.style.left = Math.min(e.clientX + 14, innerWidth - 220) + "px"; el.style.top = e.clientY + 14 + "px"; });
  root.addEventListener("pointerleave", () => { tipEl().style.opacity = 0; });
}
export function donut(data, { center = "", label = "open" } = {}) {
  const tot = data.reduce((a, d) => a + d.value, 0), R = 62, r = 40; let a0 = -Math.PI / 2;
  const arcs = data.filter(d => d.value > 0).map(d => { const a1 = a0 + (d.value / tot) * Math.PI * 2 - (data.filter(x => x.value > 0).length > 1 ? .02 : 0), big = a1 - a0 > Math.PI ? 1 : 0, P = (rr, a) => `${(80 + rr * Math.cos(a)).toFixed(2)} ${(80 + rr * Math.sin(a)).toFixed(2)}`;
    const p = tot === d.value ? `M80 ${80 - R} A${R} ${R} 0 1 1 79.99 ${80 - R} L79.99 ${80 - r} A${r} ${r} 0 1 0 80 ${80 - r}Z` : `M${P(R, a0)} A${R} ${R} 0 ${big} 1 ${P(R, a1)} L${P(r, a1)} A${r} ${r} 0 ${big} 0 ${P(r, a0)}Z`; a0 += (d.value / tot) * Math.PI * 2;
    return html`<path d="${p}" fill="${d.color}" class="seg" data-key="${d.key}" data-tip="${d.key}: ${d.value} (${Math.round(d.value / tot * 100)}%)" tabindex="0" role="button" aria-label="${d.key}: ${d.value}"/>`; });
  return html`<div class="donut"><svg viewBox="0 0 160 160" role="img" aria-label="Severity distribution">${arcs}<text x="80" y="78" text-anchor="middle" class="d-num">${tot}</text><text x="80" y="94" text-anchor="middle" class="d-lab">${label}</text></svg>
  <ul class="legend">${data.map(d => html`<li data-key="${d.key}" tabindex="0"><i style="background:${d.color}"></i>${d.key}<b>${d.value}</b></li>`)}</ul></div>`;
}
export function bars(data, { w = 420, h = 190, horizontal = false, max } = {}) {
  const m = max || Math.max(1, ...data.map(d => d.value));
  if (horizontal) { const rh = Math.min(30, (h - 10) / Math.max(1, data.length)); return html`<svg viewBox="0 0 ${w} ${data.length * rh + 10}" class="chart" role="img">${data.map((d, i) => html`<g class="bar" data-key="${d.key}" data-tip="${d.tip || d.key + ": " + d.value}" tabindex="0" role="button"><text x="0" y="${i * rh + rh * .62 + 4}" class="ax">${d.key}</text><rect x="110" y="${i * rh + 4}" width="${Math.max(2, (w - 270) * d.value / m)}" height="${rh - 8}" rx="3" fill="${d.color || "#1f4e8c"}"/><text x="${116 + Math.max(2, (w - 270) * d.value / m)}" y="${i * rh + rh * .62 + 4}" class="val">${d.label ?? d.value}</text></g>`)}</svg>`; }
  const bw = (w - 30) / data.length;
  return html`<svg viewBox="0 0 ${w} ${h}" class="chart" role="img"><line x1="24" x2="${w}" y1="${h - 24}" y2="${h - 24}" class="axl"/>${data.map((d, i) => { const bh = (h - 52) * d.value / m; return html`<g class="bar" data-key="${d.key}" data-tip="${d.tip || d.key + ": " + d.value}" tabindex="0" role="button"><rect x="${28 + i * bw + bw * .15}" y="${h - 24 - bh}" width="${bw * .7}" height="${Math.max(bh, 1)}" rx="3" fill="${d.color || "#1f4e8c"}"/><text x="${28 + i * bw + bw / 2}" y="${h - 8}" text-anchor="middle" class="ax">${d.key}</text><text x="${28 + i * bw + bw / 2}" y="${h - 28 - bh}" text-anchor="middle" class="val">${d.value}</text></g>`; })}</svg>`;
}
export function lines(labels, series, { w = 640, h = 220, hidden = new Set() } = {}) {
  const vis = series.filter(s => !hidden.has(s.key)), m = Math.max(1, ...vis.flatMap(s => s.values)), X = i => 36 + i * (w - 52) / Math.max(1, labels.length - 1), Y = v => h - 30 - (h - 54) * v / m;
  const grid = [0, .25, .5, .75, 1].map(t => html`<line x1="36" x2="${w - 16}" y1="${Y(m * t)}" y2="${Y(m * t)}" class="grid"/><text x="30" y="${Y(m * t) + 4}" text-anchor="end" class="ax">${Math.round(m * t)}</text>`);
  const paths = vis.map(s => { const d = s.values.map((v, i) => `${i ? "L" : "M"}${X(i).toFixed(1)} ${Y(v).toFixed(1)}`).join(""); return html`<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2.4" stroke-linejoin="round"/>${s.values.map((v, i) => html`<circle cx="${X(i)}" cy="${Y(v)}" r="4" fill="${s.color}" class="pt" data-tip="${s.name} · ${labels[i]}: ${v}"/>`)}`; });
  return html`<svg viewBox="0 0 ${w} ${h}" class="chart" role="img" aria-label="Trend">${grid}${labels.map((l, i) => i % 2 === 0 || labels.length < 7 ? html`<text x="${X(i)}" y="${h - 10}" text-anchor="middle" class="ax">${l.slice(5)}</text>` : "")}${paths}</svg>
  <div class="legend row">${series.map(s => html`<button class="chip ${hidden.has(s.key) ? "off" : ""}" data-series="${s.key}"><i style="background:${s.color}"></i>${s.name}</button>`)}</div>`;
}
