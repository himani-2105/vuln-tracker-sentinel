/* Visual effects: drifting network background, 3D card tilt with glare, and rotating wireframe 3D motifs.
   All pause when the tab is hidden and respect prefers-reduced-motion. Light enough for a low-resource laptop. */
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
let visible = true; document.addEventListener("visibilitychange", () => { visible = !document.hidden; });

export function startBackground() {
  const cv = document.getElementById("bg"); if (!cv) return; const ctx = cv.getContext("2d"); let W, H, nodes = [];
  const resize = () => { const d = Math.min(devicePixelRatio || 1, 1.5); W = cv.width = innerWidth * d; H = cv.height = innerHeight * d; cv.style.width = innerWidth + "px"; cv.style.height = innerHeight + "px"; const n = Math.min(54, Math.round(innerWidth * innerHeight / 24000)); nodes = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, z: .4 + Math.random() * .9, vx: (Math.random() - .5) * .22 * d, vy: (Math.random() - .5) * .22 * d })); };
  resize(); addEventListener("resize", resize); let mx = .5, my = .5; addEventListener("pointermove", e => { mx = e.clientX / innerWidth; my = e.clientY / innerHeight; }, { passive: true });
  let last = 0;
  const draw = t => {
    requestAnimationFrame(draw); if (!visible || t - last < 33) return; last = t; ctx.clearRect(0, 0, W, H); const ox = (mx - .5) * 26, oy = (my - .5) * 18, L = 150 * (W / innerWidth);
    for (const n of nodes) { if (!reduce) { n.x += n.vx; n.y += n.vy; if (n.x < 0 || n.x > W) n.vx *= -1; if (n.y < 0 || n.y > H) n.vy *= -1; } }
    for (let i = 0; i < nodes.length; i++) { const a = nodes[i], ax = a.x + ox * a.z, ay = a.y + oy * a.z;
      for (let j = i + 1; j < nodes.length; j++) { const b = nodes[j], bx = b.x + ox * b.z, by = b.y + oy * b.z, d = Math.hypot(ax - bx, ay - by); if (d < L) { ctx.strokeStyle = `rgba(30,70,120,${(1 - d / L) * .16})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke(); } }
      ctx.fillStyle = `rgba(20,60,110,${.18 + .22 * a.z / 1.3})`; ctx.beginPath(); ctx.arc(ax, ay, 1.6 * a.z * (W / innerWidth), 0, 7); ctx.fill(); }
  };
  if (reduce) { draw(0); } else requestAnimationFrame(draw);
}

/* ---- 3D tilt + glare on .tilt elements (event delegation: works for dynamically rendered cards) ---- */
export function startTilt() {
  if (reduce) return; let cur = null;
  document.addEventListener("pointermove", e => {
    const el = e.target.closest && e.target.closest(".tilt");
    if (cur && cur !== el) { cur.style.setProperty("--rx", "0deg"); cur.style.setProperty("--ry", "0deg"); cur.classList.remove("hot"); }
    cur = el; if (!el) return; const r = el.getBoundingClientRect(), px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height, max = el.classList.contains("big") ? 2.2 : 6;
    el.style.setProperty("--ry", ((px - .5) * 2 * max).toFixed(2) + "deg"); el.style.setProperty("--rx", ((.5 - py) * 2 * max).toFixed(2) + "deg");
    el.style.setProperty("--mx", (px * 100).toFixed(0) + "%"); el.style.setProperty("--my", (py * 100).toFixed(0) + "%"); el.classList.add("hot");
  }, { passive: true });
  document.addEventListener("pointerleave", () => { if (cur) { cur.style.setProperty("--rx", "0deg"); cur.style.setProperty("--ry", "0deg"); cur.classList.remove("hot"); } }, true);
}

/* ---- wireframe 3D models drawn on small canvases ---- */
const ring = (n, r, f) => Array.from({ length: n }, (_, i) => f(Math.cos(i / n * 6.2832) * r, Math.sin(i / n * 6.2832) * r));
function line(pts, closed) { const e = []; for (let i = 0; i < pts.length - 1; i++) e.push([pts[i], pts[i + 1]]); if (closed) e.push([pts[pts.length - 1], pts[0]]); return e; }
const MODELS = {
  globe() { const E = []; for (let k = -2; k <= 2; k++) { const y = k * .38, r = Math.sqrt(1 - y * y); E.push(...line(ring(28, r, (a, b) => [a, y, b]), true)); } for (let m = 0; m < 6; m++) { const t = m / 6 * Math.PI; E.push(...line(ring(28, 1, (a, b) => [a * Math.cos(t), b, a * Math.sin(t)]), true)); } return E; },
  cube() { const v = []; for (const s of [-.62, .62]) for (const a of [-.62, .62]) for (const b of [-.62, .62]) v.push([s, a, b]); const E = []; v.forEach((p, i) => v.forEach((q, j) => { if (j > i && (p[0] === q[0]) + (p[1] === q[1]) + (p[2] === q[2]) === 2) E.push([p, q]); })); const w = []; for (const s of [-.3, .3]) for (const a of [-.3, .3]) for (const b of [-.3, .3]) w.push([s, a, b]); w.forEach((p, i) => w.forEach((q, j) => { if (j > i && (p[0] === q[0]) + (p[1] === q[1]) + (p[2] === q[2]) === 2) E.push([p, q]); })); v.forEach((p, i) => E.push([p, w[i]])); return E; },
  stack() { const E = []; for (let k = 0; k < 4; k++) { const y = (k - 1.5) * .34, a = k * .12; const c = [[-.8, y, -.55], [.8, y, -.55], [.8, y, .55], [-.8, y, .55]].map(([x, yy, z]) => [x * Math.cos(a) - z * Math.sin(a), yy, x * Math.sin(a) + z * Math.cos(a)]); E.push(...line(c, true)); } return E; },
  shield() { const o = [[0, -1], [.85, -.62], [.85, .1], [.5, .72], [0, 1.02], [-.5, .72], [-.85, .1], [-.85, -.62]]; const E = []; for (const z of [-.16, .16]) E.push(...line(o.map(([x, y]) => [x, y, z]), true)); o.forEach(([x, y]) => E.push([[x, y, -.16], [x, y, .16]])); const i = o.map(([x, y]) => [x * .55, y * .55 - .02, .16]); E.push(...line(i, true)); E.push([[0, -.45, .16], [0, .55, .16]], [[-.4, .05, .16], [.4, .05, .16]]); return E; },
  network() { const P = []; for (let i = 0; i < 14; i++) { const t = Math.acos(1 - 2 * (i + .5) / 14), p = Math.PI * (1 + Math.sqrt(5)) * i; P.push([Math.sin(t) * Math.cos(p), Math.cos(t), Math.sin(t) * Math.sin(p)]); } const E = []; P.forEach((a, i) => P.forEach((b, j) => { if (j > i && Math.hypot(a[0] - b[0], a[1] - b[1], a[2] - b[2]) < 1.05) E.push([a, b]); })); E.nodes = P; return E; },
  gyro() { const E = []; E.push(...line(ring(36, 1, (a, b) => [a, b, 0]), true), ...line(ring(36, .8, (a, b) => [a, 0, b]), true), ...line(ring(36, .6, (a, b) => [0, a, b]), true)); return E; },
  lock() { const E = []; const b = [[-.6, -.1], [.6, -.1], [.6, .85], [-.6, .85]]; for (const z of [-.25, .25]) E.push(...line(b.map(([x, y]) => [x, y, z]), true)); b.forEach(([x, y]) => E.push([[x, y, -.25], [x, y, .25]])); for (const z of [-.12, .12]) { const arc = Array.from({ length: 13 }, (_, i) => { const t = Math.PI * i / 12; return [Math.cos(t) * .38, -.1 - Math.sin(t) * .7, z]; }); E.push(...line(arc)); } return E; },
};
export function startHeroes(root = document) {
  root.querySelectorAll("canvas.hero3d:not([data-on])").forEach(cv => {
    cv.dataset.on = "1"; const m = (MODELS[cv.dataset.model] || MODELS.cube)(), ctx = cv.getContext("2d"), d = Math.min(devicePixelRatio || 1, 2), s = cv.classList.contains("sm") ? 72 : 112;
    cv.width = cv.height = s * d; cv.style.width = cv.style.height = s + "px"; let a = Math.random() * 6, last = 0;
    const draw = t => {
      if (!cv.isConnected) return; requestAnimationFrame(draw); if (!visible || t - last < 33) return; last = t; if (!reduce) a += .016;
      const ca = Math.cos(a), sa = Math.sin(a), ct = Math.cos(.45), st = Math.sin(.45), R = s * d * .36, c = s * d / 2; ctx.clearRect(0, 0, s * d, s * d);
      const proj = ([x, y, z]) => { const x1 = x * ca + z * sa, z1 = -x * sa + z * ca, y2 = y * ct - z1 * st, z2 = y * st + z1 * ct, k = 1 / (1 + z2 * .22); return [c + x1 * R * k, c + y2 * R * k, z2]; };
      for (const [p, q] of m) { const A = proj(p), B = proj(q), depth = (A[2] + B[2]) / 2; ctx.strokeStyle = `rgba(${depth > 0 ? "20,70,130" : "42,150,190"},${.35 + .35 * (1 - (depth + 1) / 2)})`; ctx.lineWidth = d; ctx.beginPath(); ctx.moveTo(A[0], A[1]); ctx.lineTo(B[0], B[1]); ctx.stroke(); }
      if (m.nodes) for (const n of m.nodes) { const P = proj(n); ctx.fillStyle = "rgba(11,31,58,.8)"; ctx.beginPath(); ctx.arc(P[0], P[1], 2.2 * d, 0, 7); ctx.fill(); }
    }; requestAnimationFrame(draw);
  });
}
