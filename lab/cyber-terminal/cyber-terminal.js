/* Cyber Terminal v1 — animated background + live data feeds.
   Sources:
     - threats.brycemaxheimer.com/feed.json  (cowrie + CISA KEV + ransomware, server-side bundle)
     - services.nvd.nist.gov/rest/json/cves/2.0  (recent CVEs, direct CORS-OK fetch)
     - hn.algolia.com/api/v1/search_by_date?tags=story&query=...  (HN security stories)
*/

(function () {
  "use strict";

  const FEED_URL = "https://threats.brycemaxheimer.com/feed.json";
  const NVD_URL =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=25&noRejected=";
  const HN_URL =
    "https://hn.algolia.com/api/v1/search_by_date?tags=story&query=security+OR+vulnerability+OR+breach+OR+malware&hitsPerPage=15";

  const REFRESH_MS = 15 * 60 * 1000;   // 15 min
  const TICKER_REFRESH_MS = 60 * 1000; // ticker rebuild more often

  const $ = (id) => document.getElementById(id);
  const esc = (s) =>
    String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmt = (n) => Number(n ?? 0).toLocaleString();
  const ago = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (s < 60) return Math.floor(s) + "s";
    if (s < 3600) return Math.floor(s / 60) + "m";
    if (s < 86400) return Math.floor(s / 3600) + "h";
    return Math.floor(s / 86400) + "d";
  };

  // ─── 1) Background animation (carry-over from v0) ─────────────────────
  const canvas = $("ct-bg");
  const ctx = canvas.getContext("2d", { alpha: true });
  let W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);
  let particles = [];

  function sizeCanvas() {
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * DPR; canvas.height = H * DPR;
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    const targetCount = Math.min(180, Math.round((W * H) / 14000));
    initParticles(targetCount);
  }
  const rand = (a, b) => a + Math.random() * (b - a);
  function initParticles(n) {
    particles = [];
    for (let i = 0; i < n; i++) {
      const depth = Math.random();
      particles.push({
        x: Math.random() * W, y: Math.random() * H,
        vx: rand(-0.06, 0.06) * (0.5 + depth),
        vy: rand(-0.04, 0.04) * (0.5 + depth),
        r: 0.6 + depth * 1.4, depth,
        hue: Math.random() < 0.08 ? "alert" : "green",
        pulsePhase: Math.random() * Math.PI * 2,
      });
    }
  }
  function tick(t) {
    ctx.clearRect(0, 0, W, H);
    const sweepY = (t * 0.04) % (H + 200);
    const grad = ctx.createLinearGradient(0, sweepY - 60, 0, sweepY + 60);
    grad.addColorStop(0, "rgba(0,255,149,0)");
    grad.addColorStop(0.5, "rgba(0,255,149,0.025)");
    grad.addColorStop(1, "rgba(0,255,149,0)");
    ctx.fillStyle = grad;
    ctx.fillRect(0, sweepY - 60, W, 120);

    ctx.lineWidth = 0.5;
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      if (p.depth < 0.5) continue;
      for (let j = i + 1; j < particles.length; j++) {
        const q = particles[j];
        if (q.depth < 0.5) continue;
        const dx = p.x - q.x, dy = p.y - q.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < 110 * 110) {
          const alpha = (1 - Math.sqrt(d2) / 110) * 0.18;
          ctx.strokeStyle = "rgba(0,255,149," + alpha.toFixed(3) + ")";
          ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke();
        }
      }
    }
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x += W; else if (p.x > W) p.x -= W;
      if (p.y < 0) p.y += H; else if (p.y > H) p.y -= H;
      const pulse = 0.55 + 0.45 * Math.sin(t * 0.002 + p.pulsePhase);
      const r = p.r * (0.8 + pulse * 0.5);
      const fill = p.hue === "alert"
        ? "rgba(255,56,96," + (0.55 * pulse).toFixed(3) + ")"
        : "rgba(0,255,149," + (0.55 * pulse * (0.5 + p.depth * 0.5)).toFixed(3) + ")";
      ctx.fillStyle = fill;
      ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI * 2); ctx.fill();
      if (p.hue === "alert" && pulse > 0.7) {
        ctx.beginPath(); ctx.fillStyle = "rgba(255,56,96,0.08)";
        ctx.arc(p.x, p.y, r * 4, 0, Math.PI * 2); ctx.fill();
      }
    }
    requestAnimationFrame(tick);
  }
  sizeCanvas();
  window.addEventListener("resize", () => {
    DPR = Math.min(window.devicePixelRatio || 1, 2); sizeCanvas();
  });
  requestAnimationFrame(tick);

  // ─── 2) Clock ──────────────────────────────────────────────────────────
  function tickClock() {
    const d = new Date();
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    const ss = String(d.getUTCSeconds()).padStart(2, "0");
    $("ct-clock").textContent = `${hh}:${mm}:${ss} UTC`;
  }
  tickClock(); setInterval(tickClock, 1000);

  // ─── 3) Data fetchers ──────────────────────────────────────────────────
  async function fetchJSON(url, init) {
    const r = await fetch(url + (url.includes("?") ? "&" : "?") + "t=" + Date.now(), {
      cache: "no-store", ...init,
    });
    if (!r.ok) throw new Error(`${url}  HTTP ${r.status}`);
    return r.json();
  }

  const state = { feed: null, nvd: null, hn: null, err: {} };

  async function refreshFeed() {
    try { state.feed = await fetchJSON(FEED_URL); state.err.feed = null; }
    catch (e) { state.err.feed = e.message; }
  }
  async function refreshNVD() {
    try {
      const since = new Date(Date.now() - 36 * 3600 * 1000)
        .toISOString().split(".")[0] + ".000";
      const url = NVD_URL + `&pubStartDate=${encodeURIComponent(since)}` +
                  `&pubEndDate=${encodeURIComponent(new Date().toISOString().split(".")[0] + ".000")}`;
      state.nvd = await fetchJSON(url);
      state.err.nvd = null;
    } catch (e) { state.err.nvd = e.message; }
  }
  async function refreshHN() {
    try { state.hn = await fetchJSON(HN_URL); state.err.hn = null; }
    catch (e) { state.err.hn = e.message; }
  }

  // ─── 4) Rendering ──────────────────────────────────────────────────────
  function severityClass(score) {
    if (score >= 9) return "sev-crit";
    if (score >= 7) return "sev-high";
    if (score >= 4) return "sev-med";
    return "sev-info";
  }

  function renderKEV() {
    const el = $("ct-kev");
    if (!el) return;
    const items = state.feed?.cisa_kev_recent || [];
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.feed || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = items.slice(0, 12).map(k => `
      <li>
        <span class="ct-sk-tag" style="color:var(--ct-red);min-width:9em">${esc(k.cve || "")}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          <span style="color:var(--ct-yellow)">${esc(k.vendor || "?")}</span>
          <span style="color:var(--ct-text-soft)">/</span>
          <span>${esc(k.product || "?")}</span>
          ${k.ransom ? '<span style="color:var(--ct-red);margin-left:0.4em">⛧</span>' : ""}
        </span>
        <span style="color:var(--ct-text-soft);font-size:0.7em">${esc(k.added || "")}</span>
      </li>`).join("");
  }

  function renderCVE() {
    const el = $("ct-cve");
    if (!el) return;
    const items = state.nvd?.vulnerabilities || [];
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.nvd || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = items.slice(0, 12).map(item => {
      const cve = item.cve;
      const id = cve.id || "?";
      // Pick highest CVSS score from primary metrics
      let score = 0;
      const m = cve.metrics || {};
      for (const k of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
        if (m[k] && m[k][0]?.cvssData?.baseScore != null) {
          score = m[k][0].cvssData.baseScore;
          break;
        }
      }
      const desc = (cve.descriptions?.find(d => d.lang === "en")?.value || "").slice(0, 100);
      const cls = severityClass(score);
      return `<li>
        <span class="ct-sk-tag ${cls}" style="min-width:9em">${esc(id)}</span>
        <span style="color:var(--ct-text-soft);min-width:2.4em" class="${cls}">${score ? score.toFixed(1) : "—"}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(desc)}</span>
      </li>`;
    }).join("");
  }

  function renderHN() {
    const el = $("ct-hn");
    if (!el) return;
    const hits = state.hn?.hits || [];
    if (!hits.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.hn || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = hits.slice(0, 8).map(h => `
      <li>
        <span class="ct-sk-tag" style="color:var(--ct-cyan);min-width:4.5em">${esc(ago(h.created_at))}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.title)}</span>
        <span style="color:var(--ct-text-soft);font-size:0.7em">${esc(h.points || 0)}▲ · ${esc(h.num_comments || 0)}💬</span>
      </li>`).join("");
  }

  function renderRansom() {
    const el = $("ct-ransom");
    if (!el) return;
    const items = state.feed?.ransomware_recent || [];
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.feed || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = items.slice(0, 12).map(r => `
      <li>
        <span class="ct-sk-tag" style="color:var(--ct-red);min-width:7em">${esc(r.group || "?")}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.victim || "?")}</span>
        <span style="color:var(--ct-text-soft);font-size:0.7em;min-width:2.5em">${esc(r.country || "")}</span>
      </li>`).join("");
  }

  function renderStats() {
    const cves = state.nvd?.vulnerabilities || [];
    const critical = cves.filter(c => {
      const m = c.cve.metrics || {};
      for (const k of ["cvssMetricV31", "cvssMetricV30"]) {
        if (m[k] && m[k][0]?.cvssData?.baseScore >= 9.0) return true;
      }
      return false;
    }).length;
    const kev = (state.feed?.cisa_kev_recent || []).length;
    const ransom = (state.feed?.ransomware_recent || []).length;
    $("ct-stat-cves").textContent = cves.length ? fmt(cves.length) : "—";
    $("ct-stat-kev").textContent = kev ? fmt(kev) : "—";
    $("ct-stat-crit").textContent = critical ? fmt(critical) : "—";
    $("ct-stat-ransom").textContent = ransom ? fmt(ransom) : "—";
  }

  function renderMap() {
    const g = $("ct-map-dots");
    if (!g) return;
    g.innerHTML = "";
    const attackers = state.feed?.top_attackers || [];
    if (!attackers.length) return;

    // SVG viewBox is 1000x500. Project lat/lon to that.
    // Equirectangular: x = (lon + 180) * (1000/360), y = (90 - lat) * (500/180)
    const proj = (lat, lon) => [(lon + 180) * (1000 / 360), (90 - lat) * (500 / 180)];

    const maxCount = Math.max(1, ...attackers.map(a => a.count));
    attackers.slice(0, 40).forEach((a, i) => {
      const lat = parseFloat(a.geoip_location_latitude);
      const lon = parseFloat(a.geoip_location_longitude);
      if (Number.isNaN(lat) || Number.isNaN(lon)) return;
      const [x, y] = proj(lat, lon);
      const r = 2 + Math.sqrt(a.count / maxCount) * 5;
      const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      dot.setAttribute("cx", String(x));
      dot.setAttribute("cy", String(y));
      dot.setAttribute("r", String(r));
      dot.setAttribute("class", "ct-map-dot");
      dot.style.animationDelay = ((i % 12) * 0.18).toFixed(2) + "s";
      g.appendChild(dot);
    });
  }

  function renderTicker() {
    const t = $("ct-ticker-track");
    if (!t) return;
    const parts = [];

    (state.feed?.cisa_kev_recent || []).slice(0, 6).forEach(k => {
      parts.push(`<span class="sev-crit">▶ KEV</span> <span class="ct-cve-id">${esc(k.cve)}</span> ${esc(k.vendor)} / ${esc(k.product)}`);
    });
    (state.nvd?.vulnerabilities || []).slice(0, 6).forEach(it => {
      const id = it.cve.id;
      const m = it.cve.metrics || {};
      let score = 0;
      for (const k of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
        if (m[k] && m[k][0]?.cvssData?.baseScore != null) { score = m[k][0].cvssData.baseScore; break; }
      }
      const cls = severityClass(score);
      parts.push(`<span class="${cls}">▶ CVE</span> <span class="ct-cve-id">${esc(id)}</span> ${score ? score.toFixed(1) : "—"}`);
    });
    (state.feed?.ransomware_recent || []).slice(0, 5).forEach(r => {
      parts.push(`<span class="sev-high">▶ RANSOM</span> ${esc(r.group)} → ${esc(r.victim)}${r.country ? " ("+esc(r.country)+")" : ""}`);
    });
    (state.hn?.hits || []).slice(0, 6).forEach(h => {
      parts.push(`<span class="sev-info">▶ HN</span> ${esc(h.title)}`);
    });

    if (!parts.length) parts.push(`<span class="sev-info">▶ awaiting feeds …</span>`);

    const block = parts.join("&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;");
    t.innerHTML =
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>` +
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>`;
  }

  // ─── 5) Orchestrator ───────────────────────────────────────────────────
  async function loadAll() {
    await Promise.all([refreshFeed(), refreshNVD(), refreshHN()]);
    renderKEV();
    renderCVE();
    renderHN();
    renderRansom();
    renderStats();
    renderMap();
    renderTicker();
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadAll();
    setInterval(loadAll, REFRESH_MS);
  });
})();
