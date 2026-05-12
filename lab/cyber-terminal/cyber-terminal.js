/* Cyber Terminal v1 — animated background + live data feeds.
   Sources:
     - threats.brycemaxheimer.com/feed.json  (cowrie + CISA KEV + ransomware, server-side bundle)
     - services.nvd.nist.gov/rest/json/cves/2.0  (recent CVEs, direct CORS-OK fetch)
     - hn.algolia.com/api/v1/search_by_date?tags=story&query=...  (HN security stories + threat research)
*/

(function () {
  "use strict";

  const FEED_URL = "https://threats.brycemaxheimer.com/feed.json";
  // NVD CVEs published in the last 7 days, max 25 results. Filter applied at the API.
  const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  // HN: single-keyword search (OR-syntax parses unreliably in Algolia).
  const HN_URL =
    "https://hn.algolia.com/api/v1/search_by_date?tags=story&query=security&hitsPerPage=20";
  // Second HN feed targeted at threat research / malware analysis content.
  const HN_RESEARCH_URL =
    "https://hn.algolia.com/api/v1/search_by_date?tags=story&query=malware&hitsPerPage=20";

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

  // Build a Google search URL for ransomware victim lookups (no canonical URL in feed).
  const ransomLookup = (group, victim) =>
    "https://www.google.com/search?q=" +
    encodeURIComponent(`${group || ""} ransomware ${victim || ""}`.trim());

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
    if (ctMap) {
      try { ctMap.invalidateSize(); } catch (_) {}
    }
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
    // Strict APIs (NVD, Algolia) reject unknown query params, so don't add a cache-buster.
    // `cache: "no-store"` is enough to defeat the browser cache.
    const r = await fetch(url, { cache: "no-store", ...init });
    if (!r.ok) throw new Error(`${url}  HTTP ${r.status}`);
    return r.json();
  }

  const state = { feed: null, nvd: null, hn: null, research: null, err: {} };

  async function refreshFeed() {
    try { state.feed = await fetchJSON(FEED_URL); state.err.feed = null; }
    catch (e) { state.err.feed = e.message; }
  }
  async function refreshNVD() {
    try {
      // NVD wants ISO 8601 with milliseconds; window of last 7 days for plenty of data
      const endDate = new Date();
      const startDate = new Date(endDate.getTime() - 7 * 24 * 3600 * 1000);
      const fmtDate = (d) => d.toISOString().split(".")[0] + ".000";
      const url = `${NVD_BASE}?resultsPerPage=25&pubStartDate=${encodeURIComponent(fmtDate(startDate))}&pubEndDate=${encodeURIComponent(fmtDate(endDate))}`;
      state.nvd = await fetchJSON(url);
      state.err.nvd = null;
    } catch (e) {
      state.err.nvd = e.message;
      console.warn("NVD fetch failed:", e);
    }
  }
  async function refreshHN() {
    try { state.hn = await fetchJSON(HN_URL); state.err.hn = null; }
    catch (e) {
      state.err.hn = e.message;
      console.warn("HN fetch failed:", e);
    }
  }
  async function refreshResearch() {
    try { state.research = await fetchJSON(HN_RESEARCH_URL); state.err.research = null; }
    catch (e) {
      state.err.research = e.message;
      console.warn("Research fetch failed:", e);
    }
  }

  // ─── 4) Rendering ──────────────────────────────────────────────────────
  function severityClass(score) {
    if (score >= 9) return "sev-crit";
    if (score >= 7) return "sev-high";
    if (score >= 4) return "sev-med";
    return "sev-info";
  }

  // NVD detail page for any CVE-#### identifier
  const cveUrl = (id) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
  // HN story URL: prefer the linked article, fall back to the HN discussion page
  const hnUrl = (h) => h?.url || `https://news.ycombinator.com/item?id=${h?.objectID || ""}`;

  function renderKEV() {
    const el = $("ct-kev");
    if (!el) return;
    const items = state.feed?.cisa_kev_recent || [];
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.feed || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = items.slice(0, 12).map(k => {
      const href = k.cve ? cveUrl(k.cve) : "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
      return `
      <li>
        <a class="ct-row" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(k.cve || "")} · ${esc(k.vendor || "")} / ${esc(k.product || "")}">
          <span class="ct-sk-tag" style="color:var(--ct-red);min-width:9em">${esc(k.cve || "")}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            <span style="color:var(--ct-yellow)">${esc(k.vendor || "?")}</span>
            <span style="color:var(--ct-text-soft)">/</span>
            <span>${esc(k.product || "?")}</span>
            ${k.ransom ? '<span style="color:var(--ct-red);margin-left:0.4em">⛧</span>' : ""}
          </span>
          <span style="color:var(--ct-text-soft);font-size:0.7em">${esc(k.added || "")}</span>
        </a>
      </li>`;
    }).join("");
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
        <a class="ct-row" href="${esc(cveUrl(id))}" target="_blank" rel="noopener" title="${esc(id)} · CVSS ${score ? score.toFixed(1) : "—"}">
          <span class="ct-sk-tag ${cls}" style="min-width:9em">${esc(id)}</span>
          <span style="color:var(--ct-text-soft);min-width:2.4em" class="${cls}">${score ? score.toFixed(1) : "—"}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(desc)}</span>
        </a>
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
        <a class="ct-row" href="${esc(hnUrl(h))}" target="_blank" rel="noopener" title="${esc(h.title)}">
          <span class="ct-sk-tag" style="color:var(--ct-cyan);min-width:4.5em">${esc(ago(h.created_at))}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.title)}</span>
          <span style="color:var(--ct-text-soft);font-size:0.7em">${esc(h.points || 0)}▲ · ${esc(h.num_comments || 0)}💬</span>
        </a>
      </li>`).join("");
  }

  function renderResearch() {
    const el = $("ct-research");
    if (!el) return;
    const hits = state.research?.hits || [];
    if (!hits.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.research || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = hits.slice(0, 8).map(h => {
      // Extract domain for a quick-glance source tag
      let host = "";
      try { host = h.url ? new URL(h.url).hostname.replace(/^www\./, "") : "news.yc"; } catch (_) { host = "news.yc"; }
      return `
      <li>
        <a class="ct-row" href="${esc(hnUrl(h))}" target="_blank" rel="noopener" title="${esc(h.title)}">
          <span class="ct-sk-tag" style="color:var(--ct-yellow);min-width:8em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(host)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.title)}</span>
          <span style="color:var(--ct-text-soft);font-size:0.7em">${esc(ago(h.created_at))}</span>
        </a>
      </li>`;
    }).join("");
  }

  function renderRansom() {
    const el = $("ct-ransom");
    if (!el) return;
    const items = state.feed?.ransomware_recent || [];
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.feed || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = items.slice(0, 12).map(r => {
      const href = r.url || ransomLookup(r.group, r.victim);
      return `
      <li>
        <a class="ct-row" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(r.group || "")} → ${esc(r.victim || "")}">
          <span class="ct-sk-tag" style="color:var(--ct-red);min-width:7em">${esc(r.group || "?")}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.victim || "?")}</span>
          <span style="color:var(--ct-text-soft);font-size:0.7em;min-width:2.5em">${esc(r.country || "")}</span>
        </a>
      </li>`;
    }).join("");
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

  // ─── Leaflet map (initialised once, markers swapped on each refresh) ─────
  let ctMap = null;
  let ctMarkers = null;

  function initMap() {
    if (typeof L === "undefined") return;
    const el = document.getElementById("ct-map");
    if (!el || ctMap) return;
    el.classList.add("leaflet-container");
    ctMap = L.map(el, {
      worldCopyJump: true,
      zoomControl: true,
      dragging: true,
      scrollWheelZoom: true,
      doubleClickZoom: true,
      boxZoom: true,
      keyboard: true,
      touchZoom: true,
      attributionControl: true,
    }).setView([22, 0], 2);
    // Base: ESRI World Imagery (true-colour satellite). No key required.
    L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}", {
      attribution: 'Tiles &copy; Esri &mdash; Earthstar Geographics, Maxar, USGS',
      maxZoom: 10,
    }).addTo(ctMap);
    // Overlay: CartoDB labels-only tiles so country/ocean names stay readable.
    L.tileLayer("https://{s}.basemaps.cartocdn.com/rastertiles/voyager_only_labels/{z}/{x}/{y}{r}.png", {
      attribution: '&copy; CARTO labels',
      subdomains: "abcd",
      maxZoom: 10,
      opacity: 0.9,
    }).addTo(ctMap);
    ctMarkers = L.layerGroup().addTo(ctMap);
  }

  function renderMap() {
    if (!ctMap) initMap();
    if (!ctMap || !ctMarkers) return;
    // Map container size changed when layout updated — let Leaflet recalc.
    setTimeout(() => { try { ctMap.invalidateSize(); } catch (_) {} }, 0);
    ctMarkers.clearLayers();
    const attackers = state.feed?.top_attackers || [];
    if (!attackers.length) return;

    const maxCount = Math.max(1, ...attackers.map(a => a.count));
    attackers.slice(0, 60).forEach((a, i) => {
      const lat = parseFloat(a.geoip_location_latitude);
      const lon = parseFloat(a.geoip_location_longitude);
      if (Number.isNaN(lat) || Number.isNaN(lon)) return;
      const size = 8 + Math.sqrt(a.count / maxCount) * 22;
      const icon = L.divIcon({
        className: "ct-attack-marker",
        html: `<div class="ct-attack-dot" style="width:${size}px;height:${size}px;animation-delay:${(i * 0.12).toFixed(2)}s"></div>`,
        iconSize: [size, size],
        iconAnchor: [size / 2, size / 2],
      });
      L.marker([lat, lon], { icon, interactive: true, riseOnHover: true })
        .bindPopup(
          `<strong>${esc(a.src_ip)}</strong><br>` +
          `${esc(a.geoip_city_name || "?")}, ${esc(a.geoip_country_name || "?")}<br>` +
          `${esc(a.geoip_autonomous_system_organization || "")}<br>` +
          `<code>${fmt(a.count)} events</code>`
        )
        .addTo(ctMarkers);
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
    (state.research?.hits || []).slice(0, 4).forEach(h => {
      parts.push(`<span class="sev-med">▶ RSRCH</span> ${esc(h.title)}`);
    });

    if (!parts.length) parts.push(`<span class="sev-info">▶ awaiting feeds …</span>`);

    const block = parts.join("&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;");
    t.innerHTML =
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>` +
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>`;
  }

  // --- 5) Orchestrator -----------------------------------------------
  async function loadAll() {
    await Promise.all([refreshFeed(), refreshNVD(), refreshHN(), refreshResearch()]);
    renderKEV();
    renderCVE();
    renderHN();
    renderResearch();
    renderRansom();
    renderStats();
    renderMap();
    renderTicker();
  }

  document.addEventListener("DOMContentLoaded", () => {
    initMap();
    loadAll();
    setInterval(loadAll, REFRESH_MS);
  });
})();
