/* Cyber Ops v1 — honeypot operations wallpaper.
   Same animated background, clock, ticker, and 15-min auto-refresh as cyber-terminal.
   Reads the same public feed.json (threats.brycemaxheimer.com/feed.json) and
   renders the Cowrie-derived fields that the cyber-terminal page doesn't surface. */

(function () {
  "use strict";

  const FEED_URL = "https://threats.brycemaxheimer.com/feed.json";
  const REFRESH_MS = 15 * 60 * 1000;  // 15 min

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

  // ─── 1) Background animation (identical to cyber-terminal so the two wallpapers feel like one stack) ─
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
    // chart needs to re-flow to the new container width
    renderChart();
    if (coMap) {
      try { coMap.invalidateSize(); } catch (_) {}
    }
  });
  requestAnimationFrame(tick);

  // ─── 2) Clock (UTC) ───
  function tickClock() {
    const d = new Date();
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    const ss = String(d.getUTCSeconds()).padStart(2, "0");
    $("ct-clock").textContent = `${hh}:${mm}:${ss} UTC`;
  }
  tickClock(); setInterval(tickClock, 1000);

  // ─── 3) Data fetch ───
  async function fetchJSON(url, init) {
    const r = await fetch(url, { cache: "no-store", ...init });
    if (!r.ok) throw new Error(`${url}  HTTP ${r.status}`);
    return r.json();
  }
  const state = { feed: null, err: null };
  let coMap = null;
  let coAttackerLayer = null;

  function initMap() {
    if (typeof L === "undefined") return;
    const el = $("tf-map");
    if (!el || coMap) return;
    coMap = L.map(el, { worldCopyJump: true, zoomControl: true }).setView([20, 0], 2);
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution: '&copy; OpenStreetMap, &copy; CARTO',
      subdomains: "abcd",
      maxZoom: 18,
    }).addTo(coMap);
    coAttackerLayer = L.layerGroup().addTo(coMap);
  }

  async function refreshFeed() {
    try { state.feed = await fetchJSON(FEED_URL); state.err = null; }
    catch (e) { state.err = e.message; console.warn("feed fetch failed:", e); }
  }

  // ─── 4) Renderers ───

  // Hero indicator numbers + topbar pill
  function renderHero() {
    const f = state.feed || {};
    $("co-h-events").textContent     = f.events_24h != null ? fmt(f.events_24h) : "—";
    $("co-h-uniq").textContent       = f.unique_ips_24h != null ? fmt(f.unique_ips_24h) : "—";
    $("co-h-breach").textContent     = f.successful_logins_24h != null ? fmt(f.successful_logins_24h) : "—";
    $("co-h-events-7d").textContent  = f.events_7d != null ? fmt(f.events_7d) : "—";
    const generated = $("tf-generated");
    if (generated && f.generated_at) {
      const dt = new Date(f.generated_at);
      generated.textContent = `generated ${dt.toLocaleTimeString("en-US", { hour12: false })} · ${dt.toLocaleDateString()}`;
    }
    const pill = $("co-pill-breach");
    if (pill) {
      const b = f.successful_logins_24h ?? 0;
      pill.textContent = `${fmt(b)} BREACHES 24h`;
    }
  }

  // 24h hourly area chart (inline SVG, no library)
  function renderChart() {
    const el = $("co-chart");
    if (!el) return;
    const data = (state.feed?.hourly_counts || []).slice(-24);
    const w = Math.max(200, el.clientWidth || 800);
    const h = Math.max(80, el.clientHeight || 140);
    if (!data.length) {
      el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><text x="50%" y="50%" text-anchor="middle" fill="#7e8aa3" font-family="JetBrains Mono, monospace" font-size="12">${esc(state.err || "no data")}</text></svg>`;
      return;
    }
    const max = Math.max(1, ...data.map(d => d.count || 0));
    const padTop = 6, padBot = 4;
    const usable = h - padTop - padBot;
    const stepX = w / Math.max(1, data.length - 1);

    const pts = data.map((d, i) => {
      const x = i * stepX;
      const y = padTop + usable - (Math.max(0, d.count || 0) / max) * usable;
      return [x, y];
    });
    const linePath = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const areaPath = linePath + ` L${w.toFixed(1)} ${h - padBot} L0 ${h - padBot} Z`;

    // Gridlines: 4 horizontal references
    let grid = "";
    for (let g = 1; g <= 3; g++) {
      const gy = padTop + (usable * g / 4);
      grid += `<line x1="0" y1="${gy}" x2="${w}" y2="${gy}" stroke="rgba(0,255,149,0.06)" stroke-width="1"/>`;
    }

    // Dots every ~4 hours so the trend reads even at-a-glance
    const dots = pts.map((p, i) => (i % 4 === 0)
      ? `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2.2" fill="#00ff95"/>` : "").join("");

    const peakIdx = data.reduce((bi, d, i, a) => (d.count > a[bi].count ? i : bi), 0);
    const peak = data[peakIdx];
    const peakX = pts[peakIdx][0], peakY = pts[peakIdx][1];

    el.innerHTML = `
      <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="co-area-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#00ff95" stop-opacity="0.45"/>
            <stop offset="100%" stop-color="#00ff95" stop-opacity="0"/>
          </linearGradient>
        </defs>
        ${grid}
        <path d="${areaPath}" fill="url(#co-area-grad)"/>
        <path d="${linePath}" fill="none" stroke="#00ff95" stroke-width="1.4"/>
        ${dots}
        <circle cx="${peakX.toFixed(1)}" cy="${peakY.toFixed(1)}" r="3.5" fill="none" stroke="#ffd166" stroke-width="1.5"/>
        <text x="${(peakX + 6).toFixed(1)}" y="${(peakY - 6).toFixed(1)}" fill="#ffd166" font-family="JetBrains Mono, monospace" font-size="10">peak ${fmt(peak.count)}</text>
      </svg>
      <div class="co-chart-axis">
        <span>${esc(new Date(data[0].ts).toUTCString().slice(17, 22))} UTC</span>
        <span>${fmt(max)} max/hr</span>
        <span>${esc(new Date(data[data.length - 1].ts).toUTCString().slice(17, 22))} UTC</span>
      </div>
    `;
  }

  // Cowrie live event tail
  function renderRecent() {
    const items = state.feed?.recent || [];
    const el = $("co-recent");
    if (!el) return;
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = items.slice(0, 20).map(r => {
      let icon = "·", color = "var(--ct-cyan)", detail = "";
      if (r.eventid === "cowrie.login.success") {
        icon = "✓"; color = "var(--ct-red)";
        detail = `<span style="color:var(--ct-yellow)">login</span> <span style="color:var(--ct-text)">${esc(r.username || "?")}</span>`;
      } else if (r.eventid === "cowrie.command.input") {
        icon = "⌘"; color = "var(--ct-yellow)";
        const cmd = (r.input || "").replace(/\s+/g, " ").trim();
        detail = `<span style="color:var(--ct-text-soft)">${esc(cmd.slice(0, 70))}</span>`;
      } else if (r.eventid === "cowrie.session.file_download") {
        icon = "⬇"; color = "var(--ct-orange)";
        detail = `<span style="color:var(--ct-text-soft)">${esc((r.shasum || "").slice(0, 16))}</span>`;
      } else {
        detail = `<span style="color:var(--ct-text-soft)">${esc(r.eventid || "")}</span>`;
      }
      const href = r.src_ip ? `https://www.abuseipdb.com/check/${encodeURIComponent(r.src_ip)}` : "#";
      const cc = (r.country || "??").slice(0, 2).toUpperCase();
      return `<li>
        <a class="ct-row" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(r.src_ip || "")} · ${esc(r.country || "")} · ${esc(r.eventid || "")}">
          <span class="co-recent-icon" style="color:${color}">${icon}</span>
          <span style="color:var(--ct-text);min-width:10em;font-size:0.75em">${esc(r.src_ip || "?")}</span>
          <span style="color:var(--ct-text-soft);min-width:2.5em;font-size:0.7em">${esc(cc)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${detail}</span>
          <span style="color:var(--ct-text-dim);font-size:0.65em">${esc(ago(r.ts))}</span>
        </a>
      </li>`;
    }).join("");
  }

  function renderMap() {
    if (!coMap) initMap();
    if (!coMap || !coAttackerLayer) return;
    coAttackerLayer.clearLayers();
    const attackers = state.feed?.top_attackers || [];
    if (!attackers.length) return;
    const max = Math.max(1, ...attackers.map((a) => a.count || 0));
    attackers.slice(0, 60).forEach((a) => {
      const lat = parseFloat(a.geoip_location_latitude);
      const lon = parseFloat(a.geoip_location_longitude);
      if (Number.isNaN(lat) || Number.isNaN(lon)) return;
      const radius = 4 + Math.sqrt((a.count || 0) / max) * 18;
      L.circleMarker([lat, lon], {
        radius,
        color: "#ff4757",
        weight: 1,
        fillColor: "#ff4757",
        fillOpacity: 0.45,
      })
        .bindPopup(
          `<strong>${esc(a.src_ip)}</strong><br>` +
          `${esc(a.geoip_city_name || "?")}, ${esc(a.geoip_country_name || "?")}<br>` +
          `${esc(a.geoip_autonomous_system_organization || "")}<br>` +
          `<code>${fmt(a.count)} events</code>`
        )
        .addTo(coAttackerLayer);
    });
    setTimeout(() => { try { coMap.invalidateSize(); } catch (_) {} }, 0);
  }

  // Shared bar-list renderer (usernames/passwords/countries/commands)
  function renderBars(elId, items, fieldKey, opts = {}) {
    const el = $(elId);
    if (!el) return;
    if (!items?.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err || "no data")}</span></li>`;
      return;
    }
    const max = Math.max(1, ...items.map(i => i.count || 0));
    const tagColor = opts.tagColor || "var(--ct-grn)";
    const limit = opts.limit || 12;
    el.innerHTML = items.slice(0, limit).map(it => {
      const v = it[fieldKey] ?? "?";
      const pct = ((it.count / max) * 100).toFixed(1);
      const label = opts.format ? opts.format(it) : esc(String(v));
      return `<li>
        <div class="co-bar-fill" style="--p:${pct}%"></div>
        <div class="co-bar-content">
          <span class="ct-sk-tag" style="color:${tagColor};min-width:3.2em">${fmt(it.count)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--ct-mono)">${label}</span>
        </div>
      </li>`;
    }).join("");
  }

  function renderUsernames() {
    renderBars("co-users", state.feed?.top_usernames, "username", { tagColor: "var(--ct-yellow)", limit: 14 });
  }
  function renderPasswords() {
    const el = $("co-pass");
    if (el) el.classList.add("co-bars-red");
    renderBars("co-pass", state.feed?.top_passwords, "password", { tagColor: "var(--ct-red)", limit: 14 });
  }
  function renderCommands() {
    const items = (state.feed?.top_commands || []).map(it => ({
      ...it,
      // Truncate noisy long commands for display
      _display: (it.input || "").replace(/\s+/g, " ").trim().slice(0, 80)
    }));
    renderBars("co-cmds", items, "_display", {
      tagColor: "var(--ct-yellow)",
      limit: 10,
      format: (it) => `<span style="color:var(--ct-text)">${esc(it._display || "—")}</span>`
    });
  }
  function renderCountries() {
    renderBars("co-countries", state.feed?.top_countries, "geoip_country_name", { tagColor: "var(--ct-yellow)", limit: 14 });
  }
  function renderASNs() {
    const items = state.feed?.top_asns || [];
    const el = $("co-asns");
    if (!el) return;
    if (!items.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err || "no data")}</span></li>`;
      return;
    }
    const max = Math.max(1, ...items.map(i => i.count || 0));
    el.innerHTML = items.slice(0, 12).map(it => {
      const pct = ((it.count / max) * 100).toFixed(1);
      const asn = it.geoip_autonomous_system_number || "?";
      const org = it.geoip_autonomous_system_organization || "?";
      const href = `https://radar.cloudflare.com/as${encodeURIComponent(asn)}`;
      return `<li>
        <div class="co-bar-fill" style="--p:${pct}%"></div>
        <div class="co-bar-content">
          <span class="ct-sk-tag" style="color:var(--ct-cyan);min-width:5.5em">AS${esc(asn)}</span>
          <a class="ct-row" href="${esc(href)}" target="_blank" rel="noopener" style="flex:1;min-width:0" title="${esc(org)} · ${fmt(it.count)} hits">
            <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(org)}</span>
            <span style="color:var(--ct-text-soft);min-width:4em;text-align:right">${fmt(it.count)}</span>
          </a>
        </div>
      </li>`;
    }).join("");
  }

  // Threat-sharing scoreboard (you contributing back to the community)
  function renderSharing() {
    const s = state.feed?.sharing || {};
    const el = $("co-shares");
    if (!el) return;
    const cells = [
      { val: s.abuseipdb_reports_24h, lbl: "AbuseIPDB reports 24h", cls: "" },
      { val: s.vt_lookups_total,      lbl: "VT lookups total",      cls: "cyan" },
      { val: s.vt_malicious_total,    lbl: "VT malicious confirmed", cls: "red" },
      { val: (s.otx_pulses_total || 0) + (s.threatfox_submits_total || 0), lbl: "OTX + ThreatFox submits", cls: "yellow" },
    ];
    el.innerHTML = cells.map(c => `
      <div class="co-share-cell">
        <div class="co-share-val ${c.cls}">${c.val != null ? fmt(c.val) : "—"}</div>
        <div class="co-hero-lbl">${esc(c.lbl)}</div>
      </div>
    `).join("");
  }

  function renderError() {
    const page = document.querySelector(".co-page");
    if (!page) return;
    const existing = page.querySelector(".co-err");
    if (!state.err) {
      if (existing) existing.remove();
      return;
    }
    const message = `feed fetch failed: ${esc(state.err)} — check that <code>threats.brycemaxheimer.com/feed.json</code> is reachable.`;
    if (existing) {
      existing.innerHTML = message;
      return;
    }
    page.insertAdjacentHTML("afterbegin", `<div class="co-err">${message}</div>`);
  }

  // Bottom ticker mixes the rendered fields into the marquee
  function renderTicker() {
    const t = $("ct-ticker-track");
    if (!t) return;
    const parts = [];
    const f = state.feed || {};
    if (f.events_24h != null)            parts.push(`<span class="sev-info">▶ EVENTS&nbsp;24h</span> ${fmt(f.events_24h)}`);
    if (f.unique_ips_24h != null)        parts.push(`<span class="sev-med">▶ UNIQUE&nbsp;IPs</span> ${fmt(f.unique_ips_24h)}`);
    if (f.successful_logins_24h != null) parts.push(`<span class="sev-crit">▶ BREACHES</span> ${fmt(f.successful_logins_24h)}`);
    (f.top_usernames || []).slice(0, 6).forEach(u => {
      parts.push(`<span class="sev-med">▶ USER</span> ${esc(u.username)} <span style="color:var(--ct-text-soft)">×${fmt(u.count)}</span>`);
    });
    (f.top_passwords || []).slice(0, 6).forEach(p => {
      parts.push(`<span class="sev-high">▶ PASS</span> ${esc(p.password)} <span style="color:var(--ct-text-soft)">×${fmt(p.count)}</span>`);
    });
    (f.top_asns || []).slice(0, 4).forEach(a => {
      parts.push(`<span class="sev-info">▶ ASN</span> ${esc(a.geoip_autonomous_system_organization)} <span style="color:var(--ct-text-soft)">×${fmt(a.count)}</span>`);
    });
    if (!parts.length) parts.push(`<span class="sev-info">▶ awaiting feeds …</span>`);
    const block = parts.join("&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;");
    t.innerHTML =
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>` +
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>`;
  }

  // ─── 5) Orchestrator ───
  async function loadAll() {
    await refreshFeed();
    renderError();
    renderHero();
    renderChart();
    renderMap();
    renderRecent();
    renderUsernames();
    renderPasswords();
    renderCommands();
    renderCountries();
    renderASNs();
    renderSharing();
    renderTicker();
  }

  document.addEventListener("DOMContentLoaded", () => {
    initMap();
    loadAll();
    const reload = $("tf-reload");
    if (reload) reload.addEventListener("click", (e) => { e.preventDefault(); loadAll(); });
    setInterval(loadAll, REFRESH_MS);
  });
})();
