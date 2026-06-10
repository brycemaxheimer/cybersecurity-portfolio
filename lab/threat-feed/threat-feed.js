/* Live Threat Feed renderer
   Fetches threat-feed JSON from R2 and paints the SOC dashboard. */

/* ── Shared wall-display chrome: animated background + UTC clock.
   Copied from /lab/cyber-terminal/cyber-terminal.js so this page renders
   the same constellation/scan-line effect and ticking clock as the other
   two immersive wall pages (cyber-terminal, cyber-ops). */
(function () {
  const canvas = document.getElementById("ct-bg");
  if (!canvas) return;
  const ctx = canvas.getContext("2d", { alpha: true });
  let W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);
  let particles = [];
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
  function sizeCanvas() {
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * DPR; canvas.height = H * DPR;
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    initParticles(Math.min(180, Math.round((W * H) / 14000)));
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
  /* Background animation retired with the site-theme re-skin. The canvas
     stays in the DOM (hidden via CSS) so nothing downstream breaks. */
  void sizeCanvas; void tick;

  // UTC clock in topbar — matches cyber-terminal/ops/grc.
  function tickClock() {
    const clk = document.getElementById("ct-clock");
    if (!clk) return;
    const d = new Date();
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    const ss = String(d.getUTCSeconds()).padStart(2, "0");
    clk.textContent = `${hh}:${mm}:${ss} UTC`;
  }
  tickClock(); setInterval(tickClock, 1000);
})();

const TF_FEED_URL = "https://threats.brycemaxheimer.com/feed.json";
const TF_REFRESH_MS = 15 * 60 * 1000;

const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n ?? 0).toLocaleString();
const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let tfMap, tfAttackerLayer, tfLastFeed = null;

function initMap() {
  if (typeof L === "undefined") return;
  tfMap = L.map("tf-map", { worldCopyJump: true, zoomControl: true }).setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: '&copy; OpenStreetMap, &copy; CARTO',
    subdomains: "abcd",
    maxZoom: 18,
  }).addTo(tfMap);
  tfAttackerLayer = L.layerGroup().addTo(tfMap);
}

function renderStats(feed) {
  const items = [
    { label: "events · 24h", val: fmt(feed.events_24h), cls: "" },
    { label: "unique attackers · 24h", val: fmt(feed.unique_ips_24h), cls: "yellow" },
    { label: "successful sessions · 24h", val: fmt(feed.successful_logins_24h), cls: "red" },
    {
      label: "events · 7d",
      val: fmt(feed.events_7d),
      sub: `${fmt(feed.unique_ips_7d)} unique`,
      cls: "blue",
    },
    {
      label: "reported · 24h",
      val: fmt(feed.sharing?.abuseipdb_reports_24h ?? 0),
      sub: "abuseipdb",
      cls: "",
    },
    {
      label: "VT-flagged payloads",
      val: fmt(feed.sharing?.vt_malicious_total ?? 0),
      sub: `${fmt(feed.sharing?.vt_lookups_total ?? 0)} looked up`,
      cls: "red",
    },
  ];
  $("tf-stats").innerHTML = items
    .map(
      (i) => `
    <div class="tf-stat">
      <div class="lbl">${esc(i.label)}</div>
      <div class="val ${i.cls}">${esc(i.val)}</div>
      ${i.sub ? `<div class="sub">${esc(i.sub)}</div>` : ""}
    </div>`
    )
    .join("");
}

function renderMap(feed) {
  if (!tfAttackerLayer) return;
  tfAttackerLayer.clearLayers();
  const max = Math.max(1, ...feed.top_attackers.map((a) => a.count));
  for (const a of feed.top_attackers) {
    const lat = parseFloat(a.geoip_location_latitude);
    const lon = parseFloat(a.geoip_location_longitude);
    if (Number.isNaN(lat) || Number.isNaN(lon)) continue;
    const r = 4 + Math.sqrt(a.count / max) * 18;
    L.circleMarker([lat, lon], {
      radius: r,
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
      .addTo(tfAttackerLayer);
  }
  setTimeout(() => { try { tfMap.invalidateSize(); } catch (_) {} }, 0);
}

function renderChart(feed) {
  const el = $("tf-chart");
  if (!el) return;
  const data = (feed?.hourly_counts || []).slice(-24);
  const w = Math.max(220, el.clientWidth || 760);
  const h = Math.max(92, el.clientHeight || 160);
  /* Resolve chart colors from the active site theme. */
  const css = getComputedStyle(document.documentElement);
  const themeColor = (name, fallback) => (css.getPropertyValue(name).trim() || fallback);
  const cAccent = themeColor("--mint-deep", "#3dd68c");
  const cPeak = themeColor("--amber", "#ffd166");
  const cMuted = themeColor("--text-3", "#7e8aa3");
  const cGrid = themeColor("--line", "rgba(255,255,255,0.07)");
  if (!data.length) {
    el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><text x="50%" y="50%" text-anchor="middle" fill="${cMuted}" font-family="ui-monospace, monospace" font-size="12">${esc("no trend data")}</text></svg>`;
    return;
  }

  const max = Math.max(1, ...data.map((d) => d.count || 0));
  const padTop = 6;
  const padBot = 4;
  const usable = h - padTop - padBot;
  const stepX = w / Math.max(1, data.length - 1);

  const pts = data.map((d, i) => {
    const x = i * stepX;
    const y = padTop + usable - (Math.max(0, d.count || 0) / max) * usable;
    return [x, y];
  });
  const linePath = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const areaPath = linePath + ` L${w.toFixed(1)} ${h - padBot} L0 ${h - padBot} Z`;

  let grid = "";
  for (let g = 1; g <= 3; g++) {
    const gy = padTop + (usable * g / 4);
    grid += `<line x1="0" y1="${gy}" x2="${w}" y2="${gy}" stroke="${cGrid}" stroke-width="1"/>`;
  }
  const dots = pts
    .map((p, i) => (i % 4 === 0 ? `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2.2" fill="${cAccent}"/>` : ""))
    .join("");
  const peakIdx = data.reduce((bi, d, i, arr) => (d.count > arr[bi].count ? i : bi), 0);
  const peak = data[peakIdx];
  const peakX = pts[peakIdx][0];
  const peakY = pts[peakIdx][1];

  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="tf-area-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${cAccent}" stop-opacity="0.35"/>
          <stop offset="100%" stop-color="${cAccent}" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${grid}
      <path d="${areaPath}" fill="url(#tf-area-grad)"/>
      <path d="${linePath}" fill="none" stroke="${cAccent}" stroke-width="1.4"/>
      ${dots}
      <circle cx="${peakX.toFixed(1)}" cy="${peakY.toFixed(1)}" r="3.5" fill="none" stroke="${cPeak}" stroke-width="1.5"/>
      <text x="${(peakX + 6).toFixed(1)}" y="${(peakY - 6).toFixed(1)}" fill="${cPeak}" font-family="ui-monospace, monospace" font-size="10">peak ${fmt(peak.count)}</text>
    </svg>
    <div class="tf-chart-axis">
      <span>${esc(new Date(data[0].ts).toUTCString().slice(17, 22))} UTC</span>
      <span>${fmt(max)} max/hr</span>
      <span>${esc(new Date(data[data.length - 1].ts).toUTCString().slice(17, 22))} UTC</span>
    </div>
  `;
}

function renderTable(id, rows, cells) {
  const tbody = document.querySelector(`#${id} tbody`);
  if (!tbody) return;
  tbody.innerHTML = (rows || []).map((r) => `<tr>${cells(r)}</tr>`).join("");
}

function renderRecent(feed) {
  const el = $("tf-recent");
  if (!el) return;
  el.innerHTML = (feed.recent || [])
    .map((e) => {
      const cls =
        e.eventid === "cowrie.login.success"
          ? "login-success"
          : e.eventid === "cowrie.command.input"
          ? "command"
          : e.eventid === "cowrie.session.file_download"
          ? "file"
          : "";
      const shortid = (e.eventid || "").replace("cowrie.", "");
      let data = "";
      if (e.input) data = "$ " + e.input;
      else if (e.username) data = "user=" + e.username;
      else if (e.url) data = "↓ " + e.url;
      else if (e.shasum) data = "sha=" + e.shasum.slice(0, 12);
      const ts = e.ts ? new Date(e.ts).toLocaleTimeString("en-US", { hour12: false }) : "";
      return `<div class="line">
        <span class="ts">${esc(ts)}</span>
        <span class="ev ${cls}">${esc(shortid)}</span>
        <span class="ip">${esc(e.src_ip || "")}</span>
        <span class="country">${esc(e.country || "")}</span>
        <span class="data">${esc(data)}</span>
      </div>`;
    })
    .join("");
}

async function load() {
  try {
    const r = await fetch(`${TF_FEED_URL}?t=${Date.now()}`, { cache: "no-store" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const feed = await r.json();
    tfLastFeed = feed;
    renderStats(feed);
    renderMap(feed);
    renderChart(feed);
    renderTable(
      "tf-countries",
      feed.top_countries,
      (c) => `<td>${esc(c.geoip_country_name)}</td><td class="r">${fmt(c.count)}</td>`
    );
    renderTable(
      "tf-asns",
      feed.top_asns,
      (a) =>
        `<td>AS${esc(a.geoip_autonomous_system_number)} ${esc(a.geoip_autonomous_system_organization)}</td><td class="r">${fmt(a.count)}</td>`
    );
    renderTable(
      "tf-ips",
      feed.top_attackers,
      (a) =>
        `<td>${esc(a.src_ip)}</td><td>${esc(a.geoip_city_name || "?")}, ${esc(a.geoip_country_name || "?")}</td><td class="r">${fmt(a.count)}</td>`
    );
    renderTable("tf-users", feed.top_usernames, (u) => `<td>${esc(u.username)}</td><td class="r">${fmt(u.count)}</td>`);
    renderTable("tf-passwords", feed.top_passwords, (p) => `<td>${esc(p.password)}</td><td class="r">${fmt(p.count)}</td>`);
    renderTable("tf-commands", feed.top_commands, (c) => `<td>${esc(c.input)}</td><td class="r">${fmt(c.count)}</td>`);
    renderRecent(feed);
    const dt = new Date(feed.generated_at);
    $("tf-generated").textContent = `generated ${dt.toLocaleTimeString("en-US", { hour12: false })} · ${dt.toLocaleDateString()}`;
  } catch (e) {
    console.error(e);
    const main = document.querySelector(".tf-page");
    if (main && !document.querySelector(".tf-err")) {
      main.insertAdjacentHTML(
        "afterbegin",
        `<div class="tf-err">feed fetch failed: ${esc(e.message)} &mdash; check that <code>threats.brycemaxheimer.com/feed.json</code> is reachable.</div>`
      );
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initMap();
  load();
  const reload = $("tf-reload");
  if (reload) reload.addEventListener("click", (e) => { e.preventDefault(); load(); });
  window.addEventListener("resize", () => {
    if (tfMap) {
      try { tfMap.invalidateSize(); } catch (_) {}
    }
    if (tfLastFeed) renderChart(tfLastFeed);
  });
  setInterval(load, TF_REFRESH_MS);
});
