/* Live Threat Feed renderer
   Fetches threat-feed JSON from R2 and paints the SOC dashboard. */

const TF_FEED_URL = "https://threats.brycemaxheimer.com/feed.json";
const TF_REFRESH_MS = 15 * 60 * 1000;

const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n ?? 0).toLocaleString();
const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let tfMap, tfAttackerLayer;

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
    renderStats(feed);
    renderMap(feed);
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
  setInterval(load, TF_REFRESH_MS);
});
