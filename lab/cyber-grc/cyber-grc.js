/* Cyber GRC v1 — framework/risk/audit wallpaper.
   Sources:
     - /lab/cyber-grc/grc-data.json (NIST CSF scores, risk register, audit findings, ATT&CK overlay, calendar)
     - https://api.github.com/advisories  (GitHub Security Advisories, CORS-friendly)
     - https://haveibeenpwned.com/api/v3/breaches  (HIBP, CORS-friendly)
   Auto-refresh every 15 min. Shared background/clock/ticker with cyber-terminal and cyber-ops. */

(function () {
  "use strict";

  const DATA_URL = "/lab/cyber-grc/grc-data.json";
  const GH_URL   = "https://api.github.com/advisories?per_page=30&severity=high";
  const HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches";
  const REFRESH_MS = 15 * 60 * 1000;

  const $ = (id) => document.getElementById(id);
  const esc = (s) =>
    String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmt = (n) => Number(n ?? 0).toLocaleString();
  const daysBetween = (a, b) => Math.round((b - a) / 86400000);
  const ageDays = (iso) => {
    if (!iso) return 0;
    return Math.max(0, daysBetween(new Date(iso), new Date()));
  };
  const fmtDate = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toISOString().slice(0, 10);
  };

  // ─── 1) Background animation (identical to the other two pages) ───
  const canvas = $("ct-bg");
  const ctx = canvas.getContext("2d", { alpha: true });
  let W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);
  let particles = [];

  function sizeCanvas() {
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * DPR; canvas.height = H * DPR;
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    initParticles(Math.min(180, Math.round((W * H) / 14000)));
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
    renderCSF();
  });
  requestAnimationFrame(tick);

  // ─── 2) Clock ───
  function tickClock() {
    const d = new Date();
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    const ss = String(d.getUTCSeconds()).padStart(2, "0");
    $("ct-clock").textContent = `${hh}:${mm}:${ss} UTC`;
  }
  tickClock(); setInterval(tickClock, 1000);

  // ─── 3) Data fetchers ───
  async function fetchJSON(url, init) {
    const r = await fetch(url, { cache: "no-store", ...init });
    if (!r.ok) throw new Error(`${url}  HTTP ${r.status}`);
    return r.json();
  }
  const state = { grc: null, gh: null, hibp: null, err: {} };

  async function refreshGRC() {
    try { state.grc = await fetchJSON(DATA_URL); state.err.grc = null; }
    catch (e) { state.err.grc = e.message; console.warn("grc-data.json fetch:", e); }
  }
  async function refreshGH() {
    try { state.gh = await fetchJSON(GH_URL); state.err.gh = null; }
    catch (e) { state.err.gh = e.message; console.warn("GitHub advisories fetch:", e); }
  }
  async function refreshHIBP() {
    try { state.hibp = await fetchJSON(HIBP_URL); state.err.hibp = null; }
    catch (e) { state.err.hibp = e.message; console.warn("HIBP fetch:", e); }
  }

  // ─── 4) NIST CSF radar (SVG) ───
  function renderCSF() {
    const el = $("cg-csf");
    if (!el) return;
    const scores = state.grc?.csf_scores || {};
    const axes = Object.keys(scores);
    if (!axes.length) {
      el.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="#7e8aa3" font-size="10">no data</text>`;
      return;
    }
    const cx = 120, cy = 110, R = 75, MAX = 5;
    const N = axes.length;
    const angle = (i) => -Math.PI / 2 + (2 * Math.PI * i / N);

    // concentric rings
    let rings = "";
    for (let r = 1; r <= MAX; r++) {
      const pts = axes.map((_, i) => {
        const a = angle(i), pr = R * r / MAX;
        return (cx + pr * Math.cos(a)).toFixed(1) + "," + (cy + pr * Math.sin(a)).toFixed(1);
      });
      rings += `<polygon points="${pts.join(" ")}" fill="none" stroke="rgba(0,255,149,${r === MAX ? 0.3 : 0.12})" stroke-width="0.5"/>`;
    }

    // axes + labels
    let axesHtml = "";
    axes.forEach((label, i) => {
      const a = angle(i);
      const x2 = (cx + R * Math.cos(a)).toFixed(1);
      const y2 = (cy + R * Math.sin(a)).toFixed(1);
      axesHtml += `<line x1="${cx}" y1="${cy}" x2="${x2}" y2="${y2}" stroke="rgba(0,255,149,0.2)" stroke-width="0.5"/>`;
      const lx = (cx + (R + 14) * Math.cos(a)).toFixed(1);
      const ly = (cy + (R + 14) * Math.sin(a)).toFixed(1);
      axesHtml += `<text x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="middle" fill="#c9d6ee" font-size="9" letter-spacing="0.05em">${esc(label.toUpperCase())}</text>`;
    });

    // data polygon
    const pts = axes.map((k, i) => {
      const a = angle(i);
      const pr = R * (scores[k] || 0) / MAX;
      return [cx + pr * Math.cos(a), cy + pr * Math.sin(a)];
    });
    const dataPoly = `<polygon points="${pts.map(p => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ")}" fill="rgba(0,255,149,0.22)" stroke="#00ff95" stroke-width="1.6"/>`;
    const dataDots = pts.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2.8" fill="#00ff95"/>`).join("");
    const valueLabels = axes.map((k, i) => {
      const a = angle(i);
      const pr = R * (scores[k] || 0) / MAX;
      const x = (cx + (pr + 8) * Math.cos(a)).toFixed(1);
      const y = (cy + (pr + 8) * Math.sin(a)).toFixed(1);
      return `<text x="${x}" y="${y}" text-anchor="middle" dominant-baseline="middle" fill="#00ff95" font-size="9" font-weight="600">${scores[k]}</text>`;
    }).join("");

    el.innerHTML = rings + axesHtml + dataPoly + dataDots + valueLabels;
    const rev = $("cg-csf-rev");
    if (rev) rev.textContent = state.grc?._last_reviewed || "—";
  }

  // ─── 5) Risk register ───
  function riskCls(score) {
    if (score >= 20) return "sev-crit";
    if (score >= 12) return "sev-high";
    if (score >= 6)  return "sev-med";
    return "sev-low";
  }
  function renderRisks() {
    const el = $("cg-risks");
    if (!el) return;
    const rows = state.grc?.risk_register || [];
    if (!rows.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.grc || "no data")}</span></li>`;
      return;
    }
    const ranked = rows.map(r => ({ ...r, score: (r.likelihood || 0) * (r.impact || 0) }))
                       .sort((a, b) => b.score - a.score);
    let highCount = 0;
    el.innerHTML = ranked.slice(0, 10).map(r => {
      const cls = riskCls(r.score);
      if (cls === "sev-crit" || cls === "sev-high") highCount++;
      return `<li>
        <div class="cg-risk-content">
          <span class="cg-risk-score ${cls}" title="${r.likelihood}×${r.impact}">${r.score}</span>
          <span class="cg-risk-name" title="${esc(r.name)}">${esc(r.id)} · ${esc(r.name)}</span>
          <span class="cg-risk-status">${esc(r.status || "")}</span>
        </div>
      </li>`;
    }).join("");
    const pill = $("cg-pill-risks");
    if (pill) pill.textContent = `${highCount} HIGH RISKS`;
  }

  // ─── 6) Audit findings ───
  function findSev(s) {
    if (s === "high")   return "sev-high";
    if (s === "med")    return "sev-med";
    return "sev-low";
  }
  function renderFindings() {
    const el = $("cg-findings");
    if (!el) return;
    const rows = state.grc?.audit_findings || [];
    if (!rows.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.grc || "no data")}</span></li>`;
      return;
    }
    const openRows = rows.filter(r => r.status !== "closed");
    el.innerHTML = openRows.slice(0, 12).map(r => {
      const age = ageDays(r.opened);
      const sev = findSev(r.severity);
      return `<li>
        <div class="cg-risk-content">
          <span class="cg-find-sev ${sev}">${esc((r.severity || "?").toUpperCase())}</span>
          <span class="cg-risk-name" title="${esc(r.title)}">${esc(r.id)} · ${esc(r.title)}</span>
          <span class="cg-find-age">${age}d</span>
        </div>
      </li>`;
    }).join("");
    const pill = $("cg-pill-findings");
    if (pill) pill.textContent = `${openRows.length} FINDINGS OPEN`;
  }

  // ─── 7) Patch Tuesday ───
  function nextPatchTuesday(now) {
    // 2nd Tuesday of the current month, in UTC
    function secondTuesdayOf(year, month) {
      const d = new Date(Date.UTC(year, month, 1));
      const firstTue = 1 + ((2 - d.getUTCDay() + 7) % 7);
      return new Date(Date.UTC(year, month, firstTue + 7));
    }
    const y = now.getUTCFullYear(), m = now.getUTCMonth();
    let next = secondTuesdayOf(y, m);
    if (next.getTime() <= now.getTime()) {
      const ny = m === 11 ? y + 1 : y;
      const nm = m === 11 ? 0 : m + 1;
      next = secondTuesdayOf(ny, nm);
    }
    const previous = (() => {
      let py = y, pm = m;
      let p = secondTuesdayOf(py, pm);
      if (p.getTime() > now.getTime()) {
        if (pm === 0) { py--; pm = 11; } else { pm--; }
        p = secondTuesdayOf(py, pm);
      }
      return p;
    })();
    return { next, previous };
  }
  function renderPatch() {
    const now = new Date();
    const { next, previous } = nextPatchTuesday(now);
    const daysTo  = daysBetween(now, next);
    const daysAgo = daysBetween(previous, now);
    $("cg-pt-days").textContent      = daysTo.toString();
    $("cg-pt-next").textContent      = next.toISOString().slice(0, 10);
    $("cg-pt-last-days").textContent = daysAgo.toString();
    $("cg-pt-last").textContent      = previous.toISOString().slice(0, 10);
  }

  // ─── 8) ATT&CK Initial Access heatmap ───
  function renderAttack() {
    const el = $("cg-attack");
    if (!el) return;
    const techs = state.grc?.attack_initial_access || [];
    if (!techs.length) {
      el.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--ct-text-soft);padding:1rem">${esc(state.err.grc || "no data")}</div>`;
      return;
    }
    el.innerHTML = techs.slice(0, 12).map(t => {
      const obs = (t.observed || "none").toLowerCase();
      const href = `https://attack.mitre.org/techniques/${encodeURIComponent(t.id)}/`;
      return `<a class="cg-attack-cell obs-${esc(obs)}" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(t.id)} · ${esc(t.name)} · observed: ${esc(obs)}">
        <span class="cg-attack-id">${esc(t.id)}</span>
        <span class="cg-attack-name">${esc(t.name)}</span>
        <span class="cg-attack-obs">${esc(obs)}</span>
      </a>`;
    }).join("");
  }

  // ─── 9) Compliance calendar ───
  function calCls(status) {
    return "s-" + (status || "scheduled").toLowerCase().replace(/\s+/g, "-");
  }
  function renderCalendar() {
    const el = $("cg-calendar");
    if (!el) return;
    const rows = state.grc?.compliance_calendar || [];
    if (!rows.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.grc || "no data")}</span></li>`;
      return;
    }
    const now = new Date();
    const upcoming = rows
      .map(r => ({ ...r, _d: new Date(r.date) }))
      .filter(r => !Number.isNaN(r._d.getTime()))
      .sort((a, b) => a._d - b._d);
    el.innerHTML = upcoming.slice(0, 10).map(r => {
      const overdue = r._d < now && r.status !== "scheduled";
      const cls = overdue ? "s-overdue" : calCls(r.status);
      const status = overdue ? "OVERDUE" : (r.status || "").toUpperCase();
      return `<li>
        <a href="#" onclick="return false" title="${esc(r.title)}">
          <span class="cg-cal-date">${esc(r.date)}</span>
          <span class="cg-cal-fw">${esc(r.framework || "")}</span>
          <span class="cg-cal-title">${esc(r.title)}</span>
          <span class="cg-cal-status ${cls}">${esc(status)}</span>
        </a>
      </li>`;
    }).join("");
  }

  // ─── 10) HIBP breaches ───
  function renderBreaches() {
    const el = $("cg-breaches");
    if (!el) return;
    const list = Array.isArray(state.hibp) ? state.hibp : [];
    if (!list.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.hibp || "no data")}</span></li>`;
      return;
    }
    // Filter: recent + large
    const cutoff = new Date(Date.now() - 365 * 86400000); // last year
    const sorted = list
      .filter(b => b.BreachDate && new Date(b.BreachDate) > cutoff && (b.PwnCount || 0) >= 100000)
      .sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate))
      .slice(0, 12);
    if (!sorted.length) {
      // Fall back to "biggest of all time" view
      sorted.push(...list.sort((a, b) => (b.PwnCount || 0) - (a.PwnCount || 0)).slice(0, 12));
    }
    el.innerHTML = sorted.map(b => {
      const href = `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(b.Name || "")}`;
      const cnt = b.PwnCount ? fmt(b.PwnCount) : "?";
      return `<li>
        <a class="ct-row" href="${esc(href)}" target="_blank" rel="noopener" title="${esc(b.Title || b.Name)} · ${esc(b.BreachDate)}">
          <span class="ct-sk-tag" style="color:var(--ct-red);min-width:5.5em">${esc(b.BreachDate || "")}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ct-text)">${esc(b.Title || b.Name || "?")}</span>
          <span style="color:var(--ct-text-soft);font-size:0.72em;min-width:5em;text-align:right">${cnt}</span>
        </a>
      </li>`;
    }).join("");
  }

  // ─── 11) GitHub advisories ───
  function renderAdvisories() {
    const el = $("cg-advisories");
    if (!el) return;
    const list = Array.isArray(state.gh) ? state.gh : [];
    if (!list.length) {
      el.innerHTML = `<li><span class="ct-sk-tag">—</span><span style="color:var(--ct-text-soft)">${esc(state.err.gh || "no data")}</span></li>`;
      return;
    }
    el.innerHTML = list.slice(0, 10).map(a => {
      const cve = a.cve_id || a.identifiers?.find(i => i.type === "CVE")?.value || a.ghsa_id || "?";
      const sev = (a.severity || "").toLowerCase();
      const sevCls = sev === "critical" ? "sev-crit" : sev === "high" ? "sev-high" : sev === "medium" ? "sev-med" : "sev-info";
      return `<li>
        <a class="ct-row" href="${esc(a.html_url || "https://github.com/advisories")}" target="_blank" rel="noopener" title="${esc(a.summary || "")}">
          <span class="ct-sk-tag ${sevCls}" style="min-width:8em">${esc(cve)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.summary || "")}</span>
          <span style="color:var(--ct-text-soft);font-size:0.7em;min-width:5em;text-align:right">${esc(fmtDate(a.published_at))}</span>
        </a>
      </li>`;
    }).join("");
  }

  // ─── 12) Ticker ───
  function renderTicker() {
    const t = $("ct-ticker-track");
    if (!t) return;
    const parts = [];
    const g = state.grc || {};
    const scores = g.csf_scores || {};
    Object.entries(scores).forEach(([k, v]) => {
      parts.push(`<span class="sev-info">▶ CSF</span> <span class="ct-cve-id">${esc(k)}</span> ${v}/5`);
    });
    (g.risk_register || []).slice(0, 6).forEach(r => {
      const s = (r.likelihood || 0) * (r.impact || 0);
      const cls = s >= 20 ? "sev-crit" : s >= 12 ? "sev-high" : s >= 6 ? "sev-med" : "sev-info";
      parts.push(`<span class="${cls}">▶ RISK</span> ${esc(r.id)} ${esc(r.name)} (${s})`);
    });
    (state.gh || []).slice(0, 6).forEach(a => {
      const cve = a.cve_id || a.ghsa_id;
      parts.push(`<span class="sev-high">▶ GHSA</span> <span class="ct-cve-id">${esc(cve)}</span> ${esc((a.summary || "").slice(0, 60))}`);
    });
    if (!parts.length) parts.push(`<span class="sev-info">▶ awaiting feeds …</span>`);
    const block = parts.join("&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;");
    t.innerHTML =
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>` +
      `<span class="ct-ticker-item">${block}&nbsp;&nbsp;&nbsp;·&nbsp;&nbsp;&nbsp;</span>`;
  }

  // ─── 13) Orchestrator ───
  async function loadAll() {
    await Promise.all([refreshGRC(), refreshGH(), refreshHIBP()]);
    renderCSF();
    renderRisks();
    renderFindings();
    renderPatch();
    renderAttack();
    renderCalendar();
    renderBreaches();
    renderAdvisories();
    renderTicker();
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadAll();
    setInterval(loadAll, REFRESH_MS);
    // patch countdown re-renders at top of every minute so the day counter stays accurate
    setInterval(renderPatch, 60 * 1000);
  });
})();
