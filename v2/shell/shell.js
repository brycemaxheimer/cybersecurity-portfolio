/* v2 shell: the whole site inside one app window.
 *
 * Facts come from /v2/site-data.json (scripts/build-v2-data.mjs); honeypot
 * numbers come from the feed through /api/live/honeypot. Views: Overview,
 * Threat feed, Intel brief, Tools, Writing, Resume, Credentials, Contact,
 * plus search across all of them. The view is mirrored in the URL hash
 * (#view/id). "/" or Ctrl+K focuses search. Charts are inline SVG with a
 * shared hover tooltip and a data table behind every chart.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var esc, fmt;
  var D = null, live = null, liveTried = false;
  var S = { view: 'home', tool: 'lab', cert: 'gcfe', post: 0, ed: 0, story: 0, q: '' };
  var VIEWS = [
    { id: 'home', label: 'Overview', group: 'EXPLORE' },
    { id: 'threat', label: 'Threat feed', group: 'EXPLORE' },
    { id: 'intel', label: 'Intel brief', group: 'EXPLORE' },
    { id: 'tools', label: 'Tools', group: 'EXPLORE' },
    { id: 'writing', label: 'Writing', group: 'ABOUT' },
    { id: 'resume', label: 'Resume', group: 'ABOUT' },
    { id: 'creds', label: 'Credentials', group: 'ABOUT' },
    { id: 'contact', label: 'Contact', group: 'ABOUT' },
  ];
  var TINT = { lab: '#10241A', intel: '#262010', honey: '#2A1414', soc: '#121C2A' };
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  /* ── small helpers ── */
  var tool = function (id) { return D.tools.filter(function (t) { return t.id === id; })[0] || D.tools[0]; };
  var cert = function (id) { return D.certs.filter(function (c) { return c.id === id; })[0] || D.certs[0]; };
  var ext = function (href) { return /^https?:/.test(href) ? ' rel="noopener"' : ''; };
  var short = function (n) { return n >= 10000 ? (n / 1000).toFixed(0) + 'k' : n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n); };
  var ym = function (s) { var m = String(s).match(/(\d{4})-(\d{2})/); return m ? +m[1] + (+m[2] - 1) / 12 : null; };
  var monthLabel = function (s) { var m = String(s).match(/(\d{4})-(\d{2})/); return m ? MONTHS[+m[2] - 1] + ' ' + m[1] : s; };
  var nowYm = function () { var d = new Date(); return d.getFullYear() + d.getMonth() / 12; };
  var span = function (a, b) {
    var months = Math.max(1, Math.round(((b == null ? nowYm() : b) - a) * 12) + 1);
    var y = Math.floor(months / 12), m = months % 12;
    return (y ? y + ' yr' + (m ? ' ' : '') : '') + (m ? m + ' mo' : '');
  };
  var dateLong = function (iso) { var d = new Date(iso); return isNaN(d) ? '' : MONTHS[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear(); };
  var inline = function (s) { return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>'); };
  var label = function (s) { return String(s || '').replace(/_/g, ' '); };
  var modulesOf = function (id) {
    var list = D.modules.filter(function (m) { return m.parent === id; });
    if (id === 'honey') list = list.concat([{ id: 'threatfeed', title: 'Live Threat Feed', href: '/lab/threat-feed/', summary: 'Top attackers, geo map, recent activity, credentials and sharing metrics.' }]);
    return list;
  };

  /* ── charts (inline SVG + HTML) ── */
  function table(head, rows) {
    return '<details class="tablev"><summary>Show data table</summary><div class="tscroll"><table><thead><tr>' + head.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') + '</tr></thead><tbody>' +
      rows.map(function (r) { return '<tr>' + r.map(function (c) { return '<td>' + esc(c) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div></details>';
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }

  function hourlyChart(hourly) {
    if (!hourly.length) return '<p class="muted">No hourly counts in the feed.</p>';
    var W = 960, H = 220, L = 40, R = 8, T = 14, B = 28, pw = W - L - R, ph = H - T - B;
    var max = niceMax(Math.max.apply(null, hourly.map(function (h) { return h.count; })));
    var step = pw / hourly.length, bw = Math.max(2, step - 2);
    var grid = [0, 0.5, 1].map(function (f) {
      var y = T + ph - ph * f;
      return '<line class="grid" x1="' + L + '" x2="' + (W - R) + '" y1="' + y + '" y2="' + y + '"></line><text class="axis" x="' + (L - 6) + '" y="' + (y + 4) + '" text-anchor="end">' + short(max * f) + '</text>';
    }).join('');
    var bars = hourly.map(function (h, i) {
      var hgt = Math.max(h.count ? 2 : 0, ph * h.count / max), x = L + i * step + 1, y = T + ph - hgt, r = Math.min(4, bw / 2, hgt);
      var d = 'M' + x + ',' + (T + ph) + 'V' + (y + r) + 'Q' + x + ',' + y + ' ' + (x + r) + ',' + y + 'H' + (x + bw - r) + 'Q' + (x + bw) + ',' + y + ' ' + (x + bw) + ',' + (y + r) + 'V' + (T + ph) + 'Z';
      var t = new Date(h.ts), lab = isNaN(t) ? '' : String(t.getUTCHours()).padStart(2, '0') + ':00 UTC';
      var hit = '<rect class="hit" x="' + (L + i * step) + '" y="' + T + '" width="' + step + '" height="' + ph + '" data-tip="' + esc(lab + ' · ' + fmt(h.count) + ' events') + '"></rect>';
      var xl = i % 6 === 0 ? '<text class="axis" x="' + (x + bw / 2) + '" y="' + (H - 8) + '" text-anchor="middle">' + esc(lab.slice(0, 5)) + '</text>' : '';
      return '<path class="bar s1" d="' + d + '"></path>' + hit + xl;
    }).join('');
    var peak = hourly.reduce(function (a, b) { return b.count > a.count ? b : a; }, hourly[0]);
    return '<svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Honeypot events per hour over ' + hourly.length + ' hours, peak ' + fmt(peak.count) + '">' + grid + bars + '</svg>' +
      table(['Hour (UTC)', 'Events'], hourly.map(function (h) { return [h.ts.replace('T', ' ').slice(0, 16), fmt(h.count)]; }));
  }

  function sparkline(hourly) {
    if (!hourly || hourly.length < 2) return '';
    var W = 140, H = 34, max = Math.max.apply(null, hourly.map(function (h) { return h.count; })) || 1;
    var pts = hourly.map(function (h, i) { return (i * W / (hourly.length - 1)).toFixed(1) + ',' + (H - 3 - (H - 6) * h.count / max).toFixed(1); });
    return '<svg class="spark" viewBox="0 0 ' + W + ' ' + H + '" aria-hidden="true"><polyline points="' + pts.join(' ') + '"></polyline></svg>';
  }

  function hbars(list, opts) {
    opts = opts || {};
    if (!list.length) return '<p class="muted">Nothing in the feed.</p>';
    var max = Math.max.apply(null, list.map(function (x) { return x.count; })) || 1;
    return '<div class="hbars' + (opts.mono ? ' mono' : '') + '">' + list.map(function (x) {
      return '<div class="hbar" data-tip="' + esc(x.name + ' · ' + fmt(x.count)) + '"><span class="hb-l" title="' + esc(x.name) + '">' + esc(x.name) + '</span><span class="hb-t"><i style="width:' + Math.max(2, 100 * x.count / max).toFixed(1) + '%"></i></span><span class="hb-v">' + fmt(x.count) + '</span></div>';
    }).join('') + '</div>';
  }

  function geoPlot(attackers) {
    if (!attackers.length) return '<p class="muted">No geolocated attackers in the feed.</p>';
    var W = 760, H = 340, top = 80, bot = -60;
    var px = function (lon) { return (lon + 180) / 360 * W; };
    var py = function (lat) { return (top - lat) / (top - bot) * H; };
    var g = '';
    for (var lon = -150; lon <= 150; lon += 30) g += '<line class="grid" x1="' + px(lon) + '" x2="' + px(lon) + '" y1="0" y2="' + H + '"></line>';
    for (var lat = -40; lat <= 60; lat += 20) g += '<line class="grid' + (lat === 0 ? ' eq' : '') + '" x1="0" x2="' + W + '" y1="' + py(lat) + '" y2="' + py(lat) + '"></line>';
    // Coarse continent outlines (lon, lat) so the dots have something to sit on.
    var LAND = [
      [[-168, 65], [-140, 70], [-95, 72], [-75, 62], [-60, 50], [-80, 25], [-97, 18], [-105, 22], [-118, 32], [-125, 48], [-140, 60], [-165, 55]],
      [[-80, 10], [-60, 8], [-35, -6], [-40, -22], [-58, -38], [-70, -52], [-75, -40], [-70, -18], [-81, -5]],
      [[-10, 36], [-9, 43], [-2, 48], [-5, 58], [10, 63], [25, 71], [40, 67], [45, 45], [30, 40], [22, 36], [10, 38], [3, 42]],
      [[-6, 50], [2, 51], [-2, 56], [-5, 58], [-7, 55]],
      [[-17, 15], [-10, 30], [10, 37], [32, 31], [43, 12], [51, 11], [40, -15], [32, -28], [20, -35], [12, -17], [9, 4], [-8, 5]],
      [[45, 45], [40, 67], [70, 73], [110, 77], [140, 72], [170, 66], [160, 58], [140, 50], [130, 35], [122, 25], [108, 18], [100, 8], [95, 15], [80, 8], [72, 20], [60, 25], [50, 30], [36, 36]],
      [[130, 31], [141, 35], [142, 43], [138, 37]],
      [[95, 5], [110, -7], [125, -9], [140, -6], [118, 2], [105, 0]],
      [[114, -22], [122, -18], [135, -12], [143, -11], [150, -24], [153, -28], [147, -38], [138, -35], [130, -31], [115, -34]],
      [[-55, 60], [-20, 70], [-25, 80], [-60, 80]],
    ];
    g += LAND.map(function (poly) { return '<polygon class="land" points="' + poly.map(function (p) { return px(p[0]).toFixed(1) + ',' + py(p[1]).toFixed(1); }).join(' ') + '"></polygon>'; }).join('');
    g += '<text class="axis" x="6" y="' + (py(0) - 6) + '">equator</text>';
    var max = Math.max.apply(null, attackers.map(function (a) { return a.count; })) || 1;
    var sorted = attackers.slice().sort(function (a, b) { return a.count - b.count; });
    var dots = sorted.map(function (a) {
      var r = (4 + 14 * Math.sqrt(a.count / max)).toFixed(1);
      var place = (a.city ? a.city + ', ' : '') + (a.country || 'unknown');
      return '<circle class="dot s1" cx="' + px(a.lon).toFixed(1) + '" cy="' + py(a.lat).toFixed(1) + '" r="' + r + '" data-tip="' + esc(a.ip + ' · ' + place + ' · ' + fmt(a.count) + ' events') + '"></circle>';
    }).join('');
    var seen = {}, placed = [];
    var labels = attackers.slice().sort(function (a, b) { return b.count - a.count; }).filter(function (a) { if (seen[a.country]) return false; seen[a.country] = 1; return true; }).slice(0, 4)
      .map(function (a) {
        var x = px(a.lon) + 8 + 14 * Math.sqrt(a.count / max), y = py(a.lat) + 4, w = a.country.length * 7 + 4;
        for (var tries = 0; tries < 6 && placed.some(function (b) { return x < b.x + b.w && x + w > b.x && Math.abs(y - b.y) < 14; }); tries++) y += 15;
        placed.push({ x: x, y: y, w: w });
        return '<text class="dlabel" x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '">' + esc(a.country) + '</text>';
      }).join('');
    return '<svg class="chart geo" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Attacker origins by latitude and longitude; circle size is event count">' + g + dots + labels + '</svg>' +
      table(['IP', 'Place', 'Events'], attackers.map(function (a) { return [a.ip, (a.city ? a.city + ', ' : '') + a.country, fmt(a.count)]; }));
  }

  function stackBar(parts) {
    var total = parts.reduce(function (n, p) { return n + p.value; }, 0) || 1;
    return '<div class="stack">' + parts.map(function (p, i) {
      return '<span class="seg s' + (i + 1) + '" style="flex:' + p.value + '" data-tip="' + esc(p.label + ' · ' + p.value) + '">' + esc(p.label) + ' ' + p.value + '</span>';
    }).join('') + '</div><span class="muted small">' + total + ' total</span>';
  }

  function careerTimeline() {
    var R = D.resume, x0 = 2020, x1 = 2027.5, W = 960, L = 230, Rr = 14, rowH = 36, rows = [];
    var shortOrg = function (o) { var m = o.match(/\(([^)]+)\)/); return m ? m[1] : /Marine/.test(o) ? 'USMC' : o; };
    R.roles.slice().reverse().forEach(function (r) { rows.push({ kind: 'role', label: shortOrg(r.org) + ' · ' + r.title.split(' / ')[0], a: ym(r.start), b: /present/i.test(r.end) ? nowYm() : ym(r.end), tip: r.title + ' · ' + monthLabel(r.start) + ' to ' + (/present/i.test(r.end) ? 'present' : monthLabel(r.end)) }); });
    rows.push({ kind: 'edu', label: 'Education', points: R.education.map(function (e) { return { x: ym(e.date), tip: e.school + ' · ' + e.status.toLowerCase() + ' ' + monthLabel(e.date), hollow: /expected/i.test(e.status) }; }).filter(function (p) { return p.x; }) });
    rows.push({ kind: 'cred', label: 'Credentials and awards', points: D.certs.map(function (c) { return { x: ym(c.issued), tip: c.code + ' · ' + monthLabel(c.issued) }; }).concat(R.awards.map(function (a) { return { x: ym(a.date), tip: a.title + ' · ' + monthLabel(a.date) }; })).filter(function (p) { return p.x; }) });
    var H = rows.length * rowH + 34, pw = W - L - Rr;
    var px = function (v) { return L + (v - x0) / (x1 - x0) * pw; };
    var g = '';
    for (var y = 2020; y <= 2027; y++) g += '<line class="grid" x1="' + px(y) + '" x2="' + px(y) + '" y1="4" y2="' + (H - 24) + '"></line><text class="axis" x="' + px(y) + '" y="' + (H - 8) + '" text-anchor="middle">' + y + '</text>';
    var nowX = px(nowYm());
    g += '<line class="now" x1="' + nowX + '" x2="' + nowX + '" y1="4" y2="' + (H - 24) + '"></line><text class="axis" x="' + (nowX + 4) + '" y="14">now</text>';
    var marks = rows.map(function (row, i) {
      var cy = 10 + i * rowH + rowH / 2;
      var out = '<text class="rlabel" x="' + (L - 10) + '" y="' + (cy + 4) + '" text-anchor="end">' + esc(row.label) + '</text>';
      if (row.kind === 'role') out += '<rect class="s1 gbar" x="' + px(row.a) + '" y="' + (cy - 7) + '" width="' + Math.max(4, px(row.b) - px(row.a)) + '" height="14" rx="4" data-tip="' + esc(row.tip) + '"></rect>';
      else row.points.forEach(function (p) {
        out += row.kind === 'edu'
          ? '<circle class="' + (p.hollow ? 'hollow s2' : 's2') + ' gpt" cx="' + px(p.x) + '" cy="' + cy + '" r="6" data-tip="' + esc(p.tip) + '"></circle>'
          : '<rect class="s3 gpt" x="' + (px(p.x) - 5) + '" y="' + (cy - 5) + '" width="10" height="10" transform="rotate(45 ' + px(p.x) + ' ' + cy + ')" data-tip="' + esc(p.tip) + '"></rect>';
      });
      return out;
    }).join('');
    return '<svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Career timeline from 2020 to 2027: roles, education and credentials">' + g + marks + '</svg>' +
      '<div class="legend"><span><i class="lg s1"></i>Roles</span><span><i class="lg s2 round"></i>Education (hollow: expected)</span><span><i class="lg s3 diamond"></i>Credentials and awards</span></div>';
  }

  function certTimeline(selId) {
    var list = D.certs.slice().sort(function (a, b) { return ym(a.issued) - ym(b.issued); });
    var x0 = 2024, x1 = 2026.6, W = 960, H = 150, L = 24, R = 24, pw = W - L - R;
    var px = function (v) { return L + (v - x0) / (x1 - x0) * pw; };
    var g = '';
    [2024, 2025, 2026].forEach(function (y) { g += '<line class="grid" x1="' + px(y) + '" x2="' + px(y) + '" y1="20" y2="118"></line><text class="axis" x="' + px(y) + '" y="140" text-anchor="middle">' + y + '</text>'; });
    g += '<line class="axisline" x1="' + L + '" x2="' + (W - R) + '" y1="80" y2="80"></line>';
    var marks = list.map(function (c, i) {
      var x = px(ym(c.issued)), up = i % 2 === 0, on = c.id === selId;
      return '<line class="stem" x1="' + x + '" x2="' + x + '" y1="80" y2="' + (up ? 46 : 104) + '"></line>' +
        '<circle class="' + (c.issuer === 'GIAC' ? 's1' : 's2') + ' cpt' + (on ? ' on' : '') + '" cx="' + x + '" cy="80" r="' + (on ? 8 : 6) + '" data-tip="' + esc(c.code + ' · ' + c.issuer + ' · ' + monthLabel(c.issued)) + '" data-cert="' + c.id + '" tabindex="0" role="button" aria-label="' + esc(c.code) + '"></circle>' +
        '<text class="dlabel' + (on ? ' on' : '') + '" x="' + x + '" y="' + (up ? 40 : 118) + '" text-anchor="middle">' + esc(c.code) + '</text>';
    }).join('');
    return '<svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Credential issue dates from 2024 to 2026">' + g + marks + '</svg>' +
      '<div class="legend"><span><i class="lg s1 round"></i>GIAC</span><span><i class="lg s2 round"></i>Other issuers</span></div>';
  }

  /* ── shared pieces ── */
  function liveBadge() {
    if (!liveTried) return '<span class="badge"><i class="dot"></i>connecting</span>';
    if (!live) return '<span class="badge warn"><i class="dot"></i>feed unreachable</span>';
    if (live.stale) return '<span class="badge warn" title="Feed generated ' + esc(dateLong(live.generatedAt)) + '"><i class="dot"></i>stale · ' + esc(V2.ago(live.generatedAt)) + '</span>';
    return '<span class="badge good"><i class="dot"></i>live · ' + esc(V2.ago(live.generatedAt)) + '</span>';
  }

  function cveChips(cves) {
    return cves.map(function (c) {
      var bits = [c.id];
      if (c.cvss) bits.push('CVSS ' + c.cvss);
      if (c.epss != null) bits.push('EPSS ' + (c.epss * 100).toFixed(c.epss >= 0.1 ? 0 : 1) + '%');
      return '<span class="cve' + (c.kev ? ' kev' : '') + '">' + esc(bits.join(' · ')) + (c.kev ? ' <b>KEV</b>' : '') + '</span>';
    }).join('');
  }

  function exploitBadge(x) {
    if (!x) return '';
    var cls = /in_wild|confirmed/.test(x) ? 'crit' : /poc|public/.test(x) ? 'serious' : '';
    return '<span class="tag ' + cls + '">' + esc(label(x)) + '</span>';
  }

  /* ── views ── */
  function viewHome() {
    var ed = D.editions[0], post = D.posts[0], role = D.resume.roles[0];
    var latestCert = D.certs.slice().sort(function (a, b) { return ym(b.issued) - ym(a.issued); })[0];
    var hpTile = live
      ? '<button type="button" class="kpi" data-go="threat"><span class="kpi-h">Honeypot events · 24h ' + liveBadge() + '</span><b>' + fmt(live.events24h) + '</b>' + sparkline(live.hourly) + '<span class="kpi-f">' + fmt(live.events7d) + ' in 7 days · feed from ' + esc(dateLong(live.generatedAt)) + '</span></button>' +
        '<button type="button" class="kpi" data-go="threat"><span class="kpi-h">Unique attackers · 24h</span><b>' + fmt(live.unique24h) + '</b><span class="kpi-f">Top origin: ' + esc((live.countryCounts[0] || {}).name || 'n/a') + ' · ' + fmt(live.reported24h) + ' reported to AbuseIPDB</span></button>'
      : '<button type="button" class="kpi" data-go="threat"><span class="kpi-h">Honeypot ' + liveBadge() + '</span><b>' + D.practice.total + '</b><span class="kpi-f">graded KQL questions while the feed reconnects</span></button>' +
        '<div class="kpi"><span class="kpi-h">Hunt templates</span><b>' + D.templates.length + '</b><span class="kpi-f">public KQL hunts in the lab</span></div>';
    var stories = ed ? ed.stories.slice(0, 3).map(function (s, i) {
      return '<button type="button" class="srow" data-go="intel/0/' + i + '"><span class="rank">' + s.rank + '</span><span class="stitle">' + esc(s.title) + '<span class="smeta">' + esc(label(s.category)) + (s.cves.length ? ' · ' + esc(s.cves[0].id) : '') + '</span></span><span class="score"><i style="width:' + s.score + '%"></i><em>' + s.score + '</em></span></button>';
    }).join('') : '';
    var firstPara = post && post.sections[0] ? post.sections[0].paragraphs[0] : (post ? post.summary : '');
    return '<div class="view">' +
      '<div class="hero"><div><h1>Threat hunting,<br>in the open.</h1><p>' + esc(D.person.name) + '. ' + esc(D.person.summary) + '</p></div>' +
      '<div class="hero-actions"><a class="btn btn-blue btn-lg" href="/lab/">Open the lab</a><button type="button" class="btn btn-lg" data-go="resume">Read the resume</button></div></div>' +
      '<div class="kpis">' + hpTile +
      (ed ? '<button type="button" class="kpi" data-go="intel"><span class="kpi-h">Latest intel brief</span><b>' + esc(ed.date.slice(5).replace('-', '/')) + '</b><span class="kpi-f">' + ed.stories.length + ' ranked stories · ' + ed.kev.length + ' new KEV · ' + ed.stats.sourcesOk + ' sources checked</span></button>' : '') +
      '<button type="button" class="kpi" data-go="creds"><span class="kpi-h">Credentials</span><b>' + D.certs.length + '</b><span class="kpi-f">Latest: ' + esc(latestCert.code) + ', ' + esc(monthLabel(latestCert.issued)) + '</span></button></div>' +
      '<div class="cols">' +
      (ed ? '<section class="card grow"><div class="card-h"><h2>Today\'s brief · ' + esc(ed.date) + '</h2><button type="button" class="link-btn" data-go="intel">Open the brief →</button></div>' +
        (ed.explainer ? '<p class="explain"><b>Explainer:</b> ' + esc(ed.explainer.concept) + '</p>' : '') + '<div class="srows">' + stories + '</div><p class="prov">Stories triaged by ' + esc(ed.models ? ed.models.triage : 'a model') + ' and written up by ' + esc(ed.models ? ed.models.writeup : 'a model') + '.</p></section>' : '') +
      '<div class="stackcol">' +
      (post ? '<button type="button" class="card left" data-go="writing/0"><span class="eyebrow">LATEST POST · ' + esc(post.date) + ' · ' + post.minutes + ' MIN</span><b class="ctitle">' + esc(post.title) + '</b><span class="sub">' + inline(firstPara) + '</span><span class="chips">' + post.tags.map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('') + '</span></button>' : '') +
      '<button type="button" class="card left" data-go="resume"><span class="eyebrow">NOW · SINCE ' + esc(monthLabel(role.start).toUpperCase()) + '</span><b class="ctitle">' + esc(role.title) + ', ' + esc(role.org.replace(/.*\((.*)\)/, '$1')) + '</b><span class="sub">' + esc(role.bullets[0]) + '</span></button>' +
      '</div></div>' +
      '<div class="section-head"><h2>Tools</h2><button type="button" class="link-btn" data-go="tools">All tools →</button></div>' +
      '<div class="grid">' + D.tools.map(function (t, i) {
        return '<button type="button" class="tcard" data-go="tools/' + t.id + '"><span class="numeral" aria-hidden="true">' + (i + 1) + '</span>' +
          '<span class="media" style="background:' + TINT[t.id] + '"><span class="icon" style="background:' + t.color + '">' + esc(t.title.charAt(0)) + '</span></span>' +
          '<span class="meta"><b>' + esc(t.title) + '</b><span>' + esc(t.facts[0][1]) + '</span></span>' +
          '<span class="peek" aria-hidden="true"><b>' + esc(t.title) + '</b><span>' + esc(t.summary) + '</span><em>Open details</em></span></button>';
      }).join('') + '</div></div>';
  }

  function viewThreat() {
    var head = '<div class="view-head"><div><h1>Threat feed</h1><p>A residential Cowrie SSH honeypot. Every login attempt, command and download is logged, geolocated and shared with AbuseIPDB and AlienVault OTX.</p></div><div class="row-actions">' + liveBadge() + '<a class="btn" href="/lab/threat-feed/">Full feed ↗</a></div></div>';
    if (!live) return '<div class="view">' + head + '<div class="empty">' + (liveTried ? 'The honeypot feed is unreachable right now. This view shows hourly activity, attacker origins, top credentials and commands, CISA KEV additions and recent ransomware victims once it reconnects.' : 'Connecting to the honeypot feed…') + '</div></div>';
    var L = live;
    var stale = L.stale ? '<div class="note warn"><b>Heads up:</b> this feed was last generated ' + esc(dateLong(L.generatedAt)) + ' (' + esc(V2.ago(L.generatedAt)) + '). The numbers below describe the 24 hours before that, not today.</div>' : '';
    var kpi = function (v, l, f) { return '<div class="kpi static"><span class="kpi-h">' + esc(l) + '</span><b>' + v + '</b>' + (f ? '<span class="kpi-f">' + esc(f) + '</span>' : '') + '</div>'; };
    return '<div class="view">' + head + stale +
      '<div class="kpis six">' + kpi(fmt(L.events24h), 'Events · 24h', fmt(L.events7d) + ' in 7 days') + kpi(fmt(L.unique24h), 'Unique IPs · 24h', fmt(L.unique7d) + ' in 7 days') + kpi(fmt(L.logins24h), 'Successful logins · 24h', 'attackers who got a shell') +
      kpi(fmt(L.sharing.abuseipdb24h), 'Reported to AbuseIPDB', 'last 24h') + kpi(fmt(L.sharing.vtMalicious), 'VT-flagged payloads', fmt(L.sharing.vtLookups) + ' looked up') + kpi(fmt(L.sharing.otxPulses), 'OTX pulses', 'shared to date') + '</div>' +
      '<section class="card"><div class="card-h"><h2>Events per hour</h2><span class="muted small">UTC · hover a bar</span></div>' + hourlyChart(L.hourly) + '</section>' +
      '<div class="cols"><section class="card grow"><div class="card-h"><h2>Where attacks come from</h2><span class="muted small">circle size = events</span></div>' + geoPlot(L.attackers) + '</section>' +
      '<div class="stackcol"><section class="card"><div class="card-h"><h2>Top countries</h2></div>' + hbars(L.countryCounts.slice(0, 6)) + '</section><section class="card"><div class="card-h"><h2>Top networks</h2></div>' + hbars(L.asns.slice(0, 5)) + '</section></div></div>' +
      '<div class="cols three"><section class="card"><div class="card-h"><h2>Usernames tried</h2></div>' + hbars(L.usernames, { mono: true }) + '</section>' +
      '<section class="card"><div class="card-h"><h2>Passwords tried</h2></div>' + hbars(L.passwords, { mono: true }) + '</section>' +
      '<section class="card"><div class="card-h"><h2>Commands run</h2></div>' + hbars(L.commands, { mono: true }) + '</section></div>' +
      '<div class="cols"><section class="card grow"><div class="card-h"><h2>Recent CISA KEV additions</h2></div><div class="tscroll"><table class="tbl"><thead><tr><th>CVE</th><th>Vendor / product</th><th>Added</th><th>Due</th></tr></thead><tbody>' +
      L.kev.map(function (k) { return '<tr><td class="mono">' + esc(k.cve) + (k.ransom ? ' <span class="tag crit">ransomware</span>' : '') + '</td><td>' + esc(k.vendor + ' ' + k.product) + '</td><td class="mono">' + esc(k.added) + '</td><td class="mono">' + esc(k.due) + '</td></tr>'; }).join('') + '</tbody></table></div></section>' +
      '<section class="card grow"><div class="card-h"><h2>Recent ransomware victims</h2></div><div class="tscroll"><table class="tbl"><thead><tr><th>Victim</th><th>Group</th><th>Sector</th><th>Posted</th></tr></thead><tbody>' +
      L.ransomware.map(function (r) { return '<tr><td>' + esc(r.victim) + ' <span class="muted">' + esc(r.country) + '</span></td><td>' + esc(r.group) + '</td><td>' + esc(r.activity) + '</td><td class="mono">' + esc(r.published) + '</td></tr>'; }).join('') + '</tbody></table></div></section></div></div>';
  }

  function viewIntel() {
    if (!D.editions.length) return '<div class="view"><div class="empty">No intel editions in this build.</div></div>';
    var ed = D.editions[Math.min(S.ed, D.editions.length - 1)];
    var st = ed.stories[Math.min(S.story, ed.stories.length - 1)] || ed.stories[0];
    var pills = D.editions.map(function (e, i) { return '<button type="button" class="pill-btn" data-ed="' + i + '" aria-pressed="' + (i === S.ed) + '">' + esc(e.date.slice(5).replace('-', '/')) + '<small>' + e.stories.length + '</small></button>'; }).join('');
    var items = ed.stats.items || {};
    var list = ed.stories.map(function (s, i) {
      return '<button type="button" class="srow" data-story="' + i + '" aria-pressed="' + (i === S.story) + '"><span class="rank">' + s.rank + '</span><span class="stitle">' + esc(s.title) + '<span class="smeta">' + esc(label(s.category)) + (s.vendor ? ' · ' + esc(s.vendor) : '') + '</span></span><span class="score"><i style="width:' + s.score + '%"></i><em>' + s.score + '</em></span></button>';
    }).join('');
    var detail = st ? '<article class="story">' +
      '<div class="story-tags"><span class="tag">#' + st.rank + ' · score ' + st.score + '</span><span class="tag">' + esc(label(st.category)) + '</span>' + exploitBadge(st.exploitation) + (st.confidence ? '<span class="tag">confidence: ' + esc(st.confidence) + '</span>' : '') + '</div>' +
      '<h2>' + esc(st.title) + '</h2>' + (st.cves.length ? '<div class="cves">' + cveChips(st.cves) + '</div>' : '') +
      (st.what ? '<h3>What happened</h3><p>' + esc(st.what) + '</p>' : '') + (st.why ? '<h3>Why it matters</h3><p>' + esc(st.why) + '</p>' : '') +
      (st.actions.length ? '<h3>Recommended actions</h3><ul>' + st.actions.map(function (a) { return '<li>' + esc(a) + '</li>'; }).join('') + '</ul>' : '') +
      (st.queries.length ? '<h3>Hunting query <span class="muted small">(' + st.queryCount + ' in the edition)</span></h3><p class="small muted">' + esc(st.queries[0].title) + '</p><pre class="kql"><code>' + esc(st.queries[0].kql) + '</code></pre>' : '') +
      (st.sources.length ? '<h3>Sources</h3><ul class="sources">' + st.sources.map(function (s) { return '<li><a href="' + esc(s.url) + '" rel="noopener">' + esc(s.title) + '</a> <span class="muted">' + esc(s.source) + '</span></li>'; }).join('') + '</ul>' : '') +
      '<p class="prov">Written up by ' + esc(ed.models ? ed.models.writeup : 'a model') + ' from the sources above. Check the sources before acting.</p></article>' : '';
    return '<div class="view"><div class="view-head"><div><h1>Intel brief</h1><p>Each morning: news, advisories, KEV and NVD entries and social chatter, scored for exploitation, prevalence and severity, with AI-written summaries and hunting queries.</p></div><a class="btn" href="' + esc(ed.href) + '" rel="noopener">Read this edition ↗</a></div>' +
      '<div class="pills" role="group" aria-label="Edition">' + pills + '</div>' +
      '<div class="kpis six"><div class="kpi static"><span class="kpi-h">Stories ranked</span><b>' + ed.stories.length + '</b><span class="kpi-f">of ' + ed.stats.storiesFound + ' found</span></div><div class="kpi static"><span class="kpi-h">Sources checked</span><b>' + ed.stats.sourcesOk + '</b><span class="kpi-f">of ' + ed.stats.sourcesTotal + ' configured</span></div>' +
      '<div class="kpi static"><span class="kpi-h">NVD entries</span><b>' + fmt(items.nvd || 0) + '</b></div><div class="kpi static"><span class="kpi-h">News items</span><b>' + fmt(items.news || 0) + '</b></div><div class="kpi static"><span class="kpi-h">New KEV</span><b>' + ed.kev.length + '</b></div><div class="kpi static"><span class="kpi-h">Social posts</span><b>' + fmt(items.social || 0) + '</b></div></div>' +
      (ed.explainer ? '<section class="card explainer"><span class="eyebrow">TODAY\'S EXPLAINER</span><b class="ctitle">' + esc(ed.explainer.concept) + '</b><p>' + esc(ed.explainer.dek) + '</p>' + (ed.explainer.takeaways.length ? '<ul>' + ed.explainer.takeaways.map(function (t) { return '<li>' + esc(t) + '</li>'; }).join('') + '</ul>' : '') + '</section>' : '') +
      '<div class="split"><div class="list"><div class="card-h"><h2>Ranked stories</h2><span class="muted small">score out of 100</span></div><div class="srows">' + list + '</div></div><div class="detail">' + detail + '</div></div>' +
      (ed.kev.length ? '<section class="card"><div class="card-h"><h2>Added to CISA KEV</h2></div><div class="tscroll"><table class="tbl"><thead><tr><th>CVE</th><th>Vulnerability</th><th>Added</th><th>Due</th></tr></thead><tbody>' + ed.kev.map(function (k) { return '<tr><td class="mono">' + esc(k.cve) + '</td><td>' + esc(k.name) + '</td><td class="mono">' + esc(k.added) + '</td><td class="mono">' + esc(k.due) + '</td></tr>'; }).join('') + '</tbody></table></div></section>' : '') +
      '<div class="cols">' + (ed.goodNews.length ? '<section class="card grow"><div class="card-h"><h2>Good news</h2></div>' + ed.goodNews.map(function (g) { return '<p><b>' + esc(g.headline) + '.</b> ' + esc(g.summary) + '</p>'; }).join('') + '</section>' : '') +
      (ed.more.length ? '<section class="card grow"><div class="card-h"><h2>Also seen</h2></div><ul class="plain">' + ed.more.map(function (m) { return '<li>' + (m.url ? '<a href="' + esc(m.url) + '" rel="noopener">' + esc(m.title) + '</a>' : esc(m.title)) + ' <span class="muted mono">' + m.score + '</span></li>'; }).join('') + '</ul></section>' : '') + '</div></div>';
  }

  function viewTools() {
    var t = tool(S.tool);
    var rows = D.tools.map(function (x, i) {
      return '<button type="button" class="row" data-tool="' + x.id + '" aria-pressed="' + (x.id === t.id) + '"><span class="numeral" aria-hidden="true">' + (i + 1) + '</span><span class="sq" style="background:' + x.color + '">' + esc(x.title.charAt(0)) + '</span><span class="meta"><b>' + esc(x.title) + '</b><span>' + esc(x.facts[0][0] + ': ' + x.facts[0][1]) + '</span></span></button>';
    }).join('');
    var facts = t.facts;
    if (t.id === 'honey' && live) facts = [['Sensor', 'Cowrie, SSH'], ['Events 24h', fmt(live.events24h)], ['Unique IPs 24h', fmt(live.unique24h)], ['Reported 24h', fmt(live.reported24h)], ['Feed generated', dateLong(live.generatedAt)]];
    var extra = '';
    if (t.id === 'lab') {
      var pd = D.practice.byDifficulty;
      extra = '<h3>Practice set</h3>' + stackBar([{ label: 'Easy', value: pd.easy || 0 }, { label: 'Medium', value: pd.medium || 0 }, { label: 'Hard', value: pd.hard || 0 }]) +
        '<h3>Hunt templates</h3><div class="accordion">' + D.templates.map(function (h) {
          return '<details><summary><b>' + esc(h.name) + '</b>' + (h.verifiedAgainst ? '<span class="tag">verified: ' + esc(h.verifiedAgainst) + '</span>' : '') + '</summary><p>' + esc(h.description) + '</p>' +
            (h.tags.length ? '<span class="chips">' + h.tags.map(function (x) { return '<span class="chip">' + esc(x) + '</span>'; }).join('') + '</span>' : '') +
            (h.kql ? '<pre class="kql"><code>' + esc(h.kql) + '</code></pre>' : '') + '<a class="link-btn" href="/lab/templates/">Open in the lab →</a></details>';
        }).join('') + '</div>';
    } else if (t.id === 'intel') {
      var e = D.editions[0];
      extra = e ? '<h3>Latest edition · ' + esc(e.date) + '</h3><div class="srows">' + e.stories.slice(0, 5).map(function (s, i) { return '<button type="button" class="srow" data-go="intel/0/' + i + '"><span class="rank">' + s.rank + '</span><span class="stitle">' + esc(s.title) + '</span><span class="score"><i style="width:' + s.score + '%"></i><em>' + s.score + '</em></span></button>'; }).join('') + '</div><button type="button" class="btn" data-go="intel">Open the intel view</button>' : '';
    } else if (t.id === 'honey') {
      extra = live ? '<h3>Last 24 hours</h3>' + sparkline(live.hourly) + '<button type="button" class="btn" data-go="threat">Open the threat feed view</button>' : '<button type="button" class="btn" data-go="threat">Open the threat feed view</button>';
    } else if (t.id === 'soc') {
      var p = D.posts.filter(function (x) { return x.slug === 'inside-invoke-kqlps'; })[0];
      extra = p ? '<h3>Read the build notes</h3><button type="button" class="card left" data-go="writing/' + D.posts.indexOf(p) + '"><b class="ctitle">' + esc(p.title) + '</b><span class="sub">' + esc(p.summary) + '</span></button>' : '';
    }
    var mods = modulesOf(t.id).map(function (m) { return '<a class="module" href="' + esc(m.href) + '"' + ext(m.href) + '><b>' + esc(m.title) + '</b><span>' + esc(m.summary) + '</span></a>'; }).join('');
    return '<div class="view"><div class="view-head"><div><h1>Tools</h1><p>Four things I built and run. Pick one for its parts, data and links.</p></div></div>' +
      '<div class="split"><div class="list">' + rows + '</div>' +
      '<div class="detail"><div class="detail-head"><span class="sq big" style="background:' + t.color + '">' + esc(t.title.charAt(0)) + '</span><div><b>' + esc(t.title) + '</b><span>#' + (D.tools.indexOf(t) + 1) + ' of ' + D.tools.length + '</span></div><a class="btn btn-blue push" href="' + esc(t.href) + '"' + ext(t.href) + '>' + esc(t.cta) + '</a></div>' +
      '<p>' + esc(t.summary) + '</p><div class="facts">' + facts.map(function (f) { return '<div class="fact"><span>' + esc(f[0]) + '</span><span>' + esc(f[1]) + '</span></div>'; }).join('') + '</div>' +
      (mods ? '<h3>Parts</h3><div class="modules">' + mods + '</div>' : '') + extra + '</div></div></div>';
  }

  function viewWriting() {
    var p = D.posts[Math.min(S.post, D.posts.length - 1)];
    var list = D.posts.map(function (x, i) {
      return '<button type="button" class="card left" data-post="' + i + '" aria-pressed="' + (i === S.post) + '"><span class="eyebrow">' + esc(x.date) + ' · ' + x.minutes + ' MIN · ' + fmt(x.words) + ' WORDS</span><b class="ctitle">' + esc(x.title) + '</b><span class="sub">' + esc(x.summary) + '</span><span class="chips">' + x.tags.map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('') + '</span></button>';
    }).join('');
    var outline = p.sections.filter(function (s) { return s.heading; }).map(function (s, i) { return '<li><a href="#sec-' + i + '" data-anchor="sec-' + i + '">' + esc(s.heading) + '</a></li>'; }).join('');
    var body = p.sections.map(function (s, i) {
      return (s.heading ? '<h3 id="sec-' + i + '">' + esc(s.heading) + '</h3>' : '') + s.paragraphs.map(function (para) { return '<p>' + inline(para) + '</p>'; }).join('');
    }).join('');
    return '<div class="view"><div class="view-head"><div><h1>Writing</h1><p>Posts from the workbench, readable right here. The Daily Intel Brief lives in its own view.</p></div><div class="row-actions"><button type="button" class="btn" data-go="intel">Intel brief</button><a class="btn" href="/blog/">Blog ↗</a></div></div>' +
      '<div class="split"><div class="list">' + list + '</div>' +
      '<article class="detail reader"><span class="eyebrow">' + esc(p.date) + ' · ' + p.minutes + ' MIN READ · ' + esc(p.tags.join(', ')) + '</span><h2 class="rtitle">' + esc(p.title) + '</h2><p class="lede">' + esc(p.summary) + '</p>' +
      (outline ? '<nav class="outline" aria-label="In this post"><span class="eyebrow">IN THIS POST</span><ol>' + outline + '</ol></nav>' : '') + body +
      '<a class="btn btn-blue" href="' + esc(p.href) + '">Read on the blog ↗</a></article></div></div>';
  }

  function viewResume() {
    var R = D.resume;
    var roles = R.roles.map(function (r) {
      var a = ym(r.start), b = /present/i.test(r.end) ? null : ym(r.end);
      return '<section class="card role"><div class="role-h"><div><span class="eyebrow">' + esc(monthLabel(r.start).toUpperCase()) + ' TO ' + esc((b ? monthLabel(r.end) : 'PRESENT').toUpperCase()) + ' · ' + esc(span(a, b).toUpperCase()) + '</span><h2>' + esc(r.title) + '</h2><span class="sub">' + esc(r.org) + '</span></div>' + (b ? '' : '<span class="badge good"><i class="dot"></i>current</span>') + '</div><ul>' + r.bullets.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul></section>';
    }).join('');
    var nums = R.accomplishments.map(function (a) {
      var m = a.match(/Diamond \d/) || a.match(/\d[\d.,]*[MK]?\+/) || a.match(/\d+/);
      return '<div class="kpi static"><b>' + esc(m ? m[0] : '•') + '</b><span class="kpi-f">' + esc(a) + '</span></div>';
    }).join('');
    return '<div class="view"><div class="view-head"><div><h1>Resume</h1><p>' + esc(R.summary) + '</p></div><div class="row-actions"><a class="btn" href="/resume/Bryce_Maxheimer_Resume.pdf">PDF ↗</a><a class="btn" href="/resume/">Full resume ↗</a></div></div>' +
      '<div class="kpis">' + nums + '</div>' +
      '<section class="card"><div class="card-h"><h2>Timeline</h2><span class="muted small">hover any mark</span></div>' + careerTimeline() + '</section>' +
      roles +
      '<div class="cols"><section class="card grow"><div class="card-h"><h2>Skills</h2></div>' + R.skills.map(function (s) { return '<div class="skill"><span class="eyebrow">' + esc(s.label.toUpperCase()) + '</span><span class="chips">' + s.items.map(function (x) { return '<span class="chip">' + esc(x) + '</span>'; }).join('') + '</span></div>'; }).join('') + '</section>' +
      '<div class="stackcol"><section class="card"><div class="card-h"><h2>Education and training</h2></div><ul class="plain">' + R.education.map(function (e) { return '<li><b>' + esc(e.school) + '</b>' + (e.detail ? '<br><span class="sub">' + esc(e.detail) + '</span>' : '') + '<br><span class="muted mono small">' + esc(e.status) + ' ' + esc(e.date) + '</span></li>'; }).join('') + '</ul></section>' +
      '<section class="card"><div class="card-h"><h2>Awards</h2></div><ul class="plain">' + R.awards.map(function (a) { return '<li><b>' + esc(a.title) + '</b> <span class="muted mono small">' + esc(a.date) + '</span></li>'; }).join('') + '</ul><p class="sub">Clearance: ' + esc(D.person.clearance) + '</p></section></div></div></div>';
  }

  function viewCreds() {
    var c = cert(S.cert);
    var groups = {};
    D.certs.forEach(function (x) { (groups[x.issuer] = groups[x.issuer] || []).push(x); });
    return '<div class="view"><div class="view-head"><div><h1>Credentials</h1><p>Red team training from Marine Corps Cyberspace Operations Group, blue team credentials from SANS and GIAC, offensive testing from CompTIA, and competition results.</p></div><a class="btn" href="' + esc(D.person.giac) + '" rel="noopener">GIAC record ↗</a></div>' +
      '<section class="card"><div class="card-h"><h2>When they were earned</h2><span class="muted small">click a dot</span></div>' + certTimeline(c.id) + '</section>' +
      '<div class="cert-hero"><span class="stripe" style="background:' + c.color + '"></span><div class="txt"><b>' + esc(c.code) + '</b><span class="sub">' + esc(c.name) + '</span><small>' + esc(c.issuer) + ' · ' + esc(monthLabel(c.issued)) + '</small><p>' + esc(c.summary) + '</p><span class="chips">' + c.tags.map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('') + '</span></div><a class="btn" href="' + esc(c.verify) + '"' + ext(c.verify) + '>Verify ↗</a></div>' +
      Object.keys(groups).map(function (g) {
        return '<div class="section-head"><h2>' + esc(g) + '</h2><span class="muted small">' + groups[g].length + '</span></div><div class="grid">' + groups[g].map(function (x) {
          return '<button type="button" class="ccard" data-cert="' + x.id + '" aria-pressed="' + (x.id === c.id) + '"><span class="stripe" style="background:' + x.color + '"></span><b>' + esc(x.code) + '</b><span>' + esc(x.name) + '</span><small>' + esc(monthLabel(x.issued)) + '</small></button>';
        }).join('') + '</div>';
      }).join('') +
      '<div class="note">In progress: B.S. Applied Cybersecurity, SANS Technology Institute, expected January 2027.</div></div>';
  }

  function viewContact() {
    var p = D.person;
    return '<div class="view"><div class="view-head"><div><h1>Contact</h1><p>Questions, corrections and collaboration are welcome.</p></div></div>' +
      '<div class="cert-hero"><div class="txt"><span class="eyebrow">EMAIL</span><a class="big-link" href="mailto:' + esc(p.email) + '">' + esc(p.email) + '</a></div><button type="button" class="btn" data-copy="' + esc(p.email) + '">Copy email</button></div>' +
      '<div class="grid wide"><a class="box" href="' + esc(p.linkedin) + '" rel="noopener"><span class="eyebrow">LINKEDIN</span><b>bryce-maxheimer ↗</b><span class="sub">Work history and recommendations</span></a><a class="box" href="' + esc(p.github) + '" rel="noopener"><span class="eyebrow">GITHUB</span><b>brycemaxheimer ↗</b><span class="sub">Source for this site, the lab and the SOC Dashboard</span></a><a class="box" href="' + esc(p.giac) + '" rel="noopener"><span class="eyebrow">GIAC RECORD</span><b>Verify credentials ↗</b><span class="sub">Public record of every GIAC certification</span></a></div></div>';
  }

  /* ── search ── */
  function searchIndex() {
    var idx = [];
    var add = function (type, title, sub, color, badge, go, href) { idx.push({ type: type, title: title, sub: sub, color: color, badge: badge, go: go, href: href }); };
    D.tools.forEach(function (t) { add('tool', t.title, t.summary, t.color, t.title.charAt(0), 'tools/' + t.id); });
    D.modules.forEach(function (m) { add(m.kind, m.title, m.summary, tool(m.parent).color, m.title.charAt(0), 'tools/' + m.parent); });
    D.templates.forEach(function (t) { add('hunt template', t.name, t.description, '#45D0A0', 'H', 'tools/lab'); });
    D.certs.forEach(function (c) { add('credential', c.code, c.name + '. ' + c.summary, c.color, 'C', 'creds/' + c.id); });
    D.posts.forEach(function (p, i) {
      add('post', p.title, p.summary + ' ' + p.tags.join(' '), '#C4B5FD', 'P', 'writing/' + i);
      p.sections.forEach(function (s) { if (s.heading) add('post section', s.heading, p.title + ': ' + (s.paragraphs[0] || ''), '#C4B5FD', '§', 'writing/' + i); });
    });
    D.editions.forEach(function (e, i) { e.stories.forEach(function (s, j) { add('intel ' + e.date, s.title, (s.what || '') + ' ' + s.cves.map(function (c) { return c.id; }).join(' '), '#F5C542', 'E', 'intel/' + i + '/' + j); }); });
    D.resume.roles.forEach(function (r) { add('resume', r.title, r.org + '. ' + r.bullets.join(' '), '#F2F2F5', 'R', 'resume'); });
    D.resume.skills.forEach(function (s) { add('skills', s.label, s.items.join(', '), '#F2F2F5', 'S', 'resume'); });
    D.resume.awards.forEach(function (a) { add('award', a.title, a.date, '#F2F2F5', 'A', 'resume'); });
    return idx;
  }

  function viewSearch() {
    var q = S.q.toLowerCase();
    var hits = searchIndex().filter(function (r) { return (r.title + ' ' + r.sub + ' ' + r.type).toLowerCase().indexOf(q) !== -1; });
    var list = hits.slice(0, 60).map(function (r) {
      var inner = '<span class="sq" style="background:' + r.color + '">' + esc(r.badge) + '</span><span class="meta"><b>' + esc(r.title) + '</b><span>' + esc(r.sub.length > 160 ? r.sub.slice(0, 159) + '…' : r.sub) + '</span></span><span class="type">' + esc(r.type) + '</span>';
      return '<button type="button" class="result" data-go="' + r.go + '">' + inner + '</button>';
    }).join('');
    return '<div class="view"><div class="view-head"><div><h1>Results for "' + esc(S.q) + '"</h1><p>' + hits.length + (hits.length === 1 ? ' match' : ' matches') + ' across tools, hunts, intel stories, writing, resume and credentials' + (hits.length > 60 ? ', showing the first 60' : '') + '</p></div></div>' +
      (hits.length ? '<div class="results">' + list + '</div>' : '<p class="empty">Nothing matches. Try "kql", "ssh", "gcih", "sentinel" or a CVE number.</p>') + '</div>';
  }

  /* ── render ── */
  var RENDER = { home: viewHome, threat: viewThreat, intel: viewIntel, tools: viewTools, writing: viewWriting, resume: viewResume, creds: viewCreds, contact: viewContact };

  function render() {
    $('main').innerHTML = S.q ? viewSearch() : (RENDER[S.view] || viewHome)();
    renderNav();
  }

  function renderNav() {
    var last = '';
    $('views').innerHTML = VIEWS.map(function (v) {
      var n = v.id === 'tools' ? D.tools.length : v.id === 'creds' ? D.certs.length : v.id === 'writing' ? D.posts.length : v.id === 'intel' ? D.editions.length : v.id === 'threat' ? (live ? short(live.events24h) : '') : '';
      var head = v.group !== last ? '<span class="side-label">' + v.group + '</span>' : '';
      last = v.group;
      return head + '<button type="button" data-go="' + v.id + '"' + (!S.q && v.id === S.view ? ' aria-current="page"' : '') + '><span class="dot"></span>' + esc(v.label) + '<span class="n">' + n + '</span></button>';
    }).join('');
    var crumb = S.q ? 'search' : S.view === 'tools' ? 'tools / ' + tool(S.tool).title.toLowerCase() : S.view === 'creds' ? 'credentials / ' + cert(S.cert).code.toLowerCase()
      : S.view === 'intel' && D.editions.length ? 'intel / ' + D.editions[S.ed].date : S.view === 'writing' ? 'writing / ' + D.posts[S.post].slug : S.view;
    $('crumb').textContent = 'explore / ' + crumb;
  }

  function renderStatus() {
    $('status-live').textContent = !liveTried ? 'connecting to honeypot feed…' : !live ? 'honeypot feed unreachable · showing site data'
      : 'honeypot feed ' + (live.stale ? 'stale' : 'live') + ' · generated ' + dateLong(live.generatedAt) + ' (' + V2.ago(live.generatedAt) + ')';
    $('status-built').textContent = 'site data built ' + D.generatedAt.slice(0, 10);
    $('pin-live').textContent = live ? (live.stale ? 'Stale' : 'Live') : 'Off';
    $('pin-live').className = 'pill pill-live' + (live ? (live.stale ? ' warn' : ' on') : '');
    $('presence').classList.toggle('on', !!live && !live.stale);
  }

  function hashFor() {
    if (S.view === 'tools') return 'tools/' + S.tool;
    if (S.view === 'creds') return 'creds/' + S.cert;
    if (S.view === 'intel') return 'intel/' + S.ed + '/' + S.story;
    if (S.view === 'writing') return 'writing/' + S.post;
    return S.view;
  }

  function go(target, keepScroll) {
    var parts = String(target).split('/');
    if (!RENDER[parts[0]]) return;
    S.q = ''; $('q').value = '';
    S.view = parts[0];
    if (parts[0] === 'tools' && parts[1]) S.tool = parts[1];
    if (parts[0] === 'creds' && parts[1]) S.cert = parts[1];
    if (parts[0] === 'writing' && parts[1]) S.post = Math.max(0, Math.min(D.posts.length - 1, +parts[1] || 0));
    if (parts[0] === 'intel') {
      if (parts[1] != null) S.ed = Math.max(0, Math.min(D.editions.length - 1, +parts[1] || 0));
      S.story = parts[2] != null ? Math.max(0, +parts[2] || 0) : 0;
    }
    render();
    if (!keepScroll) $('main').scrollTop = 0;
    try { history.replaceState(null, '', '#' + hashFor()); } catch (e) { /* ignore */ }
  }

  /* ── tooltip ── */
  function wireTooltip() {
    var tip = $('tip');
    var place = function (ev) {
      var x = ev.clientX + 14, y = ev.clientY + 14, w = tip.offsetWidth, h = tip.offsetHeight;
      if (x + w > innerWidth - 8) x = ev.clientX - w - 14;
      if (y + h > innerHeight - 8) y = ev.clientY - h - 14;
      tip.style.transform = 'translate(' + x + 'px,' + y + 'px)';
    };
    document.addEventListener('mouseover', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-tip]');
      if (!t) { tip.hidden = true; return; }
      tip.textContent = t.getAttribute('data-tip');
      tip.hidden = false;
      place(ev);
    });
    document.addEventListener('mousemove', function (ev) { if (!tip.hidden) place(ev); });
    document.addEventListener('focusin', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-tip]');
      if (!t) { tip.hidden = true; return; }
      var r = t.getBoundingClientRect();
      tip.textContent = t.getAttribute('data-tip');
      tip.hidden = false;
      place({ clientX: r.left + r.width / 2, clientY: r.bottom });
    });
  }

  function wire() {
    document.addEventListener('click', function (ev) {
      var t = ev.target.closest('[data-go],[data-tool],[data-cert],[data-copy],[data-ed],[data-story],[data-post],[data-anchor]');
      if (!t) return;
      if (t.hasAttribute('data-anchor')) {
        ev.preventDefault();
        var el = document.getElementById(t.getAttribute('data-anchor'));
        if (el) el.scrollIntoView({ behavior: V2.reducedMotion ? 'auto' : 'smooth', block: 'start' });
      } else if (t.hasAttribute('data-go')) go(t.getAttribute('data-go'));
      else if (t.hasAttribute('data-tool')) go('tools/' + t.getAttribute('data-tool'), true);
      else if (t.hasAttribute('data-cert')) go('creds/' + t.getAttribute('data-cert'), true);
      else if (t.hasAttribute('data-ed')) go('intel/' + t.getAttribute('data-ed') + '/0', true);
      else if (t.hasAttribute('data-story')) go('intel/' + S.ed + '/' + t.getAttribute('data-story'), true);
      else if (t.hasAttribute('data-post')) go('writing/' + t.getAttribute('data-post'), true);
      else V2.copy(t.getAttribute('data-copy')).then(function () { t.textContent = 'Copied'; setTimeout(function () { t.textContent = 'Copy email'; }, 1600); });
    });
    document.addEventListener('keydown', function (ev) {
      var tag = (ev.target.tagName || '').toLowerCase();
      if (ev.key === 'Enter' && ev.target.hasAttribute && ev.target.hasAttribute('data-cert') && tag !== 'button') { go('creds/' + ev.target.getAttribute('data-cert'), true); return; }
      if ((ev.key === '/' && tag !== 'input' && tag !== 'textarea') || (ev.key.toLowerCase() === 'k' && (ev.ctrlKey || ev.metaKey))) { ev.preventDefault(); $('q').focus(); $('q').select(); }
      if (ev.key === 'Escape' && ev.target === $('q')) { $('q').value = ''; S.q = ''; render(); }
    });
    $('q').addEventListener('input', function (ev) { S.q = ev.target.value.trim(); render(); });
    window.addEventListener('hashchange', function () {
      var h = (location.hash || '').slice(1);
      if (h && h !== hashFor()) go(h);
    });
    wireTooltip();
  }

  function start() {
    esc = V2.esc; fmt = V2.fmt;
    V2.load().then(function (data) {
      D = data;
      wire();
      var hash = (location.hash || '').slice(1);
      go(hash && RENDER[hash.split('/')[0]] ? hash : 'home');
      renderStatus();
      V2.honeypot(D.live.honeypotFeed, function (summary) {
        var changed = !liveTried || !!summary !== !!live || (summary && live && summary.generatedAt !== live.generatedAt);
        liveTried = true;
        live = summary;
        renderStatus();
        renderNav();
        if (changed && !S.q && ['home', 'threat', 'tools'].indexOf(S.view) !== -1) {
          var top = $('main').scrollTop;
          render();
          $('main').scrollTop = top;
        }
      });
    }).catch(function (err) {
      $('main').innerHTML = '<p class="empty">Could not load site data: ' + V2.esc(err.message) + '. Run <code>node scripts/build-v2-data.mjs</code> and reload.</p>';
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
