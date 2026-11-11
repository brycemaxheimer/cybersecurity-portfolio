/* v2 inspector: the portfolio as a design-tool canvas.
 *
 * Reads /v2/site-data.json (scripts/build-v2-data.mjs) for every fact on the
 * page and polls the public honeypot feed for live numbers. Pages: Network,
 * Resume, Credentials, Writing, Contact. Keys 1 to 5 switch pages, arrow keys
 * move through layers. Selection is mirrored in the URL hash (#page/id).
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var esc, fmt;
  var D = null;            // site data
  var live = null;         // honeypot summary, or null when unreachable
  var liveTried = false;
  var S = { page: 'network', sel: 'bryce', inspect: true };
  var PAGES = {};          // page id -> { label, items: [...] }
  var ORDER = ['network', 'resume', 'creds', 'writing', 'contact'];
  var EDGES = [];          // network edges
  var packets = [];
  var raf = 0;
  var tickerIdx = 0;
  var tickerTimer = 0;

  var trunc = function (s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  var byId = function (id) {
    for (var p in PAGES) {
      var list = PAGES[p].items;
      for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    }
    return null;
  };

  /* ── data model ── */
  function build() {
    var tool = function (id) { return D.tools.filter(function (t) { return t.id === id; })[0]; };
    var mod = function (id) { return D.modules.filter(function (m) { return m.id === id; })[0]; };
    var post = function (slug) { return D.posts.filter(function (p) { return p.id === 'post-' + slug; })[0]; };
    var person = D.person;
    var lab = tool('lab'), intel = tool('intel'), honey = tool('honey'), soc = tool('soc');

    var fromTool = function (t, x, y, sub) {
      return { id: t.id, x: x, y: y, group: 'TOOLS', title: t.title, sub: sub, kind: 'tool', color: t.color, badge: t.title.charAt(0), summary: t.summary, facts: t.facts, href: t.href, cta: t.cta };
    };
    var fromMod = function (m, x, y, sub, color) {
      return { id: m.id, x: x, y: y, minor: true, group: m.kind === 'data sharing' ? 'DATA SHARING' : 'MODULES', title: m.title, sub: sub, kind: m.kind, color: color, badge: m.title.charAt(0), summary: m.summary, facts: [['Part of', tool(m.parent).title]], href: m.href, cta: 'Open' };
    };
    var ed = D.editions.slice(0, 3);
    var pk = post('inside-invoke-kqlps'), pm = post('mitre-crosswalks-in-the-lab');

    var net = [
      { id: 'bryce', x: 500, y: 320, group: 'PEOPLE AND ROLES', title: person.name, sub: 'person · shift lead, DFAS', kind: 'person', color: '#EDEDF0', badge: 'B', summary: person.summary, facts: [['Now', 'Shift Lead, DFAS'], ['Before', 'USMC Cyber Warfare Operator'], ['Study', 'B.S., SANS.edu, Jan 2027'], ['Clearance', person.clearance]], href: '/resume/', cta: 'Open resume' },
      { id: 'dfas', x: 500, y: 70, minor: true, group: 'PEOPLE AND ROLES', title: 'Shift Lead, DFAS', sub: 'role · 2025-07 to present', kind: 'role', color: '#7AB8FF', badge: 'D', summary: D.experience[0].summary, facts: [['Org', D.experience[0].org], ['Dates', '2025-07 to present']], href: '/resume/', cta: 'Open resume' },
      { id: 'usmc', x: 520, y: 578, minor: true, group: 'PEOPLE AND ROLES', title: 'USMC Defensive Cyber Ops', sub: 'role · 2022-02 to 2025-05', kind: 'role', color: '#45D0A0', badge: 'M', summary: D.experience[1].summary, facts: [['Title', D.experience[1].title], ['Dates', '2022-02 to 2025-05']], href: '/resume/', cta: 'Open resume' },
      fromTool(lab, 300, 190, 'tool · 5 pages'),
      fromTool(intel, 700, 190, 'tool · latest ' + (ed[0] ? ed[0].date : 'n/a')),
      fromTool(honey, 700, 450, 'tool · Cowrie SSH'),
      fromTool(soc, 300, 450, 'tool · PowerShell'),
      fromMod(mod('playground'), 105, 95, 'module · KQL on WASM', '#45D0A0'),
      fromMod(mod('practice'), 95, 190, 'module · ' + D.practiceQuestions + ' questions', '#45D0A0'),
      fromMod(mod('builder'), 105, 285, 'module · visual queries', '#45D0A0'),
      fromMod(mod('templates'), 300, 70, 'module · ' + D.templates.length + ' hunts', '#45D0A0'),
      { id: 'threatfeed', x: 760, y: 592, minor: true, group: 'MODULES', title: 'Live Threat Feed', sub: 'page · live map and stats', kind: 'lab page', color: '#FF7A7A', badge: 'F', summary: 'Real-time SSH honeypot data from a residential research network: top attackers, geo map, recent activity, credentials and sharing metrics.', facts: [['Source', 'threats.brycemaxheimer.com'], ['Refresh', 'auto']], href: '/lab/threat-feed/', cta: 'Open the feed' },
      fromMod(mod('abuseipdb'), 890, 410, 'sharing · reports', '#FF7A7A'),
      fromMod(mod('otx'), 890, 500, 'sharing · pulses', '#FF7A7A'),
      fromMod(mod('kqlps'), 100, 450, 'engine · KQL in PowerShell', '#7AB8FF'),
    ];
    ed.forEach(function (e, i) {
      net.push({ id: 'ed' + i, x: 880, y: [95, 190, 285][i], minor: true, group: 'INTEL EDITIONS', title: 'Edition ' + e.date, sub: trunc(e.headlines[0] || 'edition', 26), kind: 'intel edition', color: '#F5C542', badge: 'E', summary: e.title + '. Top stories from that morning:', headlines: e.headlines, facts: [['Date', e.date], ['Stories shown', String(e.headlines.length)]], href: e.href, cta: 'Read the edition' });
    });
    if (pk) net.push({ id: 'post_kqlps', x: 110, y: 570, minor: true, group: 'WRITING', title: pk.title, sub: 'post · ' + pk.date + ' · ' + pk.minutes + ' min', kind: 'blog post', color: '#C4B5FD', badge: 'P', summary: pk.summary, facts: [['Date', pk.date], ['Tags', pk.tags.join(', ')], ['Reading', pk.minutes + ' min']], href: pk.href, cta: 'Read the post' });
    if (pm) net.push({ id: 'post_mitre', x: 130, y: 345, minor: true, group: 'WRITING', title: pm.title, sub: 'post · ' + pm.date + ' · ' + pm.minutes + ' min', kind: 'blog post', color: '#C4B5FD', badge: 'P', summary: pm.summary, facts: [['Date', pm.date], ['Tags', pm.tags.join(', ')], ['Reading', pm.minutes + ' min']], href: pm.href, cta: 'Read the post' });

    net.forEach(function (n) {
      n.w = Math.round(Math.max(n.title.length * (n.minor ? 6.7 : 7.4), n.sub.length * 6.2) + 40);
      n.h = 40;
    });

    EDGES = [
      ['bryce', 'lab'], ['bryce', 'intel'], ['bryce', 'honey'], ['bryce', 'soc'], ['bryce', 'dfas'], ['bryce', 'usmc'],
      ['lab', 'playground'], ['lab', 'practice'], ['lab', 'builder'], ['lab', 'templates'],
      ['intel', 'ed0'], ['intel', 'ed1'], ['intel', 'ed2'],
      ['honey', 'abuseipdb'], ['honey', 'otx'], ['honey', 'threatfeed'], ['honey', 'lab', 'dash'],
      ['soc', 'kqlps'], ['soc', 'lab', 'dash'], ['kqlps', 'post_kqlps'], ['lab', 'post_mitre'],
    ].filter(function (e) {
      var ids = net.map(function (n) { return n.id; });
      return ids.indexOf(e[0]) !== -1 && ids.indexOf(e[1]) !== -1;
    });

    var exp = D.experience.map(function (x, i) {
      return { id: 'exp-' + x.id, group: 'ROLES AND EDUCATION', eyebrow: x.start + ' to ' + x.end, title: x.title, sub: x.org, kind: i === 2 ? 'education' : 'role', color: ['#7AB8FF', '#45D0A0', '#C4B5FD'][i], badge: x.title.charAt(0), summary: x.summary, facts: [['Org', x.org], ['Dates', x.start + ' to ' + x.end]], href: '/resume/', cta: 'Open full resume' };
    });
    var hl = [
      ['30,000+ alerts', 'Processed and analyzed while baselining network behavior in a federal SOC.'],
      ['3.5M+ packets a day', 'Analyzed across critical networks during defensive operations in Okinawa, Japan.'],
      ['NCL Diamond 1', 'National Cyber League Fall 2025, 97th percentile in the Individual Game.'],
      ['100+ users', 'Virtual infrastructure architected and maintained for mission-critical tools.'],
    ].map(function (h, i) {
      return { id: 'hl' + i, group: 'HIGHLIGHTS', eyebrow: 'highlight', title: h[0], sub: h[1], kind: 'accomplishment', color: '#F5A524', badge: '★', summary: h[1], facts: [['Source', 'resume']], href: '/resume/', cta: 'Open full resume' };
    });
    var clearance = { id: 'clearance', group: 'HIGHLIGHTS', eyebrow: 'clearance', title: person.clearance, sub: 'Held for federal SOC work.', kind: 'clearance', color: '#EDEDF0', badge: 'C', summary: 'Clearance as listed on the resume.', facts: [['Level', person.clearance]], href: '/resume/', cta: 'Open full resume' };

    var certs = D.certs.map(function (c) {
      var verify = c.issuer === 'GIAC' ? 'https://www.giac.org/certified-professional/Bryce-Maxheimer/243145' : '/certs/';
      return { id: 'cert-' + c.id, group: c.issuer === 'GIAC' ? 'GIAC (SANS)' : 'OTHER ISSUERS', eyebrow: c.issued + ' · ' + c.issuer, title: c.code, sub: c.name, kind: 'credential', color: c.color, badge: c.code.charAt(0), summary: c.summary, facts: [['Name', c.name], ['Issuer', c.issuer], ['Issued', c.issued]], href: verify, cta: c.issuer === 'GIAC' ? 'Verify on GIAC' : 'View on certs page' };
    });

    var posts = D.posts.map(function (p) {
      return { id: p.id, group: 'BLOG POSTS', eyebrow: p.date + ' · ' + p.minutes + ' min', title: p.title, sub: p.summary, kind: 'blog post', color: '#C4B5FD', badge: 'P', summary: p.summary, facts: [['Date', p.date], ['Tags', p.tags.join(', ')]], href: p.href, cta: 'Read the post' };
    });
    var eds = D.editions.map(function (e, i) {
      return { id: 'edition-' + i, group: 'DAILY INTEL BRIEF', eyebrow: e.date, title: 'Edition ' + e.date, sub: e.headlines[0] || '', kind: 'intel edition', color: '#F5C542', badge: 'E', summary: e.title + '. Top stories:', headlines: e.headlines, facts: [['Date', e.date]], href: e.href, cta: 'Read the edition' };
    });

    var contact = [
      { id: 'c-email', group: 'CONTACT', eyebrow: 'email', title: person.email, sub: 'Fastest way to reach me.', kind: 'link', color: '#A78BFA', badge: '@', summary: 'Questions, corrections and collaboration are welcome.', facts: [['Address', person.email]], href: 'mailto:' + person.email, cta: 'Send an email', copy: person.email },
      { id: 'c-linkedin', group: 'CONTACT', eyebrow: 'linkedin', title: 'bryce-maxheimer', sub: 'Professional profile.', kind: 'link', color: '#7AB8FF', badge: 'in', summary: 'LinkedIn profile.', facts: [['URL', person.linkedin]], href: person.linkedin, cta: 'Open LinkedIn' },
      { id: 'c-github', group: 'CONTACT', eyebrow: 'github', title: 'brycemaxheimer', sub: 'Source for this site, the lab and the SOC Dashboard.', kind: 'link', color: '#EDEDF0', badge: 'GH', summary: 'GitHub, where the site and its tools live.', facts: [['URL', person.github]], href: person.github, cta: 'Open GitHub' },
      { id: 'c-giac', group: 'VERIFICATION', eyebrow: 'giac', title: 'Verify GIAC credentials', sub: 'Public GIAC certified professional record.', kind: 'link', color: '#45D0A0', badge: 'G', summary: 'Every GIAC credential on this site can be checked on the GIAC record.', facts: [['Record', 'Bryce-Maxheimer/243145']], href: 'https://www.giac.org/certified-professional/Bryce-Maxheimer/243145', cta: 'Open GIAC record' },
    ];

    PAGES = {
      network: { label: 'Network', title: 'Network', items: net },
      resume: { label: 'Resume', title: 'Resume', intro: 'Two roles, a degree in progress, and the numbers from the resume.', items: exp.concat(hl, [clearance]) },
      creds: { label: 'Credentials', title: 'Credentials', intro: 'Red team training from Marine Corps Cyberspace Operations Group, blue team credentials from SANS and GIAC, and offensive work from CompTIA.', items: certs },
      writing: { label: 'Writing', title: 'Writing', intro: 'Blog posts from the workbench and the latest editions of the Daily Intel Brief.', items: posts.concat(eds) },
      contact: { label: 'Contact', title: 'Contact', intro: 'Questions, corrections and collaboration are welcome.', items: contact },
    };
  }

  /* ── live data hooks ── */
  function applyLive() {
    var honey = byId('honey'), abuse = byId('abuseipdb');
    if (!honey) return;
    if (live) {
      honey.sub = 'tool · ' + fmt(live.events24h) + ' events / 24h';
      honey.facts = [['Sensor', 'Cowrie, SSH'], ['Events 24h', fmt(live.events24h)], ['Unique IPs 24h', fmt(live.unique24h)], ['Logins 24h', fmt(live.logins24h)], ['Top origins', live.countries.join(', ') || 'n/a']];
      abuse.sub = 'sharing · ' + fmt(live.reported24h) + ' reports / 24h';
      abuse.facts = [['Part of', 'Honeypot'], ['Reported 24h', fmt(live.reported24h)]];
    }
    honey.w = Math.round(Math.max(honey.title.length * 7.4, honey.sub.length * 6.2) + 40);
    abuse.w = Math.round(Math.max(abuse.title.length * 6.7, abuse.sub.length * 6.2) + 40);
  }

  /* ── rendering ── */
  function renderPages() {
    $('pages').innerHTML = ORDER.map(function (p, i) {
      var cur = p === S.page;
      return '<button type="button" data-page="' + p + '"' + (cur ? ' aria-current="page"' : '') + '><span class="num">' + (i + 1) + '</span>' + esc(PAGES[p].label) + '<span class="count">' + PAGES[p].items.length + '</span></button>';
    }).join('');
  }

  function renderLayers() {
    var last = '';
    $('layers').innerHTML = PAGES[S.page].items.map(function (n) {
      var head = '';
      if (n.group !== last) { last = n.group; head = '<div class="layer-group">' + esc(n.group) + '</div>'; }
      var on = n.id === S.sel;
      var icon = n.kind === 'tool' ? '▢' : n.kind === 'person' ? '#' : n.kind.indexOf('post') !== -1 ? 'T' : n.kind === 'credential' ? '✓' : '◇';
      return head + '<button type="button" data-sel="' + n.id + '" aria-pressed="' + on + '"><span class="icon">' + icon + '</span><span class="label">' + esc(n.title) + '</span></button>';
    }).join('');
  }

  function nodeSvg(n) {
    var x = n.x - n.w / 2, y = n.y - n.h / 2;
    var pulse = n.id === 'honey' ? '<rect class="pulse' + (live ? ' go' : '') + '" x="' + x + '" y="' + y + '" width="' + n.w + '" height="' + n.h + '" rx="7"></rect>' : '';
    return '<g class="node' + (n.minor ? ' minor' : '') + '" data-node="' + n.id + '" tabindex="0" role="button" aria-label="' + esc(n.title + ', ' + n.kind) + '">' + pulse +
      '<rect x="' + x + '" y="' + y + '" width="' + n.w + '" height="' + n.h + '" rx="7"></rect>' +
      '<circle cx="' + (x + 13) + '" cy="' + (n.y - 6) + '" r="3.5" fill="' + n.color + '"></circle>' +
      '<text class="t" x="' + (x + 23) + '" y="' + (n.y - 2) + '">' + esc(n.title) + '</text>' +
      '<text class="s" x="' + (x + 13) + '" y="' + (n.y + 13) + '">' + esc(n.sub) + '</text></g>';
  }

  function renderFrame() {
    cancelAnimationFrame(raf);
    clearInterval(tickerTimer);
    var page = PAGES[S.page];
    $('frame-label').textContent = 'Frame / ' + page.label;
    $('crumb').textContent = page.label.toLowerCase();
    if (S.page === 'network') {
      var net = page.items;
      var pos = {}; net.forEach(function (n) { pos[n.id] = n; });
      var edges = EDGES.map(function (e, i) {
        var a = pos[e[0]], b = pos[e[1]];
        return '<line class="edge' + (e[2] ? ' dash' : '') + '" data-edge="' + i + '" x1="' + a.x + '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y + '"></line>';
      }).join('');
      var stats = live
        ? '<div class="stats"><div class="stat"><b>' + fmt(live.events24h) + '</b><span>honeypot events · 24h' + (live.stale ? ' (as of ' + esc(new Date(live.generatedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })) + ')' : '') + '</span></div><div class="stat"><b>' + fmt(live.unique24h) + '</b><span>unique attackers · 24h</span></div><div class="stat"><b>' + fmt(live.reported24h) + '</b><span>reported to AbuseIPDB · 24h</span></div><div class="stat"><b>' + esc(D.editions[0] ? D.editions[0].date.slice(5) : 'n/a') + '</b><span>latest intel edition</span></div></div>'
        : '<div class="stats"><div class="stat"><b>' + D.practiceQuestions + '</b><span>graded KQL questions</span></div><div class="stat"><b>' + D.templates.length + '</b><span>hunt templates</span></div><div class="stat"><b>' + D.certs.length + '</b><span>credentials</span></div><div class="stat"><b>' + esc(D.editions[0] ? D.editions[0].date.slice(5) : 'n/a') + '</b><span>latest intel edition</span></div></div>';
      $('frame').innerHTML = '<div class="rise" style="display:flex;flex-direction:column;gap:16px;">' +
        '<div class="frame-head"><h1>' + esc(D.person.name) + '</h1><p>Threat hunter. Everything I build and run, drawn as one network. Click any frame to inspect it.</p></div>' +
        '<div class="net"><svg viewBox="0 0 1000 650" role="group" aria-label="Network of tools, modules, writing and roles">' + edges +
        '<g id="packets"></g>' + net.map(nodeSvg).join('') +
        '<g class="selbox" id="selbox"><rect class="box" x="0" y="0"></rect><rect class="h" width="7" height="7"></rect><rect class="h" width="7" height="7"></rect><rect class="h" width="7" height="7"></rect><rect class="h" width="7" height="7"></rect><rect class="tag" x="0" y="-24" height="17" rx="3"></rect><text x="6" y="-12"></text></g>' +
        '</svg></div>' +
        '<div class="ticker' + (live && !live.stale ? ' live' : '') + '" aria-live="polite"><span class="src"><i class="dot"></i><span id="ticker-src">' + (live && !live.stale ? 'LIVE' : 'FEED') + '</span></span><span class="msg" id="ticker-msg"></span></div>' + stats + '</div>';
      startPackets();
      startTicker();
    } else {
      var lastGroup = '';
      var cards = page.items.map(function (c) {
        var head = '';
        if (c.group !== lastGroup) { head = (lastGroup ? '</div>' : '') + '<div class="section-title">' + esc(c.group) + '</div><div class="cards">'; lastGroup = c.group; }
        return head + '<button type="button" class="card" data-sel="' + c.id + '" aria-pressed="' + (c.id === S.sel) + '">' +
          '<span class="bar" style="background:' + c.color + '"></span><span class="eyebrow">' + esc(c.eyebrow) + '</span><b>' + esc(c.title) + '</b><span class="sub">' + esc(c.sub) + '</span>' +
          '<span class="hd tl"></span><span class="hd tr"></span><span class="hd bl"></span><span class="hd br"></span><span class="tagline">' + esc(c.kind) + '</span></button>';
      }).join('') + '</div>';
      $('frame').innerHTML = '<div class="rise" style="display:flex;flex-direction:column;gap:18px;"><div class="frame-head"><h1>' + esc(page.title) + '</h1><p>' + esc(page.intro) + '</p></div>' + cards + '</div>';
    }
    updateSelection();
  }

  function neighbors(id) {
    return EDGES.filter(function (e) { return e[0] === id || e[1] === id; }).map(function (e) { return e[0] === id ? e[1] : e[0]; });
  }

  function updateSelection() {
    var n = byId(S.sel);
    if (S.page === 'network' && n) {
      var near = neighbors(n.id);
      Array.prototype.forEach.call(document.querySelectorAll('.node'), function (g) {
        var id = g.getAttribute('data-node');
        g.classList.toggle('on', id === n.id);
        g.classList.toggle('near', near.indexOf(id) !== -1);
      });
      Array.prototype.forEach.call(document.querySelectorAll('.edge'), function (l) {
        var e = EDGES[+l.getAttribute('data-edge')];
        l.classList.toggle('on', e[0] === n.id || e[1] === n.id);
      });
      var box = $('selbox');
      if (box) {
        var pad = 6, bw = n.w + pad * 2, bh = n.h + pad * 2;
        var label = 'x ' + n.x + ' · y ' + n.y + ' · ' + n.kind;
        box.style.transform = 'translate(' + (n.x - n.w / 2 - pad) + 'px,' + (n.y - n.h / 2 - pad) + 'px)';
        var r = box.querySelectorAll('rect');
        r[0].setAttribute('width', bw); r[0].setAttribute('height', bh);
        var hs = [[-3.5, -3.5], [bw - 3.5, -3.5], [-3.5, bh - 3.5], [bw - 3.5, bh - 3.5]];
        for (var i = 0; i < 4; i++) { r[i + 1].setAttribute('x', hs[i][0]); r[i + 1].setAttribute('y', hs[i][1]); }
        r[5].setAttribute('width', label.length * 6.2 + 12);
        box.querySelector('text').textContent = label;
      }
    } else {
      Array.prototype.forEach.call(document.querySelectorAll('.card'), function (c) {
        c.setAttribute('aria-pressed', String(c.getAttribute('data-sel') === S.sel));
      });
    }
  }

  function renderInspector() {
    var n = byId(S.sel);
    if (!n) { $('inspector').innerHTML = ''; return; }
    $('sel-kind').textContent = n.kind;
    var near = S.page === 'network' ? neighbors(n.id).map(byId).filter(Boolean) : [];
    var html = '<div class="ins-head rise"><span class="badge" style="background:' + n.color + '">' + esc(n.badge) + '</span><div><b>' + esc(n.title) + '</b><span>' + esc(n.kind) + '</span></div></div>' +
      '<p>' + esc(n.summary) + '</p>';
    if (n.headlines && n.headlines.length) html += '<ol class="headlines">' + n.headlines.map(function (h) { return '<li>' + esc(h) + '</li>'; }).join('') + '</ol>';
    html += '<div class="props"><span class="props-title">PROPERTIES</span>' + (n.facts || []).map(function (f) { return '<div class="prop"><span>' + esc(f[0]) + '</span><span>' + esc(f[1]) + '</span></div>'; }).join('') + '</div>';
    if (near.length) html += '<div class="props"><span class="props-title">CONNECTED TO</span><div class="chips">' + near.map(function (m) { return '<button type="button" class="chip" data-sel="' + m.id + '"><i style="background:' + m.color + '"></i>' + esc(m.title) + '</button>'; }).join('') + '</div></div>';
    if (n.href) {
      var ext = /^https?:/.test(n.href);
      var copyText = n.copy || (ext ? n.href : location.origin + n.href);
      html += '<div class="actions"><a class="btn-accent" href="' + esc(n.href) + '"' + (ext ? ' rel="noopener"' : '') + '>' + esc(n.cta) + '</a><button type="button" class="btn" data-copy="' + esc(copyText) + '">Copy link</button></div>';
    }
    $('inspector').innerHTML = html;
  }

  function renderStatus() {
    var n = byId(S.sel);
    $('status-sel').textContent = 'selected: ' + (n ? n.title + (n.x != null ? '  (x ' + n.x + ', y ' + n.y + ')' : '') : 'none');
    $('status-live').textContent = !liveTried ? 'connecting to honeypot feed…'
      : live ? 'honeypot feed ' + (live.stale ? 'stale' : 'live') + ' · generated ' + new Date(live.generatedAt).toLocaleString('en-US', { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) + ' (' + V2.ago(live.generatedAt) + ')'
        : 'honeypot feed unreachable · showing site data';
    $('status-built').textContent = 'data built ' + D.generatedAt.slice(0, 10);
  }

  function select(id, opts) {
    if (!byId(id)) return;
    S.sel = id;
    renderLayers();
    updateSelection();
    renderInspector();
    renderStatus();
    try { history.replaceState(null, '', '#' + S.page + '/' + id); } catch (e) { /* ignore */ }
    if (opts && opts.focus) {
      var el = document.querySelector('[data-node="' + id + '"], .card[data-sel="' + id + '"]');
      if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest', behavior: V2.reducedMotion ? 'auto' : 'smooth' });
    }
  }

  function goPage(p, sel) {
    if (!PAGES[p]) return;
    S.page = p;
    S.sel = sel && PAGES[p].items.some(function (i) { return i.id === sel; }) ? sel : PAGES[p].items[0].id;
    renderPages();
    renderLayers();
    renderFrame();
    renderInspector();
    renderStatus();
    try { history.replaceState(null, '', '#' + S.page + '/' + S.sel); } catch (e) { /* ignore */ }
  }

  /* ── life: packets along edges, rotating ticker ── */
  function startPackets() {
    var layer = $('packets');
    if (!layer || V2.reducedMotion) return;
    var pos = {}; PAGES.network.items.forEach(function (n) { pos[n.id] = n; });
    var rate = live ? Math.min(0.55, 0.12 + live.events24h / 40000) : 0.12;
    packets = [];
    EDGES.forEach(function (e, i) {
      var honeyEdge = e[0] === 'honey' || e[1] === 'honey';
      var count = honeyEdge && live ? 2 : 1;
      for (var k = 0; k < count; k++) packets.push({ e: i, t: Math.random(), v: (honeyEdge ? rate : 0.1) * (0.8 + Math.random() * 0.4), hot: honeyEdge && !!live });
    });
    layer.innerHTML = packets.map(function () { return '<circle class="packet" r="2.4"></circle>'; }).join('');
    var dots = layer.querySelectorAll('circle');
    var lastT = performance.now();
    var step = function (now) {
      var dt = Math.min(0.05, (now - lastT) / 1000); lastT = now;
      packets.forEach(function (p, i) {
        var e = EDGES[p.e], a = pos[e[0]], b = pos[e[1]];
        var on = e[0] === S.sel || e[1] === S.sel;
        p.t += dt * p.v * (on ? 2.2 : 1);
        if (p.t > 1) p.t -= 1;
        dots[i].setAttribute('cx', (a.x + (b.x - a.x) * p.t).toFixed(1));
        dots[i].setAttribute('cy', (a.y + (b.y - a.y) * p.t).toFixed(1));
        dots[i].setAttribute('class', 'packet' + (on ? ' on' : (p.hot ? ' hot' : '')));
      });
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
  }

  function tickerMessages() {
    var msgs = [];
    if (live) live.recent.forEach(function (r) { msgs.push(['honeypot', r.what + ' from ' + r.country + (r.user ? ' as "' + r.user + '"' : '') + (r.time ? ' · ' + r.time : '')]); });
    D.editions.slice(0, 3).forEach(function (e) { e.headlines.forEach(function (h) { msgs.push(['intel ' + e.date.slice(5), h]); }); });
    D.posts.forEach(function (p) { msgs.push(['blog', p.title + ': ' + p.summary]); });
    return msgs;
  }

  function startTicker() {
    var msgs = tickerMessages();
    var show = function () {
      var el = $('ticker-msg'), src = $('ticker-src');
      if (!el || !msgs.length) return;
      var m = msgs[tickerIdx % msgs.length]; tickerIdx++;
      src.textContent = m[0].toUpperCase();
      el.classList.remove('swap'); void el.offsetWidth; el.classList.add('swap');
      el.textContent = m[1];
    };
    show();
    if (!V2.reducedMotion) tickerTimer = setInterval(show, 3400);
  }

  /* ── events ── */
  function wire() {
    document.addEventListener('click', function (ev) {
      var t = ev.target.closest('[data-page],[data-sel],[data-node],[data-copy],#inspect-toggle');
      if (!t) return;
      if (t.id === 'inspect-toggle') {
        S.inspect = !S.inspect;
        t.setAttribute('aria-pressed', String(S.inspect));
        $('app').classList.toggle('inspect', S.inspect);
      } else if (t.hasAttribute('data-page')) {
        goPage(t.getAttribute('data-page'));
      } else if (t.hasAttribute('data-copy')) {
        V2.copy(t.getAttribute('data-copy')).then(function () { t.textContent = 'Copied'; setTimeout(function () { t.textContent = 'Copy link'; }, 1600); });
      } else {
        select(t.getAttribute('data-sel') || t.getAttribute('data-node'), { focus: !!t.closest('.inspector') });
      }
    });
    window.addEventListener('hashchange', function () {
      var h = (location.hash || '').slice(1).split('/');
      if (!PAGES[h[0]]) return;
      if (h[0] !== S.page) goPage(h[0], h[1]); else if (h[1] && h[1] !== S.sel) select(h[1], { focus: true });
    });
    document.addEventListener('keydown', function (ev) {
      var tag = (ev.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || ev.metaKey || ev.ctrlKey || ev.altKey) return;
      if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.hasAttribute && ev.target.hasAttribute('data-node')) {
        ev.preventDefault(); select(ev.target.getAttribute('data-node')); return;
      }
      var idx = ['1', '2', '3', '4', '5'].indexOf(ev.key);
      if (idx !== -1) { goPage(ORDER[idx]); return; }
      if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
        var ids = PAGES[S.page].items.map(function (i) { return i.id; });
        var i = Math.max(0, ids.indexOf(S.sel));
        var next = ev.key === 'ArrowDown' ? Math.min(ids.length - 1, i + 1) : Math.max(0, i - 1);
        ev.preventDefault();
        select(ids[next], { focus: true });
      }
    });
  }

  function start() {
    esc = V2.esc; fmt = V2.fmt;
    $('app').classList.add('inspect');
    V2.load().then(function (data) {
      D = data;
      build();
      wire();
      var hash = (location.hash || '').slice(1).split('/');
      goPage(PAGES[hash[0]] ? hash[0] : 'network', hash[1]);
      V2.honeypot(D.live.honeypotFeed, function (summary) {
        var first = !liveTried;
        liveTried = true;
        var changed = !!summary !== !!live || (summary && live && summary.events24h !== live.events24h);
        live = summary;
        applyLive();
        if (S.page === 'network' && (first || changed)) renderFrame();
        renderInspector();
        renderStatus();
      });
    }).catch(function (err) {
      $('frame').innerHTML = '<p class="loading">Could not load site data: ' + V2.esc(err.message) + '. Run <code>node scripts/build-v2-data.mjs</code> and reload.</p>';
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
