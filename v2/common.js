/* v2/common.js - shared helpers for the v2 homepage prototypes.
 *
 *   V2.load()          fetches /v2/site-data.json (built by scripts/build-v2-data.mjs)
 *   V2.esc(s)          HTML-escapes a value for template strings
 *   V2.honeypot(cb)    polls the public honeypot feed and calls cb(summary)
 *                      every 60s; cb(null) when the feed is unreachable
 *   V2.reducedMotion   true when the visitor asked for less motion
 */
(function () {
  'use strict';

  var esc = function (s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  };

  var fmt = function (n) {
    return typeof n === 'number' ? n.toLocaleString('en-US') : '0';
  };

  var load = function () {
    return fetch('/v2/site-data.json', { cache: 'no-cache' }).then(function (r) {
      if (!r.ok) throw new Error('site-data.json HTTP ' + r.status);
      return r.json();
    });
  };

  var summarize = function (feed) {
    var label = function (id) {
      if (id === 'cowrie.login.success') return 'login succeeded';
      if (id === 'cowrie.login.failed') return 'login failed';
      if (id === 'cowrie.command.input') return 'command run';
      if (id === 'cowrie.session.file_download') return 'file download';
      if (id === 'cowrie.session.connect') return 'new connection';
      return (id || 'event').replace('cowrie.', '').replace(/[._]/g, ' ');
    };
    var ageHours = feed.generated_at ? (Date.now() - new Date(feed.generated_at).getTime()) / 36e5 : null;
    var sharing = feed.sharing || {};
    return {
      generatedAt: feed.generated_at,
      ageHours: ageHours,
      stale: ageHours != null && ageHours > 6,
      events24h: feed.events_24h || 0,
      unique24h: feed.unique_ips_24h || 0,
      logins24h: feed.successful_logins_24h || 0,
      events7d: feed.events_7d || 0,
      unique7d: feed.unique_ips_7d || 0,
      reported24h: sharing.abuseipdb_reports_24h || 0,
      sharing: { abuseipdb24h: sharing.abuseipdb_reports_24h || 0, vtLookups: sharing.vt_lookups_total || 0, vtMalicious: sharing.vt_malicious_total || 0, otxPulses: sharing.otx_pulses_total || 0 },
      countries: (feed.top_countries || []).slice(0, 3).map(function (c) { return c.geoip_country_name; }),
      countryCounts: (feed.top_countries || []).slice(0, 8).map(function (c) { return { name: c.geoip_country_name, count: c.count }; }),
      asns: (feed.top_asns || []).slice(0, 6).map(function (a) { return { name: 'AS' + a.geoip_autonomous_system_number + ' ' + (a.geoip_autonomous_system_organization || ''), count: a.count }; }),
      attackers: (feed.top_attackers || []).slice(0, 30).map(function (a) {
        return { ip: a.src_ip, country: a.geoip_country_name || '', city: a.geoip_city_name || '', lat: parseFloat(a.geoip_location_latitude), lon: parseFloat(a.geoip_location_longitude), count: a.count || 0 };
      }).filter(function (a) { return isFinite(a.lat) && isFinite(a.lon); }),
      hourly: (feed.hourly_counts || []).map(function (h) { return { ts: h.ts, count: h.count || 0 }; }),
      usernames: (feed.top_usernames || []).slice(0, 8).map(function (u) { return { name: u.username, count: u.count }; }),
      passwords: (feed.top_passwords || []).slice(0, 8).map(function (p) { return { name: p.password, count: p.count }; }),
      commands: (feed.top_commands || []).slice(0, 8).map(function (c) { return { name: c.input, count: c.count }; }),
      kev: (feed.cisa_kev_recent || []).slice(0, 8).map(function (k) { return { cve: k.cve, vendor: k.vendor, product: k.product, title: k.title, added: k.added, due: k.due, ransom: !!k.ransom }; }),
      ransomware: (feed.ransomware_recent || []).slice(0, 10).map(function (r) { return { victim: r.victim, group: r.group, country: r.country, activity: r.activity, published: (r.published || '').slice(0, 10) }; }),
      recent: (feed.recent || []).slice(0, 12).map(function (e) {
        return {
          what: label(e.eventid),
          country: e.country || 'unknown',
          user: e.username || '',
          time: e.ts ? new Date(e.ts).toLocaleTimeString('en-US', { hour12: false }) : '',
        };
      }),
    };
  };

  var honeypot = function (url, cb) {
    var tick = function () {
      fetch(url + '?t=' + Date.now(), { cache: 'no-store' })
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function (feed) { cb(summarize(feed)); })
        .catch(function () { cb(null); });
    };
    tick();
    return setInterval(tick, 60000);
  };

  var copy = function (text) {
    try { if (navigator.clipboard) return navigator.clipboard.writeText(text); } catch (e) { /* ignore */ }
    return Promise.resolve();
  };

  var ago = function (iso) {
    if (!iso) return '';
    var h = (Date.now() - new Date(iso).getTime()) / 36e5;
    if (h < 1) return Math.max(1, Math.round(h * 60)) + ' min ago';
    if (h < 48) return Math.round(h) + ' h ago';
    return Math.round(h / 24) + ' days ago';
  };

  window.V2 = {
    esc: esc,
    fmt: fmt,
    ago: ago,
    load: load,
    honeypot: honeypot,
    copy: copy,
    reducedMotion: !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches),
  };
})();
