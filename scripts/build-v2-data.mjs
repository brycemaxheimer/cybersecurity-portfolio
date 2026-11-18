// Builds v2/site-data.json for the v2 homepage prototypes (shell and inspector).
//
// Everything comes from files already in the repo, so the prototypes stay in
// sync with the real site:
//   resume/ATS-friendly.txt          summary, roles and bullets, skills, education, awards
//   blog/posts.json + posts-source/  post metadata plus section-by-section text
//   intel-brief/data/editions/*.json full stories, CVEs, actions, explainers (latest 7)
//   lab/templates/data.json          hunt templates with ATT&CK techniques and KQL
//   lab/practice/questions.json      question counts by difficulty and type
// Certs and tool blurbs mirror certs/ and lab/ and are kept here in one place.
//
// Run from the repo root:  node scripts/build-v2-data.mjs

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(join(root, rel), 'utf8');
const readJson = (rel) => JSON.parse(read(rel));
const clip = (s, n) => {
  s = String(s || '').replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 1).replace(/\s+\S*$/, '') + '…' : s;
};

/* ── resume ── */
function parseResume(text) {
  const lines = text.replace(/\r/g, '').split('\n');
  const heads = ['PROFESSIONAL SUMMARY', 'SELECTED ACCOMPLISHMENTS', 'TECHNICAL SKILLS', 'PROFESSIONAL EXPERIENCE', 'EDUCATION', 'EDUCATION AND TRAINING', 'CERTIFICATIONS', 'AWARDS AND RECOGNITION'];
  const sec = {};
  let cur = null;
  for (const line of lines) {
    if (heads.includes(line.trim())) { cur = line.trim(); sec[cur] = []; continue; }
    if (cur) sec[cur].push(line);
  }
  const bullets = (arr) => {
    const out = [];
    for (const l of arr) {
      if (/^- /.test(l)) out.push(l.slice(2).trim());
      else if (/^\s+\S/.test(l) && out.length) out[out.length - 1] += ' ' + l.trim();
    }
    return out;
  };
  const blocks = (arr) => {
    const out = [[]];
    for (const l of arr) { if (!l.trim()) { if (out[out.length - 1].length) out.push([]); } else out[out.length - 1].push(l); }
    return out.filter((b) => b.length);
  };

  const skills = [];
  for (const l of sec['TECHNICAL SKILLS'] || []) {
    if (!l.trim()) continue;
    const m = l.match(/^([A-Za-z ]+):\s*(.*)$/);
    if (m) skills.push({ label: m[1].trim(), items: m[2] });
    else if (skills.length) skills[skills.length - 1].items += ' ' + l.trim();
  }
  skills.forEach((s) => { s.items = s.items.split(',').map((x) => x.trim()).filter(Boolean); });

  // "Org - Unit, City, ST" -> { name: "Org, Unit", location: "City, ST" }
  const orgLine = (l) => {
    const m = l.trim().match(/^(.*?),\s*([^,]+,\s*[A-Z]{2})$/);
    return { name: (m ? m[1] : l.trim()).replace(/\s+-\s+/g, ', '), location: m ? m[2] : '' };
  };
  // An employer can be a two-line header (org, dates) followed by several
  // roles (title, dates, bullets); a standalone role is title, org, dates, bullets.
  const roles = [];
  let employer = null;
  for (const b of blocks(sec['PROFESSIONAL EXPERIENCE'] || [])) {
    const di = b.findIndex((l) => /\d{4}-\d{2}\s+to\s+\S+/.test(l));
    const dm = di >= 0 ? b[di].match(/(\d{4}-\d{2})\s+to\s+(\S+)/) : null;
    const body = bullets(b.slice(di + 1));
    if (di === 1 && !body.length) { employer = orgLine(b[0]); continue; }
    const org = di === 1 && employer ? employer : orgLine(b[1] || '');
    if (di !== 1) employer = null;
    roles.push({ title: b[0].trim(), org: org.name, location: org.location, start: dm ? dm[1] : '', end: dm ? dm[2] : '', bullets: body });
  }

  // Bullets read "School - detail, date" or "Course - date".
  const education = bullets(sec['EDUCATION AND TRAINING'] || sec['EDUCATION'] || []).map((e) => {
    const dm = e.match(/(\d{4}-\d{2})\s*$/);
    const parts = e.replace(/(?:,|\s+-)?\s*(expected\s+)?\d{4}-\d{2}\s*$/i, '').split(/\s+-\s+/);
    const expected = /expected\s+\d{4}-\d{2}\s*$/i.test(e);
    return { school: parts[0].trim(), detail: (parts[1] || '').trim(), status: expected ? 'Expected' : 'Completed', date: dm ? dm[1] : '' };
  });

  const awards = bullets(sec['AWARDS AND RECOGNITION'] || []).map((a) => {
    const m = a.match(/^(.*?)\s*\((\d{4}-\d{2})\)\s*(?:-\s*(.*))?$/);
    return m ? { title: m[1].trim(), date: m[2], detail: (m[3] || '').trim() } : { title: a, date: '', detail: '' };
  });

  return {
    summary: (sec['PROFESSIONAL SUMMARY'] || []).join(' ').replace(/\s+/g, ' ').trim(),
    accomplishments: bullets(sec['SELECTED ACCOMPLISHMENTS'] || []),
    skills,
    roles,
    education,
    awards,
  };
}
const resume = parseResume(read('resume/ATS-friendly.txt'));
// The resume lists completion dates only; spans and short labels for the
// career timeline come from Bryce (2026-11-18). Alvin was dual-credit
// enrollment during high school.
const eduSpans = [
  [/SANS Technology Institute/, 'SANS.edu, B.S.', '2025-01'],
  [/Alvin Community College/, 'Alvin CC, A.A.', '2016-08'],
  [/Cyber Operators Specialist Course/, 'COSC', '2023-07'],
  [/Joint Cyber Analysis Course/, 'JCAC', '2022-10'],
];
resume.education.forEach((e) => {
  const m = eduSpans.find(([re]) => re.test(e.school));
  if (m) { e.short = m[1]; e.start = m[2]; }
  if (/Alvin/.test(e.school)) e.detail += ' (dual credit during high school)';
});
// The August 2026 resume dropped SELECTED ACCOMPLISHMENTS; these headline
// figures come from its role bullets and the certs page.
if (!resume.accomplishments.length) {
  resume.accomplishments = [
    'Cut daily false-positive SIEM alerts by 67% (about 300 to fewer than 100) through 30+ approved rule changes.',
    'Processed and analyzed 30,000+ security alerts and established baseline network behavior in a DoD CSSP.',
    'Analyzed 3.5M+ daily packets across critical networks during defensive cyberspace operations in Okinawa, Japan.',
    'Placed 9th of 290 teams in the NCL Fall 2026 Team Game (Experienced Student) with a perfect 3,000 / 3,000.',
  ];
}

/* ── blog posts with section text ── */
function parsePost(md) {
  const body = md.replace(/\r/g, '').replace(/^---[\s\S]*?---\n/, '');
  const sections = [];
  let cur = { heading: '', paragraphs: [] };
  let para = [];
  const flush = () => { if (para.length) { cur.paragraphs.push(para.join(' ').trim()); para = []; } };
  for (const line of body.split('\n')) {
    const h = line.match(/^#{2,3}\s+(.*)/);
    if (h) { flush(); if (cur.heading || cur.paragraphs.length) sections.push(cur); cur = { heading: h[1].trim(), paragraphs: [] }; continue; }
    if (!line.trim()) { flush(); continue; }
    if (/^```/.test(line)) continue;
    para.push(line.replace(/^[-*]\s+/, '• ').trim());
  }
  flush();
  if (cur.heading || cur.paragraphs.length) sections.push(cur);
  return { sections, words: body.split(/\s+/).filter(Boolean).length };
}
const posts = readJson('blog/posts.json').posts.map((p) => {
  const src = join('posts-source', p.slug + '.md');
  const parsed = existsSync(join(root, src)) ? parsePost(read(src)) : { sections: [], words: 0 };
  return { id: 'post-' + p.slug, slug: p.slug, title: p.title, date: p.date, summary: p.summary, tags: p.tags, minutes: p.readingTime, href: p.url, words: parsed.words, sections: parsed.sections };
});

/* ── lab ── */
const questionsRaw = readJson('lab/practice/questions.json');
const questions = Array.isArray(questionsRaw) ? questionsRaw : questionsRaw.questions || [];
const countBy = (arr, key) => arr.reduce((acc, x) => { const k = x[key] || 'other'; acc[k] = (acc[k] || 0) + 1; return acc; }, {});
const practice = { total: questions.length, byDifficulty: countBy(questions, 'difficulty'), byType: countBy(questions, 'type') };

const templatesRaw = readJson('lab/templates/data.json');
const templates = templatesRaw.templates.map((t) => ({
  name: t.name,
  slug: t.slug,
  description: clip(t.description, 320),
  tags: t.tags || [],
  techniques: t.attackTechniques || [],
  verifiedAgainst: Array.isArray(t.verifiedAgainst) ? t.verifiedAgainst.join(', ') : String(t.verifiedAgainst || ''),
  kql: String(t.kql || '').slice(0, 900),
}));

/* ── intel brief editions ── */
function trimEdition(e) {
  const story = (s) => ({
    rank: s.rank,
    score: s.score,
    title: s.title,
    category: (s.labels && s.labels.category) || '',
    exploitation: (s.labels && s.labels.exploitation) || '',
    vendor: (s.labels && s.labels.vendor) || '',
    product: (s.labels && s.labels.product) || '',
    cves: (s.cves || []).slice(0, 4).map((c) => ({ id: c.id, cvss: c.cvss || null, severity: c.severity || '', epss: typeof c.epss === 'number' ? c.epss : null, kev: !!c.in_kev })),
    what: clip(s.writeup && s.writeup.what_happened, 620),
    why: clip(s.writeup && s.writeup.why_it_matters, 420),
    actions: ((s.writeup && s.writeup.recommended_actions) || []).slice(0, 4).map((a) => clip(a, 220)),
    confidence: (s.writeup && s.writeup.confidence) || '',
    sources: (s.sources || []).slice(0, 3).map((x) => ({ title: clip(x.title, 120), url: x.url, source: x.source || '' })),
    queries: ((s.detection && s.detection.hunting_queries) || []).slice(0, 1).map((q) => ({ title: q.title, kql: String(q.kql || '').slice(0, 700) })),
    queryCount: ((s.detection && s.detection.hunting_queries) || []).length,
  });
  const ok = Object.values(e.sources_status || {}).filter((v) => /^ok/.test(String(v))).length;
  return {
    date: e.date,
    title: 'Daily Intel Brief: ' + e.date,
    href: 'https://intel.brycemaxheimer.com/editions/' + e.date + '/',
    generatedAt: e.generated_at,
    models: e.models ? { triage: e.models.triage, writeup: e.models.writeup } : null,
    headlines: (e.stories || []).map((s) => s.title),
    stories: (e.stories || []).slice(0, 10).map(story),
    more: (e.more_stories || []).slice(0, 6).map((s) => ({ title: s.title, score: s.score, url: s.sources && s.sources[0] ? s.sources[0].url : '' })),
    kev: (e.kev_new || []).map((k) => ({ cve: k.cve, vendor: k.vendor, product: k.product, name: k.name, added: k.date_added, due: k.due_date })),
    explainer: e.explainer ? { concept: e.explainer.concept, dek: clip(e.explainer.dek, 360), takeaways: (e.explainer.takeaways || []).slice(0, 4).map((t) => clip(t, 200)) } : null,
    goodNews: (e.good_news || []).map((g) => ({ headline: g.headline, summary: clip(g.summary, 260), kind: g.kind || '' })),
    stats: { items: (e.stats && e.stats.items) || {}, storiesFound: (e.stats && e.stats.stories_found) || 0, sourcesOk: ok, sourcesTotal: Object.keys(e.sources_status || {}).length },
  };
}
let editions = [];
const edDir = 'intel-brief/data/editions';
if (existsSync(join(root, edDir))) {
  editions = readdirSync(join(root, edDir)).filter((f) => /^\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort().reverse().slice(0, 7)
    .map((f) => trimEdition(readJson(join(edDir, f))));
}

/* ── Browser Lab: tables, examples and the practice time anchor ── */
// schema.js is a browser IIFE; run it against a stub global to read the tables.
function readLab() {
  const g = {};
  new Function('window', read('kql/engine/schema.js'))(g);
  const schema = g.KqlSchema || {};
  const rowsIn = (name) => {
    try { return read('kql/data/' + name + '.csv').split('\n').filter((l) => l.trim()).length - 1; } catch { return 0; }
  };
  const tables = (schema.tableNames ? schema.tableNames() : []).map((name) => ({
    name,
    rows: rowsIn(name),
    columns: schema[name].columns.map((c) => c.name + ':' + c.type),
  }));
  // The playground's example buttons, so the Shell console offers the same starts.
  const examples = [...read('kql/index.html').matchAll(/<button class="pg-example" data-q="([^"]+)">([^<]+)<\/button>/g)]
    .map((m) => ({ label: m[2].trim(), kql: m[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&') }));
  // Pin now() to the newest sample event (same anchor the practice set uses),
  // so ago() filters return rows against the static CSVs.
  const anchor = readJson('lab/practice/gold-results.json').anchor || null;
  return { tables, examples, anchor };
}
const lab = readLab();

const giacRecord = 'https://www.giac.org/certified-professional/Bryce-Maxheimer/243145';

const data = {
  generatedAt: new Date().toISOString(),
  person: {
    name: 'Bryce Maxheimer',
    role: 'Integration Specialist, Peraton (DFAS CSSP)',
    summary:
      'Four years in the Marine Corps as a Cyber Warfare Operator doing threat hunting, forensics and network defense. Now an Integration Specialist on the Defense Finance and Accounting Service CSSP Analyst Team (Peraton): technical lead and client interface for the analyst team.',
    email: 'contact@brycemaxheimer.com',
    linkedin: 'https://www.linkedin.com/in/bryce-maxheimer',
    github: 'https://github.com/brycemaxheimer',
    giac: giacRecord,
    clearance: 'TS/SCI with CI Polygraph',
  },
  resume,
  tools: [
    { id: 'lab', title: 'Browser Lab', kind: 'tool', icon: 'flask-conical', color: '#45D0A0', href: '/lab/', cta: 'Open the lab',
      summary: 'Security tools that run in your browser, ported from the SOC Dashboard so you can try them without a Sentinel tenant.',
      facts: [['Runtime', 'sql.js (WASM SQLite)'], ['Practice', practice.total + ' graded questions'], ['Hunts', templates.length + ' templates']] },
    { id: 'intel', title: 'Daily Intel Brief', kind: 'tool', icon: 'newspaper', color: '#F5C542', href: 'https://intel.brycemaxheimer.com/', cta: "Read today's edition",
      summary: 'A threat intelligence brief assembled each morning from free, structured feeds. Stories are triaged and written up by AI models, with the detections behind them checked before they ship.',
      facts: [['Cadence', 'Daily'], ['Latest', editions[0] ? editions[0].date : 'n/a'], ['Recent editions', String(editions.length)]] },
    { id: 'honey', title: 'Honeypot', kind: 'tool', icon: 'honeypot', color: '#FF7A7A', href: '/lab/threat-feed/', cta: 'Open the full feed',
      summary: 'A residential SSH honeypot (Cowrie). Observations are reported to AbuseIPDB and AlienVault OTX and power the Live Threat Feed.',
      facts: [['Sensor', 'Cowrie, SSH'], ['Reports to', 'AbuseIPDB, AlienVault OTX']] },
    { id: 'soc', title: 'SOC Dashboard', kind: 'tool', icon: 'powershell', color: '#7AB8FF', href: 'https://github.com/brycemaxheimer/cybersecurity-portfolio/tree/main/SOC%20Dashboard', cta: 'Read the source',
      summary: 'The PowerShell analyst console the browser tools grew out of, anchored by Invoke-KqlPS, a KQL interpreter written in PowerShell.',
      facts: [['Language', 'PowerShell'], ['Engine', 'Invoke-KqlPS'], ['Checks', 'Kusto emulator']] },
  ],
  modules: [
    { id: 'playground', parent: 'lab', icon: 'square-terminal', title: 'KQL Playground', kind: 'lab module', href: '/lab/', summary: 'Hand-written KQL engine running against a WASM SQLite. Type a query, run it, inspect the result set client-side.' },
    { id: 'practice', parent: 'lab', icon: 'list-checks', title: 'KQL Practice', kind: 'lab module', href: '/lab/practice/', summary: practice.total + ' graded KQL questions, easy to hard, validated against the same query model as the rest of the lab.' },
    { id: 'builder', parent: 'lab', icon: 'blocks', title: 'KQL Builder', kind: 'lab module', href: '/lab/kql-builder/', summary: 'Visual query builder for tables, filters, output columns and summarize patterns, with save and load in the browser.' },
    { id: 'templates', parent: 'lab', icon: 'library', title: 'KQL Templates', kind: 'lab module', href: '/lab/templates/', summary: 'Searchable catalog of ' + templates.length + ' public hunt templates with ATT&CK mappings.' },
    { id: 'abuseipdb', parent: 'honey', icon: 'shield-alert', title: 'AbuseIPDB', kind: 'data sharing', href: '/abuseipdb-verification.html', summary: 'Public abuse database. Honeypot indicators are reported here so other defenders can pivot on them.' },
    { id: 'otx', parent: 'honey', icon: 'share-2', title: 'AlienVault OTX', kind: 'data sharing', href: '/lab/', summary: 'Open Threat Exchange. Honeypot indicators are shared here as well.' },
    { id: 'kqlps', parent: 'soc', icon: 'powershell', title: 'Invoke-KqlPS', kind: 'engine', href: '/blog/posts/inside-invoke-kqlps.html', summary: 'A KQL interpreter in PowerShell that anchors the rest of the lab.' },
  ],
  experience: [
    { id: 'dfas', title: 'Integration Specialist, DFAS CSSP', org: 'Peraton, Defense Finance and Accounting Service CSSP', start: '2025-07', end: 'Present', summary: 'Analyst, then Shift Lead, now technical lead and client interface for the CSSP Analyst Team: SOPs and policy, 30+ approved SIEM rule changes that cut daily false positives by 67%, and new telemetry and audit reporting.' },
    { id: 'usmc', title: 'Cyber Security Analyst / Infrastructure Architect', org: 'U.S. Marine Corps, Defensive Cyber Operations', start: '2022-02', end: '2025-05', summary: 'Threat hunting in Splunk and Security Onion, forensics in Autopsy and FTK, virtual infrastructure for 100+ users, STIG compliance.' },
    { id: 'sans', title: 'B.S. Applied Cybersecurity', org: 'SANS Technology Institute', start: 'In progress', end: '2027-01', summary: 'Bachelor of Applied Cybersecurity, expected January 2027.' },
  ],
  certs: [
    { id: 'gcfa', code: 'GCFA', name: 'GIAC Certified Forensic Analyst', issuer: 'GIAC', issued: '2026-07', color: '#2DD4BF', tags: ['forensics', 'threat-hunting', 'incident-response'], verify: 'https://www.credly.com/badges/ca01e395-206d-41a5-b7ea-49ee806f57a3', summary: 'Enterprise-scale incident response and threat hunting: memory forensics, timeline analysis, lateral movement and persistence artifacts, and scoping an intrusion across many hosts.' },
    { id: 'gcfe', code: 'GCFE', name: 'GIAC Certified Forensic Examiner', issuer: 'GIAC', issued: '2026-04', color: '#F5A524', tags: ['forensics', 'windows'], verify: giacRecord, summary: 'Windows host forensics, evidence acquisition, registry and filesystem artifacts, browser and email analysis, and case management.' },
    { id: 'gpyc', code: 'GPYC', name: 'GIAC Python Coder', issuer: 'GIAC', issued: '2026-02', color: '#A78BFA', tags: ['python', 'automation'], verify: giacRecord, summary: 'Practical Python for security automation, parsing and instrumentation: the small, sharp tools an analyst actually needs.' },
    { id: 'gcih', code: 'GCIH', name: 'GIAC Certified Incident Handler', issuer: 'GIAC', issued: '2025-09', color: '#F5C542', tags: ['incident-response', 'blue-team'], verify: giacRecord, summary: 'Detecting, responding to and resolving intrusions, including privilege escalation, lateral movement, persistence and defense evasion.' },
    { id: 'gsec', code: 'GSEC', name: 'GIAC Security Essentials', issuer: 'GIAC', issued: '2025-07', color: '#45D0A0', tags: ['defense', 'fundamentals'], verify: giacRecord, summary: 'Active defense, network security, cryptography fundamentals, incident handling and the skills of a generalist security role.' },
    { id: 'gfact', code: 'GFACT', name: 'GIAC Foundational Cybersecurity Technologies', issuer: 'GIAC', issued: '2025-03', color: '#7AB8FF', tags: ['fundamentals'], verify: giacRecord, summary: 'Computing fundamentals, networking, system administration and the security concepts under every other GIAC track.' },
    { id: 'giacab', code: 'GIAC AB', name: 'GIAC Advisory Board', issuer: 'GIAC', issued: '2025-03', color: '#94A3B8', tags: ['giac'], verify: 'https://www.credly.com/badges/f69ec75b-28c4-4b3d-baf5-fc9c8557d58e', summary: 'Membership extended to GIAC holders who score 90% or higher on a certification exam. Members help review and shape future GIAC exams.' },
    { id: 'pentest', code: 'PenTest+', name: 'CompTIA PenTest+ (ce)', issuer: 'CompTIA', issued: '2024-08', color: '#FF7A7A', tags: ['pentest', 'red-team'], verify: 'https://www.certmetrics.com/comptia/public/verification.aspx', summary: 'Penetration testing end to end: scoping and rules of engagement, recon, exploitation, post-exploitation and reporting.' },
    { id: 'rtcp', code: 'RTCP', name: 'Red Team Certified Professional', issuer: 'Marine Corps Cyberspace Operations Group', issued: '2024-04', color: '#FF5C8A', tags: ['red-team', 'usmc'], verify: '/certs/', summary: 'Offensive tradecraft used in adversary emulation and red team engagements against DoD networks.' },
    { id: 'ncl26t', code: 'NCL 26 T', name: 'NCL Fall 2026, Team Game', issuer: 'Cyber Skyline', issued: '2026-11', color: '#C4B5FD', tags: ['ctf', 'ncl', 'team'], verify: 'https://cyberskyline.com/report/LK5XY4EDVQ3L', summary: '9th of 290 teams in the Experienced Student bracket (97th percentile) with a perfect 3,000 / 3,000 at 97.1% accuracy and 100% completion. 99th percentile in Open Source Intelligence.' },
    { id: 'ncl26', code: 'NCL 26', name: 'NCL Fall 2026, Individual Game', issuer: 'Cyber Skyline', issued: '2026-10', color: '#C4B5FD', tags: ['ctf', 'ncl'], verify: 'https://cyberskyline.com/report/FX8JPF9T0X05', summary: '51st of 407 in the Experienced Student bracket (88th percentile) and 281st of 6,366 overall, with 2,555 / 3,000 points at 89.6% accuracy. Full marks in OSINT, Log Analysis, Forensics, and Exploitation and Enumeration.' },
    { id: 'ncl', code: 'NCL 25', name: 'NCL Fall 2025, Diamond 1 Medal', issuer: 'Cyber Skyline', issued: '2025-11', color: '#C4B5FD', tags: ['ctf', 'ncl'], verify: 'https://cyberskyline.com/report/QCBEMP8D263T', summary: 'Fall 2025 Diamond 1 medal, 97th percentile in the Individual Game: OSINT, cryptography, log and traffic analysis, web exploitation and forensics.' },
  ],
  posts,
  editions,
  templates,
  practice,
  practiceQuestions: practice.total,
  lab,
  // Same-origin proxy in worker.js; the upstream feed only allows the
  // production origin in its CORS header.
  live: { honeypotFeed: '/api/live/honeypot' },
};

const out = join(root, 'v2', 'site-data.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(data, null, 2) + '\n');
console.log('wrote v2/site-data.json: ' + resume.roles.length + ' roles, ' + posts.length + ' posts, ' + editions.length + ' editions (' + editions.reduce((n, e) => n + e.stories.length, 0) + ' stories), ' + templates.length + ' templates, ' + practice.total + ' questions');
