/* regenerate-gold.cjs - Re-runs each canonicalKql in lab/practice/gold-results.json
 * against the current local engine + CSVs and rewrites that file with fresh
 * rows, rowCount, columns. Preserves number/title/type/difficulty/ordered/
 * canonicalKql/rewrittenKql and the file-level metadata (anchor, version, ...).
 *
 * Use after replacing kql/data/*.csv with new samples.
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const vm   = require('vm');

const REPO_ROOT  = path.resolve(__dirname, '..', '..');
const ENGINE_DIR = path.join(REPO_ROOT, 'kql', 'engine');
const VENDOR_DIR = path.join(REPO_ROOT, 'kql', 'vendor');
const DATA_DIR   = path.join(REPO_ROOT, 'kql', 'data');
const GOLD_PATH  = path.join(REPO_ROOT, 'lab', 'practice', 'gold-results.json');

async function shimFetch(url) {
    const m = /^\/kql\/data\/(.+\.csv)$/.exec(url);
    if (!m) throw new Error('shim fetch: unsupported url ' + url);
    const file = path.join(DATA_DIR, m[1]);
    const text = await fs.promises.readFile(file, 'utf8');
    return { ok: true, status: 200, text: async () => text };
}

const sandbox = {
    console, setTimeout, clearTimeout, setInterval, clearInterval,
    Promise, fetch: shimFetch, URL, URLSearchParams,
    TextDecoder, TextEncoder, process, require, Buffer,
    __dirname: VENDOR_DIR,
};
sandbox.window = sandbox;
sandbox.global = sandbox;
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
vm.createContext(sandbox);

function loadIntoSandbox(file) {
    const code = fs.readFileSync(file, 'utf8');
    vm.runInContext(code, sandbox, { filename: file });
}

loadIntoSandbox(path.join(VENDOR_DIR, 'sql-wasm.js'));
loadIntoSandbox(path.join(ENGINE_DIR, 'schema.js'));
loadIntoSandbox(path.join(ENGINE_DIR, 'engine.js'));
loadIntoSandbox(path.join(ENGINE_DIR, 'runtime.js'));

let ANCHOR_ISO = null;

function fmtKqlDatetime(d) {
    return "todatetime('" + d.toISOString().replace(/\.\d+Z$/, '.000Z') + "')";
}
function offsetSeconds(num, unit) {
    const n = parseFloat(num);
    return ({ ms: n / 1000, s: n, m: n * 60, h: n * 3600, d: n * 86400 })[unit];
}
function rewriteTimePredicates(kql) {
    if (!ANCHOR_ISO) return kql;
    const anchor = new Date(ANCHOR_ISO);
    kql = kql.replace(/ago\(\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*\)/g, (_m, num, unit) => {
        const secs = offsetSeconds(num, unit);
        if (secs == null) return _m;
        return fmtKqlDatetime(new Date(anchor.getTime() - secs * 1000));
    });
    kql = kql.replace(/now\(\s*\)/g, () => fmtKqlDatetime(anchor));
    return kql;
}

const KQL_KW = /^(where|extend|summarize|project|order|sort|by|asc|desc|let|join|on|kind|union|parse|with|take|top|distinct|render|materialize|and|or|not|in|between|true|false|null)$/;

function materializeUnwrap(kql) {
    let i = 0, out = '';
    while (i < kql.length) {
        const idx = kql.indexOf('materialize(', i);
        if (idx < 0) { out += kql.slice(i); break; }
        out += kql.slice(i, idx);
        let depth = 1, j = idx + 'materialize('.length;
        while (j < kql.length && depth > 0) {
            if (kql[j] === '(') depth++;
            else if (kql[j] === ')') { depth--; if (depth === 0) break; }
            j++;
        }
        out += kql.slice(idx + 'materialize('.length, j);
        i = j + 1;
    }
    return out;
}

function rewriteMatchesRegex(kql) {
    return kql.replace(
        /([A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)*)\s+matches\s+regex\s+(@?"[^"]*"|@?'[^']*')/g,
        (_m, expr, pat) => 'matches_regex(' + expr + ', ' + pat + ')'
    );
}

function v1CompatRewrite(kql) {
    kql = materializeUnwrap(kql);
    kql = kql.replace(/@"([^"]*)"/g, (_m, body) => '"' + body.replace(/\\/g, '\\\\') + '"');
    kql = kql.replace(/@'([^']*)'/g, (_m, body) => "'" + body.replace(/\\/g, '\\\\') + "'");
    const operandRe = "(@?\"[^\"]*\"|@?'[^']*'|[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)";
    const lhsRe     = "([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)";
    kql = kql.replace(new RegExp(lhsRe + "\\s*=~\\s*" + operandRe, "g"),
        (_m, l, r) => KQL_KW.test(l) ? _m : "tolower(" + l + ") == tolower(" + r + ")");
    kql = kql.replace(new RegExp(lhsRe + "\\s*!~\\s*" + operandRe, "g"),
        (_m, l, r) => KQL_KW.test(l) ? _m : "tolower(" + l + ") != tolower(" + r + ")");
    const dynRe = /let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*dynamic\(\s*\[([^\]]*)\]\s*\)\s*;\s*/g;
    const inlines = {};
    kql = kql.replace(dynRe, (_m, name, items) => { inlines[name] = items.trim(); return ''; });
    for (const [name, items] of Object.entries(inlines)) {
        const refRe = new RegExp('(has_any|has_all|in|!in)\\s*\\(\\s*' + name + '\\s*\\)', 'g');
        kql = kql.replace(refRe, (_m, op) => op + ' (' + items + ')');
    }
    const haRe = /([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s+(has_any|has_all)\s*\(([^)]+)\)/g;
    kql = kql.replace(haRe, (_m, col, op, list) => {
        const items = list.split(',').map(s => s.trim()).filter(Boolean);
        const joiner = op === 'has_any' ? ' or ' : ' and ';
        return '(' + items.map(it => col + ' has ' + it).join(joiner) + ')';
    });
    kql = rewriteMatchesRegex(kql);
    return kql;
}

function inferType(values) {
    let allInt = true, allNum = true, allBool = true, allDate = true, anyNonNull = false;
    for (const v of values) {
        if (v == null || v === '') continue;
        anyNonNull = true;
        if (typeof v === 'boolean') {
            allInt = false; allNum = false; allDate = false;
            continue;
        }
        if (typeof v === 'number') {
            allBool = false; allDate = false;
            if (!Number.isInteger(v)) allInt = false;
            continue;
        }
        const s = String(v);
        if (!/^(true|false)$/i.test(s)) allBool = false;
        if (!/^-?\d+$/.test(s)) allInt = false;
        if (!/^-?\d+(\.\d+)?(e[+-]?\d+)?$/i.test(s)) allNum = false;
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$/.test(s)) allDate = false;
    }
    if (!anyNonNull) return 'String';
    if (allDate) return 'DateTime';
    if (allBool) return 'Boolean';
    if (allInt) return 'Int';
    if (allNum) return 'Real';
    return 'String';
}

(async () => {
    const KqlRuntime = sandbox.KqlRuntime;
    if (!KqlRuntime) { console.error('KqlRuntime not loaded'); process.exit(1); }
    const origInit = sandbox.initSqlJs;
    sandbox.initSqlJs = function(opts) {
        return origInit({ ...opts, locateFile: f => path.join(VENDOR_DIR, f) });
    };
    process.stderr.write('Booting sql.js + ingesting CSVs...\n');
    await KqlRuntime.initialize({});
    process.stderr.write('Ready.\n\n');

    const gold = JSON.parse(fs.readFileSync(GOLD_PATH, 'utf8'));
    ANCHOR_ISO = gold.anchor;
    process.stderr.write('Anchor: ' + ANCHOR_ISO + '\n\n');

    const newQuestions = {};
    for (const numStr of Object.keys(gold.questions)) {
        const q = gold.questions[numStr];
        let rewritten = rewriteTimePredicates(q.canonicalKql);
        rewritten = v1CompatRewrite(rewritten);
        let res;
        try {
            res = KqlRuntime.query(rewritten);
        } catch (e) {
            console.log(`ERROR Q${numStr}: ${e.message}`);
            // Preserve old gold for this question if regen fails.
            newQuestions[numStr] = q;
            continue;
        }
        const cols = res.columns || [];
        const rows = res.rows || [];

        // Infer column types from observed values, falling back to old gold
        // metadata if a column existed there.
        const oldByName = {};
        for (const oc of (q.columns || [])) oldByName[oc.name || oc] = oc.type || 'String';
        const colsOut = cols.map((name, i) => {
            const vals = rows.map(r => r[i]);
            const t = oldByName[name] || inferType(vals);
            return { name, type: t };
        });

        newQuestions[numStr] = {
            number:        q.number,
            title:         q.title,
            difficulty:    q.difficulty,
            type:          q.type,
            ordered:       q.ordered,
            rowCount:      rows.length,
            columns:       colsOut,
            rows:          rows,
            canonicalKql:  q.canonicalKql,
            rewrittenKql:  q.rewrittenKql,
        };
        console.log(`Q${String(numStr).padStart(2)} ${q.title}: ${rows.length} rows, ${colsOut.length} cols`);
    }

    const out = {
        ...gold,
        createdAt: new Date().toISOString(),
        questionCount: Object.keys(newQuestions).length,
        failures: [],
        questions: newQuestions,
        regeneratedFrom: 'kql/data + kql/engine (local v1) at ' + new Date().toISOString(),
    };
    fs.writeFileSync(GOLD_PATH, JSON.stringify(out, null, 2));
    console.log('\nWrote ' + GOLD_PATH);
})().catch(e => { console.error(e); process.exit(1); });
