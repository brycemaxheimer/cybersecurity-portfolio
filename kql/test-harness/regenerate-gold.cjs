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

const { rewriteTimePredicates, v1CompatRewrite, setAnchor } = require('../engine/rewrite.js');
let ANCHOR_ISO = null;

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
    setAnchor(ANCHOR_ISO);
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
