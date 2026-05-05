/* run-validation.cjs - Drives the v1 KQL engine through validation-cases.json
 * to prove the grader's verdict matches expectations across four classes per
 * question (good, possible, partial, bad) plus verbatim anti-cheat checks for
 * FIX/BOTH questions. Reports any (expected, actual) mismatch.
 *
 * Engine bootstrap and rewrite/compare logic mirror run-gold-tests.cjs. If
 * either harness changes, mirror the change here.
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
const QUEST_PATH = path.join(REPO_ROOT, 'lab', 'practice', 'questions.json');
const CASES_PATH = path.join(__dirname, 'validation-cases.json');

const argv     = process.argv.slice(2);
const VERBOSE  = argv.includes('--verbose') || argv.includes('-v');
const onlyNums = argv.filter(a => /^\d+$/.test(a)).map(Number);
const onlyKind = (argv.find(a => a.startsWith('--kind=')) || '').slice(7) || null;

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

function unwrapRow(r) {
    if (Array.isArray(r)) return r;
    if (r && typeof r === 'object' && Array.isArray(r.value) && 'Count' in r) return r.value;
    return r;
}

function canonJson(v) {
    if (v == null) return 'null';
    if (typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(canonJson).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonJson(v[k])).join(',') + '}';
}

function normCell(v) {
    if (v == null) return '';
    if (typeof v === 'number') {
        if (!Number.isFinite(v)) return '';
        return String(v);
    }
    if (typeof v === 'boolean') return v ? '1' : '0';
    if (typeof v === 'object') {
        if (Array.isArray(v.value) && 'Count' in v) return canonJson(v.value);
        return canonJson(v);
    }
    let s = String(v);
    if (/^[\[{]/.test(s.trim())) {
        try { return canonJson(JSON.parse(s)); } catch (_) { /* fall through */ }
    }
    if (s === 'true') return '1';
    if (s === 'false') return '0';
    if (/^-?\d+$/.test(s)) return s;
    return s;
}

function compareResults(actualRows, actualColumns, gold) {
    let expected = gold.rows;
    if (gold.rowCount === 1 && expected.length === gold.columns.length && !Array.isArray(expected[0])) {
        expected = [expected];
    }
    expected = expected.map(unwrapRow);
    const goldNames = gold.columns.map(c => c.name);
    const missing = goldNames.filter(n => actualColumns.indexOf(n) < 0);
    const extra   = actualColumns.filter(n => goldNames.indexOf(n) < 0);
    if (missing.length || extra.length) {
        return { ok: false, reason: 'columns differ' +
            (missing.length ? '; missing: ' + missing.join(',') : '') +
            (extra.length   ? '; extra: '   + extra.join(',')   : '') };
    }
    if (actualRows.length !== expected.length) {
        return { ok: false, reason: 'row count: got ' + actualRows.length + ', expected ' + expected.length };
    }
    const actNameIdx = {};
    actualColumns.forEach((n, i) => { actNameIdx[n] = i; });
    function rowDict(row, side) {
        const d = {};
        if (side === 'gold') {
            goldNames.forEach((n, i) => { d[n] = normCell(row[i]); });
        } else {
            goldNames.forEach(n => {
                const i = actNameIdx[n];
                d[n] = i === undefined ? '__missing__' : normCell(row[i]);
            });
        }
        return d;
    }
    function dictKey(d) {
        return JSON.stringify(Object.keys(d).sort().map(k => [k, d[k]]));
    }
    const aDicts = actualRows.map(r => rowDict(r, 'actual'));
    const eDicts = expected.map(r => rowDict(r, 'gold'));
    if (gold.ordered) {
        let orderedOK = true;
        for (let i = 0; i < aDicts.length; i++) {
            if (dictKey(aDicts[i]) !== dictKey(eDicts[i])) { orderedOK = false; break; }
        }
        if (!orderedOK) {
            const aSet = aDicts.map(dictKey).sort();
            const eSet = eDicts.map(dictKey).sort();
            for (let k = 0; k < aSet.length; k++) {
                if (aSet[k] !== eSet[k]) {
                    return { ok: false, reason: 'row ' + k + ' differs' };
                }
            }
        }
    } else {
        const aKeys = aDicts.map(dictKey).sort();
        const eKeys = eDicts.map(dictKey).sort();
        for (let j = 0; j < aKeys.length; j++) {
            if (aKeys[j] !== eKeys[j]) {
                return { ok: false, reason: 'set differs at slot ' + j };
            }
        }
    }
    return { ok: true };
}

function findQuestions(obj) {
    if (Array.isArray(obj)) return obj.flatMap(findQuestions);
    if (obj && typeof obj === 'object') {
        if ('canonicalKql' in obj && 'number' in obj) return [obj];
        return Object.values(obj).flatMap(findQuestions);
    }
    return [];
}

function normWS(s) { return String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); }

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
    const questions = JSON.parse(fs.readFileSync(QUEST_PATH, 'utf8'));
    const cases     = JSON.parse(fs.readFileSync(CASES_PATH, 'utf8')).cases;

    const seek = o => {
        if (!o || typeof o !== 'object') return null;
        if (typeof o.anchor === 'string') return o.anchor;
        for (const v of Array.isArray(o) ? o : Object.values(o)) {
            const r = seek(v); if (r) return r;
        }
        return null;
    };
    ANCHOR_ISO = seek(gold);
    setAnchor(ANCHOR_ISO);
    process.stderr.write('Anchor: ' + ANCHOR_ISO + '\n\n');

    const goldByNum = {};
    for (const q of findQuestions(gold)) goldByNum[q.number] = q;
    const questByNum = {};
    for (const q of questions) questByNum[q.number] = q;

    let mismatches = 0, matched = 0, errors = 0;
    const verdicts = []; // { number, kind, expected, actual, reason }

    for (const c of cases) {
        if (onlyNums.length && !onlyNums.includes(c.number)) continue;
        if (onlyKind && c.kind !== onlyKind) continue;

        const gq = goldByNum[c.number];
        const uq = questByNum[c.number];
        if (!gq || !uq) {
            console.log(`SKIP  Q${c.number} ${c.kind} - missing question/gold`);
            continue;
        }

        let rewritten = rewriteTimePredicates(c.kql);
        rewritten = v1CompatRewrite(rewritten);

        let actual = 'pass'; // pass = grader gives correctness=1
        let reason = '';

        // Anti-cheat: FIX/BOTH + verbatim sample submission must fail.
        const bugVerbatim = (uq.type === 'FIX' || uq.type === 'BOTH')
            && uq.sampleQuery
            && normWS(c.kql) === normWS(uq.sampleQuery);

        let res;
        try {
            res = KqlRuntime.query(rewritten);
        } catch (e) {
            actual = 'engine-error';
            reason = (e.message || String(e)).split('\n')[0];
        }

        if (actual !== 'engine-error') {
            const cmp = compareResults(res.rows || [], res.columns || [], gq);
            if (cmp.ok) {
                actual = bugVerbatim ? 'fail' : 'pass';
                reason = bugVerbatim ? 'rejected by anti-cheat (verbatim buggy sample)' : 'rows+cols match gold';
            } else {
                actual = 'fail';
                reason = cmp.reason;
            }
        }

        // engine-error counts as a fail outcome for grading purposes (the
        // user sees an error in the UI and gets correctness=0). It's only a
        // mismatch when the case expected a pass.
        const effective = actual === 'engine-error' ? 'fail' : actual;
        const ok = effective === c.expect;
        verdicts.push({ number: c.number, kind: c.kind, expected: c.expect, actual, reason, ok });
        if (ok) matched++;
        else if (actual === 'engine-error') errors++;
        else mismatches++;

        const tag = String(c.number).padStart(2);
        const status = ok ? 'OK    ' : 'MISS  ';
        const expSlug = c.expect.padEnd(12);
        const actSlug = actual.padEnd(12);
        console.log(`${status}Q${tag} ${c.kind.padEnd(8)} expected=${expSlug} actual=${actSlug} ${reason}`);
        if (!ok && VERBOSE) {
            console.log('       kql      :', c.kql.replace(/\n/g, ' '));
            console.log('       rewritten:', rewritten.replace(/\n/g, ' ').slice(0, 240));
        }
    }

    console.log(`\nTotals: ${matched} match, ${mismatches} mismatch, ${errors} engine-error  (out of ${verdicts.length})`);
    if (mismatches || errors) process.exit(1);
})().catch(e => { console.error(e); process.exit(1); });
