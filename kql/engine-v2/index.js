/* ==========================================================================
 * KQL engine v2 — public API
 *
 * This is the eventual JS port of Invoke-KqlPS.ps1, structured for
 * incremental migration off the existing v1 engine.
 *
 * Public API (window.KqlEngineV2):
 *   ready()           -> Promise<void>            // ensures sql.js + data are loaded
 *   run(kqlString)    -> Promise<{
 *                          columns: string[],
 *                          rows:    any[][],     // each row is positional cells
 *                          elapsedMs: number
 *                        }>
 *   getSchema(table)  -> { columns: [{name, type}, ...] } | null
 *
 * Implementation strategy:
 *   1. lexer.js          — tokenize KQL
 *   2. parser.js         — build AST
 *   3. executor.js       — walk AST, dispatch operators
 *   4. functions.js      — built-in scalar/aggregate functions
 *   5. normalize.js      — KQL value canonicalization
 *
 * Each module starts as a thin interface; while operators are being ported,
 * unimplemented paths fall through to the v1 engine at /kql/engine/engine.js
 * (which is already loaded on the playground page). Eventually v2 will
 * replace v1 entirely and this fallback is removed.
 *
 * For the practice page right now: v2 falls through to v1 for everything,
 * which is sufficient to make the page functional. Operator-by-operator
 * ports land here over time without changing the public API.
 * ========================================================================== */

import { tokenize }    from './lexer.js';
import { parse }       from './parser.js';
import { execute }     from './executor.js';

const ENGINE_VERSION = '0.1.0-shim';

// ----------------------------------------------------------------------------
// SQLite/sql.js bootstrap. The /kql/ playground already wires sql-wasm.js;
// the practice page just needs to wait for it and load the same lab data.
// ----------------------------------------------------------------------------

let _sqlPromise = null;

async function getSqlDb() {
    if (_sqlPromise) return _sqlPromise;
    _sqlPromise = (async () => {
        if (!window.initSqlJs) {
            throw new Error('sql.js (window.initSqlJs) not loaded; check the script tag in the page.');
        }
        const SQL = await window.initSqlJs({ locateFile: () => '/kql/vendor/sql-wasm.wasm' });
        const db = new SQL.Database();

        // Load the same CSVs the playground uses, in the same order.
        const tables = [
            'AuditLogs', 'CommonSecurityLog', 'DHCP',
            'DeviceFileEvents', 'DeviceImageLoadEvents', 'DeviceLogonEvents',
            'DeviceNetworkEvents', 'DeviceNetworkInfo', 'DeviceProcessEvents',
            'DeviceRegistryEvents', 'SecurityAlert', 'SecurityEvent',
            'SecurityIncident', 'SigninLogs', 'Syslog', 'W3CIISLog',
        ];
        for (const t of tables) {
            try {
                const csv = await fetch(`/kql/data/${t}.csv`).then(r => r.ok ? r.text() : null);
                if (!csv) continue;
                _ingestCsvIntoDb(db, t, csv);
            } catch (e) {
                console.warn(`[KqlEngineV2] failed to load ${t}.csv:`, e);
            }
        }
        return db;
    })();
    return _sqlPromise;
}

function _ingestCsvIntoDb(db, tableName, csvText) {
    const lines = csvText.split(/\r?\n/).filter(l => l.length > 0);
    if (lines.length < 2) return;
    const cols = _splitCsvLine(lines[0]);
    const colDefs = cols.map(c => `"${c.replace(/"/g, '""')}" TEXT`).join(', ');
    db.run(`CREATE TABLE IF NOT EXISTS "${tableName}" (${colDefs});`);
    const placeholders = cols.map(() => '?').join(',');
    const stmt = db.prepare(`INSERT INTO "${tableName}" VALUES (${placeholders});`);
    db.run('BEGIN');
    for (let i = 1; i < lines.length; i++) {
        const row = _splitCsvLine(lines[i]);
        while (row.length < cols.length) row.push('');
        stmt.bind(row.slice(0, cols.length));
        stmt.step();
        stmt.reset();
    }
    db.run('COMMIT');
    stmt.free();
}

// CSV parser (handles quoted fields, escaped quotes, commas inside quotes)
function _splitCsvLine(line) {
    const out = [];
    let cur = ''; let inQ = false;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (inQ) {
            if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
            else if (c === '"')                   { inQ = false; }
            else                                  { cur += c; }
        } else {
            if (c === ',')      { out.push(cur); cur = ''; }
            else if (c === '"') { inQ = true; }
            else                { cur += c; }
        }
    }
    out.push(cur);
    return out;
}

// ----------------------------------------------------------------------------
// v1 fallback adapter
//
// The existing /kql/engine/engine.js exposes a global called `KqlRuntime` (or
// similar) that the playground uses. Until v2 covers the full KQL surface, we
// route queries through it. The fallback runs the user's KQL through v1 and
// reshapes the result into our canonical { columns, rows, elapsedMs } envelope.
// ----------------------------------------------------------------------------

let _v1Loaded = null;

async function getV1Engine() {
    if (_v1Loaded) return _v1Loaded;
    _v1Loaded = (async () => {
        // The v1 modules are plain scripts. They expose globals when loaded.
        await Promise.all([
            _ensureScript('/kql/engine/schema.js'),
            _ensureScript('/kql/engine/engine.js'),
            _ensureScript('/kql/engine/runtime.js'),
        ]);
        if (!window.KqlEngine && !window.KqlRuntime) {
            throw new Error('v1 engine globals (KqlEngine / KqlRuntime) not found.');
        }
        // Wait for sql.js DB
        const db = await getSqlDb();

        // Adapter: try whichever global exists.
        return {
            run(kql) {
                const start = performance.now();
                let cols = [], rows = [];
                try {
                    if (window.KqlRuntime && typeof window.KqlRuntime.run === 'function') {
                        const r = window.KqlRuntime.run(kql, db);
                        cols = r.columns || [];
                        rows = r.rows    || [];
                    } else if (window.KqlEngine && typeof window.KqlEngine.translate === 'function') {
                        // engine.js: translate KQL -> SQL, run via sql.js
                        const sql = window.KqlEngine.translate(kql);
                        const stmt = db.prepare(sql);
                        cols = stmt.getColumnNames();
                        while (stmt.step()) rows.push(stmt.get());
                        stmt.free();
                    } else {
                        throw new Error('v1 engine has no recognized entry point.');
                    }
                } finally { /* nothing yet */ }
                return {
                    columns: cols,
                    rows,
                    elapsedMs: performance.now() - start,
                };
            },
        };
    })();
    return _v1Loaded;
}

function _ensureScript(src) {
    return new Promise((resolve, reject) => {
        if ([...document.scripts].some(s => s.src.endsWith(src))) return resolve();
        const s = document.createElement('script');
        s.src = src;
        s.onload = () => resolve();
        s.onerror = () => reject(new Error('Failed to load ' + src));
        document.head.appendChild(s);
    });
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

const api = {
    version: ENGINE_VERSION,

    async ready() {
        // Bring up sql.js + data + v1 fallback. v2-native operators don't need
        // the v1 fallback once they're all ported, but for now we always have it.
        await getSqlDb();
        await getV1Engine();
    },

    async run(kqlString) {
        const t0 = performance.now();

        // Step 1: try the native v2 path (if any operator chain is fully ported).
        try {
            const tokens = tokenize(kqlString);
            const ast    = parse(tokens);
            if (ast && ast.allNative) {
                const db = await getSqlDb();
                const result = execute(ast, { db });
                return {
                    columns: result.columns,
                    rows:    result.rows,
                    elapsedMs: performance.now() - t0,
                };
            }
        } catch (e) {
            // v2 not ready / not capable -> fall through.
            // (Once all operators are ported, this catch is removed.)
        }

        // Step 2: delegate to the v1 engine.
        const v1 = await getV1Engine();
        return v1.run(kqlString);
    },

    async getSchema(tableName) {
        const db = await getSqlDb();
        try {
            const stmt = db.prepare(`PRAGMA table_info("${tableName}")`);
            const columns = [];
            while (stmt.step()) {
                const r = stmt.getAsObject();
                columns.push({ name: r.name, type: r.type });
            }
            stmt.free();
            return { columns };
        } catch { return null; }
    },
};

window.KqlEngineV2 = api;
