/* runtime.js — KQL playground runtime.
 *
 * Loads sql.js (WASM SQLite), creates tables from KqlSchema, fetches the
 * CSV files in /kql/data/*.csv, ingests them, and exposes a query()
 * function that takes KQL source and returns { columns, rows } or throws.
 *
 * Depends on: KqlSchema (schema.js), KqlEngine (engine.js), and the
 * sql.js global initSqlJs (loaded from /kql/vendor/sql-wasm.js).
 */
(function (global) {
    'use strict';

    var Schema = global.KqlSchema;
    var Engine = global.KqlEngine;

    var SQL = null;     // sql.js module
    var db = null;      // sqlite3 Database
    var tableLoaded = {}; // tableName -> rowCount

    // ---- CSV parser (minimal RFC 4180-ish) ----
    function parseCSV(text) {
        var rows = [];
        var i = 0, n = text.length;
        var field = '', row = [];
        var inQ = false;
        while (i < n) {
            var c = text[i];
            if (inQ) {
                if (c === '"') {
                    if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
                    inQ = false; i++; continue;
                }
                field += c; i++; continue;
            }
            if (c === '"') { inQ = true; i++; continue; }
            if (c === ',') { row.push(field); field = ''; i++; continue; }
            if (c === '\r') { i++; continue; }
            if (c === '\n') { row.push(field); rows.push(row); field = ''; row = []; i++; continue; }
            field += c; i++;
        }
        if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }
        return rows;
    }

    // Cast a CSV cell into the column's KQL type (best-effort, lenient).
    function coerce(value, kqlType) {
        if (value === '' || value === undefined || value === null) return null;
        switch (kqlType) {
            case 'int': case 'long':
                var n = parseInt(value, 10);
                return isNaN(n) ? null : n;
            case 'real':
                var f = parseFloat(value);
                return isNaN(f) ? null : f;
            case 'bool':
                return /^(true|1|yes)$/i.test(value) ? 1 : 0;
            default:
                return String(value);
        }
    }

    function createTable(name) {
        var spec = Schema[name];
        if (!spec) throw new Error('Unknown table: ' + name);
        var defs = spec.columns.map(function (c) {
            return '"' + c.name.replace(/"/g, '""') + '" ' + Schema.sqliteType(c.type);
        }).join(', ');
        db.run('DROP TABLE IF EXISTS "' + name + '"');
        db.run('CREATE TABLE "' + name + '" (' + defs + ')');
    }

    function loadTable(name, csvText) {
        var spec = Schema[name];
        if (!spec) return 0;
        var rows = parseCSV(csvText);
        if (rows.length < 2) return 0;
        var header = rows[0];
        var dataRows = rows.slice(1);

        // Map CSV header order to schema column order
        var schemaCols = spec.columns;
        var idxByName = {};
        header.forEach(function (h, idx) { idxByName[h] = idx; });

        var cols = schemaCols.map(function (c) { return '"' + c.name.replace(/"/g, '""') + '"'; }).join(', ');
        var placeholders = schemaCols.map(function () { return '?'; }).join(', ');
        var stmt = db.prepare('INSERT INTO "' + name + '" (' + cols + ') VALUES (' + placeholders + ')');

        var ingested = 0;
        for (var r = 0; r < dataRows.length; r++) {
            // Skip blank rows
            var allEmpty = dataRows[r].every(function (v) { return v === '' || v === null || v === undefined; });
            if (allEmpty) continue;
            var vals = schemaCols.map(function (c) {
                var idx = idxByName[c.name];
                return idx === undefined ? null : coerce(dataRows[r][idx], c.type);
            });
            stmt.run(vals);
            ingested++;
        }
        stmt.free();
        return ingested;
    }

    // Fetch + load a single table.
    function fetchAndLoad(tableName) {
        return fetch('/kql/data/' + tableName + '.csv').then(function (resp) {
            if (!resp.ok) throw new Error('Failed to fetch ' + tableName + ': HTTP ' + resp.status);
            return resp.text();
        }).then(function (text) {
            createTable(tableName);
            var n = loadTable(tableName, text);
            tableLoaded[tableName] = n;
            return n;
        });
    }

    // ---- Public API ----

    // initialize() loads sql.js and ingests all tables in parallel.
    // Returns a Promise that resolves when everything's ready.
    function initialize(opts) {
        opts = opts || {};
        var onProgress = opts.onProgress || function () {};
        if (typeof initSqlJs !== 'function') {
            return Promise.reject(new Error('initSqlJs not loaded — check /kql/vendor/sql-wasm.js'));
        }
        onProgress({ phase: 'loading-wasm' });
        return initSqlJs({ locateFile: function (f) { return '/kql/vendor/' + f; } }).then(function (mod) {
            SQL = mod;
            db = new SQL.Database();
            onProgress({ phase: 'loading-data' });
            var tables = Schema.tableNames();
            return Promise.all(tables.map(function (t) {
                return fetchAndLoad(t).catch(function (e) {
                    console.warn('skipping table ' + t + ': ' + e.message);
                    return 0;
                });
            }));
        }).then(function () {
            onProgress({ phase: 'ready', tables: tableLoaded });
        });
    }

    // Run a KQL query. Returns { columns, rows, sql, count }.
    function query(kqlSource) {
        if (!db) throw new Error('Engine not initialized');
        var compiled = Engine.compile(kqlSource);
        var sql = compiled.sql;

        // Handle project-away by post-filtering columns
        var awayCols = null;
        var m = sql.match(/\/\*PROJECT_AWAY:([^*]+)\*\//);
        if (m) awayCols = m[1].split(',');

        var stmt = db.prepare(sql);
        var rows = [];
        var columns = null;
        try {
            while (stmt.step()) {
                if (!columns) columns = stmt.getColumnNames();
                rows.push(stmt.get());
            }
            if (!columns) columns = stmt.getColumnNames();
        } finally {
            stmt.free();
        }

        if (awayCols) {
            var keepIdx = columns.map(function (c, i) { return awayCols.indexOf(c) < 0 ? i : -1; }).filter(function (i) { return i >= 0; });
            columns = keepIdx.map(function (i) { return columns[i]; });
            rows = rows.map(function (r) { return keepIdx.map(function (i) { return r[i]; }); });
        }

        return { columns: columns, rows: rows, sql: sql, count: rows.length };
    }

    function getLoadedTables() { return Object.assign({}, tableLoaded); }

    global.KqlRuntime = {
        initialize: initialize,
        query: query,
        getLoadedTables: getLoadedTables,
    };

})(window);
