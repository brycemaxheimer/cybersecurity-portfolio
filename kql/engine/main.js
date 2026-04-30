/* main.js — KQL playground UI controller.
 * Initializes KqlRuntime, wires up editor / run button / examples / results.
 */
(function () {
    'use strict';

    var Runtime = window.KqlRuntime;
    if (!Runtime) { console.error('KqlRuntime missing'); return; }

    var editor = document.getElementById('editor');
    var runBtn = document.getElementById('run-btn');
    var statusEl = document.getElementById('status');
    var resultsEl = document.getElementById('results');
    var sqlPreview = document.getElementById('sql-preview');
    var tablesList = document.getElementById('tables-list');
    if (!editor || !runBtn || !statusEl || !resultsEl) return;

    function setStatus(text, kind) {
        statusEl.textContent = text;
        statusEl.className = 'pg-status' + (kind ? ' pg-status-' + kind : '');
    }

    function renderEmpty(msg) {
        resultsEl.innerHTML = '<div class="placeholder">' + msg + '</div>';
    }

    function renderError(err) {
        var pos = (typeof err.pos === 'number') ? ' (col ' + (err.pos + 1) + ')' : '';
        resultsEl.innerHTML =
            '<div class="pg-error">' +
            '<strong>Error:</strong> ' + escapeHtml(err.message) + escapeHtml(pos) +
            '</div>';
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    function formatCell(v) {
        if (v === null || v === undefined) return '<span class="pg-null">null</span>';
        var s = String(v);
        if (s.length > 200) s = s.slice(0, 197) + '...';
        return escapeHtml(s);
    }

    function renderResults(res) {
        if (!res.rows.length) {
            resultsEl.innerHTML = '<div class="placeholder">No rows returned. <span class="pg-meta">' +
                escapeHtml(res.sql) + '</span></div>';
            return;
        }
        var html = '<div class="pg-result-meta">' + res.count + ' row' + (res.count === 1 ? '' : 's') + '</div>';
        html += '<div class="pg-table-wrap"><table class="pg-table"><thead><tr>';
        res.columns.forEach(function (c) { html += '<th>' + escapeHtml(c) + '</th>'; });
        html += '</tr></thead><tbody>';
        var displayRows = res.rows.slice(0, 500);
        displayRows.forEach(function (row) {
            html += '<tr>';
            row.forEach(function (cell) { html += '<td>' + formatCell(cell) + '</td>'; });
            html += '</tr>';
        });
        html += '</tbody></table></div>';
        if (res.rows.length > displayRows.length) {
            html += '<div class="pg-result-meta">Showing first ' + displayRows.length + ' of ' + res.rows.length + ' rows.</div>';
        }
        resultsEl.innerHTML = html;
    }

    function runQuery() {
        var src = editor.value.trim();
        if (!src) { setStatus('Type a query first.', 'warn'); return; }
        setStatus('Running...', 'busy');
        try {
            var t0 = performance.now();
            var res = Runtime.query(src);
            var ms = (performance.now() - t0).toFixed(1);
            renderResults(res);
            if (sqlPreview) sqlPreview.textContent = res.sql;
            setStatus('Returned ' + res.count + ' row' + (res.count === 1 ? '' : 's') + ' in ' + ms + ' ms', 'ok');
        } catch (err) {
            console.error(err);
            renderError(err);
            if (sqlPreview) sqlPreview.textContent = '';
            setStatus('Error', 'err');
        }
    }

    function wireExamples() {
        var examples = document.querySelectorAll('.pg-example');
        examples.forEach(function (btn) {
            btn.addEventListener('click', function () {
                editor.value = btn.getAttribute('data-q');
                editor.focus();
            });
        });
    }

    function fillTables(loaded) {
        if (!tablesList) return;
        var html = '';
        Object.keys(loaded).sort().forEach(function (name) {
            var n = loaded[name];
            if (n === 0) return;
            html += '<li><button class="pg-table-item" data-table="' + escapeHtml(name) + '">' +
                    '<code>' + escapeHtml(name) + '</code>' +
                    '<span class="pg-table-count">' + n + '</span></button></li>';
        });
        tablesList.innerHTML = html;
        tablesList.querySelectorAll('.pg-table-item').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var name = btn.getAttribute('data-table');
                editor.value = name + '\n| take 25';
                editor.focus();
            });
        });
    }

    runBtn.addEventListener('click', runQuery);
    editor.addEventListener('keydown', function (e) {
        // Ctrl/Cmd + Enter to run
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            runQuery();
        }
    });

    wireExamples();
    setStatus('Initializing engine...', 'busy');
    renderEmpty('Loading sample data...');

    Runtime.initialize({
        onProgress: function (info) {
            if (info.phase === 'loading-wasm')  setStatus('Loading WASM SQLite...', 'busy');
            if (info.phase === 'loading-data') setStatus('Loading sample tables...', 'busy');
            if (info.phase === 'ready') {
                fillTables(info.tables);
                var total = Object.values(info.tables).reduce(function (a, b) { return a + b; }, 0);
                var tableCount = Object.keys(info.tables).filter(function (k) { return info.tables[k] > 0; }).length;
                setStatus('Ready. ' + total + ' rows across ' + tableCount + ' tables.', 'ok');
                renderEmpty('Click <strong>Run query</strong> or press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>.');
            }
        }
    }).catch(function (err) {
        console.error(err);
        setStatus('Failed to initialize: ' + err.message, 'err');
        renderEmpty('Engine failed to load. Check the browser console for details.');
    });
})();
