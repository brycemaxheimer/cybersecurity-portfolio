/* main.js - KQL playground UI controller.
 * Initializes KqlRuntime, wires up editor / run button / examples / results.
 */
(function () {
    'use strict';

    var editor = document.getElementById('editor');
    var runBtn = document.getElementById('run-btn');
    var statusEl = document.getElementById('status');
    var resultsEl = document.getElementById('results');
    var sqlPreview = document.getElementById('sql-preview');
    var tablesList = document.getElementById('tables-list');
    var datasetSelect = document.getElementById('dataset-select');
    if (!editor || !runBtn || !statusEl || !resultsEl) return;

    // Short-circuit on isolated browsers (Menlo / Zscaler CBI / etc.) that
    // strip WASM. KqlEnv is set by /kql/engine/diagnose.js BEFORE this file.
    if (window.KqlEnv && !window.KqlEnv.allReady) {
        if (typeof window.KqlEnv.renderBanner === 'function') {
            window.KqlEnv.renderBanner(resultsEl, {
                fallbackHtml: 'The cheatsheet, examples, and reference docs still work; only query execution is disabled.',
            });
        }
        statusEl.textContent = 'engine unavailable in this browser';
        runBtn.disabled = true;
        editor.setAttribute('readonly', 'readonly');
        return;
    }

    var Runtime = window.KqlRuntime;
    if (!Runtime) { console.error('KqlRuntime missing'); return; }

    var DATASETS = {
        storyline: { basePath: '/kql/data/',       label: 'Storyline' },
        expanded:  { basePath: '/kql/data-large/', label: 'Expanded' }
    };
    var DATASET_KEY = 'kqlPlayground.dataset';
    function getSavedDataset() {
        var v = window.SafeStorage.get(DATASET_KEY, 'storyline');
        return DATASETS[v] ? v : 'storyline';
    }
    function saveDataset(v) {
        // Silent failure is fine here: the dataset toggle just won't persist
        // across reloads. Functional impact is zero.
        window.SafeStorage.set(DATASET_KEY, v);
    }

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

    var TRUNC_AT = 80; // chars beyond which a cell gets the click-to-expand treatment

    function formatCell(v) {
        if (v === null || v === undefined) return '<span class="pg-null">null</span>';
        var s = String(v);
        if (s.length > TRUNC_AT) {
            return '<span class="pg-cell-trunc" data-full="' + escapeHtml(s) + '" title="Click to expand">' +
                   escapeHtml(s) + '</span>';
        }
        return escapeHtml(s);
    }

    function attachCellExpanders() {
        var nodes = resultsEl.querySelectorAll('.pg-cell-trunc');
        nodes.forEach(function (n) {
            n.addEventListener('click', function () {
                n.classList.toggle('expanded');
            });
        });
    }

    function renderResults(res) {
        if (!res.rows.length) {
            resultsEl.innerHTML = '<div class="placeholder">No rows returned for this query.</div>';
            return;
        }

        var displayRows = res.rows.slice(0, 500);
        var html = '';
        html += '<div class="pg-result-toolbar">';
        html += '<span>' + res.count + ' row' + (res.count === 1 ? '' : 's') +
                (res.rows.length > displayRows.length ? ' (showing first ' + displayRows.length + ')' : '') +
                ' &middot; ' + res.columns.length + ' columns</span>';
        html += '<span class="toolbar-tools">';
        html += '<button data-act="expand-all">Expand all cells</button>';
        html += '<button data-act="collapse-all">Collapse</button>';
        html += '<button data-act="copy-tsv">Copy as TSV</button>';
        html += '</span>';
        html += '</div>';

        html += '<div class="pg-table-wrap"><table class="pg-table"><thead><tr>';
        res.columns.forEach(function (c) { html += '<th>' + escapeHtml(c) + '</th>'; });
        html += '</tr></thead><tbody>';
        displayRows.forEach(function (row) {
            html += '<tr>';
            row.forEach(function (cell) { html += '<td>' + formatCell(cell) + '</td>'; });
            html += '</tr>';
        });
        html += '</tbody></table></div>';
        resultsEl.innerHTML = html;

        attachCellExpanders();
        wireResultToolbar(res);
    }

    function wireResultToolbar(res) {
        var toolbar = resultsEl.querySelector('.pg-result-toolbar');
        if (!toolbar) return;
        toolbar.addEventListener('click', function (e) {
            var btn = e.target.closest('button');
            if (!btn) return;
            var act = btn.getAttribute('data-act');
            if (act === 'expand-all') {
                resultsEl.querySelectorAll('.pg-cell-trunc').forEach(function (n) { n.classList.add('expanded'); });
            } else if (act === 'collapse-all') {
                resultsEl.querySelectorAll('.pg-cell-trunc').forEach(function (n) { n.classList.remove('expanded'); });
            } else if (act === 'copy-tsv') {
                var lines = [res.columns.join('\t')];
                res.rows.forEach(function (r) {
                    lines.push(r.map(function (v) {
                        if (v === null || v === undefined) return '';
                        return String(v).replace(/[\t\n\r]/g, ' ');
                    }).join('\t'));
                });
                var text = lines.join('\n');
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(text).then(function () {
                        btn.textContent = 'Copied';
                        setTimeout(function () { btn.textContent = 'Copy as TSV'; }, 1500);
                    });
                }
            }
        });
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

    // If the user arrived from the KQL Builder via "Send to playground",
    // pull the pending query out of sessionStorage and pre-fill the editor.
    // The Builder sets the hash to #fromBuilder so we know it's intentional.
    (function pickUpFromBuilder() {
        if (window.location.hash !== '#fromBuilder') return;
        try {
            var pending = sessionStorage.getItem('kqlBuilder.pendingQuery');
            if (pending) {
                editor.value = pending;
                sessionStorage.removeItem('kqlBuilder.pendingQuery');
                // Clear the hash so refresh doesn't repeat
                history.replaceState(null, '', window.location.pathname);
            }
        } catch (e) { /* private mode etc. */ }
    })();

    wireExamples();
    setStatus('Initializing engine...', 'busy');
    renderEmpty('Loading sample data...');

    function rowsLoadedSummary(tables) {
        var total = Object.values(tables).reduce(function (a, b) { return a + b; }, 0);
        var tableCount = Object.keys(tables).filter(function (k) { return tables[k] > 0; }).length;
        return total + ' rows across ' + tableCount + ' tables';
    }

    function reloadDataset(name) {
        var ds = DATASETS[name];
        if (!ds) return Promise.reject(new Error('Unknown dataset: ' + name));
        setStatus('Loading ' + ds.label + ' dataset...', 'busy');
        renderEmpty('Re-ingesting CSVs from ' + ds.basePath + '...');
        if (datasetSelect) datasetSelect.disabled = true;
        runBtn.disabled = true;
        var t0 = performance.now();
        return Runtime.reload({ basePath: ds.basePath }).then(function (tables) {
            var dt = (performance.now() - t0).toFixed(0);
            fillTables(tables);
            saveDataset(name);
            setStatus('Ready (' + ds.label + '). ' + rowsLoadedSummary(tables) + ' in ' + dt + ' ms.', 'ok');
            renderEmpty('Dataset switched. Click <strong>Run query</strong> or press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>.');
        }).catch(function (err) {
            console.error(err);
            setStatus('Dataset load failed: ' + err.message, 'err');
            renderEmpty('Failed to load ' + ds.label + ' dataset. Check the browser console.');
        }).then(function () {
            if (datasetSelect) datasetSelect.disabled = false;
            runBtn.disabled = false;
        });
    }

    if (datasetSelect) {
        datasetSelect.value = getSavedDataset();
        datasetSelect.addEventListener('change', function () {
            reloadDataset(datasetSelect.value);
        });
    }

    Runtime.initialize({
        onProgress: function (info) {
            if (info.phase === 'loading-wasm')  setStatus('Loading WASM SQLite...', 'busy');
            if (info.phase === 'loading-data') setStatus('Loading sample tables...', 'busy');
            if (info.phase === 'ready') {
                fillTables(info.tables);
                setStatus('Ready. ' + rowsLoadedSummary(info.tables) + '.', 'ok');
                renderEmpty('Click <strong>Run query</strong> or press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>.');
                // If the user previously chose Expanded, auto-load it.
                var saved = getSavedDataset();
                if (saved === 'expanded') reloadDataset('expanded');
            }
        }
    }).catch(function (err) {
        console.error(err);
        setStatus('Failed to initialize: ' + err.message, 'err');
        renderEmpty('Engine failed to load. Check the browser console for details.');
    });
})();
