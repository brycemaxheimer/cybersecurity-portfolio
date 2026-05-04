/* builder.js - KQL Builder UI logic.
 * Reads schema from KqlSchema (loaded ahead of this script). Generates a
 * KQL query string live as the user adjusts form fields. Saves named queries
 * to localStorage. "Send to playground" stashes the query in sessionStorage
 * and redirects to /kql/ where main.js picks it up.
 */
(function () {
    'use strict';

    var Schema = window.KqlSchema;
    if (!Schema) { console.error('KqlSchema missing'); return; }

    /* ----- DOM refs ----- */
    var els = {
        table:        document.getElementById('kb-table'),
        time:         document.getElementById('kb-time'),
        filters:      document.getElementById('kb-filters'),
        addFilter:    document.getElementById('kb-add-filter'),
        columns:      document.getElementById('kb-columns'),
        summarize:    document.getElementById('kb-summarize'),
        sumOpts:      document.getElementById('kb-summarize-options'),
        agg:          document.getElementById('kb-agg'),
        aggCol:       document.getElementById('kb-agg-col'),
        by:           document.getElementById('kb-by'),
        limit:        document.getElementById('kb-limit'),
        output:       document.getElementById('kb-output'),
        send:         document.getElementById('kb-send'),
        copy:         document.getElementById('kb-copy'),
        save:         document.getElementById('kb-save'),
        reset:        document.getElementById('kb-reset'),
        savedList:    document.getElementById('kb-saved-list'),
    };

    var STORAGE_KEY = 'kqlBuilder.savedQueries';
    var PLAYGROUND_KEY = 'kqlBuilder.pendingQuery';

    /* ----- Helpers ----- */
    function tableNames() {
        return Object.keys(Schema).filter(function (k) {
            return Schema[k] && typeof Schema[k] === 'object' && Schema[k].columns;
        }).sort();
    }
    function columnsFor(table) {
        var s = Schema[table];
        return s && s.columns ? s.columns : [];
    }
    function columnNames(table) { return columnsFor(table).map(function (c) { return c.name; }); }

    function escapeKqlString(s) {
        return String(s).replace(/'/g, "\\'");
    }

    /* ----- Filter row construction ----- */
    var OPS_BY_TYPE = {
        string:   ['==', '!=', 'contains', '!contains', 'startswith', 'endswith', 'has', '!has', 'in', '!in', 'isempty', 'isnotempty'],
        int:      ['==', '!=', '<', '>', '<=', '>='],
        long:     ['==', '!=', '<', '>', '<=', '>='],
        real:     ['==', '!=', '<', '>', '<=', '>='],
        bool:     ['==', '!='],
        datetime: ['>', '<', '>=', '<='],
        dynamic:  ['contains', '!contains', 'isempty', 'isnotempty'],
    };
    function opsForColumn(table, col) {
        var spec = columnsFor(table).find(function (c) { return c.name === col; });
        if (!spec) return OPS_BY_TYPE.string;
        return OPS_BY_TYPE[spec.type] || OPS_BY_TYPE.string;
    }
    function typeOfColumn(table, col) {
        var spec = columnsFor(table).find(function (c) { return c.name === col; });
        return spec ? spec.type : 'string';
    }

    function buildFilterRow(initial) {
        initial = initial || { col: '', op: '==', value: '' };
        var row = document.createElement('div');
        row.className = 'kb-row';
        row.innerHTML =
            '<select class="kb-select kb-f-col"></select>' +
            '<select class="kb-select kb-f-op"></select>' +
            '<input class="kb-input mono kb-f-val" type="text" placeholder="value">' +
            '<button class="kb-remove" title="Remove">&times;</button>';

        var colSel = row.querySelector('.kb-f-col');
        var opSel  = row.querySelector('.kb-f-op');
        var valIn  = row.querySelector('.kb-f-val');

        function refreshColumns() {
            var current = els.table.value;
            var cols = columnNames(current);
            colSel.innerHTML = '<option value="">- column -</option>' +
                cols.map(function (c) { return '<option value="' + c + '">' + c + '</option>'; }).join('');
            if (initial.col && cols.indexOf(initial.col) >= 0) colSel.value = initial.col;
        }
        function refreshOps() {
            var ops = opsForColumn(els.table.value, colSel.value || '');
            opSel.innerHTML = ops.map(function (o) { return '<option value="' + o + '">' + o + '</option>'; }).join('');
            if (initial.op) opSel.value = initial.op;
        }
        refreshColumns();
        refreshOps();
        valIn.value = initial.value || '';

        colSel.addEventListener('change', function () { refreshOps(); render(); });
        opSel.addEventListener('change',  render);
        valIn.addEventListener('input',   render);
        row.querySelector('.kb-remove').addEventListener('click', function () {
            row.remove(); render();
        });

        // Expose a refresh hook so the table-changed handler can update column options
        row._refreshColumns = function () { refreshColumns(); refreshOps(); };
        return row;
    }

    /* ----- Initialize selects from schema ----- */
    function init() {
        // Tables dropdown
        els.table.innerHTML = tableNames().map(function (t) {
            return '<option value="' + t + '">' + t + '</option>';
        }).join('');
        // Default to a hunting-friendly table if available
        if (tableNames().indexOf('DeviceLogonEvents') >= 0) {
            els.table.value = 'DeviceLogonEvents';
        }

        rebuildColumnControls();
        rebuildFilterRows();   // ensures any pre-existing filter rows stay in sync
        rebuildAggColumns();
        renderSavedList();
        render();
    }

    /* ----- Re-render column-driven controls when table changes ----- */
    function rebuildColumnControls() {
        var cols = columnNames(els.table.value);

        // Output-column checkboxes
        els.columns.innerHTML = cols.map(function (c) {
            return '<label class="kb-checkbox"><input type="checkbox" value="' + c + '"><span>' + c + '</span></label>';
        }).join('');
        els.columns.querySelectorAll('.kb-checkbox input').forEach(function (cb) {
            cb.addEventListener('change', function () {
                cb.parentNode.classList.toggle('is-checked', cb.checked);
                render();
            });
        });

        // group-by + agg-column dropdowns
        rebuildAggColumns();
    }
    function rebuildAggColumns() {
        var cols = columnNames(els.table.value);
        var opts = '<option value="">- column -</option>' +
            cols.map(function (c) { return '<option value="' + c + '">' + c + '</option>'; }).join('');
        els.by.innerHTML = opts;
        els.aggCol.innerHTML = opts;
    }

    function rebuildFilterRows() {
        // Refresh column options on existing filter rows
        els.filters.querySelectorAll('.kb-row').forEach(function (row) {
            if (row._refreshColumns) row._refreshColumns();
        });
    }

    /* ----- Query generation ----- */
    function timestampColFor(table) {
        // KQL convention: prefer Timestamp, fall back to TimeGenerated, then any datetime col.
        var cols = columnsFor(table);
        var byName = function (n) { return cols.find(function (c) { return c.name === n; }); };
        if (byName('Timestamp'))     return 'Timestamp';
        if (byName('TimeGenerated')) return 'TimeGenerated';
        var first = cols.find(function (c) { return c.type === 'datetime'; });
        return first ? first.name : null;
    }

    function readForm() {
        return {
            table:    els.table.value,
            time:     els.time.value,
            filters:  Array.from(els.filters.querySelectorAll('.kb-row')).map(function (row) {
                return {
                    col:   row.querySelector('.kb-f-col').value,
                    op:    row.querySelector('.kb-f-op').value,
                    value: row.querySelector('.kb-f-val').value,
                };
            }).filter(function (f) { return f.col; }),
            project:  Array.from(els.columns.querySelectorAll('input:checked')).map(function (cb) { return cb.value; }),
            summarize: els.summarize.checked,
            agg:      els.agg.value,
            aggCol:   els.aggCol.value,
            by:       els.by.value,
            limit:    parseInt(els.limit.value, 10) || 0,
        };
    }

    function emitWhereClause(filter, table) {
        var col = filter.col;
        var op = filter.op;
        var val = filter.value;
        var type = typeOfColumn(table, col);

        // Operators that don't take a RHS
        if (op === 'isempty' || op === 'isnotempty') {
            return op + '(' + col + ')';
        }

        // 'in' / '!in' want a parenthesized list
        if (op === 'in' || op === '!in') {
            var items = val.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
            if (items.length === 0) return null;
            var rendered;
            if (type === 'int' || type === 'long' || type === 'real' || type === 'bool') {
                rendered = items.join(', ');
            } else {
                rendered = items.map(function (s) { return "'" + escapeKqlString(s) + "'"; }).join(', ');
            }
            return col + ' ' + op + ' (' + rendered + ')';
        }

        // Numeric vs. string vs. datetime literal
        var rhs;
        if (type === 'int' || type === 'long' || type === 'real') {
            rhs = val.trim();  // numeric, no quotes
            if (rhs === '') return null;
        } else if (type === 'bool') {
            rhs = /^(true|1|yes)$/i.test(val) ? 'true' : 'false';
        } else if (type === 'datetime') {
            rhs = "datetime('" + escapeKqlString(val) + "')";
        } else {
            // string / dynamic
            if (val === '' && (op === '==' || op === '!=')) {
                rhs = "''";
            } else {
                rhs = "'" + escapeKqlString(val) + "'";
            }
        }
        return col + ' ' + op + ' ' + rhs;
    }

    function generate() {
        var f = readForm();
        if (!f.table) return '';

        var lines = [f.table];

        // Time-range filter
        if (f.time) {
            var ts = timestampColFor(f.table);
            if (ts) {
                lines.push('| where ' + ts + ' > ago(' + f.time + ')');
            }
        }

        // Custom filters - one '| where ...' per filter for readability.
        f.filters.forEach(function (flt) {
            var clause = emitWhereClause(flt, f.table);
            if (clause) lines.push('| where ' + clause);
        });

        // Summarize OR project (mutually exclusive top-of-pipe)
        if (f.summarize && f.by) {
            var aggExpr;
            if (f.agg === 'count()') {
                aggExpr = 'count()';
            } else if (f.aggCol) {
                aggExpr = f.agg + '(' + f.aggCol + ')';
            } else {
                aggExpr = 'count()';
            }
            lines.push('| summarize ' + aggExpr + ' by ' + f.by);
        } else if (f.project.length) {
            lines.push('| project ' + f.project.join(', '));
        }

        // Take / limit
        if (f.limit > 0) {
            lines.push('| take ' + f.limit);
        }

        return lines.join('\n');
    }

    function render() {
        els.output.value = generate();
    }

    /* ----- Save / load (localStorage) ----- */
    function readSaved() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
        catch (e) { return []; }
    }
    function writeSaved(list) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    }
    function renderSavedList() {
        var list = readSaved();
        if (list.length === 0) {
            els.savedList.innerHTML = '<li class="kb-saved-empty">No saved queries yet.</li>';
            return;
        }
        els.savedList.innerHTML = list.map(function (q, i) {
            return '<li>' +
                '<span class="name" data-i="' + i + '">' + escapeHtml(q.name) + '</span>' +
                '<span class="meta">' + escapeHtml(q.table || '') + ' &middot; ' + new Date(q.savedAt).toISOString().slice(0, 10) + '</span>' +
                '<button class="kb-remove" data-del="' + i + '" title="Delete">&times;</button>' +
                '</li>';
        }).join('');
        els.savedList.querySelectorAll('[data-i]').forEach(function (n) {
            n.addEventListener('click', function () { loadSaved(parseInt(n.dataset.i, 10)); });
        });
        els.savedList.querySelectorAll('[data-del]').forEach(function (n) {
            n.addEventListener('click', function () {
                var list = readSaved();
                list.splice(parseInt(n.dataset.del, 10), 1);
                writeSaved(list);
                renderSavedList();
            });
        });
    }
    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    function loadSaved(i) {
        var list = readSaved();
        var entry = list[i];
        if (!entry) return;
        var st = entry.state;

        els.table.value = st.table || els.table.value;
        rebuildColumnControls();

        els.time.value = st.time || '';

        els.filters.innerHTML = '';
        (st.filters || []).forEach(function (f) {
            els.filters.appendChild(buildFilterRow(f));
        });

        els.columns.querySelectorAll('input').forEach(function (cb) {
            cb.checked = (st.project || []).indexOf(cb.value) >= 0;
            cb.parentNode.classList.toggle('is-checked', cb.checked);
        });

        els.summarize.checked = !!st.summarize;
        els.sumOpts.style.display = st.summarize ? '' : 'none';
        els.agg.value = st.agg || 'count()';
        els.aggCol.value = st.aggCol || '';
        els.by.value = st.by || '';
        els.limit.value = st.limit || 50;

        render();
    }

    function saveCurrent() {
        var name = prompt('Name this saved query:');
        if (!name) return;
        var list = readSaved();
        list.unshift({
            name: name,
            table: els.table.value,
            savedAt: Date.now(),
            state: readForm(),
        });
        writeSaved(list);
        renderSavedList();
    }

    /* ----- Reset ----- */
    function resetForm() {
        els.time.value = '24h';
        els.filters.innerHTML = '';
        els.columns.querySelectorAll('input').forEach(function (cb) {
            cb.checked = false;
            cb.parentNode.classList.remove('is-checked');
        });
        els.summarize.checked = false;
        els.sumOpts.style.display = 'none';
        els.limit.value = 50;
        render();
    }

    /* ----- Send to playground ----- */
    function sendToPlayground() {
        var q = generate();
        if (!q) return;
        try { sessionStorage.setItem(PLAYGROUND_KEY, q); } catch (e) { /* private mode etc. */ }
        // Hash signals to /kql/main.js to read pendingQuery from sessionStorage
        window.location.href = '/kql/#fromBuilder';
    }

    /* ----- Wire up top-level events ----- */
    els.table.addEventListener('change', function () {
        rebuildColumnControls();
        rebuildFilterRows();
        render();
    });
    els.time.addEventListener('change', render);
    els.limit.addEventListener('input', render);
    els.summarize.addEventListener('change', function () {
        els.sumOpts.style.display = els.summarize.checked ? '' : 'none';
        render();
    });
    els.agg.addEventListener('change', render);
    els.aggCol.addEventListener('change', render);
    els.by.addEventListener('change', render);
    els.addFilter.addEventListener('click', function () {
        els.filters.appendChild(buildFilterRow());
        render();
    });
    els.copy.addEventListener('click', function () {
        if (!els.output.value) return;
        if (navigator.clipboard) {
            navigator.clipboard.writeText(els.output.value).then(function () {
                var orig = els.copy.textContent;
                els.copy.textContent = 'Copied';
                setTimeout(function () { els.copy.textContent = orig; }, 1500);
            });
        } else {
            els.output.select(); document.execCommand('copy');
        }
    });
    els.save.addEventListener('click', saveCurrent);
    els.reset.addEventListener('click', resetForm);
    els.send.addEventListener('click', sendToPlayground);

    init();

    // Seed one default filter so the user sees the row pattern
    if (els.table.value === 'DeviceLogonEvents') {
        els.filters.appendChild(buildFilterRow({ col: 'ActionType', op: '==', value: 'LogonFailed' }));
        render();
    }
})();
