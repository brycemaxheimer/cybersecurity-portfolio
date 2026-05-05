/* templates.js - KQL Templates browser.
 * Loads /lab/templates/data.json and renders a searchable / tag-filterable
 * catalog. Empty data is the steady-state until the catalog is populated.
 *
 * Expected entry shape (when data is added):
 *   { name: "Failed-logon hunter",
 *     description: "Surface accounts with > 5 failed logons in 1h",
 *     tags: ["logon", "hunting"],
 *     kql: "DeviceLogonEvents | where ..." }
 */
(function () {
    'use strict';

    var DATA = null;
    var query = '';
    var activeTags = new Set();

    var els = {
        q:        document.getElementById('q'),
        list:     document.getElementById('list'),
        tagFilter: document.getElementById('tag-filter'),
        mCount:   document.getElementById('m-count'),
        mUpdated: document.getElementById('m-updated'),
    };

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    fetch('/lab/templates/data.json', { cache: 'no-cache' })
        .then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (d) {
            DATA = d;
            els.mCount.textContent = (d.templates || []).length;
            els.mUpdated.textContent = d.updated || 'never';
            buildTagFilter();
            render();
        })
        .catch(function (e) {
            els.list.innerHTML = '<div class="tpl-empty"><p>Failed to load catalog: ' +
                escapeHtml(e.message) + '</p></div>';
            console.error(e);
        });

    function buildTagFilter() {
        var counts = {};
        (DATA.templates || []).forEach(function (t) {
            (t.tags || []).forEach(function (tag) { counts[tag] = (counts[tag] || 0) + 1; });
        });
        var tags = Object.keys(counts).sort();
        if (tags.length === 0) { els.tagFilter.classList.add('hidden'); return; }
        els.tagFilter.innerHTML = tags.map(function (t) {
            return '<button class="tpl-tag" data-tag="' + escapeHtml(t) + '">' +
                escapeHtml(t) + ' &middot; ' + counts[t] + '</button>';
        }).join('');
        els.tagFilter.addEventListener('click', function (e) {
            var btn = e.target.closest('.tpl-tag');
            if (!btn) return;
            var t = btn.dataset.tag;
            if (activeTags.has(t)) { activeTags.delete(t); btn.classList.remove('active'); }
            else { activeTags.add(t); btn.classList.add('active'); }
            render();
        });
    }

    els.q.addEventListener('input', function () {
        query = els.q.value.trim().toLowerCase();
        render();
    });

    function matches(t) {
        if (activeTags.size > 0) {
            var hit = (t.tags || []).some(function (tag) { return activeTags.has(tag); });
            if (!hit) return false;
        }
        if (query) {
            var blob = (t.name + ' ' + t.description + ' ' + (t.tags || []).join(' ') + ' ' + (t.kql || '')).toLowerCase();
            if (blob.indexOf(query) < 0) return false;
        }
        return true;
    }

    function renderItem(t, idx) {
        var tags = (t.tags || []).map(function (x) { return '<span class="tag">' + escapeHtml(x) + '</span>'; }).join('');
        return '<details class="tpl-item" data-idx="' + idx + '">' +
            '<summary>' +
                '<div class="tpl-summary-row">' +
                    '<span class="tpl-name">' + escapeHtml(t.name || '(unnamed)') + '</span>' +
                    '<span class="tpl-tags">' + tags + '</span>' +
                '</div>' +
                (t.description ? '<p class="tpl-desc">' + escapeHtml(t.description) + '</p>' : '') +
            '</summary>' +
            '<div class="tpl-detail">' +
                '<pre>' + escapeHtml(t.kql || '(no query body)') + '</pre>' +
                '<div class="tpl-actions">' +
                    '<button class="tpl-btn tpl-btn-primary" data-act="send" data-idx="' + idx + '">Send to playground &rarr;</button>' +
                    '<button class="tpl-btn" data-act="copy" data-idx="' + idx + '">Copy KQL</button>' +
                '</div>' +
            '</div>' +
        '</details>';
    }

    function emptyState() {
        return '<div class="tpl-empty">' +
            '<h3>Catalog is empty</h3>' +
            '<p>This page is the browser shell - no templates ship with the public site yet.</p>' +
            '<p>The same UI also serves as a recipe for populating it: edit ' +
            '<code>/lab/templates/data.json</code> and add entries to the <code>templates</code> array.</p>' +
            '<div class="recipe"><strong>Entry shape:</strong>' +
            '<ol>' +
                '<li><code>name</code> - short title</li>' +
                '<li><code>description</code> - one or two sentences</li>' +
                '<li><code>tags</code> - array of strings (used for filter chips)</li>' +
                '<li><code>kql</code> - the query body, multi-line OK</li>' +
            '</ol></div></div>';
    }

    function render() {
        if (!DATA) return;
        var tpls = DATA.templates || [];
        if (tpls.length === 0) {
            els.list.innerHTML = emptyState();
            return;
        }
        var matched = tpls.filter(matches);
        if (matched.length === 0) {
            els.list.innerHTML = '<div class="tpl-empty"><p>No templates match the current filters.</p></div>';
            return;
        }
        els.list.innerHTML = matched.map(function (t) {
            return renderItem(t, tpls.indexOf(t));
        }).join('');
        // Click listener is attached ONCE in init() via event delegation -- not
        // re-attached per render. Earlier code attached a {once:true} listener
        // here that consumed clicks on <details> summaries, swallowing the
        // browser's native expand/collapse and forcing a full re-render.
    }

    // Persistent delegated handler -- attached once below. Only acts on the
    // tpl-btn buttons; lets every other click (<details> summary, links, etc)
    // bubble through to the browser's default behavior.
    function onAction(e) {
        var btn = e.target.closest('.tpl-btn');
        if (!btn) return;
        var idx = parseInt(btn.dataset.idx, 10);
        var act = btn.dataset.act;
        var t = (DATA.templates || [])[idx];
        if (!t) return;

        if (act === 'send') {
            try { sessionStorage.setItem('kqlBuilder.pendingQuery', t.kql || ''); } catch (e) {}
            window.location.href = '/kql/#fromBuilder';
            return;
        }
        if (act === 'copy') {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(t.kql || '').then(function () {
                    var orig = btn.textContent;
                    btn.textContent = 'Copied';
                    setTimeout(function () { btn.textContent = orig; }, 1200);
                });
            }
            return;
        }
    }
    els.list.addEventListener('click', onAction);
})();
