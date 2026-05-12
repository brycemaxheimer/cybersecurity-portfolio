/* Hunting Cookbook index.
 * Reads the public KQL template catalog and renders it as a writeups-friendly
 * list without duplicating the source data.
 */
(function () {
    'use strict';

    var list = document.getElementById('cookbook-list');
    var meta = document.getElementById('cookbook-meta');
    if (!list || !meta) return;

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    function renderTags(tags) {
        return (tags || []).map(function (tag) {
            return '<span class="tag">' + escapeHtml(tag) + '</span>';
        }).join('');
    }

    function renderTemplate(tpl) {
        var firstLine = (tpl.kql || '').split('\n')[0] || '';
        return '<li class="card">' +
            '<h3>' + escapeHtml(tpl.name || '(unnamed)') + '</h3>' +
            '<div class="meta">template  &middot;  Browser Lab catalog</div>' +
            '<p class="summary">' + escapeHtml(tpl.description || 'No description provided.') + '</p>' +
            (firstLine ? '<p class="text-muted fs-sm"><code>' + escapeHtml(firstLine.slice(0, 140)) + '</code></p>' : '') +
            renderTags(tpl.tags) +
            '</li>';
    }

    fetch('/lab/templates/data.json', { cache: 'no-store' })
        .then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (payload) {
            var templates = (payload && payload.templates) || [];
            if (!templates.length) {
                meta.textContent = 'No templates are currently published in the catalog.';
                list.innerHTML = '<li class="card"><h3>Catalog is empty</h3><p class="summary">Add entries to /lab/templates/data.json to populate this page.</p></li>';
                return;
            }
            meta.textContent = templates.length + ' templates · catalog updated ' + (payload.updated || 'unknown');
            list.innerHTML = templates.map(renderTemplate).join('');
        })
        .catch(function (err) {
            meta.textContent = 'Failed to load the template catalog.';
            list.innerHTML = '<li class="card"><h3>Catalog unavailable</h3><p class="summary">' + escapeHtml(err.message) + '</p></li>';
        });
})();
