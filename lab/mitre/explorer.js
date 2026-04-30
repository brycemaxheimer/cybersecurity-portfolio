/* explorer.js — MITRE ATT&CK Explorer.
 * Loads /lab/mitre/data.json and powers the search / filter / detail UI.
 * No external deps, no API calls; all data shipped with the page.
 */
(function () {
    'use strict';

    var DATA = null;
    var view = 'techniques';
    var query = '';
    var activeTactics = new Set();
    var platform = '';

    var els = {
        q:           document.getElementById('q'),
        list:        document.getElementById('list'),
        status:      document.getElementById('status'),
        tabs:        document.getElementById('view-tabs'),
        tacticChips: document.getElementById('tactic-chips'),
        platform:    document.getElementById('platform'),
        clear:       document.getElementById('clear'),
        filterTactics:   document.getElementById('filter-tactics'),
        filterPlatforms: document.getElementById('filter-platforms'),
    };

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    function setStatus(msg) { els.status.textContent = msg; }

    /* -------- Data loading -------- */
    fetch('/lab/mitre/data.json')
        .then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (d) {
            DATA = d;
            // Index by id for relationship resolution
            DATA.byId = {};
            ['tactics', 'techniques', 'subtechniques', 'mitigations', 'groups', 'software'].forEach(function (k) {
                d[k].forEach(function (item) { DATA.byId[item.id] = item; });
            });
            // Tactic shortName -> id map (techniques reference tactics by shortName)
            DATA.tacticByShortName = {};
            d.tactics.forEach(function (t) { DATA.tacticByShortName[t.shortName] = t; });

            populateMeta();
            populateTacticChips();
            populatePlatformOptions();
            render();
        })
        .catch(function (e) {
            setStatus('Failed to load data: ' + e.message);
            console.error(e);
        });

    function populateMeta() {
        var m = ['techniques', 'subtechniques', 'tactics', 'groups', 'software', 'mitigations'];
        m.forEach(function (k) {
            var el = document.getElementById('m-' + k);
            if (el) el.textContent = DATA[k].length;
        });
    }

    function populateTacticChips() {
        els.tacticChips.innerHTML = DATA.tactics.map(function (t) {
            return '<button class="tactic-chip" data-tactic="' + escapeHtml(t.shortName) + '" title="' + escapeHtml(t.id + ': ' + (t.description || '').slice(0, 200)) + '">' +
                escapeHtml(t.name) + '</button>';
        }).join('');
        els.tacticChips.addEventListener('click', function (e) {
            var btn = e.target.closest('.tactic-chip');
            if (!btn) return;
            var s = btn.dataset.tactic;
            if (activeTactics.has(s)) { activeTactics.delete(s); btn.classList.remove('active'); }
            else { activeTactics.add(s); btn.classList.add('active'); }
            render();
        });
    }

    function populatePlatformOptions() {
        var set = new Set();
        DATA.techniques.forEach(function (t) { (t.platforms || []).forEach(function (p) { set.add(p); }); });
        var opts = Array.from(set).sort();
        opts.forEach(function (p) {
            var o = document.createElement('option');
            o.value = p; o.textContent = p;
            els.platform.appendChild(o);
        });
    }

    /* -------- View switching -------- */
    els.tabs.addEventListener('click', function (e) {
        var btn = e.target.closest('button');
        if (!btn) return;
        view = btn.dataset.view;
        els.tabs.querySelectorAll('button').forEach(function (b) {
            b.classList.toggle('active', b === btn);
        });
        var showTactic = view === 'techniques';
        var showPlat = view === 'techniques' || view === 'software';
        els.filterTactics.style.display   = showTactic ? '' : 'none';
        els.filterPlatforms.style.display = showPlat   ? '' : 'none';
        render();
    });

    els.q.addEventListener('input', function () { query = els.q.value.trim().toLowerCase(); render(); });
    els.platform.addEventListener('change', function () { platform = els.platform.value; render(); });
    els.clear.addEventListener('click', function () {
        query = ''; els.q.value = '';
        platform = ''; els.platform.value = '';
        activeTactics.clear();
        els.tacticChips.querySelectorAll('.tactic-chip.active').forEach(function (b) { b.classList.remove('active'); });
        render();
    });

    /* -------- Filtering -------- */
    function matchesQuery(item, fields) {
        if (!query) return true;
        for (var i = 0; i < fields.length; i++) {
            var v = fields[i];
            if (v == null) continue;
            if (Array.isArray(v)) {
                for (var j = 0; j < v.length; j++) if (String(v[j]).toLowerCase().indexOf(query) >= 0) return true;
            } else if (String(v).toLowerCase().indexOf(query) >= 0) {
                return true;
            }
        }
        return false;
    }

    function filterTechniques() {
        var pool = DATA.techniques.concat(DATA.subtechniques);
        return pool.filter(function (t) {
            if (activeTactics.size > 0) {
                var ok = (t.tactics || []).some(function (tac) { return activeTactics.has(tac); });
                if (!ok) return false;
            }
            if (platform) {
                if (!(t.platforms || []).indexOf || (t.platforms || []).indexOf(platform) < 0) return false;
            }
            return matchesQuery(t, [t.id, t.name, t.description, t.detection, t.dataSources]);
        });
    }
    function filterGroups()      { return DATA.groups.filter(function (g)     { return matchesQuery(g, [g.id, g.name, g.description, g.aliases]); }); }
    function filterSoftware()    { return DATA.software.filter(function (s)   {
        if (platform && (s.platforms || []).indexOf(platform) < 0) return false;
        return matchesQuery(s, [s.id, s.name, s.description]);
    }); }
    function filterMitigations() { return DATA.mitigations.filter(function (m) { return matchesQuery(m, [m.id, m.name, m.description]); }); }

    /* -------- Rendering -------- */
    function tacticTagSpan(shortName) {
        var t = DATA.tacticByShortName[shortName];
        return '<span class="tactic-tag">' + escapeHtml(t ? t.name : shortName) + '</span>';
    }
    function refLink(id) {
        var item = DATA.byId[id];
        var label = item ? (id + ': ' + item.name) : id;
        return '<a href="#' + escapeHtml(id) + '" data-jump="' + escapeHtml(id) + '" title="' + escapeHtml(label) + '">' + escapeHtml(id) + '</a>';
    }

    function renderTechnique(t) {
        var tactics = (t.tactics || []).map(tacticTagSpan).join('');
        var platforms = (t.platforms || []).map(function (p) {
            return '<span class="platform-tag">' + escapeHtml(p) + '</span>';
        }).join('');
        var detail = '<div class="mitre-detail">';
        detail += '<div>';
        if (t.description) detail += '<h5>Description</h5><div class="description">' + escapeHtml(t.description) + '</div>';
        if (t.detection)   detail += '<h5>Detection</h5><div class="detection">' + escapeHtml(t.detection) + '</div>';
        if (t.dataSources && t.dataSources.length) {
            detail += '<h5>Data Sources</h5><div style="font-size:0.88rem;color:var(--text-1)">' +
                t.dataSources.map(escapeHtml).join('<br>') + '</div>';
        }
        detail += '</div><div>';
        if (t.subtechniques && t.subtechniques.length) {
            detail += '<h5>Sub-techniques</h5><div class="ref-list">' + t.subtechniques.map(refLink).join('') + '</div>';
        }
        if (t.mitigations && t.mitigations.length) {
            detail += '<h5>Mitigations</h5><div class="ref-list">' + t.mitigations.map(refLink).join('') + '</div>';
        }
        if (t.groups && t.groups.length) {
            detail += '<h5>Used by groups</h5><div class="ref-list">' + t.groups.map(refLink).join('') + '</div>';
        }
        if (t.software && t.software.length) {
            detail += '<h5>Used by software</h5><div class="ref-list">' + t.software.map(refLink).join('') + '</div>';
        }
        detail += '</div></div>';

        return '<details class="mitre-item" id="' + escapeHtml(t.id) + '">' +
            '<summary>' +
                '<span class="id-badge">' + escapeHtml(t.id) + '</span>' +
                '<span class="name">' + escapeHtml(t.name) + '</span>' +
                (tactics || platforms
                    ? '<div class="meta-row" style="flex-basis:100%">' + tactics + (tactics && platforms ? ' &middot; ' : '') + platforms + '</div>'
                    : '') +
            '</summary>' +
            detail +
        '</details>';
    }

    function renderSimple(item, kind) {
        var detail = '<div class="mitre-detail"><div>';
        if (item.description) detail += '<h5>Description</h5><div class="description">' + escapeHtml(item.description) + '</div>';
        if (item.aliases && item.aliases.length) {
            detail += '<h5>Aliases</h5><div style="font-size:0.88rem;color:var(--text-1)">' +
                item.aliases.map(escapeHtml).join(', ') + '</div>';
        }
        detail += '</div><div>';
        if (item.techniques && item.techniques.length) {
            detail += '<h5>Techniques used</h5><div class="ref-list">' + item.techniques.map(refLink).join('') + '</div>';
        }
        if (item.software && item.software.length && kind === 'group') {
            detail += '<h5>Software used</h5><div class="ref-list">' + item.software.map(refLink).join('') + '</div>';
        }
        if (item.platforms && item.platforms.length) {
            detail += '<h5>Platforms</h5><div style="font-size:0.88rem;color:var(--text-1)">' +
                item.platforms.map(escapeHtml).join(', ') + '</div>';
        }
        detail += '</div></div>';

        var subline = '';
        if (kind === 'software' && item.kind) subline = '<div class="meta-row">' + escapeHtml(item.kind) + '</div>';

        return '<details class="mitre-item" id="' + escapeHtml(item.id) + '">' +
            '<summary>' +
                '<span class="id-badge">' + escapeHtml(item.id) + '</span>' +
                '<span class="name">' + escapeHtml(item.name) + '</span>' +
                subline +
            '</summary>' +
            detail +
        '</details>';
    }

    function render() {
        if (!DATA) return;
        var rows;
        if (view === 'techniques')   rows = filterTechniques();
        else if (view === 'groups')      rows = filterGroups();
        else if (view === 'software')    rows = filterSoftware();
        else if (view === 'mitigations') rows = filterMitigations();
        else rows = [];

        setStatus('<strong>' + rows.length + '</strong> ' + view +
                  (query || activeTactics.size || platform ? ' matching filters' : ''));

        var MAX = 250;
        var capped = rows.length > MAX;
        var slice = rows.slice(0, MAX);

        var html;
        if (slice.length === 0) {
            html = '<div class="mitre-empty">No matches. Adjust filters or clear them.</div>';
        } else if (view === 'techniques') {
            html = slice.map(renderTechnique).join('');
        } else if (view === 'groups') {
            html = slice.map(function (g) { return renderSimple(g, 'group'); }).join('');
        } else if (view === 'software') {
            html = slice.map(function (s) { return renderSimple(s, 'software'); }).join('');
        } else {
            html = slice.map(function (m) { return renderSimple(m, 'mitigation'); }).join('');
        }
        if (capped) {
            html += '<div class="mitre-empty" style="padding:1.5rem">Showing first ' + MAX + ' of ' + rows.length + '. Refine the search to narrow further.</div>';
        }
        els.list.innerHTML = html;

        // Wire jump-to-id links inside detail panels
        els.list.querySelectorAll('a[data-jump]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                var id = a.dataset.jump;
                if (!id) return;
                e.preventDefault();
                jumpTo(id);
            });
        });
    }

    /* Cross-reference jump: given an ID like T1059.001 / G0007 / S0001 / M1018,
     * switch to the right view, expand the matching item, scroll to it. */
    function jumpTo(id) {
        var prefix = id.charAt(0);
        var newView;
        if (prefix === 'T') newView = 'techniques';
        else if (prefix === 'G') newView = 'groups';
        else if (prefix === 'S') newView = 'software';
        else if (prefix === 'M') newView = 'mitigations';
        else return;

        // Clear filters so we can find it
        query = ''; els.q.value = '';
        platform = ''; els.platform.value = '';
        activeTactics.clear();
        els.tacticChips.querySelectorAll('.tactic-chip.active').forEach(function (b) { b.classList.remove('active'); });

        if (newView !== view) {
            view = newView;
            els.tabs.querySelectorAll('button').forEach(function (b) {
                b.classList.toggle('active', b.dataset.view === view);
            });
            els.filterTactics.style.display = view === 'techniques' ? '' : 'none';
            els.filterPlatforms.style.display = (view === 'techniques' || view === 'software') ? '' : 'none';
        }
        render();

        // Wait for render, then expand + scroll
        setTimeout(function () {
            var det = document.getElementById(id);
            if (det && det.tagName === 'DETAILS') {
                det.open = true;
                det.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }, 0);
    }
})();
