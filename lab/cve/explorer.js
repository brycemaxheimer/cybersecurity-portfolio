/* explorer.js - CVE / KEV / EPSS Browser.
 * Loads /lab/cve/data.json (KEV catalog with EPSS scores) and powers
 * the search / filter / sort / detail UI. No external API calls.
 */
(function () {
    'use strict';

    var DATA = null;
    var query = '';
    var vendor = '';
    var ransomOnly = false;
    var recentOnly = false;
    var epssMin = 0;
    var sortBy = 'dateAdded';
    var NOW = Date.now();
    var NINETY_DAYS_MS = 90 * 24 * 3600 * 1000;

    var els = {
        q:         document.getElementById('q'),
        vendor:    document.getElementById('vendor'),
        ransom:    document.getElementById('ransom-only'),
        recent:    document.getElementById('recent-only'),
        epssMin:   document.getElementById('epss-min'),
        epssVal:   document.getElementById('epss-min-val'),
        sort:      document.getElementById('sort'),
        clear:     document.getElementById('clear'),
        list:      document.getElementById('list'),
        status:    document.getElementById('status'),
    };

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }
    function setStatus(msg) { els.status.innerHTML = msg; }

    fetch('/lab/cve/data.json')
        .then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (d) {
            DATA = d;
            populateMeta();
            populateVendors();
            render();
        })
        .catch(function (e) {
            setStatus('Failed to load data: ' + e.message);
            console.error(e);
        });

    function populateMeta() {
        var v = DATA.vulnerabilities;
        var ransom = 0, high = 0, recent = 0;
        for (var i = 0; i < v.length; i++) {
            if (v[i].ransomware) ransom++;
            if (v[i].epss && v[i].epss >= 0.7) high++;
            if (v[i].dateAdded && (NOW - Date.parse(v[i].dateAdded)) <= NINETY_DAYS_MS) recent++;
        }
        document.getElementById('m-total').textContent = v.length;
        document.getElementById('m-ransom').textContent = ransom;
        document.getElementById('m-high').textContent = high;
        document.getElementById('m-recent').textContent = recent;
        document.getElementById('m-kev-ver').textContent = DATA.catalogVersion || '';
        document.getElementById('m-epss-date').textContent = DATA.epssDate || '';
    }

    function populateVendors() {
        var seen = {};
        DATA.vulnerabilities.forEach(function (x) {
            if (x.vendor) seen[x.vendor] = (seen[x.vendor] || 0) + 1;
        });
        var vendors = Object.keys(seen).sort(function (a, b) {
            return seen[b] - seen[a] || a.localeCompare(b);
        });
        var html = '';
        vendors.forEach(function (v) {
            html += '<option value="' + escapeHtml(v) + '">' + escapeHtml(v) + ' (' + seen[v] + ')</option>';
        });
        els.vendor.insertAdjacentHTML('beforeend', html);
    }

    /* -------- Event wiring -------- */
    els.q.addEventListener('input',  function () { query = els.q.value.trim().toLowerCase(); render(); });
    els.vendor.addEventListener('change', function () { vendor = els.vendor.value; render(); });
    els.ransom.addEventListener('change', function () { ransomOnly = els.ransom.checked; render(); });
    els.recent.addEventListener('change', function () { recentOnly = els.recent.checked; render(); });
    els.epssMin.addEventListener('input', function () {
        epssMin = parseInt(els.epssMin.value, 10) / 100;
        els.epssVal.textContent = els.epssMin.value + '%';
        render();
    });
    els.sort.addEventListener('click', function (e) {
        var btn = e.target.closest('button');
        if (!btn) return;
        sortBy = btn.dataset.sort;
        els.sort.querySelectorAll('button').forEach(function (b) {
            b.classList.toggle('active', b === btn);
        });
        render();
    });
    els.clear.addEventListener('click', function () {
        query = ''; els.q.value = '';
        vendor = ''; els.vendor.value = '';
        ransomOnly = false; els.ransom.checked = false;
        recentOnly = false; els.recent.checked = false;
        epssMin = 0; els.epssMin.value = 0; els.epssVal.textContent = '0%';
        render();
    });

    /* -------- Filtering & sorting -------- */
    function matches(v) {
        if (vendor && v.vendor !== vendor) return false;
        if (ransomOnly && !v.ransomware) return false;
        if (recentOnly && Date.parse(v.dateAdded) < NOW - NINETY_DAYS_MS) return false;
        if (epssMin > 0 && (v.epss == null || v.epss < epssMin)) return false;
        if (query) {
            var blob = (v.id + ' ' + v.vendor + ' ' + v.product + ' ' + v.name + ' ' + v.description).toLowerCase();
            if (blob.indexOf(query) < 0) return false;
        }
        return true;
    }

    function sortRows(rows) {
        if (sortBy === 'dateAdded') {
            return rows.slice().sort(function (a, b) {
                return (b.dateAdded || '').localeCompare(a.dateAdded || '');
            });
        }
        if (sortBy === 'epss') {
            return rows.slice().sort(function (a, b) {
                return (b.epss || 0) - (a.epss || 0);
            });
        }
        if (sortBy === 'dueDate') {
            // Earliest due date first; entries with no due date go last.
            return rows.slice().sort(function (a, b) {
                var da = a.dueDate || '9999-12-31';
                var db = b.dueDate || '9999-12-31';
                return da.localeCompare(db);
            });
        }
        return rows;
    }

    /* -------- Rendering -------- */
    function epssClass(score) {
        if (score == null) return '';
        if (score >= 0.7) return 'epss-high';
        if (score >= 0.3) return 'epss-med';
        return 'epss-low';
    }

    function fmtEpss(score, pct) {
        if (score == null) return '<span class="cve-epss">no EPSS</span>';
        var p = (score * 100).toFixed(score >= 0.1 ? 1 : 2);
        var pp = pct != null ? (pct * 100).toFixed(1) + 'th pct' : '';
        return '<span class="cve-epss ' + epssClass(score) + '" title="EPSS score ' + score.toFixed(4) + ' &middot; ' + pp + '">EPSS ' + p + '%</span>';
    }

    function fmtDate(iso) {
        if (!iso) return '';
        return iso.slice(0, 10);
    }

    function renderItem(v) {
        var ransom = v.ransomware ? '<span class="ransom-badge" title="Known to be used in ransomware campaigns">ransomware</span>' : '';
        var summary =
            '<summary><div class="cve-row">' +
                '<span class="cve-id-badge">' + escapeHtml(v.id) + '</span>' +
                '<div class="cve-name">' +
                    '<span class="vendor">' + escapeHtml(v.vendor) + ' &middot; ' + escapeHtml(v.product) + '</span>' +
                    escapeHtml(v.name) + ransom +
                '</div>' +
                '<span class="cve-date">added ' + escapeHtml(fmtDate(v.dateAdded)) + '</span>' +
                fmtEpss(v.epss, v.epssPercentile) +
            '</div></summary>';

        var detail = '<div class="cve-detail"><div>' +
            '<div class="block"><h5>Short description</h5><div class="value">' + escapeHtml(v.description || '(none)') + '</div></div>' +
            '<div class="block"><h5>Required action</h5><div class="value">' + escapeHtml(v.requiredAction || '(none)') + '</div></div>' +
            (v.notes ? '<div class="block full"><h5>CISA notes / references</h5><div class="value">' + linkifyNotes(v.notes) + '</div></div>' : '') +
        '</div><div>' +
            '<dl class="meta-list">' +
                '<dt>CVE</dt><dd><a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.id) + '" target="_blank" rel="noopener">' + escapeHtml(v.id) + ' &nearr;</a></dd>' +
                '<dt>Date added</dt><dd>' + escapeHtml(fmtDate(v.dateAdded)) + '</dd>' +
                '<dt>Federal due date</dt><dd>' + escapeHtml(fmtDate(v.dueDate) || '-') + '</dd>' +
                (v.epss != null
                    ? '<dt>EPSS score</dt><dd>' + (v.epss * 100).toFixed(2) + '% (' + ((v.epssPercentile || 0) * 100).toFixed(1) + 'th percentile)</dd>'
                    : '<dt>EPSS</dt><dd>not scored</dd>') +
                (v.cwes && v.cwes.length
                    ? '<dt>CWE</dt><dd>' + v.cwes.map(escapeHtml).join(', ') + '</dd>'
                    : '') +
            '</dl>' +
        '</div></div>';

        return '<details class="cve-item" id="' + escapeHtml(v.id) + '">' + summary + detail + '</details>';
    }

    // Convert URLs in CISA notes to clickable links (notes are often a list of URLs separated by ; or whitespace).
    function linkifyNotes(text) {
        var safe = escapeHtml(text);
        return safe.replace(/(https?:\/\/[^\s;]+)/g, function (m) {
            return '<a href="' + m + '" target="_blank" rel="noopener">' + m + '</a>';
        });
    }

    function render() {
        if (!DATA) return;
        var rows = DATA.vulnerabilities.filter(matches);
        rows = sortRows(rows);

        setStatus('<strong>' + rows.length + '</strong> KEV ' +
                  (rows.length === 1 ? 'entry' : 'entries') +
                  (query || vendor || ransomOnly || recentOnly || epssMin > 0 ? ' matching filters' : ''));

        var MAX = 300;
        var capped = rows.length > MAX;
        var slice = rows.slice(0, MAX);

        if (slice.length === 0) {
            els.list.innerHTML = '<div class="cve-empty">No entries match the current filters.</div>';
            return;
        }
        var html = slice.map(renderItem).join('');
        if (capped) {
            html += '<div class="cve-empty" style="padding:1.5rem">Showing first ' + MAX + ' of ' + rows.length + '. Refine the filters to narrow further.</div>';
        }
        els.list.innerHTML = html;
    }
})();
