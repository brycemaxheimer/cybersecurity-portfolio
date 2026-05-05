/* Intel Lookup Demo - calls the backend route /api/intel/lookup so the
 * provider keys never reach the browser. Health probe runs at page load.
 */
(function () {
    'use strict';

    var ind     = document.getElementById('ild-ind');
    var type    = document.getElementById('ild-type');
    var goBtn   = document.getElementById('ild-go');
    var statusE = document.getElementById('ild-status');
    var results = document.getElementById('ild-results');
    var providersE = document.getElementById('ild-providers');

    if (!ind || !goBtn || !results) return;

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function renderHealth(data) {
        if (!data || !Array.isArray(data.providers)) {
            providersE.innerHTML = '<div class="ild-provider"><span class="ild-pname">health probe failed</span></div>';
            return;
        }
        providersE.innerHTML = data.providers.map(function (p) {
            var pill;
            if (!p.reachable) {
                pill = '<span class="ild-pill bad">unreachable</span>';
            } else if (!p.configured) {
                pill = '<span class="ild-pill warn">no key</span>';
            } else {
                pill = '<span class="ild-pill ok">ready</span>';
            }
            return '<div class="ild-provider">'
                + '<div><span class="ild-pname">' + escapeHtml(p.label) + '</span>' + pill + '</div>'
                + '<div class="ild-pdetail">' + escapeHtml(p.detail || '') + '</div>'
                + '</div>';
        }).join('');
    }

    function renderResults(data) {
        if (!data) { results.innerHTML = ''; return; }
        if (data.error) {
            results.innerHTML = '<div class="ild-result-card error">'
                + '<h4>Error</h4>'
                + '<div>' + escapeHtml(data.error) + '</div>'
                + '</div>';
            return;
        }
        var head = '<div class="ild-rmeta" style="margin-bottom: 0.6rem">'
            + escapeHtml(data.indicator) + ' &middot; type=' + escapeHtml(data.type)
            + ' &middot; ' + escapeHtml(String(data.elapsedMs)) + 'ms'
            + '</div>';
        var cards = (data.results || []).map(function (r) {
            var verdictClass = r.verdict === 'malicious' ? 'malicious'
                            : r.verdict === 'suspicious' ? 'suspicious'
                            : r.error ? 'error' : '';
            var body;
            if (r.error) {
                body = '<div class="ild-rmeta">' + escapeHtml(r.error)
                    + (r.skipped ? ' &middot; skipped' : '') + '</div>'
                    + (r.detail ? '<pre>' + escapeHtml(r.detail) + '</pre>' : '');
            } else {
                var meta = [];
                if (r.verdict)    meta.push('verdict=' + r.verdict);
                if (r.score != null) meta.push('score=' + r.score);
                if (r.reports != null) meta.push('reports=' + r.reports);
                if (r.country)    meta.push('country=' + r.country);
                if (r.region)     meta.push('region=' + r.region);
                if (r.city)       meta.push('city=' + r.city);
                if (r.isp)        meta.push('isp=' + r.isp);
                if (r.org && r.org !== r.isp) meta.push('org=' + r.org);
                if (r.asn)        meta.push('asn=' + r.asn);
                if (r.usageType)  meta.push('use=' + r.usageType);
                if (r.isTor)      meta.push('tor');
                body = '<div class="ild-rmeta">' + escapeHtml(meta.join(' · ')) + '</div>';
                if (r.lastReport) body += '<div class="ild-rmeta">last reported: ' + escapeHtml(r.lastReport) + '</div>';
                if (r.note)       body += '<div class="ild-rmeta" style="margin-top: 0.4rem">' + escapeHtml(r.note) + '</div>';
                if (r.link) body += '<div class="ild-rmeta" style="margin-top: 0.4rem">'
                    + '<a href="' + escapeHtml(r.link) + '" target="_blank" rel="noopener noreferrer" style="color: var(--mint-deep)">view at provider &rarr;</a>'
                    + '</div>';
            }
            return '<div class="ild-result-card ' + verdictClass + '">'
                + '<h4>' + escapeHtml(r.provider || 'provider') + '</h4>'
                + body
                + '</div>';
        }).join('');
        results.innerHTML = head + cards;
    }

    async function loadHealth() {
        try {
            var r = await fetch('/api/intel/health', { cache: 'no-store' });
            if (!r.ok) throw new Error('HTTP ' + r.status);
            renderHealth(await r.json());
        } catch (e) {
            providersE.innerHTML = '<div class="ild-provider"><span class="ild-pname">health probe failed</span>'
                + '<div class="ild-pdetail">' + escapeHtml(String(e.message || e)) + '</div></div>';
        }
    }

    async function runLookup() {
        var v = (ind.value || '').trim();
        if (!v) { statusE.textContent = 'Enter an indicator'; return; }
        statusE.textContent = 'Looking up...';
        goBtn.disabled = true;
        results.innerHTML = '';
        try {
            var r = await fetch('/api/intel/lookup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ indicator: v, type: type.value }),
            });
            var data = await r.json();
            if (!r.ok) {
                renderResults({ error: data.error || ('HTTP ' + r.status) });
            } else {
                renderResults(data);
                statusE.textContent = '';
            }
        } catch (e) {
            renderResults({ error: 'Request failed: ' + (e.message || e) });
        } finally {
            goBtn.disabled = false;
            if (statusE.textContent === 'Looking up...') statusE.textContent = '';
        }
    }

    goBtn.addEventListener('click', runLookup);
    ind.addEventListener('keydown', function (e) { if (e.key === 'Enter') runLookup(); });

    loadHealth();
})();
