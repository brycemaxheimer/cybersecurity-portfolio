/* ==========================================================================
 * KQL rewrite layer
 *
 * Single source of truth for the surface-syntax adjustments the v1 engine
 * needs in order to run real-Defender / real-Sentinel queries. Used by:
 *   - kql/engine/api.js          (browser, attaches to window.KqlEngineApi)
 *   - kql/test-harness/*.cjs     (Node, via require())
 *
 * UMD: works as a plain <script> (sets window.KqlRewrite) AND as CommonJS
 * (sets module.exports). Do NOT add ES-module syntax here -- the browser
 * loads this as a classic script.
 *
 * What it does:
 *   1. rewriteTimePredicates(kql)
 *      ago(N) / now() / now(-N) -> todatetime('<anchor +/- offset>'),
 *      so storyline data with fixed timestamps still matches user queries.
 *   2. v1CompatRewrite(kql)  composes:
 *        - materialize(...)      -> bare expression
 *        - @"..." / @'...'       -> "..." / '...' with literal backslashes
 *        - <col> =~ x / !~ x     -> tolower(col) == / != tolower(x)
 *        - let X = dynamic([..]) -> inlined into has_any/has_all/in/!in
 *        - <col> has_any (a,b)   -> (col has a or col has b)
 *        - <expr> matches regex p-> matches_regex(<expr>, p)
 * ========================================================================== */
(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.KqlRewrite = api;
    }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : null), function () {
    'use strict';

    var _anchorIso = null;

    function setAnchor(iso)  { _anchorIso = iso || null; }
    function getAnchor()     { return _anchorIso; }

    function _formatKqlDatetime(d) {
        return "todatetime('" + d.toISOString().replace(/\.\d+Z$/, '.000Z') + "')";
    }
    function _offsetSeconds(num, unit) {
        var n = parseFloat(num);
        if (unit === 'ms') return n / 1000;
        if (unit === 's')  return n;
        if (unit === 'm')  return n * 60;
        if (unit === 'h')  return n * 3600;
        if (unit === 'd')  return n * 86400;
        return null;
    }

    function rewriteTimePredicates(kql, anchorOverride) {
        var iso = anchorOverride || _anchorIso;
        if (!iso) return kql;
        var anchor = new Date(iso);
        kql = kql.replace(/ago\(\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*\)/g, function (_m, num, unit) {
            var secs = _offsetSeconds(num, unit);
            if (secs == null) return _m;
            return _formatKqlDatetime(new Date(anchor.getTime() - secs * 1000));
        });
        kql = kql.replace(/now\(\s*\)/g, function () { return _formatKqlDatetime(anchor); });
        kql = kql.replace(/now\(\s*-\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*\)/g, function (_m, num, unit) {
            var secs = _offsetSeconds(num, unit);
            if (secs == null) return _m;
            return _formatKqlDatetime(new Date(anchor.getTime() - secs * 1000));
        });
        return kql;
    }

    var KQL_KW = /^(where|extend|summarize|project|order|sort|by|asc|desc|let|join|on|kind|union|parse|with|take|top|distinct|render|materialize|and|or|not|in|between|true|false|null)$/;

    function _materializeUnwrap(kql) {
        var i = 0, out = '';
        while (i < kql.length) {
            var idx = kql.indexOf('materialize(', i);
            if (idx < 0) { out += kql.slice(i); break; }
            out += kql.slice(i, idx);
            var depth = 1, j = idx + 'materialize('.length;
            while (j < kql.length && depth > 0) {
                if (kql[j] === '(') depth++;
                else if (kql[j] === ')') { depth--; if (depth === 0) break; }
                j++;
            }
            out += kql.slice(idx + 'materialize('.length, j);
            i = j + 1;
        }
        return out;
    }

    function _rewriteRawStrings(kql) {
        kql = kql.replace(/@"([^"]*)"/g, function (_m, body) { return '"' + body.replace(/\\/g, '\\\\') + '"'; });
        kql = kql.replace(/@'([^']*)'/g, function (_m, body) { return "'" + body.replace(/\\/g, '\\\\') + "'"; });
        return kql;
    }

    function _rewriteEqTilde(kql) {
        var operandRe = '(@?"[^"]*"|@?\'[^\']*\'|[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)';
        var lhsRe = '([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)';
        kql = kql.replace(new RegExp(lhsRe + '\\s*=~\\s*' + operandRe, 'g'),
            function (_m, l, r) { return KQL_KW.test(l) ? _m : 'tolower(' + l + ') == tolower(' + r + ')'; });
        kql = kql.replace(new RegExp(lhsRe + '\\s*!~\\s*' + operandRe, 'g'),
            function (_m, l, r) { return KQL_KW.test(l) ? _m : 'tolower(' + l + ') != tolower(' + r + ')'; });
        return kql;
    }

    function _rewriteDynamicLetInline(kql) {
        var re = /let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*dynamic\(\s*\[([^\]]*)\]\s*\)\s*;\s*/g;
        var inlines = {};
        kql = kql.replace(re, function (_m, name, items) { inlines[name] = items.trim(); return ''; });
        var names = Object.keys(inlines);
        if (names.length === 0) return kql;
        for (var k = 0; k < names.length; k++) {
            var name = names[k];
            var refRe = new RegExp('(has_any|has_all|in|!in)\\s*\\(\\s*' + name + '\\s*\\)', 'g');
            kql = kql.replace(refRe, (function (items) {
                return function (_m, op) { return op + ' (' + items + ')'; };
            })(inlines[name]));
        }
        return kql;
    }

    function _rewriteHasAnyAll(kql) {
        var haRe = /([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s+(has_any|has_all)\s*\(([^)]+)\)/g;
        return kql.replace(haRe, function (_m, col, op, list) {
            var items = list.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
            var joiner = op === 'has_any' ? ' or ' : ' and ';
            return '(' + items.map(function (it) { return col + ' has ' + it; }).join(joiner) + ')';
        });
    }

    function _rewriteMatchesRegex(kql) {
        return kql.replace(
            /([A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)*)\s+matches\s+regex\s+(@?"[^"]*"|@?'[^']*')/g,
            function (_m, expr, pat) { return 'matches_regex(' + expr + ', ' + pat + ')'; }
        );
    }

    function v1CompatRewrite(kql) {
        kql = _materializeUnwrap(kql);
        kql = _rewriteRawStrings(kql);
        kql = _rewriteEqTilde(kql);
        kql = _rewriteDynamicLetInline(kql);
        kql = _rewriteHasAnyAll(kql);
        kql = _rewriteMatchesRegex(kql);
        return kql;
    }

    return {
        setAnchor: setAnchor,
        getAnchor: getAnchor,
        rewriteTimePredicates: rewriteTimePredicates,
        v1CompatRewrite: v1CompatRewrite,
    };
});
