/* themes.js — Customize page logic.
 * Renders 6 theme cards with palette previews. Clicking a card sets the
 * data-theme attribute on <html> and persists to localStorage. The bootstrap
 * script in every page's <head> picks up the stored value on next load.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'siteTheme';

    var DEFAULT_THEME = 'dark';

    var THEMES = [
        {
            id: 'dark',
            name: 'Pure Dark',
            desc: 'The default. True charcoal OLED, no color cast, crisp contrast. Easy on the eyes and on AMOLED screens.',
            palette: ['#0e0e0e', '#101010', '#3dd68c', '#ff5f6d', '#ffd166', '#ebebeb'],
            mini: { bg: '#101010', text: '#c4c4c4', accent: '#3dd68c', heading: '#ebebeb', border: 'rgba(255,255,255,0.07)', code: '#080808' },
        },
        {
            id: 'mint',
            name: 'Mint Grove',
            desc: 'Deep teal-mint surfaces, warm parchment text, mint accents. The original site palette.',
            palette: ['#071512', '#0f231c', '#46d09a', '#ef9273', '#e9c66d', '#f4fbf6'],
            mini: { bg: '#0f231c', text: '#d4e5dc', accent: '#46d09a', heading: '#f4fbf6', border: 'rgba(157,223,199,0.20)', code: '#050f0d' },
        },
        {
            id: 'tokyo',
            name: 'Tokyo Night',
            desc: 'Deep navy-indigo dark with violet accent. The definitive editor-night palette. Sharp, technical.',
            palette: ['#10142a', '#0d1120', '#7c6dfc', '#f07088', '#f0c060', '#d8defc'],
            mini: { bg: '#0d1120', text: '#b3bee0', accent: '#7c6dfc', heading: '#d8defc', border: 'rgba(140,160,255,0.13)', code: '#0c1020' },
        },
        {
            id: 'sage',
            name: 'Sage Grove',
            desc: 'Warm amber-earth dark. Cozy, grounded. Lower color temperature for late-night sessions.',
            palette: ['#28201a', '#211a12', '#d4a84a', '#d06858', '#e0c266', '#ede0cc'],
            mini: { bg: '#211a12', text: '#d4c5a8', accent: '#d4a84a', heading: '#ede0cc', border: 'rgba(200,180,140,0.16)', code: '#190f06' },
        },
        {
            id: 'light',
            name: 'Soft Light',
            desc: 'Off-white with warm depth. Darkened bg + ink for better contrast in bright environments.',
            palette: ['#d4dbe5', '#e0e6ee', '#176048', '#92291f', '#6a5114', '#08111e'],
            mini: { bg: '#e0e6ee', text: '#182232', accent: '#176048', heading: '#08111e', border: 'rgba(8,17,30,0.20)', code: '#f1f4fa' },
        },
        {
            id: 'contrast',
            name: 'High Contrast',
            desc: 'WCAG AA accessible. Pure black base, amber accent, maximum text contrast for low vision or bright environments.',
            palette: ['#000000', '#040404', '#ffbf00', '#ff1744', '#ffea00', '#ffffff'],
            mini: { bg: '#040404', text: '#f0f0f0', accent: '#ffbf00', heading: '#ffffff', border: 'rgba(255,255,255,0.55)', code: '#000000' },
        },
    ];

    var grid    = document.getElementById('theme-grid');
    var resetBtn= document.getElementById('reset-btn');
    var nameEl  = document.getElementById('active-name');
    var statusEl= document.getElementById('status');

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    function getActive() {
        try {
            return localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
        } catch (e) { return DEFAULT_THEME; }
    }

    function setActive(id) {
        try {
            if (id === DEFAULT_THEME) {
                // Default is in :root - no attribute needed.
                localStorage.removeItem(STORAGE_KEY);
                document.documentElement.removeAttribute('data-theme');
            } else {
                localStorage.setItem(STORAGE_KEY, id);
                document.documentElement.setAttribute('data-theme', id);
            }
        } catch (e) { /* private mode */ }

        // Update UI
        var theme = THEMES.find(function (t) { return t.id === id; });
        if (theme) nameEl.textContent = theme.name;
        Array.prototype.forEach.call(grid.querySelectorAll('.cu-card'), function (c) {
            c.classList.toggle('is-active', c.dataset.theme === id);
        });

        flashStatus('Theme applied');
    }

    function flashStatus(text) {
        statusEl.textContent = text;
        statusEl.classList.add('visible');
        clearTimeout(flashStatus._timer);
        flashStatus._timer = setTimeout(function () {
            statusEl.classList.remove('visible');
        }, 1600);
    }

    function renderCard(t) {
        var swatches = t.palette.map(function (c) {
            return '<div class="cu-swatch" style="background:' + c + '" title="' + escapeHtml(c) + '"></div>';
        }).join('');

        var mini = t.mini;
        var miniStyle =
            'background:' + mini.bg + ';' +
            'color:' + mini.text + ';' +
            'border-color:' + mini.border + ';';
        var pillStyle =
            'background:transparent;' +
            'color:' + mini.accent + ';' +
            'border-color:' + mini.accent + ';';
        var headStyle = 'color:' + mini.heading + ';';
        var linkStyle = 'color:' + mini.accent + ';';

        return '<button class="cu-card" data-theme="' + escapeHtml(t.id) + '" type="button">' +
            '<div class="cu-card-header">' +
                '<h3>' + escapeHtml(t.name) + '</h3>' +
                '<span class="active-mark">Active</span>' +
            '</div>' +
            '<p class="desc">' + escapeHtml(t.desc) + '</p>' +
            '<div class="cu-swatch-row">' + swatches + '</div>' +
            '<div class="cu-mini" style="' + miniStyle + '">' +
                '<div class="mini-h" style="' + headStyle + '">Section heading <span class="mini-pill" style="' + pillStyle + '">tag</span></div>' +
                'Body text reads at this contrast. <a class="mini-link" style="' + linkStyle + '" tabindex="-1">Link</a>.' +
            '</div>' +
        '</button>';
    }

    function init() {
        grid.innerHTML = THEMES.map(renderCard).join('');

        var active = getActive();
        var theme = THEMES.find(function (t) { return t.id === active; });
        if (theme) nameEl.textContent = theme.name;

        Array.prototype.forEach.call(grid.querySelectorAll('.cu-card'), function (c) {
            if (c.dataset.theme === active) c.classList.add('is-active');
            c.addEventListener('click', function () {
                setActive(c.dataset.theme);
            });
        });

        resetBtn.addEventListener('click', function () { setActive(DEFAULT_THEME); });
    }

    init();
})();
