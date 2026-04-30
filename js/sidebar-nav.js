/* Sidebar section-nav active-state highlighting.
 * Uses IntersectionObserver to mark the currently-visible section
 * link in the homepage sidebar. Same-origin script, CSP-safe.
 */
(function () {
    'use strict';

    var navLinks = document.querySelectorAll('.section-nav a[data-target]');
    if (navLinks.length === 0) return;

    // Build a map of section id -> nav anchor for quick lookup
    var linkByTarget = {};
    navLinks.forEach(function (a) {
        linkByTarget[a.getAttribute('data-target')] = a;
    });

    var sections = [];
    Object.keys(linkByTarget).forEach(function (id) {
        var el = document.getElementById(id);
        if (el) sections.push(el);
    });

    if (sections.length === 0) return;

    function setActive(id) {
        navLinks.forEach(function (a) {
            if (a.getAttribute('data-target') === id) {
                a.classList.add('is-active');
            } else {
                a.classList.remove('is-active');
            }
        });
    }

    // Track which sections are currently in view; pick the topmost-visible one.
    var visible = new Set();

    var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
            if (entry.isIntersecting) {
                visible.add(entry.target.id);
            } else {
                visible.delete(entry.target.id);
            }
        });

        // Pick the first section (in DOM order) that's currently visible.
        for (var i = 0; i < sections.length; i++) {
            if (visible.has(sections[i].id)) {
                setActive(sections[i].id);
                return;
            }
        }
    }, {
        // Trigger when the section's top is ~30% into the viewport
        // and exit when it scrolls past the top half.
        rootMargin: '-30% 0px -55% 0px',
        threshold: 0
    });

    sections.forEach(function (s) { observer.observe(s); });

    // Smooth-scroll behavior (handled by CSS scroll-behavior: smooth, but
    // also handle the case where the user clicks a link by giving the
    // active state immediate visual feedback rather than waiting for the
    // observer to catch up).
    navLinks.forEach(function (a) {
        a.addEventListener('click', function () {
            var target = a.getAttribute('data-target');
            if (target) setActive(target);
        });
    });

    // Set initial active state to the first section so the sidebar
    // doesn't render with everything muted on load.
    if (sections.length > 0) setActive(sections[0].id);
})();
