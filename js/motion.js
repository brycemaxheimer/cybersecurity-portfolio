/* motion.js - the parts of the site that move.
 *
 * Progressive enhancement only: with no JS the page is complete and the
 * CSS keyframe drift still runs. Honors prefers-reduced-motion by doing
 * nothing at all.
 *
 *   1. Ambient field - the background color blobs wander on their own
 *      and lean toward the cursor, lazily, like water.
 *   2. Scroll reveal - entries surface as they enter the viewport.
 *   3. Tilt - cards lean toward the pointer.
 *   4. Center-focus roulette - the card nearest the viewport center
 *      takes focus; scrolling swaps it card to card.
 *   5. Live pulse - the homepage hero shows the honeypot's last 24h.
 */
(function () {
  'use strict';
  if (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  document.documentElement.classList.add('js-motion');

  /* ── 1. Ambient field ── */
  var tx = 0, ty = 0, ts = 1;       // targets (cursor influence)
  var cx = 0, cy = 0, cs = 1;       // current (lerped)
  addEventListener('pointermove', function (e) {
    var nx = e.clientX / innerWidth - 0.5;
    var ny = e.clientY / innerHeight - 0.5;
    tx = nx * 44; ty = ny * 32; ts = 1 + Math.abs(nx) * 0.05;
  }, { passive: true });
  var root = document.documentElement.style;
  function drift(t) {
    var wx = Math.sin(t / 9000) * 18 + Math.sin(t / 23000) * 10;
    var wy = Math.cos(t / 11000) * 14 + Math.sin(t / 17000) * 8;
    cx += ((tx + wx) - cx) * 0.018;
    cy += ((ty + wy) - cy) * 0.018;
    cs += (ts - cs) * 0.018;
    root.setProperty('--drift-x', cx.toFixed(2) + 'px');
    root.setProperty('--drift-y', cy.toFixed(2) + 'px');
    root.setProperty('--drift-s', cs.toFixed(4));
    requestAnimationFrame(drift);
  }
  requestAnimationFrame(drift);

  /* ── 2. Scroll reveal ──
     Flow cards and lab cards are excluded: the roulette below owns
     their opacity. Reveal handles the rest. */
  var tiltEls = [].slice.call(document.querySelectorAll('.card, .exp-entry, .proj-card, .lab-card, .role, .award'));
  var revealEls = tiltEls.filter(function (el) {
    return !el.closest('.card-list.flow') && !el.closest('.lab-grid');
  });
  if ('IntersectionObserver' in window && revealEls.length) {
    revealEls.forEach(function (el, i) {
      el.classList.add('reveal');
      el.style.setProperty('--reveal-delay', (i % 5) * 70 + 'ms');
    });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add('is-visible'); io.unobserve(en.target); }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.05 });
    revealEls.forEach(function (el) { io.observe(el); });
  }

  /* ── 3. Tilt toward the pointer ── */
  tiltEls.forEach(function (el) {
    el.addEventListener('pointermove', function (e) {
      var r = el.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width - 0.5;
      var py = (e.clientY - r.top) / r.height - 0.5;
      el.style.setProperty('--tilt-y', (px * 3.2).toFixed(2) + 'deg');
      el.style.setProperty('--tilt-x', (-py * 2.6).toFixed(2) + 'deg');
    });
    el.addEventListener('pointerleave', function () {
      el.style.removeProperty('--tilt-x');
      el.style.removeProperty('--tilt-y');
    });
  });

  /* ── 4. Center-focus roulette ──
     Whichever card sits nearest the viewport's center line holds
     focus. Queried live so cards injected later (blog.js) join in. */
  var FOCUS_SEL = '.card-list.flow .card, .lab-grid .lab-card';
  var current = null, ticking = false;
  function pickCenter() {
    ticking = false;
    var els = document.querySelectorAll(FOCUS_SEL);
    if (!els.length) return;
    var mid = innerHeight / 2, best = null, bd = Infinity;
    for (var i = 0; i < els.length; i++) {
      var r = els[i].getBoundingClientRect();
      if (r.bottom < 0 || r.top > innerHeight) continue;
      var d = Math.abs((r.top + r.height / 2) - mid);
      if (d < bd) { bd = d; best = els[i]; }
    }
    if (best !== current) {
      if (current) current.classList.remove('is-center');
      if (best) best.classList.add('is-center');
      current = best;
    }
  }
  function queuePick() {
    if (!ticking) { ticking = true; requestAnimationFrame(pickCenter); }
  }
  if (document.querySelector(FOCUS_SEL)) {
    addEventListener('scroll', queuePick, { passive: true });
    addEventListener('resize', queuePick, { passive: true });
    // settle once after load (and again after late-rendered lists)
    queuePick();
    setTimeout(queuePick, 600);
  }

  /* ── 5. Live pulse (homepage hero only; element is opt-in) ── */
  var pulse = document.getElementById('live-pulse');
  if (pulse && 'fetch' in window) {
    fetch('https://threats.brycemaxheimer.com/feed.json')
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (f) {
        if (f == null || f.events_24h == null) return;
        var ev = Number(f.events_24h).toLocaleString();
        var ips = Number(f.unique_ips_24h || 0).toLocaleString();
        pulse.innerHTML = '<span class="dot"></span><span>honeypot, last 24h: <strong>' +
          ev + '</strong> events from <strong>' + ips + '</strong> attackers</span>';
        pulse.hidden = false;
      })
      .catch(function () { /* feed unreachable - the pulse just stays hidden */ });
  }
})();
