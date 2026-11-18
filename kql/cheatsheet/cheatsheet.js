/* cheatsheet.js - toolbar buttons for both KQL cheatsheets.
 *
 * The site CSP has no 'unsafe-inline' for scripts, so inline onclick
 * handlers never run. The buttons carry data-cheatsheet="expand|collapse|print"
 * and this file wires them up.
 */
(function () {
  'use strict';
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest('[data-cheatsheet]');
    if (!btn) return;
    var action = btn.getAttribute('data-cheatsheet');
    if (action === 'print') { window.print(); return; }
    var open = action === 'expand';
    document.querySelectorAll('details').forEach(function (d) { d.open = open; });
  });
})();
