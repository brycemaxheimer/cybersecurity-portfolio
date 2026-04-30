/* KQL Playground — preview-mode interactivity.
 * Loads canned example queries into the editor. Until the in-browser KQL
 * engine ships, the Run button shows a placeholder result.
 */
(function () {
    'use strict';

    var editor  = document.getElementById('editor');
    var status  = document.getElementById('status');
    var results = document.getElementById('results');
    var runBtn  = document.getElementById('run-btn');

    if (!editor || !status || !results || !runBtn) {
        return;
    }

    // Wire up the example-query buttons in the sidebar.
    var examples = document.querySelectorAll('.pg-example');
    Array.prototype.forEach.call(examples, function (btn) {
        btn.addEventListener('click', function () {
            editor.value = btn.getAttribute('data-q');
            editor.focus();
        });
    });

    runBtn.addEventListener('click', function () {
        status.textContent = 'Engine not yet wired (preview mode)';
        results.innerHTML =
            '<div class="placeholder">' +
            '<p style="margin-bottom:0.5rem; color: var(--text)">' +
            'Query received — but the in-browser KQL engine isn\'t wired up yet.' +
            '</p>' +
            '<p style="color: var(--muted); font-size: 0.85rem">' +
            'When the engine ships, you\'ll see a results table here. ' +
            'Until then, you can run this query against the PowerShell module locally — ' +
            'see the link below.' +
            '</p>' +
            '</div>';
    });
})();
