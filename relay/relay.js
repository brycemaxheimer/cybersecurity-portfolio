/* ==========================================================================
 * /relay/ front-end.
 *
 * Talks only to same-origin /api/relay/* (satisfies connect-src 'self'), and
 * holds no credential of its own -- the Cloudflare Access cookie rides along
 * automatically and the Worker holds the GitHub token.
 *
 * Rendering rule, no exceptions: every value that originates from GitHub
 * (titles, comment bodies, author logins) is written with textContent or
 * createTextNode. Issue content is attacker-influenced -- anyone who can
 * comment on the repo can put HTML in it -- so nothing here uses innerHTML
 * with remote data.
 * ========================================================================== */

(function () {
    'use strict';

    var THREAD_POLL_MS = 20000;

    var el = {
        whoami:        document.getElementById('whoami'),
        banner:        document.getElementById('banner'),
        compose:       document.getElementById('compose'),
        composePanel:  document.getElementById('compose-panel'),
        title:         document.getElementById('title'),
        body:          document.getElementById('body'),
        dispatch:      document.getElementById('dispatch'),
        composeStatus: document.getElementById('compose-status'),
        tasks:         document.getElementById('tasks'),
        refresh:       document.getElementById('refresh'),
        threadPanel:   document.getElementById('thread-panel'),
        threadTitle:   document.getElementById('thread-title'),
        thread:        document.getElementById('thread'),
        closeThread:   document.getElementById('close-thread'),
        reply:         document.getElementById('reply'),
        replyBody:     document.getElementById('reply-body'),
        sendReply:     document.getElementById('send-reply'),
        replyStatus:   document.getElementById('reply-status'),
    };

    var openThread = null;
    var pollTimer = null;

    /* --- helpers -------------------------------------------------------- */

    function api(path, options) {
        return fetch('/api/relay/' + path, Object.assign({
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
        }, options || {})).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (data) {
                if (!r.ok) {
                    var err = new Error(data.error || ('HTTP ' + r.status));
                    err.status = r.status;
                    throw err;
                }
                return data;
            });
        });
    }

    function postJson(path, payload) {
        return api(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(payload),
        });
    }

    function showBanner(message, ok) {
        el.banner.textContent = message;
        el.banner.classList.toggle('is-ok', Boolean(ok));
        el.banner.hidden = false;
    }

    function setStatus(node, message, kind) {
        node.textContent = message;
        node.classList.toggle('is-error', kind === 'error');
        node.classList.toggle('is-ok', kind === 'ok');
    }

    function relTime(iso) {
        var then = new Date(iso).getTime();
        if (!then) return '';
        var mins = Math.round((Date.now() - then) / 60000);
        if (mins < 1) return 'just now';
        if (mins < 60) return mins + 'm ago';
        var hrs = Math.round(mins / 60);
        if (hrs < 24) return hrs + 'h ago';
        return Math.round(hrs / 24) + 'd ago';
    }

    // Auth problems are terminal for the page -- there is no retry the browser
    // can perform, so stop polling and tell the user how to recover.
    function handleFatal(err) {
        stopPolling();
        if (err.status === 401) {
            showBanner('Access session expired or missing. Reload the page to sign in again.');
        } else if (err.status === 403) {
            showBanner('Signed in, but this identity is not on the relay allowlist.');
        } else if (err.status === 503) {
            showBanner('Relay is not fully configured yet. See functions/api/relay/README.md for the remaining setup steps.');
        } else {
            return false;
        }
        return true;
    }

    /* --- identity ------------------------------------------------------- */

    function loadWhoami() {
        return api('whoami').then(function (data) {
            el.whoami.textContent = data.email;
        }).catch(function (err) {
            el.whoami.textContent = 'not signed in';
            if (!handleFatal(err)) showBanner('Could not verify identity: ' + err.message);
            throw err;
        });
    }

    /* --- task list ------------------------------------------------------ */

    function renderTasks(tasks) {
        el.tasks.textContent = '';

        if (!tasks.length) {
            var empty = document.createElement('p');
            empty.className = 'relay-empty';
            empty.textContent = 'No tasks dispatched yet.';
            el.tasks.appendChild(empty);
            return;
        }

        tasks.forEach(function (t) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'relay-task';

            var num = document.createElement('span');
            num.className = 'relay-task-num';
            num.textContent = '#' + t.number;

            var title = document.createElement('span');
            title.className = 'relay-task-title';
            title.textContent = t.title;

            var pill = document.createElement('span');
            pill.className = 'relay-pill' + (t.state === 'open' ? ' is-open' : '');
            pill.textContent = t.state;

            var meta = document.createElement('span');
            meta.className = 'relay-task-meta';
            meta.textContent = t.comments + ' · ' + relTime(t.updatedAt);

            btn.appendChild(num);
            btn.appendChild(title);
            btn.appendChild(pill);
            btn.appendChild(meta);
            btn.addEventListener('click', function () { openTask(t.number); });

            el.tasks.appendChild(btn);
        });
    }

    function loadTasks() {
        return api('tasks').then(function (data) {
            renderTasks(data.tasks || []);
        }).catch(function (err) {
            if (handleFatal(err)) return;
            el.tasks.textContent = '';
            var p = document.createElement('p');
            p.className = 'relay-empty';
            p.textContent = 'Could not load tasks: ' + err.message;
            el.tasks.appendChild(p);
        });
    }

    /* --- thread --------------------------------------------------------- */

    function messageNode(author, isBot, when, body) {
        var wrap = document.createElement('div');
        wrap.className = 'relay-msg' + (isBot ? ' is-bot' : '');

        var head = document.createElement('div');
        head.className = 'relay-msg-head';

        var who = document.createElement('span');
        who.textContent = author || 'unknown';

        var stamp = document.createElement('span');
        stamp.textContent = relTime(when);

        head.appendChild(who);
        head.appendChild(stamp);

        var pre = document.createElement('p');
        pre.className = 'relay-msg-body';
        pre.textContent = body;

        wrap.appendChild(head);
        wrap.appendChild(pre);
        return wrap;
    }

    function renderThread(data) {
        el.threadTitle.textContent = '#' + data.task.number + ' — ' + data.task.title;

        el.thread.textContent = '';
        if (!data.comments.length) {
            var p = document.createElement('p');
            p.className = 'relay-empty';
            p.textContent = 'No replies yet. Claude picks tasks up within a minute or two of dispatch.';
            el.thread.appendChild(p);
        } else {
            data.comments.forEach(function (c) {
                el.thread.appendChild(messageNode(c.author, c.isBot, c.createdAt, c.body));
            });
        }
        el.thread.scrollTop = el.thread.scrollHeight;
    }

    function loadThread(number) {
        return api('thread?n=' + encodeURIComponent(number)).then(renderThread);
    }

    function startPolling(number) {
        stopPolling();
        pollTimer = setInterval(function () {
            loadThread(number).catch(function (err) { handleFatal(err); });
        }, THREAD_POLL_MS);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function openTask(number) {
        openThread = number;
        el.threadPanel.hidden = false;
        el.thread.textContent = '';
        setStatus(el.replyStatus, '');

        loadThread(number).then(function () {
            el.threadPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
            startPolling(number);
        }).catch(function (err) {
            if (handleFatal(err)) return;
            setStatus(el.replyStatus, 'Could not load thread: ' + err.message, 'error');
        });
    }

    function closeTask() {
        stopPolling();
        openThread = null;
        el.threadPanel.hidden = true;
    }

    /* --- actions -------------------------------------------------------- */

    el.compose.addEventListener('submit', function (e) {
        e.preventDefault();
        var title = el.title.value.trim();
        var body = el.body.value.trim();
        if (!title || !body) return;

        el.dispatch.disabled = true;
        setStatus(el.composeStatus, 'Dispatching…');

        postJson('task', { title: title, body: body }).then(function (data) {
            el.title.value = '';
            el.body.value = '';
            setStatus(el.composeStatus, 'Dispatched as #' + data.task.number, 'ok');
            loadTasks();
            openTask(data.task.number);
        }).catch(function (err) {
            if (handleFatal(err)) return;
            setStatus(el.composeStatus, 'Failed: ' + err.message, 'error');
        }).then(function () {
            el.dispatch.disabled = false;
        });
    });

    el.reply.addEventListener('submit', function (e) {
        e.preventDefault();
        if (!openThread) return;
        var body = el.replyBody.value.trim();
        if (!body) return;

        el.sendReply.disabled = true;
        setStatus(el.replyStatus, 'Sending…');

        postJson('reply', { number: openThread, body: body }).then(function () {
            el.replyBody.value = '';
            setStatus(el.replyStatus, 'Sent', 'ok');
            return loadThread(openThread);
        }).catch(function (err) {
            if (handleFatal(err)) return;
            setStatus(el.replyStatus, 'Failed: ' + err.message, 'error');
        }).then(function () {
            el.sendReply.disabled = false;
        });
    });

    el.refresh.addEventListener('click', loadTasks);
    el.closeThread.addEventListener('click', closeTask);

    // Stop polling while the tab is hidden -- no reason to spend GitHub API
    // quota on a thread nobody is looking at.
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            stopPolling();
        } else if (openThread) {
            loadThread(openThread).catch(function (err) { handleFatal(err); });
            startPolling(openThread);
        }
    });

    loadWhoami().then(loadTasks).catch(function () { /* banner already shown */ });
})();
