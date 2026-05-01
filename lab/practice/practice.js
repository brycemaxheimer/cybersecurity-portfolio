/* ==========================================================================
 * KQL Practice page controller
 *
 * Loads:
 *   - /lab/practice/questions.json   30 questions (number, title, type, prompt, ...)
 *   - /lab/practice/gold-results.json 30 canonical results from ADX (the truth)
 *
 * For each question the user can:
 *   - Test Run (unlimited)  -- runs query through the in-browser KQL engine,
 *                              shows result + diff vs gold + score breakdown.
 *   - Submit (once per Q)   -- locks the score, persists to IndexedDB.
 *
 * Score is on a 3-axis scale (each 0..1):
 *   Correctness  rows match gold (set or ordered, per gold metadata)
 *   Refinement   query uses canonical KQL idioms (=~, top, named aggs, ...)
 *   Speed        user_time / canonical_time ratio
 *
 * The engine itself is loaded as window.KqlEngineV2 from /kql/engine-v2/index.js .
 * That module is currently a thin shim over the existing v1 engine; it will be
 * swapped in piece by piece as Invoke-KqlPS.ps1 is ported to JS.
 * ========================================================================== */

// ----------------------------------------------------------------------------
// 0. Module-level state
// ----------------------------------------------------------------------------

const STATE = {
    questions: [],          // [{number, title, type, difficulty, prompt, sampleQuery}]
    gold:      {},          // { "1": {...}, "2": {...} }   keyed by question number
    activeNum: null,        // currently selected question number
    filter:    'all',       // 'all' | 'easy' | 'medium' | 'hard'
    scores:    {},          // { "1": { correctness, refinement, speed, total, submittedAt } }
    drafts:    {},          // { "1": "user query draft..." }   in-memory unsaved drafts
    lastRun:   null,        // last Test Run result for the active question (for re-display)
    engine:    null,        // resolved engine adapter (set on init)
};

const DB_NAME       = 'kql-practice';
const STORE_SCORES  = 'scores';
const STORE_DRAFTS  = 'drafts';
const DB_VERSION    = 1;

// ----------------------------------------------------------------------------
// 1. IndexedDB persistence (scores + drafts)
// ----------------------------------------------------------------------------

function openDb() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE_SCORES)) {
                db.createObjectStore(STORE_SCORES, { keyPath: 'number' });
            }
            if (!db.objectStoreNames.contains(STORE_DRAFTS)) {
                db.createObjectStore(STORE_DRAFTS, { keyPath: 'number' });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

async function dbAll(storeName) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const req = tx.objectStore(storeName).getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror   = () => reject(req.error);
    });
}

async function dbPut(storeName, value) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).put(value);
        tx.oncomplete = () => resolve();
        tx.onerror    = () => reject(tx.error);
    });
}

async function loadScoresFromDb() {
    try {
        const rows = await dbAll(STORE_SCORES);
        for (const r of rows) STATE.scores[String(r.number)] = r;
    } catch (e) { console.warn('Score load failed:', e); }
}

async function loadDraftsFromDb() {
    try {
        const rows = await dbAll(STORE_DRAFTS);
        for (const r of rows) STATE.drafts[String(r.number)] = r.text;
    } catch (e) { console.warn('Draft load failed:', e); }
}

async function persistScore(num, score) {
    STATE.scores[String(num)] = score;
    try { await dbPut(STORE_SCORES, { number: num, ...score }); }
    catch (e) { console.warn('Score persist failed:', e); }
}

async function persistDraft(num, text) {
    STATE.drafts[String(num)] = text;
    try { await dbPut(STORE_DRAFTS, { number: num, text, savedAt: new Date().toISOString() }); }
    catch (e) { /* fine -- private mode */ }
}

// ----------------------------------------------------------------------------
// 2. Asset loaders
// ----------------------------------------------------------------------------

async function loadJson(url) {
    const r = await fetch(url, { cache: 'force-cache' });
    if (!r.ok) throw new Error(`Failed to load ${url}: ${r.status}`);
    return r.json();
}

async function loadAssets() {
    const [questions, gold] = await Promise.all([
        loadJson('/lab/practice/questions.json'),
        loadJson('/lab/practice/gold-results.json'),
    ]);
    STATE.questions = questions;
    STATE.gold = gold.questions || {};
    STATE.goldMeta = {
        anchor: gold.anchor,
        cluster: gold.adxCluster,
        database: gold.adxDatabase,
        createdAt: gold.createdAt,
    };
}

// ----------------------------------------------------------------------------
// 3. Engine adapter
//
// Resolves an object of the form:
//     { run(kqlString) -> Promise<{ columns: string[], rows: any[][], elapsedMs: number }> }
//
// In production this is /kql/engine-v2/index.js (the new ported interpreter).
// While porting, engine-v2 falls back internally to the v1 engine for
// operators it hasn't implemented yet.
// ----------------------------------------------------------------------------

async function resolveEngine() {
    // engine-v2 module sets window.KqlEngineV2 on load.
    let attempts = 0;
    while (!window.KqlEngineV2 && attempts < 50) {
        await new Promise(r => setTimeout(r, 100));
        attempts++;
    }
    if (!window.KqlEngineV2) {
        throw new Error('KQL engine failed to initialize (window.KqlEngineV2 missing).');
    }
    await window.KqlEngineV2.ready();
    return window.KqlEngineV2;
}

// ----------------------------------------------------------------------------
// 4. Result comparison + grading
// ----------------------------------------------------------------------------

function normalizeCell(v) {
    if (v === null || v === undefined) return '';
    if (v instanceof Date) return v.toISOString().replace(/\.\d+Z$/, 'Z').replace(/\.\d+$/, '');
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (Array.isArray(v) || (typeof v === 'object')) {
        try { return JSON.stringify(v); } catch { return String(v); }
    }
    const s = String(v);
    // ISO datetime → second precision
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$/.test(s)) {
        try {
            const d = new Date(s);
            return d.toISOString().replace(/\.\d+Z$/, 'Z');
        } catch {}
    }
    return s;
}

function rowSignature(row) {
    return row.map(normalizeCell).join('');
}

function compareResults(userResult, goldRecord) {
    const userCols = userResult.columns || [];
    const userRows = userResult.rows    || [];
    const goldCols = (goldRecord.columns || []).map(c => c.name || c);
    const goldRows = goldRecord.rows || [];

    const sharedCols = goldCols.filter(c => userCols.includes(c));
    const userIdx = new Map(userCols.map((c, i) => [c, i]));
    const goldIdx = new Map(goldCols.map((c, i) => [c, i]));

    const missingFromUser = goldCols.filter(c => !userCols.includes(c));

    // Column shape
    const colsMatch = missingFromUser.length === 0 && sharedCols.length === goldCols.length;

    // Row count
    const rowCountMatch = userRows.length === goldRows.length;

    // Row content over shared cols
    const userSigs = new Set(
        userRows.map(r => rowSignature(sharedCols.map(c => r[userIdx.get(c)])))
    );
    const goldSigs = new Set(
        goldRows.map(r => rowSignature(sharedCols.map(c => r[goldIdx.get(c)])))
    );
    let rowsMatch = userSigs.size === goldSigs.size;
    if (rowsMatch) {
        for (const s of goldSigs) {
            if (!userSigs.has(s)) { rowsMatch = false; break; }
        }
    }
    // Tolerate empty-result schema gap (engine returns rows but no metadata)
    if (userRows.length === 0 && goldRows.length === 0) rowsMatch = true;

    return {
        colsMatch,
        rowCountMatch,
        rowsMatch,
        missingFromUser,
        userRowCount: userRows.length,
        goldRowCount: goldRows.length,
    };
}

function gradeRefinement(userKql, goldRecord) {
    const checks = [];
    const text = userKql.toLowerCase();

    // Encourage ago()/now() over absolute datetime literals when relevant
    const goldUsesAgo = /ago\(/.test(String(goldRecord.canonicalKql || ''));
    if (goldUsesAgo) {
        if (/ago\(/.test(text))      checks.push({ pass: true,  msg: 'Used ago() for time-relative filter' });
        else                          checks.push({ pass: false, msg: 'Canonical answer uses ago() for the time filter' });
    }

    // Discourage tolower(col) == "..."  (kills the index)
    if (/tolower\([^)]*\)\s*==/.test(text)) {
        checks.push({ pass: false, msg: 'Avoid tolower(col) == "..."  -- breaks index. Use =~ instead.' });
    }

    // Encourage =~ when canonical uses it
    if (/=~/.test(String(goldRecord.canonicalKql || ''))) {
        if (/=~/.test(userKql))      checks.push({ pass: true,  msg: 'Used =~ for case-insensitive match' });
        else                          checks.push({ pass: false, msg: 'Consider =~ for case-insensitive equality' });
    }

    // Encourage filter-before-project
    const tokens = userKql.split('|').map(s => s.trim().toLowerCase());
    const projectIdx = tokens.findIndex(t => t.startsWith('project '));
    const lastWhere  = tokens.lastIndexOf(tokens.find(t => t.startsWith('where ')));
    if (projectIdx >= 0 && lastWhere > projectIdx) {
        checks.push({ pass: false, msg: 'Filter before project for less work downstream' });
    }

    // Encourage top X by ... over `order by | take`
    if (goldRecord.ordered && /\btop\s+\d+/i.test(String(goldRecord.canonicalKql || ''))) {
        if (/\btop\s+\d+/i.test(userKql))   checks.push({ pass: true,  msg: 'Used top N (sorted + limited in one op)' });
        else if (/\border\s+by/i.test(text) && /\btake\s+\d+/i.test(text))
                                             checks.push({ pass: false, msg: '`top N by ...` is more efficient than order + take' });
    }

    // Score: pass / total, default 1.0 if no checks ran
    if (checks.length === 0) return { value: 1.0, checks: [{ pass: true, msg: 'No specific refinement checks for this question' }] };
    const passed = checks.filter(c => c.pass).length;
    return { value: passed / checks.length, checks };
}

function gradeSpeed(userMs, goldMs) {
    if (!goldMs || goldMs <= 0) return { value: 1.0, ratio: null };
    const ratio = userMs / goldMs;
    let value;
    if (ratio <= 1.0)      value = 1.0;
    else if (ratio >= 4.0) value = 0.0;
    else                   value = 1.0 - (ratio - 1.0) / 3.0;
    return { value, ratio };
}

function grade(userResult, userKql, goldRecord) {
    const cmp = compareResults(userResult, goldRecord);
    const correctness = cmp.colsMatch && cmp.rowCountMatch && cmp.rowsMatch ? 1.0 : 0.0;
    const refinement  = gradeRefinement(userKql, goldRecord);
    const speed       = gradeSpeed(userResult.elapsedMs, goldRecord.adxMs ?? 100);

    return {
        correctness,
        refinement,
        speed,
        cmp,
        total: correctness + refinement.value + speed.value,
    };
}

// ----------------------------------------------------------------------------
// 5. UI rendering
// ----------------------------------------------------------------------------

const $ = sel => document.querySelector(sel);

function statusFor(num) {
    const s = STATE.scores[String(num)];
    if (!s)                return 'pending';
    if (s.total >= 2.7)    return 'passed';
    if (s.total >= 1.5)    return 'partial';
    return 'failed';
}

function renderQuestionList() {
    const list = $('#q-list');
    list.innerHTML = '';
    let visible = 0;
    for (const q of STATE.questions) {
        const status = statusFor(q.number);
        const li = document.createElement('li');
        li.dataset.num = q.number;
        li.dataset.diff = q.difficulty;
        li.classList.toggle('is-active', q.number === STATE.activeNum);
        if (STATE.filter !== 'all' && q.difficulty !== STATE.filter) {
            li.classList.add('is-hidden');
        } else { visible++; }
        li.innerHTML = `
            <span class="q-num">${q.number}</span>
            <span class="q-title">${escapeHtml(q.title)}</span>
            <span class="q-status ${status}">${status === 'pending' ? '-' : statusBadge(status)}</span>
        `;
        li.addEventListener('click', () => selectQuestion(q.number));
        list.appendChild(li);
    }
    // Score summary
    const passedCount = STATE.questions.filter(q => statusFor(q.number) === 'passed').length;
    $('#score-summary').textContent = `${passedCount} / ${STATE.questions.length}`;
}

function statusBadge(s) {
    return s === 'passed' ? '✓' : s === 'partial' ? '~' : '✗';
}

function renderQuestionDetail() {
    const num = STATE.activeNum;
    const detail = $('#q-detail');
    if (!num) {
        detail.innerHTML = `<div class="placeholder">Pick a question on the left to begin.</div>`;
        return;
    }
    const q = STATE.questions.find(x => x.number === num);
    if (!q) return;
    detail.innerHTML = `
        <h2>${q.number}. ${escapeHtml(q.title)}</h2>
        <div class="q-meta">
            <span class="tag diff-${q.difficulty}">${q.difficulty}</span>
            <span class="tag">${q.type}</span>
            ${STATE.scores[String(num)] ? `<span class="tag" title="Submitted: ${STATE.scores[String(num)].submittedAt}">submitted &middot; ${STATE.scores[String(num)].total.toFixed(2)} / 3</span>` : ''}
        </div>
        <div class="prompt">${renderPrompt(q.prompt)}</div>
        ${q.sampleQuery ? `<pre class="sample-block">${escapeHtml(q.sampleQuery)}</pre>` : ''}
    `;
}

function renderPrompt(text) {
    // very lightweight markdown: wrap inline `code` in <code>, escape rest
    return escapeHtml(text || '').replace(/`([^`]+)`/g, '<code>$1</code>');
}

function renderEditor() {
    const num = STATE.activeNum;
    const editor = $('#editor');
    if (!num) { editor.value = ''; editor.disabled = true; return; }
    editor.disabled = false;
    const draft = STATE.drafts[String(num)];
    const q = STATE.questions.find(x => x.number === num);
    if (typeof draft === 'string') editor.value = draft;
    else editor.value = q && q.sampleQuery && q.type !== 'GEN' ? q.sampleQuery : '';
    // Re-show last results if any
    if (STATE.lastRun && STATE.lastRun.questionNum === num) {
        showResult(STATE.lastRun.result, STATE.lastRun.isSubmit);
    } else {
        renderEmptyResults();
    }
    // Disable submit if already submitted
    const submitted = !!STATE.scores[String(num)];
    $('#btn-submit').disabled = submitted;
    $('#btn-submit').title = submitted ? 'Already submitted (locked)' : 'Lock your final score for this question';
}

function renderEmptyResults() {
    $('#results-panel').innerHTML = `<div class="results-empty"><em>No run yet. Hit Test Run when you've got a query worth checking.</em></div>`;
}

function showResult(grade, isSubmit) {
    const cmp = grade.cmp;
    const axisCorr = grade.correctness === 1 ? 'is-perfect' : 'is-zero';
    const axisRef  = grade.refinement.value >= 0.99 ? 'is-perfect' : grade.refinement.value >= 0.5 ? 'is-partial' : 'is-zero';
    const axisSpd  = grade.speed.value      >= 0.99 ? 'is-perfect' : grade.speed.value      >= 0.5 ? 'is-partial' : 'is-zero';

    const notes = [];
    if (cmp.colsMatch) notes.push({ kind: 'good', msg: `Columns match (${cmp.userRowCount} rows)` });
    else notes.push({ kind: 'bad',  msg: `Columns differ. Missing: ${cmp.missingFromUser.join(', ') || '(none)'}` });
    if (cmp.rowCountMatch) notes.push({ kind: 'good', msg: `Row count matches (${cmp.goldRowCount})` });
    else notes.push({ kind: 'bad',  msg: `Row count: yours=${cmp.userRowCount}, gold=${cmp.goldRowCount}` });
    if (cmp.rowsMatch) notes.push({ kind: 'good', msg: 'Row content matches gold' });
    else notes.push({ kind: 'bad', msg: 'Row content differs from gold' });
    for (const c of grade.refinement.checks) {
        notes.push({ kind: c.pass ? 'good' : 'bad', msg: c.msg });
    }
    if (grade.speed.ratio) {
        notes.push({ kind: grade.speed.value >= 0.99 ? 'good' : grade.speed.value >= 0.5 ? 'info' : 'bad',
                     msg: `Your time is ${grade.speed.ratio.toFixed(2)}x the canonical (${(grade.speed.value*1).toFixed(2)} pts)` });
    }

    $('#results-panel').innerHTML = `
        <div class="score-card">
            <div class="score-axis ${axisCorr}">
                <div class="axis-label">Correctness</div>
                <div class="axis-value">${grade.correctness.toFixed(2)}</div>
                <div class="axis-detail">${cmp.rowsMatch ? 'Rows match gold' : 'Diff vs gold'}</div>
            </div>
            <div class="score-axis ${axisRef}">
                <div class="axis-label">Refinement</div>
                <div class="axis-value">${grade.refinement.value.toFixed(2)}</div>
                <div class="axis-detail">${grade.refinement.checks.filter(c=>c.pass).length}/${grade.refinement.checks.length} idioms</div>
            </div>
            <div class="score-axis ${axisSpd}">
                <div class="axis-label">Speed</div>
                <div class="axis-value">${grade.speed.value.toFixed(2)}</div>
                <div class="axis-detail">${grade.speed.ratio ? grade.speed.ratio.toFixed(2)+'x canonical' : 'no baseline'}</div>
            </div>
            <div class="score-total">
                <div class="total-label">Total</div>
                <div class="total-value">${grade.total.toFixed(2)}</div>
            </div>
        </div>
        <ul class="results-notes">
            ${notes.map(n => `<li class="note-${n.kind}">${escapeHtml(n.msg)}</li>`).join('')}
        </ul>
        ${isSubmit
            ? `<div class="submit-banner"><strong>Submitted.</strong> Score locked for this question.</div>`
            : `<div class="submit-banner">Test Run only. Hit <strong>Submit</strong> when you're ready to lock the score.</div>`
        }
    `;
}

function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
        '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
}

// ----------------------------------------------------------------------------
// 6. Selection / filter / draft handlers
// ----------------------------------------------------------------------------

function selectQuestion(num) {
    STATE.activeNum = num;
    STATE.lastRun = null;
    renderQuestionList();
    renderQuestionDetail();
    renderEditor();
    $('#editor-status').textContent = 'Ready.';
}

function setFilter(f) {
    STATE.filter = f;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('is-active', b.dataset.filter === f));
    renderQuestionList();
}

// ----------------------------------------------------------------------------
// 7. Run / Submit
// ----------------------------------------------------------------------------

async function runQuery(isSubmit) {
    const num = STATE.activeNum;
    if (!num) return;
    const editor = $('#editor');
    const userKql = editor.value.trim();
    if (!userKql) {
        $('#editor-status').textContent = 'Type a query first.';
        return;
    }

    if (isSubmit && STATE.scores[String(num)]) {
        $('#editor-status').textContent = 'Already submitted. Reset to a new question or Test Run only.';
        return;
    }

    persistDraft(num, userKql);
    $('#editor-status').textContent = isSubmit ? 'Submitting...' : 'Running...';
    $('#btn-run').disabled = true;
    $('#btn-submit').disabled = true;

    let result;
    try {
        result = await STATE.engine.run(userKql);
    } catch (e) {
        $('#editor-status').textContent = 'Error: ' + (e && e.message || e);
        $('#results-panel').innerHTML = `<div class="results-empty" style="color:var(--coral)">Engine error: ${escapeHtml(String(e && e.message || e))}</div>`;
        $('#btn-run').disabled = false;
        $('#btn-submit').disabled = !!STATE.scores[String(num)];
        return;
    }

    const goldRecord = STATE.gold[String(num)];
    if (!goldRecord) {
        $('#editor-status').textContent = `No gold result for Q${num}.`;
        $('#btn-run').disabled = false;
        $('#btn-submit').disabled = !!STATE.scores[String(num)];
        return;
    }

    const g = grade(result, userKql, goldRecord);
    STATE.lastRun = { questionNum: num, result: g, isSubmit };
    showResult(g, isSubmit);
    $('#editor-status').textContent = `${result.rows.length} rows, ${result.elapsedMs.toFixed(0)} ms`;
    $('#btn-run').disabled = false;

    if (isSubmit) {
        await persistScore(num, {
            number: num,
            correctness: g.correctness,
            refinement:  g.refinement.value,
            speed:       g.speed.value,
            total:       g.total,
            submittedAt: new Date().toISOString(),
        });
        renderQuestionList();
        $('#btn-submit').disabled = true;
    } else {
        $('#btn-submit').disabled = !!STATE.scores[String(num)];
    }
}

function resetEditor() {
    const num = STATE.activeNum;
    if (!num) return;
    const q = STATE.questions.find(x => x.number === num);
    const editor = $('#editor');
    editor.value = q && q.sampleQuery && q.type !== 'GEN' ? q.sampleQuery : '';
    persistDraft(num, editor.value);
    STATE.lastRun = null;
    renderEmptyResults();
    $('#editor-status').textContent = 'Reset.';
}

// ----------------------------------------------------------------------------
// 8. Init
// ----------------------------------------------------------------------------

async function init() {
    $('#editor-status').textContent = 'Loading questions and gold contract...';
    try {
        await Promise.all([loadAssets(), loadScoresFromDb(), loadDraftsFromDb()]);
    } catch (e) {
        $('#editor-status').textContent = 'Asset load failed: ' + (e.message || e);
        $('#q-list').innerHTML = `<li style="color:var(--coral); padding:0.5rem;">Failed to load questions: ${escapeHtml(e.message || String(e))}</li>`;
        return;
    }

    // Wire UI + render the question list immediately so the user can see and
    // navigate questions even if the engine takes a moment (or fails) to init.
    document.querySelectorAll('.filter-btn').forEach(b =>
        b.addEventListener('click', () => setFilter(b.dataset.filter)));
    $('#btn-run').addEventListener('click', () => runQuery(false));
    $('#btn-submit').addEventListener('click', () => {
        if (confirm('Submit this question? This locks your score for it.')) runQuery(true);
    });
    $('#btn-reset').addEventListener('click', resetEditor);
    $('#editor').addEventListener('input', e => {
        if (STATE.activeNum) persistDraft(STATE.activeNum, e.target.value);
    });

    renderQuestionList();
    renderQuestionDetail();
    renderEditor();
    if (!STATE.activeNum && STATE.questions.length) {
        selectQuestion(STATE.questions[0].number);
    }

    $('#editor-status').textContent = 'Initializing KQL engine...';
    $('#btn-run').disabled = true;
    $('#btn-submit').disabled = true;
    try {
        STATE.engine = await resolveEngine();
        // Pin the engine's now() to the gold contract's anchor so `ago(24h)`
        // resolves against the storyline window instead of the user's wall
        // clock. Without this, every ago()/now() query returns 0 rows.
        if (STATE.goldMeta && STATE.goldMeta.anchor && typeof STATE.engine.setAnchor === 'function') {
            STATE.engine.setAnchor(STATE.goldMeta.anchor);
        }
        $('#editor-status').textContent = 'Ready.';
        $('#btn-run').disabled = false;
        $('#btn-submit').disabled = !!(STATE.activeNum && STATE.scores[String(STATE.activeNum)]);
    } catch (e) {
        $('#editor-status').textContent = 'Engine init failed: ' + (e.message || e);
        // Leave the run buttons disabled but keep the question list usable so
        // the user can read prompts and at least review the curriculum.
    }
}

init();
