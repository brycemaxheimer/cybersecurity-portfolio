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

// Canonicalize a JS value to a stable JSON string (sorted keys, no whitespace)
// so 'true'/'false' vs 1/0, '{"a":1}' vs '{"a": 1}', and similar PS-vs-JS
// serialization quirks compare equal.
function _canonJson(v) {
    if (v == null) return 'null';
    if (typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(_canonJson).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + _canonJson(v[k])).join(',') + '}';
}

// Normalize a single cell to a comparable string form. Mirrors the test
// harness's normCell in kql/test-harness/run-gold-tests.cjs so the browser
// grades the same way the harness does.
function normalizeCell(v) {
    if (v == null) return '';
    if (v instanceof Date) return v.toISOString().replace(/\.\d+Z$/, 'Z');
    if (typeof v === 'number') {
        if (!Number.isFinite(v)) return '';
        return String(v);
    }
    if (typeof v === 'boolean') return v ? '1' : '0';
    if (typeof v === 'object') {
        // Unwrap PS 5.1's `{value: [...], Count: N}` array envelope
        if (Array.isArray(v.value) && 'Count' in v) return _canonJson(v.value);
        return _canonJson(v);
    }
    let s = String(v);
    // JSON-shaped strings -> canonical JSON so PS-vs-JS spacing compares equal
    if (/^[\[{]/.test(s.trim())) {
        try { return _canonJson(JSON.parse(s)); } catch (_) { /* fall through */ }
    }
    // Bool serialization: PS gold has "true"/"false" strings while v1 stores 0/1.
    if (s === 'true')  return '1';
    if (s === 'false') return '0';
    if (/^-?\d+$/.test(s)) return s;
    // ISO datetime -> second precision
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$/.test(s)) {
        try {
            const d = new Date(s);
            return d.toISOString().replace(/\.\d+Z$/, 'Z');
        } catch (_) {}
    }
    return s;
}

function rowSignature(row) {
    return row.map(normalizeCell).join('\u001f');
}

// PowerShell 5.1 ConvertTo-Json wraps nested arrays as
// `{value: [...], Count: N}` envelopes. The gold file goes through that
// pipeline, so most rows look like
//     { "value": ["2026-04-29T...","SVR-WEB-01",...], "Count": 4 }
// Detect and unwrap.
function _unwrapRow(r) {
    if (r && !Array.isArray(r) && Array.isArray(r.value) && (typeof r.Count === 'number' || 'Count' in r)) {
        return r.value;
    }
    return r;
}

function compareResults(userResult, goldRecord) {
    const userCols = userResult.columns || [];
    const userRows = userResult.rows    || [];
    const goldCols = (goldRecord.columns || []).map(c => c.name || c);

    // PS sometimes emits a single row as a flat array (rowCount=1, rows=[c1,c2,c3])
    // instead of [[c1,c2,c3]]. Detect and re-wrap.
    let goldRows = goldRecord.rows || [];
    if (goldRecord.rowCount === 1
            && goldRows.length === goldCols.length
            && !Array.isArray(goldRows[0])) {
        goldRows = [goldRows];
    }
    goldRows = goldRows.map(_unwrapRow);

    const userIdx = new Map(userCols.map((c, i) => [c, i]));
    const missingFromUser = goldCols.filter(c => !userCols.includes(c));
    const colsMatch = missingFromUser.length === 0;
    const rowCountMatch = userRows.length === goldRows.length;

    // Build column-name-keyed dicts for each row so column ORDER differences
    // (e.g. summarize arg_max(*, *) putting by-col first) don't matter.
    function userDict(row) {
        const d = {};
        for (const c of goldCols) {
            const i = userIdx.get(c);
            d[c] = i === undefined ? '__missing__' : normalizeCell(row[i]);
        }
        return d;
    }
    function goldDict(row) {
        const d = {};
        goldCols.forEach((c, i) => { d[c] = normalizeCell(row[i]); });
        return d;
    }
    function dictKey(d) {
        return JSON.stringify(Object.keys(d).sort().map(k => [k, d[k]]));
    }

    const userKeys = userRows.map(r => dictKey(userDict(r))).sort();
    const goldKeys = goldRows.map(r => dictKey(goldDict(r))).sort();

    let rowsMatch = userKeys.length === goldKeys.length;
    if (rowsMatch) {
        for (let i = 0; i < userKeys.length; i++) {
            if (userKeys[i] !== goldKeys[i]) { rowsMatch = false; break; }
        }
    }
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

    // Encourage filter-before-project. Only check the MAIN pipeline so let-bound
    // sub-pipelines (which legitimately end with `| project ... ;`) don't trigger
    // a false positive. The main pipeline starts after the last `;` if any.
    const lastSemi = userKql.lastIndexOf(';');
    const mainKql = lastSemi >= 0 ? userKql.slice(lastSemi + 1) : userKql;
    const tokens = mainKql.split('|').map(s => s.trim().toLowerCase());
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
        userResult,    // {columns, rows, elapsedMs, rewrittenKql}
        goldRecord,    // gold contract entry {columns, rows, ordered, ...}
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

function renderResultTable(cols, rows, opts) {
    opts = opts || {};
    const cap = opts.cap == null ? 50 : opts.cap;
    const cls = opts.cls || '';
    if (!cols || !cols.length) {
        return '<div class="results-empty"><em>(no columns)</em></div>';
    }
    if (!rows || !rows.length) {
        return `<table class="results-table ${cls}"><thead><tr>${cols.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr></thead><tbody><tr><td colspan="${cols.length}" class="results-empty">no rows</td></tr></tbody></table>`;
    }
    const shown = rows.slice(0, cap);
    const headers = cols.map(c => `<th>${escapeHtml(c)}</th>`).join('');
    const body = shown.map(r => {
        const cells = cols.map((_, i) => {
            const v = r[i];
            const s = v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
            return `<td>${escapeHtml(s)}</td>`;
        }).join('');
        return `<tr>${cells}</tr>`;
    }).join('');
    const more = rows.length > cap
        ? `<tfoot><tr><td colspan="${cols.length}" class="results-more">+${rows.length - cap} more rows (showing first ${cap})</td></tr></tfoot>`
        : '';
    return `<table class="results-table ${cls}"><thead><tr>${headers}</tr></thead><tbody>${body}</tbody>${more}</table>`;
}

// Unwrap gold rows into bare positional arrays in the same shape v1 returns
// (PS 5.1 ConvertTo-Json wraps as {value, Count}). Mirrors _unwrapRow above.
function unwrapGoldRowsForRender(goldRecord) {
    let rows = goldRecord.rows || [];
    const cols = goldRecord.columns || [];
    if (goldRecord.rowCount === 1
            && rows.length === cols.length
            && rows.every(c => typeof c !== 'object' || c === null)) {
        rows = [rows];
    }
    return rows.map(_unwrapRow);
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
        <div class="results-tables">
            <div class="results-table-block">
                <div class="results-table-title">Your result <span class="results-table-meta">${grade.userResult.rows ? grade.userResult.rows.length : 0} rows &middot; ${(grade.userResult.elapsedMs || 0).toFixed(0)} ms</span></div>
                ${renderResultTable(grade.userResult.columns || [], grade.userResult.rows || [], { cls: 'is-user', cap: 50 })}
            </div>
            <div class="results-table-block">
                <div class="results-table-title">Expected (gold) <span class="results-table-meta">${grade.goldRecord.rowCount} rows</span></div>
                ${renderResultTable(
                    (grade.goldRecord.columns || []).map(c => c.name || c),
                    unwrapGoldRowsForRender(grade.goldRecord),
                    { cls: 'is-gold', cap: 50 }
                )}
            </div>
        </div>
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
