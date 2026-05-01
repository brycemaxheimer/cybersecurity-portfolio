/* ==========================================================================
 * KQL lexer (v2)
 *
 * Ports the lexer in Invoke-KqlPS.ps1 (the Get-KqlTokens path) to JavaScript.
 *
 * Token shape:
 *   { kind: 'KEYWORD' | 'IDENT' | 'NUMBER' | 'STRING' | 'OP' | 'LPAREN' |
 *           'RPAREN' | 'LBRACK' | 'RBRACK' | 'COMMA' | 'PIPE' | 'SEMI' |
 *           'ASSIGN' | 'DOT' | 'EOF',
 *     value: string, pos: number }
 *
 * Notes carried over from the PS port:
 *   - Multi-char operators sorted longest-first so '!endswith' beats 'endswith'.
 *   - Keyword set includes pipeline operators and word-form like 'mv-expand'.
 *   - Strings: single OR double quoted, with backslash escapes.
 *   - Numbers: integer + decimal; negative-sign handling deferred to parser.
 *   - Datetime literals like `datetime(2026-04-25)` are LEXED as
 *     KEYWORD 'datetime' + LPAREN + IDENT '2026-04-25' + RPAREN — the parser
 *     reassembles them. The harness rewrites time predicates to `todatetime('...')`
 *     form which lexes as a normal function call, so this works out.
 * ========================================================================== */

const KEYWORDS = new Set([
    'where','project','project-keep','project-rename','project-away',
    'extend','summarize','order','sort','by','asc','desc',
    'take','limit','top','distinct','union','join','kind','on',
    'let','parse','with','mv-expand','mv-apply','getschema','materialize',
    'render','between','and','or','not','true','false','null','dynamic',
    'matches','regex','in','print',
    'datetime','todatetime','timespan','now','ago','bin','startofday','endofday',
]);

// Multi-char operators sorted longest-first so '!endswith' is tried before 'endswith'.
const MULTI_OPS = [
    '!endswith_cs','!startswith_cs','!contains_cs',
    '!endswith','!startswith','!contains','!has',
    'endswith_cs','startswith_cs','contains_cs',
    'has_any','has_all','has_cs','hasprefix','hassuffix',
    '==','!=','<=','>=','<>','<','>','=~','!~',
    'has','contains','startswith','endswith','in~','!in',
];

const SINGLE = {
    '(':'LPAREN', ')':'RPAREN', '[':'LBRACK', ']':'RBRACK',
    ',':'COMMA', ';':'SEMI', '|':'PIPE', '.':'DOT',
};

export function tokenize(src) {
    const tokens = [];
    const n = src.length;
    let i = 0;

    while (i < n) {
        const c = src[i];

        // Whitespace
        if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }

        // Line comment: // ... \n
        if (c === '/' && src[i+1] === '/') {
            while (i < n && src[i] !== '\n') i++;
            continue;
        }

        // String: '...' or "...", with backslash escape
        if (c === '"' || c === "'") {
            const quote = c;
            const start = i;
            i++;
            let out = '';
            while (i < n && src[i] !== quote) {
                if (src[i] === '\\' && i + 1 < n) {
                    const e = src[i+1];
                    out += { 'n':'\n','t':'\t','r':'\r','\\':'\\','"':'"',"'":"'" }[e] ?? e;
                    i += 2;
                } else {
                    out += src[i++];
                }
            }
            if (i >= n) throw new Error(`Unterminated string starting at ${start}`);
            i++; // closing quote
            tokens.push({ kind: 'STRING', value: out, pos: start });
            continue;
        }

        // Number: 1, 1.5, .5
        if ((c >= '0' && c <= '9') || (c === '.' && src[i+1] >= '0' && src[i+1] <= '9')) {
            const start = i;
            while (i < n && /[0-9.]/.test(src[i])) i++;
            tokens.push({ kind: 'NUMBER', value: src.slice(start, i), pos: start });
            continue;
        }

        // Identifier / keyword: letter or underscore start, alnum/underscore/dash continue.
        // Dash is allowed inside (eg 'mv-expand'), but only after the first letter, and we
        // disallow trailing dash so it doesn't eat the binary minus.
        if (/[A-Za-z_]/.test(c)) {
            const start = i;
            i++;
            while (i < n && /[A-Za-z0-9_]/.test(src[i])) i++;
            // Allow internal hyphens in identifiers like mv-expand, project-away.
            // Look ahead: if next is `-` and the char after is a letter, we're still in an ident.
            while (i < n && src[i] === '-' && /[A-Za-z]/.test(src[i+1] || '')) {
                i++;
                while (i < n && /[A-Za-z0-9_]/.test(src[i])) i++;
            }
            const word = src.slice(start, i);
            const lower = word.toLowerCase();
            if (KEYWORDS.has(lower)) {
                tokens.push({ kind: 'KEYWORD', value: lower, pos: start });
            } else if (lower === 'and' || lower === 'or' || lower === 'not') {
                tokens.push({ kind: 'OP', value: lower, pos: start });
            } else {
                tokens.push({ kind: 'IDENT', value: word, pos: start });
            }
            continue;
        }

        // Multi-char operator
        let matched = null;
        for (const op of MULTI_OPS) {
            if (src.startsWith(op, i)) {
                // For word-shaped ops (has, contains, etc.) require a non-ident char on each side.
                if (/^[a-z]/.test(op)) {
                    const before = i === 0 ? '' : src[i-1];
                    const after  = src[i + op.length] || '';
                    if (/[A-Za-z0-9_]/.test(before) || /[A-Za-z0-9_]/.test(after)) continue;
                }
                matched = op; break;
            }
        }
        if (matched) {
            tokens.push({ kind: 'OP', value: matched, pos: i });
            i += matched.length;
            continue;
        }

        // = (assignment, distinct from == handled above)
        if (c === '=') {
            tokens.push({ kind: 'ASSIGN', value: '=', pos: i });
            i++; continue;
        }

        // Single-char punctuation
        if (SINGLE[c]) {
            tokens.push({ kind: SINGLE[c], value: c, pos: i });
            i++; continue;
        }

        // Arithmetic
        if (c === '+' || c === '-' || c === '*' || c === '/' || c === '%') {
            tokens.push({ kind: 'OP', value: c, pos: i });
            i++; continue;
        }

        throw new Error(`Unrecognized character '${c}' at position ${i}`);
    }
    tokens.push({ kind: 'EOF', value: '', pos: n });
    return tokens;
}
