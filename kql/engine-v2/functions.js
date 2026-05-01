/* ==========================================================================
 * KQL built-in functions (v2) -- scalar + aggregate
 *
 * Mirrors the Invoke-KqlFunction switch in Invoke-KqlPS.ps1.
 *
 * Scalar functions: take args, return value.
 * Aggregates: detect group context via env.groupRows.
 *
 * STUB: only a few primitives ported here for the lexer/parser smoke test.
 * The rest land as their corresponding parser branches go native.
 * ========================================================================== */

// ----------------------------------------------------------------------------
// has-term-match: the operator that started the whole exercise.
//
// KQL `has` matches a whole TERM, where a term is a maximal run of
// alphanumeric/underscore chars. Anything else is a separator.
//
// `'powershell' has 'shell'`  -> false   (shell is embedded, not a separate term)
// `'the shell ran' has 'shell'` -> true
// ----------------------------------------------------------------------------

export function hasTerm(source, term, caseInsensitive = true) {
    if (source == null || term == null || source === '' || term === '') return false;
    const flags = caseInsensitive ? 'i' : '';
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(^|[^A-Za-z0-9_])${escaped}($|[^A-Za-z0-9_])`, flags);
    return re.test(source);
}

// ----------------------------------------------------------------------------
// String operators KQL exposes. Stubs that take operands and return bool/result.
// ----------------------------------------------------------------------------

export function strContains(haystack, needle, caseInsensitive = true) {
    if (haystack == null || needle == null) return false;
    if (caseInsensitive) {
        return String(haystack).toLowerCase().includes(String(needle).toLowerCase());
    }
    return String(haystack).includes(String(needle));
}
export function strStartsWith(haystack, needle, caseInsensitive = true) {
    if (haystack == null || needle == null) return false;
    const a = caseInsensitive ? String(haystack).toLowerCase() : String(haystack);
    const b = caseInsensitive ? String(needle  ).toLowerCase() : String(needle);
    return a.startsWith(b);
}
export function strEndsWith(haystack, needle, caseInsensitive = true) {
    if (haystack == null || needle == null) return false;
    const a = caseInsensitive ? String(haystack).toLowerCase() : String(haystack);
    const b = caseInsensitive ? String(needle  ).toLowerCase() : String(needle);
    return a.endsWith(b);
}

// ----------------------------------------------------------------------------
// Time helpers for ago()/now()/datetime() literals once they're parser-native.
// ----------------------------------------------------------------------------

export function makeNow(referenceIso) {
    return referenceIso ? new Date(referenceIso) : new Date();
}

export function ago(spec, referenceIso) {
    const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$/.exec(String(spec).trim());
    if (!m) throw new Error(`Bad ago() spec: ${spec}`);
    const n = parseFloat(m[1]);
    const unit = m[2];
    const seconds = unit === 'ms' ? n / 1000 : unit === 's' ? n : unit === 'm' ? n * 60 : unit === 'h' ? n * 3600 : n * 86400;
    const ref = makeNow(referenceIso);
    return new Date(ref.getTime() - seconds * 1000);
}

// ----------------------------------------------------------------------------
// Scalar dispatcher (parser will route function-call AST nodes here)
// ----------------------------------------------------------------------------

export function evalScalar(name, args, env) {
    const lower = name.toLowerCase();
    switch (lower) {
        case 'now':         return makeNow(env && env.referenceTime);
        case 'ago':         return ago(args[0], env && env.referenceTime);
        case 'tolower':     return args[0] == null ? null : String(args[0]).toLowerCase();
        case 'toupper':     return args[0] == null ? null : String(args[0]).toUpperCase();
        case 'isempty':     return args[0] == null || args[0] === '';
        case 'isnotempty':  return args[0] != null && args[0] !== '';
        case 'strlen':      return args[0] == null ? 0 : String(args[0]).length;
        case 'tostring':    return args[0] == null ? '' : String(args[0]);
        case 'tolong':
        case 'toint':       return args[0] == null ? 0 : parseInt(args[0], 10);
        case 'todouble':
        case 'toreal':      return args[0] == null ? 0 : parseFloat(args[0]);
        case 'tobool':      return args[0] === true || args[0] === 'true' || args[0] === 1 || args[0] === '1';
        // Many more to port: parse_json, extract, split, strcat, format_datetime,
        // bin, startofday, endofday, dcount, make_set, make_list, count, countif,
        // sum, min, max, avg, arg_max, arg_min, ...
        default:
            throw new Error(`Function not yet implemented in v2: ${name}`);
    }
}
