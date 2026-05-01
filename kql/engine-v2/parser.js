/* ==========================================================================
 * KQL parser (v2) -- minimal scaffold.
 *
 * Returns an AST of the form:
 *   { Op: 'Query', Bindings: [...], Body: <tabular>, allNative: bool }
 *
 * `allNative` flag tells the executor whether v2 can run this query end-to-end
 * (true) or whether the runtime should fall back to the v1 engine (false).
 * As operators land in executor.js, they flip their corresponding parser
 * branches to `allNative = true` and the fallback gradually fades.
 *
 * For now this is a STUB that always returns { allNative: false } so the
 * runtime always delegates to v1. The structure is here so that incremental
 * porting can land one operator at a time without changing the public API.
 * ========================================================================== */

export function parse(tokens) {
    // Quick rejection: empty / no tokens -> not native.
    if (!tokens || tokens.length === 0 || tokens[0].kind === 'EOF') {
        return { Op: 'Query', Bindings: [], Body: null, allNative: false };
    }

    // TODO: Real parser. Mirrors _ParseLet / _ParseTabular in Invoke-KqlPS.ps1.
    //
    // For each operator port:
    //   1. Recognize the keyword in _ParseOperator equivalent.
    //   2. Build the AST node.
    //   3. Set allNative=true only if every operator in the chain is native.
    //
    // The fallback path in index.js catches our `allNative=false` and routes
    // to v1, so partial coverage is safe to ship.

    return { Op: 'Query', Bindings: [], Body: null, allNative: false };
}
