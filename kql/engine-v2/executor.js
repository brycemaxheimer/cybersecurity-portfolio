/* ==========================================================================
 * KQL executor (v2) -- minimal scaffold.
 *
 * Walks the AST produced by parser.js and dispatches each Op to its handler.
 *
 * Public:
 *   execute(ast, env) -> { columns: string[], rows: any[][] }
 *
 * `env` is { db: <sql.js Database> } and additional context is added as
 * operators that need it land (Bindings, GroupRows for summarize, etc.).
 *
 * STUB: throws so the public api falls through to v1. As operators are
 * implemented, switch cases land here and they begin to handle real ASTs.
 * ========================================================================== */

import { evalScalar } from './functions.js';

export function execute(ast, env) {
    if (!ast || !ast.Body || !ast.allNative) {
        throw new Error('Native v2 path not yet supported for this AST. Falling back.');
    }
    return executeNode(ast.Body, env);
}

export function executeNode(node, env) {
    if (!node || !node.Op) throw new Error('Bad AST node');
    const handler = OPS[node.Op];
    if (!handler) throw new Error('Unsupported AST node ' + node.Op);
    return handler(node, env);
}

const OPS = {
    // Each op is a function (node, env) -> { columns, rows }.
    // As we port, fill these in. Mirrors the switch in Invoke-KqlPS.ps1's
    // Invoke-KqlAst function. Keys here line up with PS Op names so the
    // mental model is the same in both implementations.
    //
    // Already covered by v1 fallback while these are empty:
    //   TableRef, Where, Project, Extend, Summarize, Order, Take, Top,
    //   Distinct, Union, Join, Parse, MvExpand, GetSchema, Materialize, Let
};

// expose for unit tests if/when we add any
export const _internals = { OPS, evalScalar };
