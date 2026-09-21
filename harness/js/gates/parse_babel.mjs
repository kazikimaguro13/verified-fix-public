// parse_babel.mjs -- the same API as parse.mjs, on @babel/parser instead of
// acorn + acorn-typescript.
//
// WHY (v96, decision 9, owner 2026-09-07): acorn-typescript rejects
// `satisfies`, `override` and angle-bracket casts (v95, 4 of 27 constructs).
// Since v92 an unparseable post image is COULD-NOT-RUN for check12 and an
// escalation for check6, so every legitimate patch written with `satisfies`
// would be refused until the parser reads it.  @babel/parser with the
// `typescript` and `estree` plugins produces the ESTree shape every gate walks
// (`Literal` with `value`, `TemplateLiteral.quasis[].value.cooked`,
// `FunctionDeclaration` / `VariableDeclarator` / `MethodDefinition` /
// `PropertyDefinition`, `loc.start.line`, `start` / `end`), so the callers do
// not change.  Differences that matter and how they are handled:
//   * Babel returns a `File` node wrapping `Program`; the generic walkers start
//     at whatever node they are given, so `File` is returned as-is (nothing in
//     the gates reads `tree.body` -- checked v96).
//   * Babel attaches comments to nodes (`leadingComments`, ...); the walkers
//     would visit those comment nodes harmlessly, but `attachComment: false`
//     keeps the tree identical in shape to acorn's.
//   * `errorRecovery` stays off: a parse failure must throw, exactly as before,
//     because the callers turn "could not parse" into a verdict of its own.
import { parse as babelParse } from "@babel/parser";
import fs from "node:fs";

// MEASURED (v96 reach probe, first pass): with only `typescript` + `estree`,
// Babel refuses decorators, `accessor` and JSX -- each needs its plugin.  JSX
// is enabled per file (.tsx / .jsx): inside a .ts file `<T>x` is a cast, and
// TypeScript itself does not allow JSX there.
const PLUGINS = ["typescript", "estree", "decorators", "decoratorAutoAccessors"];
const DEFAULTS = {
  sourceType: "module",
  attachComment: false,
  errorRecovery: false,
  ranges: false,
  tokens: false,
};

/** Parse source text.  Throws, like acorn.parse -- callers decide what a
 *  failure means, and they must not turn it into a finding.
 *  opts.jsx = true parses as TSX. */
export function parseSource(src, opts = {}) {
  const { ecmaVersion, locations, jsx, ...rest } = opts;   // acorn-only options are ignored
  // Return the Program, not Babel's File wrapper: acorn returns a Program and
  // diffgate iterates `tree.body` (MEASURED, v96 first pass: with the File root
  // check5 crashed -- "gate produced no parseable JSON" -- and the crash was
  // filed as a hard kill, so the control S28 came back rejected).
  return babelParse(src, { ...DEFAULTS, plugins: jsx ? [...PLUGINS, "jsx"] : PLUGINS, ...rest }).program;
}

/** Parse a file.  Returns {tree} or {error} -- never a bare false, because a
 *  parse failure and an absent thing are different claims (v17). */
export function parseFile(file, opts = {}) {
  let src;
  try {
    src = fs.readFileSync(file, "utf8");
  } catch (e) {
    return { error: `unreadable: ${e.message}` };
  }
  try {
    const jsx = /\.[jt]sx$/.test(String(file));
    return { tree: parseSource(src, { jsx, ...opts }), src };
  } catch (e) {
    return { error: `UNPARSEABLE: ${String(e.message).slice(0, 120)}`, src };
  }
}

/** Depth-first walk over an ESTree-shaped tree. */
export function walk(node, fn) {
  if (!node || typeof node !== "object") return;
  if (node.type) fn(node);
  for (const k of Object.keys(node)) {
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => walk(c, fn));
    else if (v && typeof v === "object" && v.type) walk(v, fn);
  }
}

/** Named function-like declarations, with their line span. */
export function functions(tree) {
  const out = [];
  walk(tree, (n) => {
    if (n.type === "FunctionDeclaration" && n.id) {
      out.push({ name: n.id.name, lo: n.loc?.start.line, hi: n.loc?.end.line });
    } else if ((n.type === "VariableDeclarator" || n.type === "MethodDefinition" ||
                n.type === "PropertyDefinition" || n.type === "Property") &&
               n.id && n.id.name) {
      out.push({ name: n.id.name, lo: n.loc?.start.line, hi: n.loc?.end.line });
    } else if (n.type === "MethodDefinition" && n.key && n.key.name) {
      out.push({ name: n.key.name, lo: n.loc?.start.line, hi: n.loc?.end.line });
    }
  });
  return out;
}
