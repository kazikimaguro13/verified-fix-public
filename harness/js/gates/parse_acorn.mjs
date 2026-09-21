// parse.mjs — the harness's one parser, shared by every gate that reads source.
//
// WHY THIS EXISTS
// ---------------
// v17 pointed the JS harness at a real client repository (Next.js + TypeScript)
// and freeze reported
//
//     anchors: { "src/lib/client-ip.ts:アンカー A（IP の解決）": false }
//     verify:  { "pass": true }
//
// The anchor was there.  `acorn` is a JavaScript parser and the file is
// TypeScript, so the parse threw, `anchorPresent` had `catch { return false; }`,
// and "nothing was read" became "the anchor is not there" -- a finding rather
// than a non-measurement.  Every gate that walks source had the same exposure,
// so the parser is now one function and it is TypeScript-aware.
//
// WHY acorn-typescript AND NOT TYPE-STRIPPING
// -------------------------------------------
// 検査4 drives StrykerJS with `--mutate file:startLine-endLine`, built from the
// patch's own line numbers (there is no `--since` in Stryker 10; measured in
// v0 of the JS port).  Anything that rewrites the source before parsing moves
// those numbers and silently mutates the wrong region.  acorn-typescript keeps
// the original positions -- verified against the real file: the node it reports
// at line 27 is the line that actually reads `export function アンカー A`.
//
// Plain JavaScript still parses through the extended parser, so the synthetic
// testbed is unaffected.

import * as acorn from "acorn";
import { tsPlugin } from "acorn-typescript";
import fs from "node:fs";

const TS = acorn.Parser.extend(tsPlugin());

const DEFAULTS = { ecmaVersion: "latest", sourceType: "module", locations: true };

/** Parse source text.  Throws, like acorn.parse -- callers decide what a
 *  failure means, and they must not turn it into a finding. */
export function parseSource(src, opts = {}) {
  return TS.parse(src, { ...DEFAULTS, ...opts });
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
    return { tree: parseSource(src, opts), src };
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
