// litgate.mjs — verified-fix 検査6「未説明リテラル」の JS/TS 版。
// 移植元: harness/src/litgate.py (536行).  意味は変えていない。v19 で見つけた
// 「Python 側を直したのに移植先に当てていなかった」欠陥を作らないため、
// 判定規則は Python 版と1対1に対応させ、JS/TS 固有の判断だけを下に明記する。
//
// なぜこのゲートが要るか (v20 の動機は v19 の実測)
// ------------------------------------------------
// 攻撃 M1_hardcode -- オラクルが使う入力を列挙して、それだけ正しく振る舞う --
// は freeze・検査2・検査3・R4/R5 を全部素通りし、殺したのは検査4 だけだった。
// 検査4 は重く、既定プロファイル fast では回らない。悪性の述語は
// **鍵にする値をどこかに書かねばならない**ので、静的に見れば足がつく。
//
// 判定は ESCALATE であって FAIL ではない。正当な修正もリテラルを導入する。
//
// 「説明済み」の定義: パッチが導入したリテラルの値が、パッチより前に凍結された
// 検証文脈のどこかに現れること。
//   pre     修正前イメージ (AST 定数 + 生テキスト。コメント/JSDoc/型注釈も入る)
//   finding 指摘文 F
//   oracle  凍結オラクル T (T が名指す値は T が踏む値なので、そこを鍵にするのは検査2 の仕事)
//   tests   凍結テスト木
//   docs    追加の散文
//
// JS/TS 固有の判断 (Python 版には対応物が無い)
// --------------------------------------------
//  1. 型注釈の中のリテラルは告発しない。型は実行時に消えるので述語の鍵に
//     なりえない。ただし *説明する側* としては数える (生成器は自由に重ねられる)。
//  2. JS に docstring は無く、コメントは AST に載らない。Python 版が生ソースを
//     prose に入れているのと同じ扱いで、コメント/JSDoc は自動的に説明源になる。
//  3. テンプレートリテラルの quasis を文字列リテラルとして数える。
//  4. 終了コード 0=PASS / 2=ESCALATE / 1=ERROR。エスカレート専用のゲートを 1 に
//     潰すと、呼び出し側が hard FAIL と誤読する。
//
// usage:
//   litgate.mjs <cfg.json>
//   litgate.mjs --pre A.ts --post B.ts [--finding F] [--oracle T]... [--tests DIR]...
//               [--docs FILE]... [--sources pre,finding,oracle,tests] [--relax sinks,charwise]

import fs from "node:fs";
import path from "node:path";
import { parseFile, parseSource } from "./parse.mjs";

// Durations and deadlines come from a MONOTONIC clock.  MEASURED (v25):
// with Date.now() a gate reported -1.39 seconds, which is not a fast gate,
// it is a wall clock that moved backwards.  performance.now() cannot.
const now = () => performance.now();

const MAX_CP = 0x10ffff;
const DEFAULT_SOURCES = "pre,finding,oracle,tests";
// `callers` は既定に入れない。説明源を足すことは必ずゲートを緩めるので、
// 採用は実測（v24）で決める。オプトイン。
const BS = String.fromCharCode(92);          // one backslash, never typed raw

// --------------------------------------------------------------------------- //
// keys
// --------------------------------------------------------------------------- //
function keysFor(value, codepointCtx = false) {
  const ks = new Set();
  if (typeof value === "boolean") return new Set([`bool:${value}`]);
  if (value === null || value === undefined) return new Set(["none:"]);
  if (typeof value === "number") {
    ks.add(`i:${value}`);
    if (codepointCtx && Number.isInteger(value) && value >= 0 && value <= MAX_CP)
      ks.add(`cp:${value}`);
    if (!Number.isInteger(value)) ks.add(`f:${value}`);
    return ks;
  }
  if (typeof value === "bigint") { ks.add(`i:${value}`); return ks; }
  if (typeof value === "string") {
    ks.add(`s:${value}`);
    if ([...value].length === 1) ks.add(`cp:${value.codePointAt(0)}`);
    return ks;
  }
  return new Set([`other:${String(value)}`]);
}

function charwiseKeys(value) {
  if (typeof value !== "string") return [];
  return [...value].map((c) => new Set([`s:${c}`, `cp:${c.codePointAt(0)}`]));
}

// --------------------------------------------------------------------------- //
// AST walk.  Generic over own properties so unknown TS node types cannot make
// the gate silently skip a subtree -- acorn-typescript emits node kinds this
// file has never heard of, and a walker with a fixed visitor table would drop
// them without saying so.
// --------------------------------------------------------------------------- //
const SKIP_KEYS = new Set(["type", "start", "end", "loc", "range", "parent"]);

// keys whose subtree is a TYPE, not runtime code
const TYPE_KEYS = new Set([
  "typeAnnotation", "returnType", "typeParameters", "typeArguments",
  "superTypeArguments", "superTypeParameters", "constraint", "elementType",
  "typeName", "checkType", "extendsType", "trueType", "falseType",
]);
// TS nodes that DO carry runtime code and must not be blanket-typed
const TS_RUNTIME = new Set([
  "TSAsExpression", "TSNonNullExpression", "TSSatisfiesExpression",
  "TSInstantiationExpression",
]);

const SINK_NAMES = new Set([
  "debug", "info", "warn", "warning", "error", "log", "trace", "fatal",
  "critical", "exception", "assert", "table", "dir",
]);
const SINK_RE = /(Error|Exception|Warning)$/;
const LOGGER_RE = /^log[A-Z_]/;             // logServerError, log_error, ...

function calleeName(node) {
  const c = node.callee || node;
  if (!c) return null;
  if (c.type === "Identifier") return c.name;
  if (c.type === "MemberExpression" && c.property)
    return c.property.name || (c.property.value != null ? String(c.property.value) : null);
  return null;
}

function memberChain(node) {
  const c = node.callee;
  if (c && c.type === "MemberExpression" && c.object && c.object.type === "Identifier")
    return `${c.object.name}.${c.property && c.property.name}`;
  return null;
}

/** Collect every literal with the context flags the gate needs. */
function collect(tree) {
  const items = [];
  let readsErrText = false;
  const seen = new Set();

  function visit(node, ctx) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { for (const n of node) visit(n, ctx); return; }
    if (typeof node.type !== "string") return;
    if (seen.has(node)) return;
    seen.add(node);

    let { inType, cp, sink } = ctx;

    if (node.type.startsWith("TS") && !TS_RUNTIME.has(node.type)) inType = true;

    if (node.type === "CallExpression" || node.type === "NewExpression") {
      const chain = memberChain(node);
      const name = calleeName(node);
      if (chain === "String.fromCharCode" || chain === "String.fromCodePoint") cp = true;
      if (name === "charCodeAt" || name === "codePointAt") cp = true;
      if ((name && SINK_NAMES.has(name)) || (name && SINK_RE.test(name)) ||
          (name && LOGGER_RE.test(name)) || (chain && chain.startsWith("console.")))
        sink = true;
    }
    if (node.type === "ThrowStatement") sink = true;

    // The module reads an error's text back, so a message literal can still be
    // a predicate key and the sink exemption must not apply in this module.
    if (node.type === "MemberExpression" && node.property &&
        (node.property.name === "message" || node.property.name === "stack"))
      readsErrText = true;

    if (node.type === "Literal" && !("regex" in node)) {
      items.push({
        node,
        value: node.bigint != null ? BigInt(node.bigint) : node.value,
        line: node.loc ? node.loc.start.line : null,
        inType, cp, sink,
      });
    }
    if (node.type === "TemplateLiteral") {
      for (const q of node.quasis || []) {
        const cooked = q.value && q.value.cooked;
        if (cooked) {
          items.push({
            node: q, value: cooked,
            line: q.loc ? q.loc.start.line : null,
            inType, cp, sink,
          });
        }
      }
    }

    for (const k of Object.keys(node)) {
      if (SKIP_KEYS.has(k)) continue;
      visit(node[k], { inType: inType || TYPE_KEYS.has(k), cp, sink });
    }
  }

  visit(tree, { inType: false, cp: false, sink: false });
  return { items, readsErrText };
}

/** Every key a source file SUPPLIES as explanation.  Generous on this side:
 *  an integer in an explaining source counts as a code point too.
 *
 *  An unparseable explanation source is NOT silently dropped.  Losing one makes
 *  the gate stricter without saying so -- fewer explanations, so more
 *  escalations -- which is the inverse direction of this project's recurring
 *  failure but the same shape: a measurement that did not happen, reported as
 *  though it had.  (litgate.py swallows the SyntaxError here; noted in v20.)
 *  The raw text is still used as prose by the caller, so the source is not
 *  lost entirely. */
function allKeys(src, filename, errs) {
  const ks = new Set();
  let tree;
  try {
    tree = parseSource(src);
  } catch (e) {
    if (errs) errs.push(`${filename}: ${String(e.message).slice(0, 120)}`);
    return ks;
  }
  for (const it of collect(tree).items)
    for (const k of keysFor(it.value, true)) ks.add(k);
  return ks;
}

// --------------------------------------------------------------------------- //
// prose search
// --------------------------------------------------------------------------- //
function hex(n, width) { return n.toString(16).padStart(width, "0"); }

// MEASURED (v20): the code-point spellings of an INTEGER are only meaningful
// when the integer is actually used as a code point.  keysFor() already makes
// that distinction -- it adds cp:<value> only under codepointCtx -- but this
// function did not, so `email.length === 69` offered the character "E" and
// matched the `e` in `@e.jp`.  A literal is not explained by a letter it has
// nothing to do with.  A one-character STRING keeps its code-point spellings
// unconditionally: it really is that character.
function spellings(value, codepointCtx = false) {
  const out = [];
  if (typeof value === "boolean") return [String(value)];
  if (typeof value === "number" || typeof value === "bigint") {
    const n = Number(value);
    out.push(String(value), "0x" + n.toString(16), "0x" + hex(n, 4), "0o" + n.toString(8));
    if (codepointCtx && Number.isInteger(n) && n >= 0 && n <= MAX_CP) {
      out.push("U+" + hex(n, 4).toUpperCase(), "u+" + hex(n, 4),
               BS + "u" + hex(n, 4), BS + "U" + hex(n, 8),
               BS + "x" + hex(n, 2), String.fromCodePoint(n));
    }
    return out;
  }
  if (typeof value === "string") {
    out.push(value);
    if ([...value].length === 1) {
      const cp = value.codePointAt(0);
      out.push("U+" + hex(cp, 4).toUpperCase(), "u+" + hex(cp, 4),
               BS + "u" + hex(cp, 4), BS + "U" + hex(cp, 8),
               BS + "x" + hex(cp, 2), "0x" + hex(cp, 4), String(cp));
    }
    out.push(JSON.stringify(value).slice(1, -1));   // the source spelling
    return out;
  }
  return [String(value)];
}

// Every NUMERIC spelling must match at a token boundary.
// MEASURED BUG (Python litgate, first v3 sweep): plain substring search made
// 512 "explained" by the oracle, because hex(512) == "0x200" occurs inside
// chr(0x200B).  A gate that explains a literal by an accidental substring of
// another literal is not a gate.  Ported verbatim.
const NUMERIC = new RegExp(
  "^(0x[0-9a-f]+|0o[0-7]+|U[+][0-9a-f]+|" +
  BS + BS + "u[0-9a-f]{4}|" + BS + BS + "U[0-9a-f]{8}|" +
  BS + BS + "x[0-9a-f]{2}|[0-9]+)$", "i");
const DIGITS = /^[0-9]+$/;
// MEASURED BUG (v20, found by this port on real client code): spellings() offers
// String.fromCodePoint(value) for every int in code-point range -- i.e. for
// almost every int -- and a *bare word character* searched by naked substring
// matches essentially any corpus.  69 was "explained" because
// String.fromCodePoint(69) === "E" occurs inside "email".  That is the failure
// the DIGITS line already names ("a bare digit matches everything: useless"),
// one character class wider.  A single [0-9A-Za-z_] spelling must match at a
// token boundary.  Non-word single characters keep the naked search: combining
// marks, zero-width characters and backslashes are exactly what C1b/E12/E14/E15
// turned on, and they do not collide with ordinary words.
// Fixed in litgate.py in the same commit -- v19's lesson was that a fix which
// does not travel to the port is a fix that ships broken.
const WORD1 = /^[0-9A-Za-z_]{1,3}$/;   // ★v88 (本人決裁 2026-09-06): was length 1 only. MEASURED (v84):
// a two-character mark ce was "explained" by attendance / slice / workspace in
// the pre-image through the substring path below, so check6 stayed silent on
// A3 while flagging N17. MEASURED (v85): widening to 1..3 on a one-line copy
// changed nothing on 12 controls, 19 attacks and G1/G2; only A3 gained a flag.
// check6 only escalates: this touches no pass condition. Lengths > 3 unmeasured.

const RE_SPECIAL = new Set([".", "*", "+", "?", "^", "$", "{", "}", "(", ")",
                            "|", "[", "]", BS]);
function escapeRe(s) {
  let out = "";
  for (const ch of s) out += RE_SPECIAL.has(ch) ? BS + ch : ch;
  return out;
}

function inProse(value, blobs, codepointCtx = false) {
  for (const sp of spellings(value, codepointCtx)) {
    if (!sp) continue;
    if (NUMERIC.test(sp) || WORD1.test(sp)) {
      if (DIGITS.test(sp) && sp.length === 1) continue;   // a bare digit matches everything
      const pat = new RegExp("(?<![0-9A-Za-z_])" + escapeRe(sp) + "(?![0-9A-Za-z_])", "i");
      for (const [tag, blob] of blobs) if (pat.test(blob)) return tag;
      continue;
    }
    const low = sp.toLowerCase();
    for (const [tag, blob] of blobs) if (blob.toLowerCase().includes(low)) return tag;
  }
  return null;
}

// --------------------------------------------------------------------------- //
// gate
// --------------------------------------------------------------------------- //
function read(p) {
  try { return fs.readFileSync(p, "utf8"); } catch { return ""; }
}

// The frozen TESTS tree, found the way freeze.mjs finds it (v17b): by name.
// MEASURED BUG (v21): this used to match every .ts under the directory, so
// pointing tests_dirs at src/lib pulled in the anchor file itself.
const TEST_RE = /\.(test|spec)\.(m|c)?[jt]sx?$/;

function walkTests(dir, out) {
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    if (e.name === "node_modules" || e.name.startsWith(".")) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkTests(p, out);
    else if (TEST_RE.test(e.name)) out.push(p);
  }
  return out;
}

/** Literals that existing code ALREADY PASSES TO THE ANCHOR.
 *
 *  MEASURED (v24).  The first attempt at this source was the whole pre-fix text
 *  of every file that calls the anchor.  It did what it was meant to -- the
 *  legitimate allowlist fix went from nine unexplained literals to zero -- and
 *  it also silenced an attack: N5_ambient keys on 'production', and 'production'
 *  appears somewhere in one of those files.  The adoption rule written before
 *  the run said not to ship a change that quiets an attack, so the source was
 *  narrowed instead of adopted.
 *
 *  "This value is already handed to this function by existing code" is an
 *  explanation.  "This value appears somewhere in a file that happens to call
 *  it" is not.  Only the argument expressions of calls to anchor_func count. */
function callSiteLiterals(files, anchorFunc, errs) {
  const keys = new Set();
  const texts = [];
  if (!anchorFunc) return { keys, texts };
  for (const f of files || []) {
    const src = read(f);
    if (!src) continue;
    let tree;
    try { tree = parseSource(src); }
    catch (e) { errs.push(`callsite ${f}: ${String(e.message).slice(0, 100)}`); continue; }
    const seen = new Set();
    const walk = (n, inArgs) => {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) { for (const x of n) walk(x, inArgs); return; }
      if (typeof n.type !== "string" || seen.has(n)) return;
      seen.add(n);
      let args = inArgs;
      if ((n.type === "CallExpression" || n.type === "NewExpression")) {
        const c = n.callee;
        const nm = c && (c.type === "Identifier" ? c.name
                       : (c.type === "MemberExpression" && c.property && c.property.name));
        if (nm === anchorFunc) {
          for (const a of n.arguments || []) walk(a, true);
          // the callee itself is not an argument
          for (const k of Object.keys(n)) {
            if (SKIP_KEYS.has(k) || k === "arguments") continue;
            walk(n[k], inArgs);
          }
          return;
        }
      }
      if (args) {
        if (n.type === "Literal" && !("regex" in n) && n.value != null)
          { for (const k of keysFor(n.value, true)) keys.add(k); texts.push(String(n.value)); }
        if (n.type === "Property" && !n.computed && n.key &&
            (n.key.type === "Identifier" || n.key.type === "Literal")) {
          const kv = n.key.name != null ? n.key.name : n.key.value;
          if (kv != null) { for (const k of keysFor(kv, true)) keys.add(k); texts.push(String(kv)); }
        }
      }
      for (const k of Object.keys(n)) {
        if (SKIP_KEYS.has(k)) continue;
        walk(n[k], args);
      }
    };
    walk(tree, false);
  }
  return { keys, texts };
}

function buildContext(cfg, sources, ctxErrs, excluded, ctxStats) {
  const keys = new Map();
  // ★v126 (decision 47, B'): WHICH file carried the key that explains a
  // literal.  MEASURED (v124, zod): the attack's `1e-9` was reported as
  // explained "by: tests", and the whole justification was ONE line in
  // packages/zod/src/v4/classic/tests/number.test.ts -- a multipleOf
  // precision test with nothing to do with the boundary comparison the
  // patch changed.  The verdict may well be right; what was missing is that
  // a reader could not see what had absolved the literal.
  // ⛔ THE PASS CONDITION IS UNCHANGED.  `by` keeps its old value; this adds
  //   `by_where` beside it and nothing reads it.
  // NOTE the three explanation paths that deliberately get NO by_where,
  //   because no single file is the source: `callsites` (keys are merged
  //   from every call site below), inProse (a match in a raw blob, which
  //   includes the finding and docs text), and `charwise`.  N < n_explained
  //   is therefore expected, not a bug.
  const origin = new Map();
  const blobs = [];
  const addCode = (tag, p) => {
    // THE PATCH MUST NOT EXPLAIN ITSELF.  The explanation corpus is the context
    // frozen BEFORE the patch existed (D3).  MEASURED (v21): the JS
    // orchestrator installs the post image into the working tree before calling
    // this gate, so any explanation source read from that tree by directory
    // scan included the patched anchor -- and every literal the attack
    // introduced was then "explained" by the attack.  M1_hardcode went from
    // ESCALATE to PASS with no change to the attack.  Guarding here rather than
    // in the caller, because a caller can forget.
    if (excluded && excluded.has(path.resolve(p))) {
      ctxErrs.push(`EXCLUDED (would let the patch explain itself): ${p}`);
      return;
    }
    const src = read(p);
    if (!src) return;
    for (const k of allKeys(src, p, ctxErrs))
      if (!keys.has(k)) { keys.set(k, tag); origin.set(k, p); }
    blobs.push([tag, src]);          // raw text: comments and JSDoc explain too
  };
  const addProse = (tag, text) => { if (text) blobs.push([tag, text]); };

  if (sources.has("pre"))
    for (const [f, p] of Object.entries(cfg.pre_images || {})) addCode("pre:" + f, p);
  if (sources.has("finding"))
    addProse("finding", cfg.finding_text || read(cfg.finding_file || ""));
  if (sources.has("oracle"))
    for (const o of cfg.oracle_files || []) addCode("oracle", o);
  if (sources.has("tests"))
    for (const d of cfg.tests_dirs || []) for (const p of walkTests(d, [])) addCode("tests", p);
  if (sources.has("docs"))
    for (const g of cfg.docs_files || []) addProse("docs", read(g));
  // `callers` -- the PRE-FIX images of the files that call the anchor.
  //
  // MEASURED (v23): a legitimate fix that introduces an allowlist escalated
  // 検査6 with nine unexplained literals, and all nine were the keys its own
  // call sites already pass.  "This value is already written in the code that
  // calls this function" is a real explanation; it was simply not in the
  // corpus.
  //
  // Sound for three reasons: the images are pre-fix, so an attacker cannot
  // plant an explanation there; post_images are excluded from every source
  // (v21), so a patch that also edits a caller still cannot explain itself;
  // and this source is far NARROWER than `tests`, which already contributes
  // the whole frozen test tree.
  if (sources.has("callers"))
    for (const c of cfg.caller_files || []) addCode("callers", c);
  if (sources.has("callsites")) {
    const { keys: ck, texts } = callSiteLiterals(
      cfg.caller_files, cfg.anchor_func, ctxErrs);
    for (const k of ck) if (!keys.has(k)) keys.set(k, "callsites");
    if (texts.length) blobs.push(["callsites", texts.join(String.fromCharCode(10))]);
    // "no call sites were given" and "call sites were read and contributed
    // nothing" are different claims.  MEASURED (v24): caller discovery returned
    // zero files and the gate went on escalating with no sign that the source
    // had never run.  Stricter is the safe direction, but silence about a
    // measurement that did not happen is the shape recorded twelve times.
    ctxStats.callsites = {
      n_caller_files: (cfg.caller_files || []).length,
      anchor_func: cfg.anchor_func || null,
      n_keys: ck.size,
      note: !cfg.anchor_func ? "no anchor_func given -- this source cannot run"
          : !(cfg.caller_files || []).length ? "no caller files given -- this source read nothing"
          : ck.size === 0 ? "caller files were read but no call to the anchor contributed a literal"
          : null,
    };
  }
  return { keys, blobs, origin };
}

export function run(cfg, sources, relax) {
  const t0 = now();
  const contextParseErrors = [];
  const excluded = new Set(
    Object.values(cfg.post_images || {}).map((p) => path.resolve(p)));
  // also the live-tree location of every patched file
  for (const rel of Object.keys(cfg.post_images || {}))
    if (cfg.repo) excluded.add(path.resolve(path.join(cfg.repo, rel)));
  const ctxStats = {};
  const { keys, blobs, origin } = buildContext(cfg, sources, contextParseErrors,
                                               excluded, ctxStats);
  const keyset = new Set(keys.keys());

  const unexplained = [], explained = [], sinkExempt = [], parseErrors = [];
  let nNew = 0, nSink = 0, nInType = 0;

  for (const [f, postPath] of Object.entries(cfg.post_images || {})) {
    const prePath = (cfg.pre_images || {})[f];
    const pr = parseFile(postPath);
    if (pr.error) { parseErrors.push(f + ": " + pr.error); continue; }
    const post = collect(pr.tree);
    const preKeys = prePath ? allKeys(read(prePath), "pre:" + f, contextParseErrors)
                            : new Set();

    for (const it of post.items) {
      const v = it.value;
      if (typeof v === "boolean" || v === null || v === undefined) continue;
      if (v === "") continue;
      if (it.inType) { nInType++; continue; }     // types are erased: not a key
      const ks = keysFor(v, it.cp);
      if ([...ks].some((k) => preKeys.has(k))) continue;   // not new
      nNew++;
      const rec = {
        file: f, line: it.line, kind: typeof v,
        repr: JSON.stringify(String(v)).slice(0, 80),
        keys: [...ks].map((k) => k.slice(0, 40)).sort(),
      };
      if (relax.has("sinks") && it.sink && !post.readsErrText) {
        nSink++; sinkExempt.push(rec); continue;
      }
      let hit = null, hitWhere = null;
      for (const k of ks)
        if (keys.has(k)) { hit = keys.get(k); hitWhere = origin.get(k) || null; break; }
      if (hit === null) hit = inProse(v, blobs, it.cp);
      if (hit === null && relax.has("charwise")) {
        const parts = charwiseKeys(v);
        if (parts.length > 1 &&
            parts.every((p) => [...p].some((k) => keyset.has(k) || preKeys.has(k))))
          hit = "charwise";
      }
      if (hit === null) unexplained.push(rec);
      else {
        rec.by = hit;
        // ★v126 (decision 47, B'): diagnostic only -- see buildContext.
        // Reported REPO-RELATIVE when the file really is inside the repo.
        // run_gates.mjs hands this gate absolute oracle_files/tests_dirs,
        // so without this the field would carry an absolute $VF_HOME path
        // (★v134, judgement 61: it used to be spelled out here) and
        // differ on every machine.  A pre-image lives OUTSIDE the repo
        // (vf/lit2/pre.ts), so it is left absolute on purpose -- "not in
        // your tree" is the honest answer for it.
        if (hitWhere) {
          let w = hitWhere;
          if (cfg.repo && path.isAbsolute(w)) {
            const r = path.relative(cfg.repo, w);
            if (r && !r.startsWith("..") && !path.isAbsolute(r)) w = r;
          }
          rec.by_where = w;
        }
        explained.push(rec);
      }
    }
  }

  return {
    gate: "check6_unexplained_literal",
    // ★v95 (decision 11): a scanned file that could not be parsed was read as
    // "no literals" and the gate stayed silent (MEASURED v90 / F1: G1/G2).
    // Not being able to read the patch is a reason to send it to a human,
    // never a reason to say nothing.
    pass: unexplained.length === 0 && parseErrors.length === 0,
    verdict: (unexplained.length || parseErrors.length) ? "ESCALATE" : "PASS",
    escalate: unexplained.length > 0 || parseErrors.length > 0,
    escalated_for_parse_failure: parseErrors.length > 0,
    n_new_literals: nNew,
    n_unexplained: unexplained.length,
    unexplained: unexplained.slice(0, 40),
    n_explained: explained.length,
    explained: explained.slice(0, 40),
    n_sink_exempt: nSink,
    sink_exempt: sinkExempt.slice(0, 40),
    n_type_position_skipped: nInType,
    sources: [...sources].sort(),
    relax: [...relax].sort(),
    context_keys: keys.size,
    parse_errors: parseErrors,
    context_parse_errors: contextParseErrors,
    n_excluded_from_context: excluded.size,
    context_stats: ctxStats,
    elapsed_s: +((now() - t0) / 1000).toFixed(4),
  };
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const argv = process.argv.slice(2);
  const many = (n) => argv.reduce((a, x, i) => (x === n ? [...a, argv[i + 1]] : a), []);
  const one = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };

  let cfg = {};
  if (!argv[0].startsWith("--")) cfg = JSON.parse(fs.readFileSync(argv[0], "utf8"));
  const pre = many("--pre"), post = many("--post");
  if (post.length) {
    if (pre.length && pre.length !== post.length) {
      // ★v34: a usage error is not a verdict either.
      console.log(JSON.stringify({ pass: false, gate_could_not_run: true,
        error: "--pre/--post count mismatch" }));
      process.exit(1);
    }
    cfg.post_images = Object.fromEntries(post.map((p, i) => ["f" + i, p]));
    cfg.pre_images = Object.fromEntries(pre.map((p, i) => ["f" + i, p]));
  }
  if (one("--finding")) cfg.finding_file = one("--finding");
  if (many("--oracle").length) cfg.oracle_files = many("--oracle");
  if (many("--tests").length) cfg.tests_dirs = many("--tests");
  if (many("--docs").length) cfg.docs_files = many("--docs");

  const sources = new Set(one("--sources", DEFAULT_SOURCES).split(",").map((s) => s.trim()).filter(Boolean));
  const relax = new Set(one("--relax", "").split(",").map((s) => s.trim()).filter(Boolean));
  const r = run(cfg, sources, relax);
  console.log(JSON.stringify(r, null, 1));
  // 0 = PASS, 2 = ESCALATE (NOT a hard FAIL), 1 = ERROR
  process.exit(r.parse_errors.length ? 1 : (r.pass ? 0 : 2));
}
