// diffgate.mjs — 検査5 / トレーススコープ差分オラクル (DESIGN D2) の JS 版。
// Python 版 diffgate2.py の直移植。実測 0.12s / 偽陽性ゼロ を JS で再現できるかが焦点。
//
// 規則:
//   各入力 x について PRE 像を「アンカー関数にタッチフラグを仕込んだ状態」で実行し
//     touched=false → F の爆風圏外 → PRE と POST の出力一致が必須。乖離 = 即却下
//     touched=true  → 圏内 → 乖離は報告のみ（T と検査4 が守る）
//
// ★JS 固有の最重要知見（実測）:
//   Python は `setattr(mod, name, wrapped)` でモジュール属性を差し替えると
//   **モジュール内部からの呼び出しも捕捉できる**（内部呼び出しが呼び出し時に
//   モジュール globals を引くため）。
//   JS/ESM は輸出束縛が読み取り専用かつ内部呼び出しが**字句的に解決**されるので、
//   輸出をラップしても内部呼び出しは絶対に捕まらない。
//   → JS では「輸出ラップ」方式は原理的に不可。**ソース変換**が正解。
//     (mode=wrap はその事実を実証するためだけに残してある)

//
// ★v44: SECOND INPUT SOURCE (spec mode).
//   The TOKENS corpus below is a set of CCD path strings wired to two CCD
//   modules by name.  Against any other repository `registry[rel]` misses,
//   nothing is compared, and the gate correctly answers "inapplicable".  That
//   is the whole reason 検査5 sat unrun on 実クライアント（Next.js／TS の業務ポータル） -- NOT, as was once written, a
//   principled limit (HANDOFF §0-j-5).  When `cfg.spec` is present the corpus
//   comes from the anchor spec (v28) and the two images are driven through
//   vitest, which is the only thing in the box that resolves TypeScript and the
//   repository's own aliases.
//
//   ⚠ THE PASS CONDITION IS UNCHANGED, and it is narrower than it looks:
//   D2 makes ONE thing hard -- a divergence on an input whose PRE run never
//   entered the anchor.  Anchor-spec calls enter the anchor by construction, so
//   on that corpus the hard rule has nothing to range over.  A pass therefore
//   means "no out-of-scope divergence, no return-type divergence, no changed
//   function left undriven"; it is NOT a proof that behaviour is unchanged.
//   n_untouched is reported for exactly this reason (§0-c: a measurement that
//   examined nothing must say so).

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseSource } from "./parse.mjs";
import { loadSpec } from "./anchorspec.mjs";
import { driveDiff } from "./drive.mjs";

// ---------------- corpus (Python 版 TOKENS を移植) ----------------
const TOKENS = [
  "ccd", "ccd/", "ccd/guard.js", "ccd/guardPathmatch.js", "ccd_evil/x.js",
  "tests", "tests/", "tests/test_guard.js", "testsuite/x.js",
  "docs/spec_021.md", "docs/spec_021_leak.md", "docs", "doc",
  "scripts/launchers/a.sh", "scripts", "script",
  ".github/workflows/ci.yml", ".github", "package.json", "package",
  "ccd/*.js", "ccd/v?.js", "*.js", "**", "ccd/**",
  "a", "a/b", "a/b/c", "ab", "ab/c", "", "/", "//", "a//b",
  "x".repeat(40), "ccd" + String.fromCharCode(92) + "guard.js",
  "ccd/./guard.js", "ccd/../etc/passwd",
  // ---- ★JS 固有ハザードトークン（Python 版には存在しない。C1b-JS 実測で追加）----
  // プレーンオブジェクトをマップ/メモ/集合に使った実装は、これらのキーで
  // 継承値を「ヒット」と誤認して allowlist を素通りさせる。
  // T の property ジェネレータは構造上これらに到達できない（10万draw で0件を実測）
  // ので、**コーパス側で必ず持つ**のが JS 版の必須要件。
  "__proto__", "constructor", "prototype", "toString", "valueOf",
  "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
  "__defineGetter__", "__lookupGetter__",
  "then",                                   // thenable ハザード（await で化ける）
  String.fromCharCode(0),                   // NUL
  String.fromCharCode(0xd800),              // 孤立サロゲート（上位）
  String.fromCharCode(0xdfff),              // 孤立サロゲート（下位）
  "0", "1", "true", "false", "null", "undefined", "NaN",  // 型強制ハザード
];

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pathAllowedCorpus(seed = 20260820) {
  const rng = mulberry32(seed);
  const pick = (arr) => arr[Math.floor(rng() * arr.length)];
  const cases = [];
  for (const p of TOKENS) for (const a of TOKENS) cases.push([p, [a]]);
  for (let i = 0; i < 1200; i++) {
    const n = Math.floor(rng() * 4);
    cases.push([pick(TOKENS), Array.from({ length: n }, () => pick(TOKENS))]);
  }
  const ALPHA = "ab/*?[]._".split("");
  for (let i = 0; i < 400; i++) {
    const mk = (n) => Array.from({ length: n }, () => pick(ALPHA)).join("");
    cases.push([mk(Math.floor(rng() * 9)),
      Array.from({ length: Math.floor(rng() * 3) }, () => mk(Math.floor(rng() * 6)))]);
  }
  return cases;
}

export function exceptionCorpus() {
  const lens = [0, 1, 5, 50, 150, 199, 200, 201, 250, 500, 1000, 1999, 2000, 2001, 3000];
  const out = [];
  for (const n of lens) {
    out.push([Object.assign(new Error("m".repeat(n)), { name: "ValueError" })]);
    out.push([Object.assign(new Error("  " + "z".repeat(n) + "  "), { name: "RuntimeError" })]);
  }
  out.push([Object.assign(new Error("k".repeat(400)), { name: "KeyError" })]);
  return out;
}

function buildRegistry() {
  const pa = pathAllowedCorpus();
  return {
    "src/guardPathmatch.js": {
      isAllowed: [pa, (m, a) => m.isAllowed(a[0], a[1])],
      matchesAny: [pa, (m, a) => m.matchesAny(a[0], a[1])],
      normalizeAllowed: [pa.map(([, a]) => [a]), (m, a) => m.normalizeAllowed(a[0])],
    },
    "src/cliUtil.js": {
      summarizeException: [exceptionCorpus(), (m, a) => m.summarizeException(a[0])],
    },
  };
}

// ---------------- AST helpers ----------------
function parse(src) {
  // v17: one parser for the harness, and it reads TypeScript (see parse.mjs)
  return parseSource(src);
}

function topLevelFns(src) {
  const out = {};
  let tree;
  try { tree = parse(src); } catch { return out; }
  for (const n of tree.body) {
    let fn = null, name = null;
    if (n.type === "FunctionDeclaration") { fn = n; name = n.id && n.id.name; }
    else if (n.type === "ExportNamedDeclaration" && n.declaration) {
      const d = n.declaration;
      if (d.type === "FunctionDeclaration") { fn = d; name = d.id && d.id.name; }
      else if (d.type === "VariableDeclaration") {
        for (const v of d.declarations) {
          if (v.init && /Function|ArrowFunctionExpression/.test(v.init.type))
            out[v.id.name] = src.slice(v.start, v.end);
        }
      }
    } else if (n.type === "VariableDeclaration") {
      for (const v of n.declarations)
        if (v.init && /Function|ArrowFunctionExpression/.test(v.init.type))
          out[v.id.name] = src.slice(v.start, v.end);
    }
    if (fn && name) out[name] = src.slice(fn.start, fn.end);
  }
  return out;
}

export function changedFunctions(preSrc, postSrc) {
  const a = topLevelFns(preSrc), b = topLevelFns(postSrc);
  const names = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...names].filter((n) => a[n] !== b[n]);
}

export function oneHopCallers(postSrc, target) {
  let tree;
  try { tree = parse(postSrc); } catch { return new Set(); }
  const callers = new Set();
  const scan = (node, owner) => {
    if (!node || typeof node !== "object") return;
    if (node.type === "Identifier" && node.name === target && owner) callers.add(owner);
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (Array.isArray(v)) v.forEach((x) => scan(x, owner));
      else if (v && typeof v === "object" && v.type) scan(v, owner);
    }
  };
  for (const n of tree.body) {
    const d = n.type === "ExportNamedDeclaration" && n.declaration ? n.declaration : n;
    if (d.type === "FunctionDeclaration" && d.id) scan(d.body, d.id.name);
  }
  return callers;
}

// ---------------- 計装 (mode=transform): アンカー関数の本体先頭にタッチを注入 ----------------
export function instrumentAnchor(src, fnName) {
  const tree = parse(src);
  let bodyStart = null;
  const visit = (n) => {
    if (!n || typeof n !== "object") return;
    if (n.type === "FunctionDeclaration" && n.id && n.id.name === fnName) bodyStart = n.body.start;
    if (n.type === "VariableDeclarator" && n.id && n.id.name === fnName &&
        n.init && n.init.body && n.init.body.type === "BlockStatement")
      bodyStart = n.init.body.start;
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) v.forEach(visit);
      else if (v && typeof v === "object" && v.type) visit(v);
    }
  };
  visit(tree);
  if (bodyStart === null) return { src, ok: false };
  const inject = "globalThis.__VF_TOUCH.hit=true;";
  return { src: src.slice(0, bodyStart + 1) + inject + src.slice(bodyStart + 1), ok: true };
}

// --------------------------------------------------------------------------- //
// THE PASS CONDITION (D2).  ONE definition; both modes call it.
//
// v44 added SPEC MODE as a pure addition and left this expression duplicated,
// byte for byte, at two places in this file (HANDOFF §0-j-8).  §0-c's second
// lesson -- "when you fix a gate, apply the fix to the port as well" -- was
// learnt from a duplicate ACROSS languages: v13 fixed diffgate2.py's
// compared==0 hole, the JS port never got it, and it shipped on a client repo
// (v19).  A duplicate across two functions of one file drifts the same way.
//
// ⛔ The expression is unchanged, character for character.  Lifting it is
// not a change to what the gate decides; it is a change to how many places
// have to be kept in step, which is 1.
// --------------------------------------------------------------------------- //
function passCondition(outOfScope, typeDiv, uncovered) {
  return outOfScope.length === 0 && typeDiv.length === 0 && uncovered.length === 0;
}

// ---------------- 実行 ----------------
// 戻り値は「値」と「実行時型」を分けて記録する。
// ★JS 版で追加した規則（C1b-JS の実測から導出）:
//   正しい挙動修正は **値** を変えるが **型** は変えない。
//   in-scope（アンカーに触れた）であっても、typeof が pre と post で変わったら
//   それは挙動修正ではなく構造破壊なので却下する。
//   プロトタイプ汚染メモ化（boolean のはずが function/object を返す）は
//   この規則ひとつで、アンカー内部の攻撃であっても死ぬ。
function callSafe(fn, mod, args) {
  try {
    const v = fn(mod, args);
    return { t: v === null ? "null" : Array.isArray(v) ? "array" : typeof v,
             v: "ok:" + JSON.stringify(v) };
  } catch (e) {
    return { t: "throw:" + (e && e.name),
             v: "exc:" + (e && e.name) + ":" + String(e && e.message).slice(0, 60) };
  }
}

async function loadImage(absSrcPath, tmpDir, tag, anchorFn) {
  let src = fs.readFileSync(absSrcPath, "utf8");
  let instrumented = false;
  if (anchorFn) {
    const r = instrumentAnchor(src, anchorFn);
    src = r.src;
    instrumented = r.ok;
  }
  fs.mkdirSync(tmpDir, { recursive: true });
  const out = path.join(tmpDir, tag + ".mjs");
  fs.writeFileSync(out, src);
  const mod = await import(pathToFileURL(out).href + "?v=" + Date.now() + Math.random());
  return { mod, instrumented };
}

export async function runDiffgate(cfg) {
  const t0 = performance.now();
  globalThis.__VF_TOUCH = { hit: false };
  const registry = buildRegistry();
  const tmp = path.resolve(cfg.repo, ".vf/img");
  fs.rmSync(tmp, { recursive: true, force: true });

  const outOfScope = [], inScope = [], typeDiv = [];
  let compared = 0;
  const allChanged = {};

  for (const rel of cfg.changed) {
    const pre = cfg.pre_images[rel], post = cfg.post_images[rel];
    if (!pre || !post) continue;
    allChanged[rel] = changedFunctions(fs.readFileSync(pre, "utf8"), fs.readFileSync(post, "utf8"));
  }

  for (const rel of cfg.changed) {
    const funcs = registry[rel];
    if (!funcs) continue;
    const tag = rel.replace(/[^a-zA-Z0-9]/g, "_");
    const anchorHere = rel === cfg.anchor_file ? cfg.anchor_func : null;
    const { mod: preM, instrumented } = await loadImage(cfg.pre_images[rel], tmp, "pre_" + tag, anchorHere);
    const { mod: postM } = await loadImage(cfg.post_images[rel], tmp, "post_" + tag, null);
    if (anchorHere && !instrumented)
      // ★v34: could-not-run, not a rejection (the v29/v34 distinction).
      return { pass: false, gate_could_not_run: true,
               reason: `anchor ${cfg.anchor_file}:${cfg.anchor_func} not instrumentable` };

    for (const [fname, [corpus, caller]] of Object.entries(funcs)) {
      for (const args of corpus) {
        globalThis.__VF_TOUCH.hit = false;
        const a = callSafe(caller, preM, args);
        const touched = globalThis.__VF_TOUCH.hit;
        const b = callSafe(caller, postM, args);
        compared++;
        if (a.t !== b.t) {
          // 型が変わった = 圏内外を問わず却下
          typeDiv.push([rel, fname, JSON.stringify(args).slice(0, 80),
            a.t + " " + a.v, b.t + " " + b.v]);
        } else if (a.v !== b.v) {
          const rec = [rel, fname, JSON.stringify(args).slice(0, 80), a.v, b.v];
          (touched ? inScope : outOfScope).push(rec);
        }
      }
    }
  }

  // 変更されたのにコーパスで踏まれていない関数（=盲点）を検出
  const uncovered = [];
  for (const [rel, names] of Object.entries(allChanged)) {
    const postSrc = cfg.post_images[rel] ? fs.readFileSync(cfg.post_images[rel], "utf8") : "";
    const reg = registry[rel] || {};
    for (const name of names) {
      if (rel === cfg.anchor_file && name === cfg.anchor_func) continue;
      if (name in reg) continue;
      const callers = oneHopCallers(postSrc, name);
      if ([...callers].some((c) => c in reg)) continue;
      uncovered.push(rel + ":" + name);
    }
  }

  // MEASURED (v19, 実クライアント): comparing nothing left every list empty, so `ok` came
  // out true and the gate exited 0 having examined not one call.  v13 fixed
  // exactly this in diffgate2.py; the JS port never got the fix, and it went
  // out on a real client repo.  Zero comparisons is not a pass -- it means the
  // input generator does not fit this anchor (or the anchor returns nothing
  // observable, as with a Promise<void> whose whole effect is a call to an
  // injected dependency -- see SKILL 4-j: no gate observes world side effects).
  if (compared === 0) {
    return {
      compared_calls: 0,
      inapplicable: true,
      fail_reason:
        "compared 0 calls: the input generator produced nothing this anchor " +
        "accepts, or the anchor has no observable return value. A gate that " +
        "compares nothing must not report a pass.",
      changed_functions: allChanged,
      uncovered_changed_functions: uncovered,
      elapsed_s: +((performance.now() - t0) / 1000).toFixed(3),
      pass: false,
    };
  }

  const ok = passCondition(outOfScope, typeDiv, uncovered);
  return {
    compared_calls: compared,
    out_of_scope_divergences: outOfScope.length,
    out_of_scope_sample: outOfScope.slice(0, 8),
    return_type_divergences: typeDiv.length,
    return_type_sample: typeDiv.slice(0, 6),
    in_scope_divergences: inScope.length,
    in_scope_sample: inScope.slice(0, 4),
    uncovered_changed_functions: uncovered,
    changed_functions: allChanged,
    elapsed_s: +((performance.now() - t0) / 1000).toFixed(3),
    pass: ok,
  };
}

// --------------------------------------------------------------------------- //
// SPEC MODE (v44) -- the corpus comes from the anchor spec, the images are
// driven through vitest.  Everything that decides is shared with runDiffgate():
// the same shape() rule (inside the probe), the same three-way classification,
// the same pass condition.
// --------------------------------------------------------------------------- //
export async function runDiffgateFromSpec(cfg) {
  const t0 = performance.now();
  const spec = loadSpec(cfg.spec, cfg.spec_source || "inline");
  const raw = cfg.spec || {};
  // A NAME, not an expression (原則3).  Needed because an anchor may be
  // module-private: 実クライアントの fetchAccessToken is, and a probe can only import
  // what the module exports.
  const drivenExport = (raw.driver && raw.driver.export) || spec.anchorFunc;
  const calls = spec.calls().map(([id, args]) => ({ id, args }));
  const anchorFile = cfg.anchor_file || spec.anchorFile;
  const anchorFunc = cfg.anchor_func || spec.anchorFunc;
  const preImage = (cfg.pre_images || {})[anchorFile];

  const base = {
    mode: "spec",
    spec_source: cfg.spec_source || "inline",
    driven_export: drivenExport,
    anchor: anchorFile + ":" + anchorFunc,
    n_spec_calls: calls.length,
  };
  const stop = (extra) => ({
    ...base, ...extra,
    elapsed_s: +((performance.now() - t0) / 1000).toFixed(3),
    pass: false,
  });

  if (!preImage)
    return stop({ gate_could_not_run: true,
                  reason: `no pre image for ${anchorFile}` });
  if (calls.length === 0)
    return stop({ gate_could_not_run: true,
                  reason: "the spec has no `calls`; 検査5 needs concrete inputs "
                        + "and must not invent them" });

  // Touch flag: instrument the PRE image only, exactly as the registry path
  // does (D2 measures the blast radius on the UNPATCHED code).
  const preSrc = fs.readFileSync(preImage, "utf8");
  const inst = instrumentAnchor(preSrc, anchorFunc);
  if (!inst.ok)
    return stop({ gate_could_not_run: true,
                  reason: `anchor ${anchorFile}:${anchorFunc} not instrumentable` });
  const tmpDir = path.resolve(cfg.repo, ".vf/img");
  fs.mkdirSync(tmpDir, { recursive: true });
  const instPath = path.join(tmpDir, "pre_instrumented" + path.extname(anchorFile));
  fs.writeFileSync(instPath, inst.src, "utf8");

  const d = driveDiff(cfg.repo, anchorFile, calls, { preImage: instPath, drivenExport });
  if (!d.ok)
    return stop({ gate_could_not_run: true, reason: d.why,
                  stderr_tail: d.stderr_tail, stdout_tail: d.stdout_tail,
                  driver_s: d.secs });
  if ((d.missing_export || []).length)
    return stop({ gate_could_not_run: true,
                  reason: `image(s) ${d.missing_export.join("/")} do not export `
                        + `${drivenExport}; a probe can only call exports`,
                  exports_seen: d.exports_seen, driver_s: d.secs });

  // ---- classification: identical rule to runDiffgate() ------------------- //
  const outOfScope = [], inScope = [], typeDiv = [], emitDiv = [];
  let touched = 0;
  for (const p of d.pairs) {
    if (p.touched) touched++;
    if (p.pre.t !== p.post.t) {
      typeDiv.push([anchorFile, drivenExport, p.args_repr,
                    p.pre.t + " " + p.pre.v, p.post.t + " " + p.post.v]);
    } else if (p.pre.v !== p.post.v) {
      const rec = [anchorFile, drivenExport, p.args_repr, p.pre.v, p.post.v];
      (p.touched ? inScope : outOfScope).push(rec);
    }
    // REPORTED, NEVER JUDGED.  console output is not part of D2's rule, and
    // folding it in would silently widen the pass condition.  It is counted
    // because for a void anchor it is the only thing that moves at all.
    const a = (p.pre.emitted || []).join("\n"), b = (p.post.emitted || []).join("\n");
    if (a !== b) emitDiv.push([p.id, a.slice(0, 120), b.slice(0, 120)]);
  }

  // ---- undriven changed functions (the third hard condition) -------------- //
  const allChanged = {};
  const rels = cfg.changed || Object.keys(cfg.post_images || {});
  for (const rel of rels) {
    const pre = (cfg.pre_images || {})[rel], post = (cfg.post_images || {})[rel];
    if (!pre || !post) continue;
    allChanged[rel] = changedFunctions(fs.readFileSync(pre, "utf8"),
                                       fs.readFileSync(post, "utf8"));
  }
  const covered = new Set([drivenExport, anchorFunc]);
  const uncovered = [];
  for (const [rel, names] of Object.entries(allChanged)) {
    const postSrc = (cfg.post_images || {})[rel]
      ? fs.readFileSync(cfg.post_images[rel], "utf8") : "";
    for (const name of names) {
      if (covered.has(name)) continue;
      const callers = oneHopCallers(postSrc, name);
      if ([...callers].some((c) => covered.has(c))) continue;
      uncovered.push(rel + ":" + name);
    }
  }

  const compared = d.pairs.length;
  if (compared === 0)
    return stop({ inapplicable: true, compared_calls: 0,
                  fail_reason: "compared 0 calls.  A gate that compares nothing "
                             + "must not report a pass." });

  const untouched = compared - touched;
  const ok = passCondition(outOfScope, typeDiv, uncovered);
  return {
    ...base,
    compared_calls: compared,
    n_touched: touched,
    n_untouched: untouched,
    // §0-c.  The hard rule D2 states ranges over UNTOUCHED calls only.  Say out
    // loud when that set is empty instead of letting `pass: true` imply more
    // than was measured.
    blast_radius_note: untouched === 0
      ? "every driven call entered the anchor, so the out-of-scope rule -- the "
      + "only thing D2 makes hard -- ranged over ZERO calls.  This pass means "
      + "'no out-of-scope divergence, no return-type divergence, no undriven "
      + "changed function'.  It is NOT evidence that behaviour is unchanged; "
      + "in_scope_divergences below is the measurement that speaks to that, and "
      + "it is reported, not judged."
      : `${untouched} of ${compared} driven calls did not enter the anchor; the `
      + "out-of-scope rule ranged over those.",
    out_of_scope_divergences: outOfScope.length,
    out_of_scope_sample: outOfScope.slice(0, 8),
    return_type_divergences: typeDiv.length,
    return_type_sample: typeDiv.slice(0, 6),
    in_scope_divergences: inScope.length,
    in_scope_sample: inScope.slice(0, 6),
    emitted_divergences: emitDiv.length,
    emitted_sample: emitDiv.slice(0, 4),
    uncovered_changed_functions: uncovered,
    changed_functions: allChanged,
    driver_s: d.secs,
    elapsed_s: +((performance.now() - t0) / 1000).toFixed(3),
    pass: ok,
  };
}

if (process.argv[2]) {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const r = cfg.spec ? await runDiffgateFromSpec(cfg) : await runDiffgate(cfg);
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.pass ? 0 : 1);
}
