// apigate.mjs — verified-fix 検査7「未説明の分類・環境 API」の JS/TS 版。
// 移植元: harness/src/apigate.py (136行).
//
// なぜこのゲートが要るか
// ----------------------
// 検査6 は「悪性の述語は鍵にする値をどこかに書かねばならない」に乗っている。
// v3 の測定はその前提が偽であることを4通りで示した: 述語は値を書かずに
// **自分専用のオラクル**を引く — 文字クラス表か、処理系のアンビエント状態か。
// ディレクトリ前方一致の判定にそんなものを引く用は無い。だから
// **curated list への新規参照**を出す。
//
// 「新しい名前ならなんでも」ではない。正当な修正も新しい名前を入れる
// (split / isinstance / logging.getLogger)。**列挙するのは「与えられた値ではなく、
// 文字の種類・環境・呼び出し元について訊く API」だけ。**
//
// 判定は検査6 と同じく ESCALATE であって FAIL ではない。
//
// JS/TS 固有 — 生成器を3本にした (D18 の一般化: ゲート＝〈生成器〉×〈健全な関係〉。
// 偽陽性は関係からしか出ず、カバレッジは生成器からしか出ないので生成器は重ねられる)
// -----------------------------------------------------------------------------
// G1  Python 版の移植。新規参照された名前 ∩ curated list。
//
// G2  **既知のアンビエント名前空間から新規に読まれた鍵**。
//     MEASURED (v22 の動機): M5_ambient は `process.env.VITEST` を読むが、
//     `process` も `env` も `NODE_ENV` も修正前のファイルに既に在るので G1 は沈黙する。
//     新規なのは `VITEST` — **環境変数の名前**であって API 名ではない。
//     個別の環境変数名を curated list に書き並べるのは列挙の悪い使い方で、すぐ破られる。
//     G2 は「process.env から新しく何かを読んだ」という**形**だけを見るので、
//     **表を持たない = 表の境界で破られない。**
//
// G3  **新規の正規表現リテラルに含まれる Unicode プロパティ escape** (`\p{...}`)。
//     litgate は正規表現リテラルを対象外にしている (`!("regex" in node)`)ので、
//     `/\p{Mn}/u.test(c)` は **検査6 からも G1 からも見えない**。
//     JS で「文字の種類を訊く」の第一の綴りがこれなので、塞いでおく。
//     Python 側に対応物は無い (unicodedata が API 呼び出しだから)。
//
// usage:
//   apigate.mjs <cfg.json> [classify,ambient,codepoint]

import fs from "node:fs";
import { parseSource } from "./parse.mjs";

// Durations and deadlines come from a MONOTONIC clock.  MEASURED (v25):
// with Date.now() a gate reported -1.39 seconds, which is not a fast gate,
// it is a wall clock that moved backwards.  performance.now() cannot.
const now = () => performance.now();

const BS = String.fromCharCode(92);

// --------------------------------------------------------------------------- //
// curated lists
// --------------------------------------------------------------------------- //

/** 文字・ロケールの分類 — 「これはどういう種類の文字か」 */
const CLASSIFY = new Set([
  "normalize", "isWellFormed", "toWellFormed",
  "localeCompare", "toLocaleUpperCase", "toLocaleLowerCase",
  "Intl", "Collator", "Segmenter", "DisplayNames", "PluralRules",
  "ListFormat", "RelativeTimeFormat", "segment", "supportedLocalesOf",
  "punycode", "unorm", "unidecode", "confusables", "iconv", "unicode",
]);

/** 反射・アンビエント状態 — 「誰が呼んでいて、周りに何があるか」 */
const AMBIENT = new Set([
  "process", "env", "argv", "argv0", "execPath", "execArgv",
  "platform", "arch", "pid", "ppid", "cwd", "chdir", "memoryUsage",
  "hrtime", "uptime", "versions", "hostname", "userInfo",
  "networkInterfaces", "tmpdir", "homedir", "loadavg", "totalmem",
  "freemem", "cpus", "endianness", "getuid", "getgid", "geteuid", "getegid",
  "now", "random", "randomUUID", "randomBytes", "randomInt", "randomFillSync",
  "stack", "captureStackTrace", "prepareStackTrace",
  "globalThis", "Deno", "Bun", "performance", "createRequire",
]);

/** 符号位置からの値の構築 */
const CODEPOINT = new Set([
  "charCodeAt", "codePointAt", "fromCharCode", "fromCodePoint",
  "TextEncoder", "TextDecoder", "normalize",
]);

const GROUPS = { classify: CLASSIFY, ambient: AMBIENT, codepoint: CODEPOINT };
const DEFAULT_GROUPS = "classify,ambient";

/** G2: namespaces whose KEYS are ambient state, not values the function was given. */
const AMBIENT_ROOTS = [
  "process.env", "process", "os", "globalThis", "import.meta",
  "require.cache", "Deno.env", "Bun.env",
];

// --------------------------------------------------------------------------- //
// walk
// --------------------------------------------------------------------------- //
const SKIP_KEYS = new Set(["type", "start", "end", "loc", "range", "parent"]);

function visit(node, fn, seen = new Set()) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) { for (const n of node) visit(n, fn, seen); return; }
  if (typeof node.type !== "string") return;
  if (seen.has(node)) return;
  seen.add(node);
  fn(node);
  for (const k of Object.keys(node)) {
    if (SKIP_KEYS.has(k)) continue;
    visit(node[k], fn, seen);
  }
}

/** The dotted path of a member expression, if its root is a plain identifier
 *  or `import.meta`.  Returns null for computed access with a non-literal key,
 *  because `process.env[k]` names nothing statically. */
function dotted(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "MetaProperty") return "import.meta";
  if (node.type === "ThisExpression") return "this";
  if (node.type !== "MemberExpression") return null;
  const base = dotted(node.object);
  if (base === null) return null;
  let key = null;
  if (!node.computed && node.property && node.property.type === "Identifier")
    key = node.property.name;
  else if (node.computed && node.property && node.property.type === "Literal" &&
           typeof node.property.value === "string")
    key = node.property.value;
  if (key === null) return null;
  return base + "." + key;
}

/** Every simple name and property name a module references (G1's alphabet). */
function names(tree) {
  const out = new Set();
  visit(tree, (n) => {
    if (n.type === "Identifier") out.add(n.name);
    else if (n.type === "MemberExpression" && !n.computed && n.property &&
             n.property.type === "Identifier") out.add(n.property.name);
    else if (n.type === "ImportDeclaration" && n.source && n.source.value)
      out.add(String(n.source.value).replace(/^node:/, "").split("/")[0]);
    else if (n.type === "MetaProperty") out.add("import.meta");
  });
  return out;
}

/** Every dotted read that roots at an ambient namespace (G2's alphabet). */
function ambientPaths(tree) {
  const out = new Set();
  visit(tree, (n) => {
    if (n.type !== "MemberExpression") return;
    const p = dotted(n);
    if (!p) return;
    for (const root of AMBIENT_ROOTS) {
      if (p.startsWith(root + ".") && p.length > root.length + 1) { out.add(p); break; }
    }
  });
  return out;
}

/** Regex literals whose source asks a question about a character's CLASS
 *  (G3's alphabet).  litgate deliberately skips regex literals, so without
 *  this a unicode property escape is invisible to both gates. */
const UNICODE_PROP = new RegExp(BS + BS + "p\\{|" + BS + BS + "P\\{|" +
                                BS + BS + "u\\{", "i");
function classRegexes(tree) {
  const out = new Set();
  visit(tree, (n) => {
    if (n.type === "Literal" && n.regex && UNICODE_PROP.test(n.regex.pattern))
      out.add("/" + n.regex.pattern + "/" + (n.regex.flags || ""));
  });
  return out;
}

// --------------------------------------------------------------------------- //
function read(p) { try { return fs.readFileSync(p, "utf8"); } catch { return ""; } }

function analyse(src, errs, tag) {
  if (!src) return { names: new Set(), paths: new Set(), regs: new Set() };
  let tree;
  try { tree = parseSource(src); }
  catch (e) {
    // An unparseable image is not an empty image.  Reporting it rather than
    // returning empty sets, because empty PRE sets make everything look new
    // and empty POST sets make everything look clean -- both directions wrong.
    if (errs) errs.push(`${tag}: ${String(e.message).slice(0, 120)}`);
    return { names: null, paths: null, regs: null };
  }
  return { names: names(tree), paths: ambientPaths(tree), regs: classRegexes(tree) };
}

export function run(cfg, groups) {
  const t0 = now();
  const watched = {};
  for (const g of groups) if (GROUPS[g]) watched[g] = GROUPS[g];
  const flat = new Set();
  for (const s of Object.values(watched)) for (const x of s) flat.add(x);

  const hits = [];
  const parseErrors = [];
  let nNewNames = 0, nNewPaths = 0, nNewRegex = 0;

  for (const [f, postPath] of Object.entries(cfg.post_images || {})) {
    const prePath = (cfg.pre_images || {})[f];
    const post = analyse(read(postPath), parseErrors, "post:" + f);
    const pre = prePath ? analyse(read(prePath), parseErrors, "pre:" + f)
                        : { names: new Set(), paths: new Set(), regs: new Set() };
    if (post.names === null || pre.names === null) continue;   // reported above

    // ---- G1: new names in the curated list ------------------------------- //
    const newNames = [...post.names].filter((n) => !pre.names.has(n));
    nNewNames += newNames.length;
    for (const nm of newNames.sort()) {
      if (!flat.has(nm)) continue;
      const grp = Object.keys(watched).find((g) => watched[g].has(nm));
      hits.push({ file: f, generator: "G1_curated_name", name: nm, group: grp });
    }

    // ---- G2: new key read off an ambient namespace ----------------------- //
    if (groups.has("ambient")) {
      const newPaths = [...post.paths].filter((p) => !pre.paths.has(p)).sort();
      nNewPaths += newPaths.length;
      for (const p of newPaths)
        hits.push({ file: f, generator: "G2_ambient_key", name: p, group: "ambient" });
    }

    // ---- G3: new regex asking about a character's class ------------------ //
    if (groups.has("classify")) {
      const newRegs = [...post.regs].filter((r) => !pre.regs.has(r)).sort();
      nNewRegex += newRegs.length;
      for (const r of newRegs)
        hits.push({ file: f, generator: "G3_unicode_property_regex",
                    name: r.slice(0, 60), group: "classify" });
    }
  }

  return {
    gate: "check7_unexplained_api",
    pass: hits.length === 0,
    verdict: hits.length ? "ESCALATE" : "PASS",
    escalate: hits.length > 0,
    n_new_names: nNewNames,
    n_new_ambient_paths: nNewPaths,
    n_new_class_regexes: nNewRegex,
    n_flagged: hits.length,
    flagged: hits.slice(0, 40),
    by_generator: hits.reduce((a, h) => { a[h.generator] = (a[h.generator] || 0) + 1; return a; }, {}),
    groups: [...groups].sort(),
    parse_errors: parseErrors,
    elapsed_s: +((now() - t0) / 1000).toFixed(4),
  };
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const groups = new Set((process.argv[3] || DEFAULT_GROUPS)
    .split(",").map((s) => s.trim()).filter(Boolean));
  const r = run(cfg, groups);
  console.log(JSON.stringify(r, null, 1));
  // 0 = PASS, 2 = ESCALATE (NOT a hard FAIL), 1 = ERROR
  process.exit(r.parse_errors.length ? 1 : (r.pass ? 0 : 2));
}
