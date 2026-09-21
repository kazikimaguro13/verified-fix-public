// ambgate.mjs — verified-fix 検査9「アンビエント不変性スイープ」の JS/TS 版。
// 移植元の考え方: harness/src/ambgate.py (663行)。**移植ではなく再設計**（下記2点）。
//
// これが答える問題
// ----------------
// 静的な列挙は境界で破られる。v22 でそれを9回目として実測した:
// `M7_ambient_zero_new` は **新規の名前ゼロ・新規のリテラルゼロ・新規のアンビエント鍵ゼロ**で
// 環境依存の分岐を作る（修正前のファイルが既に読んでいる環境変数を再利用する）。
// **検査6 も検査7 も原理的に見えない** — どちらも差分の上で働くので、
// 「既にそこに在るもの」には何も出せない。
//
// このゲートは「どのアンビエントが重要か」を訊かない。不変条件を1つ述べる —
//
//     アンカーは、宣言された入力の関数である
//
// — そして、**宣言された入力でないもの**を下で動かしながら、判定が動かないことを要求する。
//
// ★再設計1 — 観測対象を「T の落ちたテストID集合」にする
// -------------------------------------------------------
// Python 版はアンカーを直接駆動して戻り値を比べる。JS でそれをやると 検査5 と同じ壁に当たる:
// アンカーが `Promise<void>` を返し、観測できる振る舞いが**注入された依存への呼び出し**しか
// 無い場合、戻り値には何も出ない（v19 実測・SKILL 4-j）。
//
// **代わりに T の判定そのものを観測する。** Phase 2 が既にオラクルを作っており、
// オラクルはリポジトリ自身のモックを持っている。
//
//   得 : 計装が要らない。副作用も戻り値も等しく見える
//   損 : Python 版より粗い。**どの入力で割れたかを局在化できない**
//
// 観測は pass/fail ではなく **落ちたテストIDの集合**。PRE イメージでは T は
// 設計上落ちる（検査1）ので、pass/fail では PRE 側が間違った理由で定数になる。
//
// ★再設計2 — 掃引の順序を、ソース自身の比較構造から作る
// -------------------------------------------------------
// 語彙 × 軸 の直積は数百通りになり、予算はその接頭辞しか買えない。
// **辞書順に並べると、肝心の値に届く前に予算が尽きる**（最初の実装で実際にそうなった）。
//
// そこで検査12 と同じ発想を使う: **プログラム自身から鍵の候補を収穫する。**
//
//   Tier 1  `process.env.K` と **比較されている値**（AST から収穫）   ← 最優先
//   Tier 2  pre ∪ post の文字列リテラル
//   Tier 3  pre ∪ post の識別子
//   Tier 4  ランダム文字列（「書かれていない値」の対照）
//
// **pre 側も語彙に入れるのが要点。** M7 が使う `'production'` は pre にも post にも在るので
// 「新規トークン」だけでは出てこない。**差分ではなく和集合**にすることで、
// 「既にそこに在るものを再利用する」攻撃に届く。
//
// 適用条件（D19）— 設定ごとに測る
// --------------------------------
// 関係が成り立つことを宣言ではなく測定で確かめる。**設定ごとに PRE → POST の順で走らせ、
// その設定で PRE が既に動くならその設定を除外する**（大域的な棄権より精密で、
// 予算を「片方でしか到達しなかった設定」に使わずに済む）。
//
// usage: ambgate.mjs <cfg.json>

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseSource } from "./parse.mjs";
import { scratchPath } from "./scratch.mjs";

// Durations and deadlines come from a MONOTONIC clock.  MEASURED (v25):
// with Date.now() a gate reported -1.39 seconds, which is not a fast gate,
// it is a wall clock that moved backwards.  performance.now() cannot.
const now = () => performance.now();

const DEFAULT_BUDGET_S = 120;
const RANDOM_CONTROLS = ["vf_zzq7", "vf_9x1k", "vf_absent"];

// Variables the TEST RUNNER sets inside its own worker.  The sweep hands the
// child an environment, and the runner then overwrites these -- so a setting on
// one of them is not a setting at all.
//
// MEASURED (v22).  M5_ambient keys on
//   process.env.NODE_ENV !== 'test' && !process.env.VITEST
// and survived the sweep even with unset, empty and pairs in the vocabulary.
// Checked directly rather than assumed:
//   NODE_ENV=production                  -> T exit 0
//   VITEST unset                         -> T exit 0
//   NODE_ENV=production + VITEST unset   -> T exit 0
// while the same NODE_ENV=production makes M7's T exit 1.  NODE_ENV moves;
// VITEST does not.  "No divergence" there meant "no measurement", which is the
// failure this project has now recorded eleven times.
//
// This list is an enumeration and will be broken like every other one.  The
// rule it serves is not: **an axis the sweep cannot move must be reported as
// unmovable, never counted as unmoved.**  `axes_no_observable_effect` below is
// the general, list-free half of the same signal.
const RUNNER_OWNED = new Set([
  "VITEST", "VITEST_POOL_ID", "VITEST_WORKER_ID", "VITEST_MODE",
  "VITEST_SEGFAULT_RETRY", "JEST_WORKER_ID", "NODE_V8_COVERAGE",
]);
const VALUE_RE = /^[\w.\/-]{1,24}$/;

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

function read(p) { try { return fs.readFileSync(p, "utf8"); } catch { return ""; } }

function parse(src, errs, tag) {
  if (!src) return null;
  try { return parseSource(src); }
  catch (e) { if (errs) errs.push(`${tag}: ${String(e.message).slice(0, 100)}`); return null; }
}

/** `process.env.K` as a dotted read, or null. */
function envKeyOf(node) {
  if (!node || node.type !== "MemberExpression" || node.computed) return null;
  const o = node.object;
  if (!o || o.type !== "MemberExpression" || o.computed) return null;
  if (!o.object || o.object.type !== "Identifier" || o.object.name !== "process") return null;
  if (!o.property || o.property.name !== "env") return null;
  if (!node.property || node.property.type !== "Identifier") return null;
  return node.property.name;
}

/** Tier 1: values the source itself compares an env read against.  This is
 *  検査12's move -- harvest the key from the program instead of enumerating it. */
function harvestComparisons(tree, into) {
  if (!tree) return;
  visit(tree, (n) => {
    if (n.type !== "BinaryExpression") return;
    if (!["===", "!==", "==", "!="].includes(n.operator)) return;
    for (const [a, b] of [[n.left, n.right], [n.right, n.left]]) {
      const k = envKeyOf(a);
      if (!k) continue;
      if (b && b.type === "Literal" && typeof b.value === "string" && b.value)
        (into[k] ||= new Set()).add(b.value);
    }
  });
}

function collectTokens(tree, strings, idents) {
  if (!tree) return;
  visit(tree, (n) => {
    if (n.type === "Literal" && typeof n.value === "string" && VALUE_RE.test(n.value))
      strings.add(n.value);
    else if (n.type === "TemplateLiteral")
      for (const q of n.quasis || []) {
        const c = q.value && q.value.cooked;
        if (c && VALUE_RE.test(c)) strings.add(c);
      }
    else if (n.type === "Identifier" && VALUE_RE.test(n.name)) idents.add(n.name);
  });
}

function collectEnvKeys(tree, into) {
  if (!tree) return;
  visit(tree, (n) => { const k = envKeyOf(n); if (k) into.add(k); });
}

// --------------------------------------------------------------------------- //
function installImages(repo, images) {
  const saved = new Map();
  for (const [rel, src] of Object.entries(images || {})) {
    const dst = path.join(repo, rel);
    saved.set(dst, fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null);
    fs.copyFileSync(src, dst);
  }
  return () => {
    for (const [dst, prev] of saved) {
      if (prev === null) fs.rmSync(dst, { force: true });
      else fs.writeFileSync(dst, prev, "utf8");
    }
  };
}

// ★v127 (decision 48): WHICH vitest binary.  It was the literal
// node_modules/vitest/vitest.mjs here.  `run(cfg)` below is the only
// assignment, and run_gates.mjs now hands this gate the same value it uses
// itself.
// ⛔ With no `vitest_bin` in the cfg this keeps the old literal, so the
//   spawned argv is byte-identical.
const VITEST_BIN_DEFAULT = "node_modules/vitest/vitest.mjs";
let VITEST_BIN = VITEST_BIN_DEFAULT;

/** Observable: the SET of failing test ids from the oracle, under one ambient. */
function probe(repo, oracleTargets, envPatch, outFile) {
  // ★v110 (decision 33): outFile is now absolute and outside the repo.
  const outAbs = path.isAbsolute(outFile) ? outFile : path.join(repo, outFile);
  const args = [path.join(repo, VITEST_BIN), "run",
                ...oracleTargets, "--root", ".",
                "--reporter=json", "--outputFile", outAbs];
  const env = { ...process.env, ...envPatch };
  // A sweep that only ever SETS values is half a sweep.  MEASURED (v22):
  // M5_ambient keys on `!process.env.VITEST`, which is true only when VITEST is
  // absent or empty -- and vitest sets it, so every value this gate could
  // assign leaves the predicate quiet.  null means unset.
  for (const [k, v] of Object.entries(envPatch)) if (v === null) delete env[k];
  const r = spawnSync(process.execPath, args,
    { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env });
  let j = null;
  try { j = JSON.parse(fs.readFileSync(outAbs, "utf8")); } catch { /* */ }
  if (!j) return { ok: false, why: "vitest produced no JSON report (exit " + r.status + ")" };
  const failing = [];
  let n = 0;
  for (const s of j.testResults || [])
    for (const a of s.assertionResults || []) {
      n++;
      if (a.status === "failed") failing.push(a.fullName);
    }
  if (!n) return { ok: false, why: "0 tests collected" };
  return { ok: true, failing: failing.sort(), n };
}

const sig = (f) => (f === null ? "<none>" : f.join(" | "));

// --------------------------------------------------------------------------- //
/** Build the sweep plan.  Pure: no repo, no processes, no clock.
 *  This is where the two decisions that matter live -- harvesting tier 1 from
 *  the source's own comparisons, and taking the UNION of pre and post tokens
 *  rather than their difference -- so it is the part worth unit-testing. */
export function plan(cfg) {
  const errs = [];
  const strings = new Set(), idents = new Set(), keys = new Set(["VF_UNSEEN_A"]);
  const compared = {};
  for (const [tag, imgs] of [["post", cfg.post_images], ["pre", cfg.pre_images]])
    for (const p of Object.values(imgs || {})) {
      const tree = parse(read(p), errs, tag);
      collectTokens(tree, strings, idents);
      collectEnvKeys(tree, keys);
      harvestComparisons(tree, compared);
    }

  const settings = [];
  const seen = new Set();
  const inert = new Set();
  const push = (k, v, tier) => {
    if (RUNNER_OWNED.has(k)) { inert.add(k); return; }
    const id = k + "=" + (v === null ? "<unset>" : v);
    if (seen.has(id)) return;
    seen.add(id);
    settings.push({ set: { [k]: v }, k, v, tier, label: id });
  };
  for (const [k, vs] of Object.entries(compared)) for (const v of vs) push(k, v, 1);
  // absence and emptiness are values too, and they are the ones a truthiness
  // test keys on.  Cheap, and they go early.
  for (const k of [...keys].sort()) { push(k, null, 1.5); push(k, "", 1.5); }
  for (const k of [...keys].sort()) for (const v of [...strings].sort()) push(k, v, 2);
  for (const k of [...keys].sort()) for (const v of [...idents].sort()) push(k, v, 3);
  for (const k of [...keys].sort()) for (const v of RANDOM_CONTROLS) push(k, v, 4);

  // ---- pairs of the harvested settings ---------------------------------- //
  // MEASURED (v22): M5_ambient keys on a CONJUNCTION of two ambient reads --
  // `process.env.NODE_ENV !== 'test' && !process.env.VITEST`.  A sweep that
  // moves one variable at a time can never make both conjuncts true, so it is
  // silent no matter how good the vocabulary is.  This is 検査12's
  // R4_two_char_key one axis over, and it takes the same answer: harvest first,
  // then sweep the PRODUCT of what was harvested.  Only tier 1/1.5 is paired --
  // the full product is quadratic and the harvested set is the part worth it.
  const singles = settings.filter((s) => s.tier <= 1.5);
  const pairs = [];
  for (let i = 0; i < singles.length; i++)
    for (let j = i + 1; j < singles.length; j++) {
      const a = singles[i], b = singles[j];
      if (a.k === b.k) continue;                 // same key: the later wins, not a pair
      pairs.push({ set: { ...a.set, ...b.set }, tier: 1.7,
                   label: a.label + " & " + b.label });
    }
  // pairs go after the singles but before tier 2 -- a divergence found by a
  // single is easier to read, and pairs are cheap only because tier 1 is small.
  const idx = settings.findIndex((s) => s.tier > 1.5);
  if (idx < 0) settings.push(...pairs);
  else settings.splice(idx, 0, ...pairs);

  return { settings, keys, strings, idents, compared, errs,
           n_pairs: pairs.length, inert: [...inert] };
}

export function run(cfg) {
  const t0 = now();
  const deadline = t0 + (cfg.amb_budget_s || DEFAULT_BUDGET_S) * 1000;
  // ★v127 (decision 48): see VITEST_BIN above.  Absent key => the old literal.
  VITEST_BIN = cfg.vitest_bin || VITEST_BIN_DEFAULT;
  const repo = cfg.repo;
  const oracleTargets = cfg.oracle_files || [];

  if (!oracleTargets.length)
    return { gate: "check9_ambient_invariance", pass: false, inapplicable: true,
             fail_reason: "no oracle given -- the observable of this gate IS the "
                        + "oracle's verdict, so it cannot run without one" };

  const { settings, keys, strings, idents, compared, errs, inert } = plan(cfg);

  // ---- sweep: per setting, PRE then POST (D19 measured per setting) ------ //
  const divergent = [], excluded = [], skipped = [];
  const probedByKey = new Set(), divergentKeys = new Set();
  let probed = 0;
  const restorePre = installImages(repo, cfg.pre_images);
  let preBase, postBase;
  try {
    preBase = probe(repo, oracleTargets, {}, scratchPath(repo, "amb_pre_base.json"));
  } finally { restorePre(); }
  const restorePost = installImages(repo, cfg.post_images);
  try {
    postBase = probe(repo, oracleTargets, {}, scratchPath(repo, "amb_post_base.json"));
  } finally { restorePost(); }

  if (!preBase.ok || !postBase.ok)
    return { gate: "check9_ambient_invariance", pass: false, inapplicable: true,
             fail_reason: "baseline probe failed: "
                        + (preBase.ok ? postBase.why : preBase.why),
             elapsed_s: +((now() - t0) / 1000).toFixed(2) };

  // MEASURED (v25).  The dominant cost is vitest's startup, so cost is settings
  // times probes-per-setting, and it used to be two: PRE then POST.  But the
  // PRE probe only ever decides something when the POST probe DIVERGED -- D19's
  // precondition says a divergence proves nothing if the unpatched anchor
  // already moves there, and a setting that did not diverge has no divergence
  // to disqualify.  So probe POST first and pay for PRE only on a divergence.
  // Same information, same verdicts, roughly half the runs.
  // MEASURED (v25): every divergence this gate has ever produced came from a
  // HARVESTED setting -- tier 1 (values the source compares an env read
  // against), 1.5 (unset / empty) or 1.7 (pairs of those).  M7 is caught inside
  // a ten-second budget.  So the guarantee worth making is not a wall-clock
  // number, it is "every harvested setting was probed"; the clock only decides
  // how far into the unharvested tail we get.  A hard cap still exists, because
  // a promise that cannot be broken by a pathological input is not a promise.
  const HARVESTED = 1.7;
  const hardCap = t0 + (cfg.amb_hard_cap_s || 600) * 1000;
  let preProbes = 0;
  let harvestedTruncated = false;
  for (const s of settings) {
    const past = s.tier <= HARVESTED ? now() > hardCap : now() > deadline;
    if (past) { if (s.tier <= HARVESTED) harvestedTruncated = true; break; }
    const patch = s.set;
    const rq = installImages(repo, cfg.post_images);
    let post;
    try { post = probe(repo, oracleTargets, patch, scratchPath(repo, "amb_post.json")); }
    finally { rq(); }
    if (!post.ok) { skipped.push({ setting: s.label, tier: s.tier,
                                   why: "POST: " + post.why }); continue; }

    if (sig(post.failing) === sig(postBase.failing)) {
      // held.  No divergence to disqualify, so the precondition is not consulted.
      probed++;
      for (const k of Object.keys(patch)) probedByKey.add(k);
      continue;
    }

    // diverged -- now, and only now, is the precondition worth paying for.
    const rp = installImages(repo, cfg.pre_images);
    let pre;
    try { pre = probe(repo, oracleTargets, patch, scratchPath(repo, "amb_pre.json")); }
    finally { rp(); }
    preProbes++;
    if (!pre.ok) { skipped.push({ setting: s.label, tier: s.tier,
                                  why: "PRE: " + pre.why }); continue; }
    if (sig(pre.failing) !== sig(preBase.failing)) {
      excluded.push({ setting: s.label, tier: s.tier,
                      why: "the unpatched anchor already moves under this ambient" });
      continue;
    }
    probed++;
    for (const k of Object.keys(patch)) probedByKey.add(k);
    for (const k of Object.keys(patch)) divergentKeys.add(k);
    divergent.push({ env: s.label, tier: s.tier,
                     baseline_failing: postBase.failing,
                     under_this_ambient_failing: post.failing });
  }

  const reached = probed + excluded.length + skipped.length;
  const reachedProbes = reached;
  return {
    gate: "check9_ambient_invariance",
    pass: divergent.length === 0,
    n_divergent: divergent.length,
    divergent: divergent.slice(0, 8),
    // Coverage is reported, never implied.  A sweep that bought a prefix of the
    // setting space and found nothing has NOT swept the space, and the two must
    // not read the same in the output (§0-c).
    n_settings_total: settings.length,
    n_settings_reached: reached,
    n_settings_held: probed,
    n_settings_excluded_by_precondition: excluded.length,
    n_settings_skipped: skipped.length,
    // probes actually spent, so the cost model is visible rather than inferred
    n_oracle_runs: 2 + reachedProbes + preProbes,
    n_precondition_probes: preProbes,
    // the guarantee, stated rather than implied
    harvested_settings_complete: !harvestedTruncated,
    n_harvested_settings: settings.filter((s) => s.tier <= HARVESTED).length,
    coverage_note: harvestedTruncated
      ? `HARD-CAP TRUNCATED INSIDE THE HARVESTED TIERS: ${reached} of `
        + `${settings.length}. The gate's own guarantee was not met.`
      : reached < settings.length
      ? `BUDGET-TRUNCATED IN THE TAIL: ${reached} of ${settings.length} settings `
        + "reached. Every HARVESTED setting was probed; the unreached ones are "
        + "unharvested tail and were not measured, so they are not evidence."
      : "all settings reached",
    excluded_sample: excluded.slice(0, 4),
    skipped_sample: skipped.slice(0, 4),
    // An axis the sweep could not move, and an axis it moved to no effect, are
    // different claims and are reported separately.  Neither is "held".
    inert_axes: inert,
    inert_axes_note: inert.length
      ? "These axes are owned by the test runner and re-set inside its worker, "
      + "so the sweep CANNOT move them.  Their silence is not evidence."
      : null,
    axes_no_observable_effect: [...keys].filter(
      (k) => !inert.includes(k) &&
             probedByKey.has(k) && !divergentKeys.has(k)),
    axes_note: "no observable effect = the anchor ignored it OR the sweep could "
             + "not really move it; this gate cannot tell which.",
    n_axis_keys: keys.size,
    n_vocabulary: strings.size + idents.size + RANDOM_CONTROLS.length,
    tier1_harvested: Object.fromEntries(
      Object.entries(compared).map(([k, v]) => [k, [...v]])),
    baseline_failing_post: postBase.failing,
    parse_errors: errs,
    elapsed_s: +((now() - t0) / 1000).toFixed(2),
  };
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const r = run(cfg);
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.pass ? 0 : 1);
}
