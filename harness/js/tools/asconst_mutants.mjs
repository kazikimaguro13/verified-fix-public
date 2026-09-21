// asconst_mutants.mjs — §12-A15 の道具。**ゲートではない。**
// 番号なし・`run_gates.mjs` 非接続・合否に一切参加しない。出すのは数字と証人だけで、
// 判定はしない。検査4 に配線するかどうかは、この数字を見てから人間が決める。
//
// WHY THIS EXISTS (HANDOFF §0-j-9 ④ / §0-j-10 ③ / §0-j-12 ②)
// -----------------------------------------------------------
// MEASURED (v46): StrykerJS 10.0.0 treats `TSAsExpression` as a TYPE node and
// skips the whole subtree:
//     instrumenter/util/syntax-helpers.js:116  isTypeNode() includes
//     instrumenter/util/syntax-helpers.js:140  tsTypeAnnotationNodeTypes = ["TSAsExpression", ...]
//     instrumenter/transformers/babel-transformer.js:137  shouldSkip()
// Every allow-list in this repository is written `[...] as const`, so 検査4 has
// never mutated one.  v47 put a back door inside that hole (`N18_asconst_
// predicate`) and it walked through every gate.  v48 counted the minimal
// combinations whose plugs are all absent: 45, and **all 45 go through
// `as const`**.  So there is exactly one point to probe here.
//
// WHAT IT DOES
// ------------
//   1. install the POST image and compute the SAME `--mutate` ranges 検査4
//      computes (by running 検査4 itself, so they cannot drift)
//   2. build a PRE-PROCESSED copy in which every `as T` / `as const` /
//      `satisfies T` / `<T>x` is blanked out with SPACES of the same length.
//      `as` is a type-level assertion, erased before anything runs, so the
//      blanked copy is runtime-equivalent -- and because the blanking is
//      length-preserving, **every line and column is unchanged**, which makes
//      the position mapping back to the real source the IDENTITY.
//   3. let Stryker generate mutants against the blanked copy, with the ranges
//      from step 1
//   4. ★apply each mutant to the REAL source (not the blanked copy) and run T
//
// ⚠ THE POINT OF STEP 4.  Measuring on the blanked copy would mean measuring
// something that is not the source under test.  The blanked copy exists only to
// make the generator look at the subtree; the verdict has to come from the real
// text.  Three machine checks stand between the two (see `mapping` in the
// output):
//   a. blanked and original have the SAME byte length and differ only inside
//      the blanked spans
//   b. for each mutant span [a,b): blanked.slice(a,b) === original.slice(a,b)
//      -- if not, the span overlaps a blanked region and the mutant is counted
//      as UNMAPPABLE and NOT applied (§0-c: do not drop it silently)
//   c. after splicing, the new text differs from the original in exactly one
//      contiguous region, and that region is [a,b)
//
// WHAT IT IS NOT
// --------------
// Not a gate.  It does not edit a gate, a pass condition or an oracle.  It
// prints `verdict_if_wired` as a COUNT-DERIVED HYPOTHETICAL, clearly labelled;
// nothing reads it.
//
// usage:
//   node asconst_mutants.mjs <cfg.json> --gates <dir> [options]
//     --gates <dir>     where mutgate.mjs lives (used for the "before" pass)
//     --controls <n>    self-check: hand-apply n mutants Stryker called Killed
//                       in the "before" pass; they MUST come back killed (default 3)
//     --count-only      count mutants per range, do not run T at all
//     --raw-dir <dir>   copy both Stryker reports here
//     --out <file>      write the whole measurement as JSON

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { execFileSync, spawnSync } from "node:child_process";

const NL = String.fromCharCode(10);        // 罠8: バックスラッシュを転送に載せない

function opt(flag, dflt = null) {
  const i = process.argv.indexOf(flag);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : dflt;
}
const has = (flag) => process.argv.includes(flag);

const cfgPath = process.argv[2];
if (!cfgPath || cfgPath.startsWith("--")) {
  console.error("usage: node asconst_mutants.mjs <cfg.json> --gates <dir> "
              + "[--controls N] [--count-only] [--raw-dir D] [--out F]");
  process.exit(2);
}
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;
const baseRef = cfg.base_ref || "HEAD";
const oracles = cfg.oracle_files || [];
const gatesDir = opt("--gates");
const nControls = +opt("--controls", "3");
const countOnly = has("--count-only");
const rawDir = opt("--raw-dir");
const outFile = opt("--out");
if (!gatesDir) { console.error("--gates <dir> is required"); process.exit(2); }
if (rawDir) fs.mkdirSync(rawDir, { recursive: true });

const reportFile = path.join(repo, "reports/mutation.json");
const say = (s) => console.log(s);

// --------------------------------------------------------------------------- //
// 0. refuse to run on a dirty tree (罠9: 同じ作業ツリーに2実験を走らせない)
// --------------------------------------------------------------------------- //
const targets = Object.keys(cfg.post_images || {});
if (!targets.length) { console.error("cfg has no post_images"); process.exit(2); }
const dirty = execFileSync("git", ["status", "--porcelain", "--", ...targets],
                           { cwd: repo, encoding: "utf8" }).trim();
if (dirty) {
  console.error("REFUSING: " + targets.join(", ") + " is already modified.");
  console.error(dirty);
  process.exit(2);
}

// --------------------------------------------------------------------------- //
// 1. install the POST image and keep its bytes.  This text is THE SOURCE; every
//    verdict below is about it.
// --------------------------------------------------------------------------- //
const post = {};                       // rel -> { abs, text }
for (const [rel, src] of Object.entries(cfg.post_images)) {
  const abs = path.join(repo, rel);
  const text = fs.readFileSync(src, "utf8");
  fs.writeFileSync(abs, text, "utf8");
  post[rel] = { abs, text };
}
function restorePost() {
  for (const rel of Object.keys(post)) fs.writeFileSync(post[rel].abs, post[rel].text, "utf8");
}
function restoreHead() {
  execFileSync("git", ["checkout", "--", ...targets], { cwd: repo });
}

// --------------------------------------------------------------------------- //
// 2. "before" pass: run 検査4 itself.  Using the gate rather than re-deriving
//    the ranges is deliberate -- the instruction is "the same ranges as 検査4",
//    and the only way that cannot drift is to ask it.
// --------------------------------------------------------------------------- //
say("# variant : " + (cfg.name || path.basename(cfgPath)));
say("# repo    : " + repo + "   base_ref=" + baseRef);
say("# oracles : " + oracles.join(", "));
fs.rmSync(reportFile, { force: true });
const g = spawnSync(process.execPath,
                    [path.join(gatesDir, "mutgate.mjs"), repo, baseRef, oracles.join(",")],
                    { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
// 判定は終了コードで取らない（HANDOFF）。読むのは JSON と report ファイル。
let before;
try { before = JSON.parse(g.stdout); }
catch { console.error("検査4 の出力が JSON ではない:" + NL + String(g.stdout).slice(0, 400)
                    + NL + String(g.stderr).slice(-400)); restoreHead(); process.exit(3); }
const specs = before.mutate_spec || [];
if (!specs.length) {
  console.error("検査4 が mutate_spec を出さなかった（gate_could_not_run="
              + before.gate_could_not_run + "）。ここで止める。");
  restoreHead(); process.exit(3);
}
const beforeRep = fs.existsSync(reportFile)
  ? JSON.parse(fs.readFileSync(reportFile, "utf8")) : { files: {} };
if (rawDir && fs.existsSync(reportFile))
  fs.copyFileSync(reportFile, path.join(rawDir, (cfg.name || "v") + ".before.mutation.json"));
say("# 検査4(before): mutants=" + before.mutants + " killed=" + before.killed
  + " survived=" + before.survived + " noCov=" + before.no_coverage
  + "  spec=" + specs.join(","));

// --------------------------------------------------------------------------- //
// 3. strip `as` — length-preserving, so the position mapping is the identity
// --------------------------------------------------------------------------- //
const requireFromRepo = createRequire(path.join(repo, "package.json"));
let ts;
try { ts = requireFromRepo("typescript"); }
catch (e) { console.error("typescript が repo から解決できない: " + e.message);
            restoreHead(); process.exit(3); }

function stripAs(text, fileName) {
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true,
                                 fileName.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const spans = [];
  (function walk(node) {
    // `X as T` / `X as const` / `X satisfies T`: the type sits between the end
    // of the operand and the end of the node.
    if (ts.isAsExpression(node) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(node)))
      spans.push([node.expression.end, node.end, text.slice(node.expression.end, node.end)]);
    // `<T>x`: the type sits between the start of the node and the operand.
    else if (ts.isTypeAssertionExpression && ts.isTypeAssertionExpression(node))
      spans.push([node.getStart(sf), node.expression.getStart(sf),
                  text.slice(node.getStart(sf), node.expression.getStart(sf))]);
    ts.forEachChild(node, walk);
  })(sf);
  const chars = text.split("");
  for (const [a, b] of spans)
    for (let i = a; i < b; i++) if (chars[i] !== NL) chars[i] = " ";
  const outText = chars.join("");
  const diag = ts.createSourceFile(fileName, outText, ts.ScriptTarget.Latest, true,
                                   ts.ScriptKind.TS).parseDiagnostics || [];
  return { text: outText, spans, parse_errors: diag.length };
}

const strip = {};
for (const [rel, p] of Object.entries(post)) {
  const s = stripAs(p.text, rel);
  // ★機械検算 (a): 同じバイト長で、潰した範囲以外はバイト同一
  const sameLen = s.text.length === p.text.length;
  const diffIdx = [];
  for (let i = 0; i < Math.min(s.text.length, p.text.length); i++)
    if (s.text[i] !== p.text[i]) diffIdx.push(i);
  const inSpan = diffIdx.every((i) => s.spans.some(([a, b]) => i >= a && i < b));
  strip[rel] = { ...s, same_length: sameLen, n_diff_chars: diffIdx.length,
                 all_diffs_inside_spans: inSpan,
                 sites: s.spans.map(([a, b, t]) => ({
                   line: p.text.slice(0, a).split(NL).length,
                   text: t.replace(/\s+/g, " ").trim().slice(0, 40) })) };
  say("# strip   : " + rel + "  sites=" + s.spans.length + " same_length=" + sameLen
    + " diffs_inside_spans=" + inSpan + " parse_errors=" + s.parse_errors);
  if (!sameLen || !inSpan || s.parse_errors) {
    console.error("★測定不能: 潰した版が位置を保っていない（または構文が壊れた）。");
    restoreHead(); process.exit(3);
  }
}

// --------------------------------------------------------------------------- //
// 4. "after" pass: Stryker on the stripped copy, WITH THE SAME RANGES
// --------------------------------------------------------------------------- //
for (const rel of Object.keys(post)) fs.writeFileSync(post[rel].abs, strip[rel].text, "utf8");
fs.rmSync(reportFile, { force: true });
const nodeDir = path.dirname(process.execPath);
const env = { ...process.env, PATH: nodeDir + path.delimiter + (process.env.PATH || "") };
const t0 = Date.now();
const sr = spawnSync("npx", ["stryker", "run",
                             "--mutate", specs.join(","),
                             "--testFiles", oracles.join(","),
                             "--reporters", "json,clear-text",
                             "--logLevel", "warn", "--allowEmpty"],
                     { cwd: repo, encoding: "utf8", env, maxBuffer: 128 * 1024 * 1024 });
const strykerSecs = +((Date.now() - t0) / 1000).toFixed(2);
const afterRep = fs.existsSync(reportFile)
  ? JSON.parse(fs.readFileSync(reportFile, "utf8")) : null;
if (rawDir && fs.existsSync(reportFile))
  fs.copyFileSync(reportFile, path.join(rawDir, (cfg.name || "v") + ".after.mutation.json"));
restorePost();                                    // ★ここから先は本物のソース
if (!afterRep) {
  console.error("★測定不能: 潰した版で Stryker が report を出さなかった。rc=" + sr.status);
  console.error(String(sr.stderr || "").split(NL).slice(-12).join(NL));
  restoreHead(); process.exit(3);
}

// --------------------------------------------------------------------------- //
// 5. per-range counts (§12-A11 の形。0件のレンジは「検証されていない」と読める形で出す)
// --------------------------------------------------------------------------- //
function parseSpec(s) {
  const m = /^(.*):(\d+)-(\d+)$/.exec(s);
  return { spec: s, file: m[1], lo: +m[2], hi: +m[3] };
}
function tally(rep) {
  const rows = specs.map(parseSpec).map((r) => ({ ...r, mutants: 0, killed: 0,
                                                  survived: 0, no_coverage: 0, operators: {} }));
  const list = [];
  for (const [file, f] of Object.entries((rep && rep.files) || {}))
    for (const m of f.mutants || []) {
      const line = m.location.start.line;
      const hit = rows.filter((r) => file.endsWith(r.file) && line >= r.lo && line <= r.hi);
      list.push({ ...m, file, ranges: hit.map((r) => r.spec) });
      for (const r of hit) {
        r.mutants++;
        r.operators[m.mutatorName] = (r.operators[m.mutatorName] || 0) + 1;
        if (m.status === "Killed") r.killed++;
        else if (m.status === "Survived") r.survived++;
        else if (m.status === "NoCoverage") r.no_coverage++;
      }
    }
  return { rows, list,
           total: list.length,
           n_unverified_ranges: rows.filter((r) => r.mutants === 0).length };
}
const B = tally(beforeRep), A = tally(afterRep);
say("# stryker(after): mutants=" + A.total + "  (" + strykerSecs + "s)");
say("");
say("レンジごとの変異数（★差が本題）");
say("range".padEnd(30) + "before".padEnd(8) + "after".padEnd(8) + "delta");
for (let i = 0; i < B.rows.length; i++)
  say(String(B.rows[i].spec).padEnd(30) + String(B.rows[i].mutants).padEnd(8)
    + String(A.rows[i].mutants).padEnd(8) + (A.rows[i].mutants - B.rows[i].mutants));
say("");

// --------------------------------------------------------------------------- //
// 6. map every "after" mutant back onto the REAL source and check it
// --------------------------------------------------------------------------- //
function offsetOf(src, line, column) {           // schema 1.0: 1-origin, end exclusive
  let off = 0;
  for (let i = 1; i < line; i++) {
    const nl = src.indexOf(NL, off);
    if (nl < 0) return -1;
    off = nl + 1;
  }
  return off + (column - 1);
}
function locate(m) {
  const rel = Object.keys(post).find((r) => m.file.endsWith(r));
  if (!rel) return { ok: false, why: "mutant is in a file this cfg does not carry: " + m.file };
  const orig = post[rel].text, blanked = strip[rel].text;
  const a = offsetOf(blanked, m.location.start.line, m.location.start.column);
  const b = offsetOf(blanked, m.location.end.line, m.location.end.column);
  if (a < 0 || b < 0 || b < a) return { ok: false, why: "span out of range", rel };
  // ★機械検算 (b): その span の本文が、潰した版と元の版で同一か
  if (blanked.slice(a, b) !== orig.slice(a, b))
    return { ok: false, rel, a, b, why: "UNMAPPABLE: the span overlaps a blanked "
             + "`as` region, so the location does not name the same text in the real source",
             blanked_text: blanked.slice(a, b).slice(0, 60),
             original_text: orig.slice(a, b).slice(0, 60) };
  return { ok: true, rel, a, b, original: orig.slice(a, b) };
}
// ★機械検算 (c): splice 後の本文が、元と1区間だけ違うこと
function spliceAndVerify(orig, a, b, replacement) {
  const text = orig.slice(0, a) + replacement + orig.slice(b);
  let i = 0;
  while (i < Math.min(text.length, orig.length) && text[i] === orig[i]) i++;
  let j = 0;
  while (j < Math.min(text.length, orig.length) - i
         && text[text.length - 1 - j] === orig[orig.length - 1 - j]) j++;
  const changedFrom = i, changedToOrig = orig.length - j, changedToNew = text.length - j;
  const oneRegion = changedFrom >= a && changedToOrig <= b
                 && changedToNew <= a + replacement.length;
  return { text, one_region: oneRegion,
           region: [changedFrom, changedToOrig], intended: [a, b] };
}

// --------------------------------------------------------------------------- //
// 7. run T
// --------------------------------------------------------------------------- //
let vitestRuns = 0;
function runOracle(tag) {
  const outRel = ".vf/asconst.json";
  fs.mkdirSync(path.join(repo, ".vf"), { recursive: true });
  fs.rmSync(path.join(repo, outRel), { force: true });
  const t = Date.now();
  const r = spawnSync(process.execPath,
                      [path.join(repo, "node_modules/vitest/vitest.mjs"), "run", ...oracles,
                       "--root", ".", "--reporter=json", "--outputFile", outRel],
                      { cwd: repo, encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
  vitestRuns++;
  const p = path.join(repo, outRel);
  if (!fs.existsSync(p))
    return { tag, ok: false, n: 0, failed: 0, names: [], exit: r.status,
             error: "vitest produced no JSON report",
             stderr_tail: String(r.stderr || "").split(NL).slice(-6).join(" | "),
             secs: +((Date.now() - t) / 1000).toFixed(2) };
  const j = JSON.parse(fs.readFileSync(p, "utf8"));
  let n = 0; const names = [];
  for (const s of j.testResults || [])
    for (const x of s.assertionResults || []) { n++; if (x.status === "failed") names.push(x.fullName); }
  return { tag, ok: true, n, failed: names.length, names: names.slice(0, 4),
           exit: r.status, secs: +((Date.now() - t) / 1000).toFixed(2) };
}

const rows = [];
let baseline = null;
if (!countOnly) {
  baseline = runOracle("baseline");
  say("# baseline: " + baseline.n + " tests, " + baseline.failed + " failed ("
    + baseline.secs + "s)" + (baseline.error ? "  ERROR " + baseline.error : ""));
  if (!baseline.ok || baseline.n === 0 || baseline.failed !== 0) {
    console.error("★測定不能: 変異を当てる前から T が緑でない。ここで数えても意味がない。");
    restoreHead(); process.exit(3);
  }

  function apply(m, role) {
    const loc = locate(m);
    const row = { role, id: m.id, file: m.file, line: m.location.start.line,
                  mutator: m.mutatorName, ranges: m.ranges,
                  replacement: String(m.replacement).slice(0, 48),
                  stryker: m.status, static: m.static };
    if (!loc.ok) {
      rows.push({ ...row, verdict: "UNMAPPABLE", why: loc.why,
                  blanked_text: loc.blanked_text, original_text: loc.original_text });
      return;
    }
    const p = post[loc.rel];
    const sp = spliceAndVerify(p.text, loc.a, loc.b, String(m.replacement));
    if (!sp.one_region) {
      rows.push({ ...row, verdict: "SPLICE-NOT-ONE-REGION",
                  region: sp.region, intended: sp.intended });
      return;
    }
    let res;
    try { fs.writeFileSync(p.abs, sp.text, "utf8"); res = runOracle(String(m.id)); }
    finally { fs.writeFileSync(p.abs, p.text, "utf8"); }
    const killed = res.ok && res.failed > 0;
    let verdict;
    if (role === "selfcheck") verdict = killed ? "SELFCHECK-OK" : "★SELFCHECK-BROKEN";
    else verdict = killed ? "KILLED" : "★SURVIVED";
    rows.push({ ...row, original: loc.original.slice(0, 48),
                t_failed: res.failed, t_total: res.n, secs: res.secs,
                t_failing: res.names, verdict });
  }

  // ★自己検査: 撃墜されると分かっている変異（before の走行で Stryker が Killed と
  //   言ったもの）を混ぜる。これが撃墜と出なければ splice が壊れており、他の行は全部無効。
  const ctl = B.list.filter((m) => m.status === "Killed").slice(0, Math.max(0, nControls));
  for (const m of ctl) apply(m, "selfcheck");

  // ★本題: 「外して初めて出た」変異だけを当てる。before にも在った本体側の12件は
  //   検査4 が既に測っているので、ここで測り直しても新しいことは言わない。
  const beforeKey = new Set(B.list.map((m) => m.file + ":" + m.location.start.line + ":"
                                            + m.location.start.column + ":" + m.mutatorName
                                            + ":" + String(m.replacement)));
  const fresh = A.list.filter((m) => !beforeKey.has(m.file + ":" + m.location.start.line + ":"
                                                  + m.location.start.column + ":" + m.mutatorName
                                                  + ":" + String(m.replacement)));
  say("# 手で当てる: 新規 " + fresh.length + " 件 ＋ 自己検査 " + ctl.length + " 件");
  say("");
  for (const m of fresh) apply(m, "new");
}

restorePost();
// ★§0-c: 「戻したつもり」を数えない。POST イメージのバイトと一致しているかを見る。
const notRestored = Object.keys(post)
  .filter((rel) => fs.readFileSync(post[rel].abs, "utf8") !== post[rel].text);
restoreHead();
const finalDirty = execFileSync("git", ["status", "--porcelain", "--", ...targets],
                                { cwd: repo, encoding: "utf8" }).trim();

// --------------------------------------------------------------------------- //
// 8. output
// --------------------------------------------------------------------------- //
const pad = (s, n) => String(s === null || s === undefined ? "-" : s).padEnd(n).slice(0, n);
if (rows.length) {
  say(pad("id", 5) + pad("line", 6) + pad("mutator", 22) + pad("replacement", 26)
    + pad("stryker", 10) + pad("T", 9) + "verdict");
  say("-".repeat(116));
  for (const r of rows)
    say(pad(r.id, 5) + pad(r.line, 6) + pad(r.mutator, 22) + pad(r.replacement, 26)
      + pad(r.stryker, 10)
      + pad(r.t_failed === undefined ? "-" : r.t_failed + "/" + r.t_total, 9) + r.verdict);
  say("");
}
const news = rows.filter((r) => r.role === "new");
const selfs = rows.filter((r) => r.role === "selfcheck");
const nKilled = news.filter((r) => r.verdict === "KILLED").length;
const nSurv = news.filter((r) => r.verdict === "★SURVIVED").length;
const nUnmap = rows.filter((r) => r.verdict === "UNMAPPABLE").length;
const nBadSplice = rows.filter((r) => r.verdict === "SPLICE-NOT-ONE-REGION").length;
const selfBroken = selfs.filter((r) => r.verdict === "★SELFCHECK-BROKEN").length;

const out = {
  tool: "asconst_mutants",
  note: "NOT A GATE.  番号なし・run_gates 非接続・合否に不参加。数字と証人だけを出す。",
  variant: cfg.name || null, repo, base_ref: baseRef, oracles,
  // ★v18 の教訓（§0-c 7例目）: 生存変異体の行を引用するとき、リポジトリの作業ツリー
  //   から読むと別の本文を引いてしまう。ゲートが実際に読んだ POST イメージが正本。
  post_images: cfg.post_images,
  mutate_spec: specs,
  strip: Object.fromEntries(Object.entries(strip).map(([rel, s]) => [rel, {
    n_sites: s.spans.length, sites: s.sites, same_length: s.same_length,
    n_diff_chars: s.n_diff_chars, all_diffs_inside_spans: s.all_diffs_inside_spans,
    parse_errors: s.parse_errors }])),
  before: { source: "検査4 (mutgate.mjs) をそのまま回した", mutants: before.mutants,
            killed: before.killed, survived: before.survived,
            no_coverage: before.no_coverage, pass: before.pass,
            elapsed_s: before.elapsed_s,
            by_range: B.rows, n_unverified_ranges: B.n_unverified_ranges },
  after: { source: "同じ --mutate レンジで、`as` を潰した版に Stryker を当てた",
           mutants: A.total, elapsed_s: strykerSecs, stryker_rc: sr.status,
           by_range: A.rows, n_unverified_ranges: A.n_unverified_ranges },
  delta_by_range: B.rows.map((r, i) => ({ spec: r.spec, before: r.mutants,
                                          after: A.rows[i].mutants,
                                          delta: A.rows[i].mutants - r.mutants })),
  t_baseline: baseline,
  rows,
  summary: {
    n_new_mutants: A.total - B.total,
    n_applied: news.length, n_killed: nKilled, n_survived: nSurv,
    n_unmappable: nUnmap, n_splice_rejected: nBadSplice,
    selfcheck_total: selfs.length,
    selfcheck_ok: selfs.filter((r) => r.verdict === "SELFCHECK-OK").length,
    selfcheck_broken: selfBroken,
    vitest_runs: vitestRuns,
    n_files_not_restored: notRestored.length, files_not_restored: notRestored,
    tree_restored: notRestored.length === 0 && finalDirty === "",
    // ★HYPOTHETICAL.  検査4 の合格条件をこの測定に当てたらどうなるか、というだけ。
    //   このフィールドは何にも読まれない。配線するかは人間が決める。
    verdict_if_wired: countOnly ? null
      : (A.total >= 1 && nSurv === 0 && nKilled + nSurv === news.length ? "pass" : "fail"),
    verdict_if_wired_note:
      "HYPOTHETICAL ONLY.  これは 検査4 の合格条件 (mutants>=1 && survived===0) を "
      + "この測定に当てた場合の値であって、検査4 が実際に出した判定ではない。"
      + "この道具は合否に参加しない。",
  },
};
say("自己検査 : " + out.summary.selfcheck_ok + "/" + out.summary.selfcheck_total
  + (selfBroken ? "  ★" + selfBroken + " 件が食い違う → splice を疑え" : "  OK"));
say("新規変異 : " + out.summary.n_new_mutants + " 件（as を外して初めて出た分）");
say("  撃墜   : " + nKilled + "   生存 : " + nSurv
  + "   UNMAPPABLE : " + nUnmap + "   splice 却下 : " + nBadSplice);
say("vitest   : " + vitestRuns + " 回 ／ tree_restored=" + out.summary.tree_restored);
say("★検査4 に入れたら（仮定）: " + out.summary.verdict_if_wired);
if (outFile) { fs.writeFileSync(outFile, JSON.stringify(out, null, 1), "utf8"); say("→ " + outFile); }
process.exit(0);
