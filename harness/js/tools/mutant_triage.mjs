// mutant_triage.mjs — 検査4 の「生存」報告を、手で同じ変異を当てて検算する（v42）
//
// WHY THIS EXISTS
// ---------------
// MEASURED (v40, `reports/v40_more_controls_results.md` §5-c-b): 検査4 reported
// nine surviving mutants on `S16_scrypt_cost`.  Applying the SAME mutations by
// hand and running the SAME oracle files showed that FIVE of the nine are killed
// by T.  The gate said "survived" about mutants T can actually kill, so
// `fp_to_oracle.py` handed a human five obligations that were already met.
//
//   §0-c records fourteen instances of "not measured" wearing the mask of
//   "nothing wrong".  This is the SAME defect with the sign flipped: "could not
//   measure" wearing the mask of "something is wrong".  fail-closed keeps the
//   accept side safe -- and pollutes the obligation list, which is the half a
//   human reads.
//
// v39 and v40 both did this triage in a throwaway script and both threw it away,
// so v41 had to invent it again.  It lives here now.
//
// WHAT IT DOES
// ------------
//   1. read the Stryker JSON report (the one 検査4 just produced)
//   2. CHECK that the source Stryker mutated is byte-identical to the file on
//      disk -- if it is not, the locations point into a different text and the
//      whole measurement is void.  Say so and stop.
//   3. run the oracle files unmutated: that baseline MUST be green, or nothing
//      below means anything
//   4. for each selected mutant: splice `replacement` into the span the report
//      names, run the oracle files, count failures, restore the file
//   5. ALSO do the same for a few mutants Stryker reported as Killed.  This is
//      the tool measuring itself: if a hand-applied Killed mutant does not fail
//      a test, the splice is wrong and every other row is garbage.
//   6. print the cross-tab against the report's `static` flag
//
// WHAT IT IS NOT
// --------------
// It does not touch a gate, a pass condition, or an oracle.  It is a measuring
// instrument for the gate's witness, and its only output is a table.
//
// usage:
//   node mutant_triage.mjs <cfg.json> [options]
//     --report <path>     Stryker json report (default <repo>/reports/mutation.json)
//     --run                regenerate the report by invoking mutgate.mjs first
//     --gates <dir>        where mutgate.mjs lives (needed by --run)
//     --only <statuses>    comma list, default Survived,NoCoverage
//     --controls <n>       also hand-apply n mutants reported Killed (default 3)
//     --extra-args <s>     extra flags handed to mutgate.mjs (e.g. for stryker)
//     --out <path>         write the full result as JSON

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

function opt(flag, dflt = null) {
  const i = process.argv.indexOf(flag);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : dflt;
}
const has = (flag) => process.argv.includes(flag);

const cfgPath = process.argv[2];
if (!cfgPath || cfgPath.startsWith("--")) {
  console.error("usage: node mutant_triage.mjs <cfg.json> [--run] [--gates D] "
              + "[--report F] [--only Survived,NoCoverage] [--controls N] [--out F]");
  process.exit(2);
}
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;
const oracles = cfg.oracle_files || [];
const only = new Set((opt("--only", "Survived,NoCoverage")).split(",").map((s) => s.trim()));
const nControls = +opt("--controls", "3");
const reportFile = opt("--report", path.join(repo, "reports/mutation.json"));

// --------------------------------------------------------------------------- //
// 0. optionally re-run 検査4 so the report belongs to THIS variant
// --------------------------------------------------------------------------- //
if (has("--run")) {
  const gates = opt("--gates");
  if (!gates) { console.error("--run needs --gates <dir>"); process.exit(2); }
  const extra = (opt("--extra-args", "") || "").split(" ").filter(Boolean);
  const args = [path.join(gates, "mutgate.mjs"), repo,
                cfg.base_ref || "HEAD", oracles.join(","), ...extra];
  console.log("# 検査4 を回して report を作り直す: " + args.join(" "));
  const r = spawnSync(process.execPath, args,
                      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  // 検査4 exits non-zero whenever it FAILS, which is the normal case here.
  // The report file is what matters, not the exit code (HANDOFF: 判定は終了
  // コードで取らない).
  console.log((r.stdout || "").trim().split("\n").slice(0, 40).join("\n"));
  if (r.stderr) console.log("# stderr tail: " + String(r.stderr).split("\n").slice(-4).join(" | "));
}

if (!fs.existsSync(reportFile)) {
  console.error("★ report が無い: " + reportFile + "  (--run を付けるか --report で指す)");
  process.exit(2);
}
const rep = JSON.parse(fs.readFileSync(reportFile, "utf8"));

// --------------------------------------------------------------------------- //
// 1. gather mutants, and check the text they were located against
// --------------------------------------------------------------------------- //
const files = {};       // rel -> { source, onDisk, sameBytes, abs }
const mutants = [];
for (const [rel, fd] of Object.entries(rep.files || {})) {
  const abs = path.join(repo, rel);
  const onDisk = fs.existsSync(abs) ? fs.readFileSync(abs, "utf8") : null;
  files[rel] = { source: fd.source, onDisk, abs,
                 sameBytes: onDisk !== null && onDisk === fd.source };
  for (const m of fd.mutants || []) mutants.push({ ...m, file: rel });
}
const badFiles = Object.entries(files).filter(([, v]) => !v.sameBytes);
if (badFiles.length) {
  console.error("★ 測定不能: Stryker が変異させた本文と、いま disk にある本文が違う。");
  for (const [rel, v] of badFiles)
    console.error("   " + rel + "  report=" + (v.source || "").length
                + " 文字 / disk=" + (v.onDisk === null ? "無い" : v.onDisk.length + " 文字"));
  console.error("   位置(line,col)は report の本文に対する座標なので、この状態で splice すると"
              + " 別の場所を書き換える。report を作り直すこと（--run）。");
  process.exit(3);
}

// mutation-testing schema 1.0: location.start は含む / location.end は含まない、
// line も column も 1 起点。
function offsetOf(src, line, column) {
  let off = 0;
  for (let i = 1; i < line; i++) {
    const nl = src.indexOf("\n", off);
    if (nl < 0) return -1;
    off = nl + 1;
  }
  return off + (column - 1);
}
function spliced(src, m) {
  const a = offsetOf(src, m.location.start.line, m.location.start.column);
  const b = offsetOf(src, m.location.end.line, m.location.end.column);
  if (a < 0 || b < 0 || b < a) return null;
  return { text: src.slice(0, a) + m.replacement + src.slice(b),
           original: src.slice(a, b) };
}

// --------------------------------------------------------------------------- //
// 2. running the oracle
// --------------------------------------------------------------------------- //
let vitestRuns = 0;
function runOracle(tag) {
  const outFile = ".vf/triage.json";
  fs.mkdirSync(path.join(repo, ".vf"), { recursive: true });
  fs.rmSync(path.join(repo, outFile), { force: true });
  const args = [path.join(repo, "node_modules/vitest/vitest.mjs"), "run",
                ...oracles, "--root", ".", "--reporter=json",
                "--outputFile", outFile];
  const t0 = Date.now();
  const r = spawnSync(process.execPath, args,
                      { cwd: repo, encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
  vitestRuns++;
  const p = path.join(repo, outFile);
  if (!fs.existsSync(p)) {
    return { tag, ok: false, n: 0, failed: 0, names: [],
             error: "vitest produced no JSON report",
             exit: r.status,
             stderr_tail: String(r.stderr || "").split("\n").slice(-6).join(" | "),
             secs: +((Date.now() - t0) / 1000).toFixed(2) };
  }
  const j = JSON.parse(fs.readFileSync(p, "utf8"));
  let n = 0; const names = [];
  for (const s of j.testResults || [])
    for (const a of s.assertionResults || []) {
      n++;
      if (a.status === "failed") names.push(a.fullName);
    }
  return { tag, ok: true, n, failed: names.length, names: names.slice(0, 6),
           exit: r.status, secs: +((Date.now() - t0) / 1000).toFixed(2) };
}

// --------------------------------------------------------------------------- //
// 3. baseline: the oracle must be green with nothing mutated
// --------------------------------------------------------------------------- //
console.log("# variant : " + (cfg.name || path.basename(cfgPath)));
console.log("# repo    : " + repo);
console.log("# oracles : " + oracles.join(", "));
console.log("# report  : " + reportFile);
console.log("# mutants : " + mutants.length + "  "
          + JSON.stringify(mutants.reduce((a, m) => (a[m.status] = (a[m.status] || 0) + 1, a), {})));
const base = runOracle("baseline");
console.log("# baseline: " + base.n + " tests, " + base.failed + " failed ("
          + base.secs + "s)" + (base.error ? "  ERROR " + base.error : ""));
if (!base.ok || base.n === 0 || base.failed !== 0) {
  console.error("★ 測定不能: 変異を当てる前からオラクルが緑ではない。"
              + " この状態で「手で当てたら落ちた」を数えても意味がない。");
  if (base.names && base.names.length) console.error("   " + base.names.join("\n   "));
  if (base.stderr_tail) console.error("   " + base.stderr_tail);
  process.exit(3);
}

// --------------------------------------------------------------------------- //
// 4. triage
// --------------------------------------------------------------------------- //
const picked = mutants.filter((m) => only.has(m.status));
const ctlPool = mutants.filter((m) => m.status === "Killed");
const controls = ctlPool.slice(0, Math.max(0, Math.min(nControls, ctlPool.length)));
console.log("# 手で当てる: " + picked.length + " 件（" + [...only].join("/") + "）"
          + " ＋ 自己検査 " + controls.length + " 件（Stryker が Killed と言ったもの）");
console.log("");

const rows = [];
function triage(m, role) {
  const f = files[m.file];
  const sp = spliced(f.source, m);
  if (!sp) {
    rows.push({ role, id: m.id, file: m.file, line: m.location.start.line,
                mutator: m.mutatorName, replacement: String(m.replacement).slice(0, 48),
                static: m.static, stryker: m.status, hand_failed: null, hand_n: null,
                verdict: "SPLICE-FAILED" });
    return;
  }
  let res;
  try {
    fs.writeFileSync(f.abs, sp.text, "utf8");
    res = runOracle(m.id);
  } finally {
    fs.writeFileSync(f.abs, f.source, "utf8");        // 必ず戻す
  }
  const kills = res.ok && res.failed > 0;
  let verdict;
  if (m.status === "Killed") verdict = kills ? "SELFCHECK-OK" : "★SELFCHECK-BROKEN";
  else verdict = kills ? "★DISAGREE (偽の義務)" : "AGREE (本物の生存)";
  rows.push({ role, id: m.id, file: m.file, line: m.location.start.line,
              mutator: m.mutatorName, replacement: String(m.replacement).slice(0, 48),
              original: sp.original.slice(0, 48),
              static: m.static, stryker: m.status,
              hand_failed: res.failed, hand_n: res.n,
              hand_error: res.error || null, secs: res.secs, verdict });
}
for (const m of controls) triage(m, "selfcheck");
for (const m of picked) triage(m, "triage");

// 最後に、ファイルが本当に元へ戻っているかを確かめる（§0-c: 戻したつもりを数えない）
const dirty = Object.entries(files)
  .filter(([, v]) => fs.readFileSync(v.abs, "utf8") !== v.source)
  .map(([rel]) => rel);

// --------------------------------------------------------------------------- //
// 5. output
// --------------------------------------------------------------------------- //
const pad = (s, n) => String(s === null || s === undefined ? "-" : s).padEnd(n).slice(0, n);
console.log(pad("id", 4) + pad("line", 6) + pad("mutator", 22) + pad("replacement", 34)
          + pad("static", 8) + pad("stryker", 11) + pad("hand", 10) + "verdict");
console.log("-".repeat(120));
for (const r of rows)
  console.log(pad(r.id, 4) + pad(r.line, 6) + pad(r.mutator, 22)
            + pad(r.replacement, 34) + pad(r.static, 8) + pad(r.stryker, 11)
            + pad(r.hand_failed === null ? "-" : r.hand_failed + "/" + r.hand_n, 10)
            + r.verdict);
console.log("");

const t = rows.filter((r) => r.role === "triage");
const dis = t.filter((r) => r.verdict.includes("DISAGREE"));
const agr = t.filter((r) => r.verdict.startsWith("AGREE"));
const selfBad = rows.filter((r) => r.verdict === "★SELFCHECK-BROKEN");
console.log("自己検査 : " + (rows.length - t.length) + " 件中 "
          + (rows.length - t.length - selfBad.length) + " 件で手当ても撃墜した"
          + (selfBad.length ? "  ★" + selfBad.length + " 件が食い違う → splice を疑え" : ""));
console.log("食い違い : " + dis.length + " / " + t.length
          + "（検査4 は「生存」と言ったが、手で当てると T が落ちる＝偽の義務）");
console.log("一致     : " + agr.length + " / " + t.length + "（本物の生存）");

// static との相関。原因の仮説を「測った」形にするのはこの2行だけである。
function tab(pred) {
  const g = t.filter(pred);
  return g.length + " 件中 " + g.filter((r) => r.verdict.includes("DISAGREE")).length + " 件が食い違い";
}
console.log("static=true  : " + tab((r) => r.static === true));
console.log("static=false : " + tab((r) => r.static === false));
console.log("static 不明  : " + tab((r) => r.static !== true && r.static !== false));
console.log("vitest 走行数: " + vitestRuns + " 回");
if (dirty.length) console.log("★戻し損ね: " + dirty.join(", ") + " — 手で戻すこと");

const out = opt("--out");
if (out) {
  fs.writeFileSync(out, JSON.stringify({
    variant: cfg.name, repo, oracles, report: reportFile,
    baseline: base, rows,
    summary: { n_triaged: t.length, n_disagree: dis.length, n_agree: agr.length,
               n_selfcheck: rows.length - t.length, n_selfcheck_broken: selfBad.length,
               vitest_runs: vitestRuns, restored: dirty.length === 0 },
  }, null, 1), "utf8");
  console.log("→ " + out);
}
process.exit(dirty.length ? 3 : 0);
