// mutgate.mjs — 検査4: per-patch ミューテーション (StrykerJS)。
//
// ★実測で確定した最重要事項:
//   StrykerJS 10.0.0 に **`--since` は存在しない**（cosmic-ray の cr-filter-git 相当が無い）。
//   代替は `--mutate` の **mutation range**:  `path/to/file.js:startLine[:col]-endLine[:col]`
//   → git diff から変更行を取り出して範囲を組み立てれば、cosmic-ray より
//     むしろ厳密に「パッチ行だけ」に絞れる。
//   `--incremental` は「前回結果の再利用」であって差分限定ではない（別物）。
//
// 合格条件: パッチ行の mutant が1つ以上生成され、生存者ゼロ（= オラクル T が
// パッチ行のどんな改悪にも気づく）。

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { execFileSync, spawnSync } from "node:child_process";
import { scratchPath } from "./scratch.mjs";

// 罠8: バックスラッシュを転送に載せない。改行が要るところは全部これを使う。
const NL = String.fromCharCode(10);

const repo = process.argv[2] || ".";
const baseRef = process.argv[3] || "HEAD";
const testFiles = process.argv[4] || "tests/guard.property.test.js";
// ★v125 (decision 46, owner 2026-09-19): WHERE the sources live.
// MEASURED (v124, zod): this pathspec used to be the literal string "src".
// 実クライアント（Next.js／TS の業務ポータル） runs with repo=apps/portal-web, and valibot and hono keep their sources
// at src/, so it always hit -- until zod, a monorepo whose sources sit at
// packages/zod/src.  There the diff came back EMPTY and 検査4 reported a
// could-not-run "no changed source lines", so the control and the attack got
// byte-identical gate maps: 12 gates ran and separated nothing.  Handed the
// correct range by hand, the same pair splits cleanly -- control 10 mutants /
// 0 survived, attack 21 / 4 survived, every survivor inside the inserted
// backdoor.
// ⛔ The default is unchanged, and NOTHING else about the output moved (no new
//   field, no reworded reason), so every repository that worked before yields
//   a byte-identical report.  That is what the regression checks.
const sourceDirs = (process.argv[5] || "src")
  .split(",").map((s) => s.trim()).filter(Boolean);
// ★v127 (decision 48): WHICH vitest binary the hand-applied as-const pass
// runs (argv[6]), and WHICH package.json `typescript` is resolved from
// (argv[7]).  Both were literals -- node_modules/vitest/vitest.mjs and the
// repo-root package.json -- and in a monorepo neither is guaranteed to be
// at the root of the directory this gate is pointed at.
// ⛔ The defaults ARE those literals, so with no extra argv this gate spawns
//   the same binary and requires the same module as before, and nothing
//   about the output moved (no new field, no reworded reason).
const vitestBin = process.argv[6] || "node_modules/vitest/vitest.mjs";
const typescriptFrom = process.argv[7] || "package.json";

function changedRanges(repo, baseRef, sourceDirs) {
  // -U0 で文脈ゼロの diff。post 側の行番号 (+a,b) を拾う。
  // MEASURED (v19, 実クライアント): git prints paths relative to the REPOSITORY ROOT, but
  // Stryker resolves --mutate relative to its own cwd.  In a monorepo those are
  // different directories (git root = the workspace, test root = apps/<app>),
  // so every spec pointed at a path that did not exist and Stryker mutated
  // nothing.  --relative makes git print paths relative to cwd, which is what
  // Stryker needs; when cwd IS the root it changes nothing.
  const out = execFileSync("git", ["diff", "-U0", "--relative", baseRef, "--", ...sourceDirs], {
    cwd: repo, encoding: "utf8",
  });
  const ranges = {};
  let file = null;
  for (const line of out.split("\n")) {
    const m1 = /^\+\+\+ b\/(.+)$/.exec(line);
    if (m1) { file = m1[1]; continue; }
    const m2 = /^@@ -\S+ \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (m2 && file) {
      const start = +m2[1];
      const count = m2[2] === undefined ? 1 : +m2[2];
      if (count === 0) continue; // 削除のみ = post 側に行が無い
      (ranges[file] ||= []).push([start, start + count - 1]);
    }
  }
  return ranges;
}

const ranges = changedRanges(repo, baseRef, sourceDirs);
const specs = [];
for (const [f, rs] of Object.entries(ranges))
  for (const [a, b] of rs) specs.push(`${f}:${a}-${b}`);

if (!specs.length) {
  // ★v34: this early exit is the SECOND shape of the v29 defect.  That fix keyed
  // on `gate_could_not_run`, which the Stryker path sets -- this path did not,
  // so a patch that changes no SOURCE lines (N6_weaken_oracle only touches the
  // oracle) was reported with check4 among its hard killers.  検査4 mutates
  // changed source; with none changed it has nothing to say, and "nothing to
  // say" is not "rejected".  N6 is still rejected -- by freeze, check3 and R4,
  // which are the gates that actually looked at it.
  console.log(JSON.stringify({
    pass: false,
    gate_could_not_run: true,
    reason: "no changed source lines vs " + baseRef,
    detail: "検査4 mutates the source lines the patch changed.  This patch "
          + "changed none of them (it may touch only tests, config or data), "
          + "so this gate did not measure anything -- it did not reject the "
          + "patch.  A patch that changes no source is freeze's and 検査3's "
          + "business, not this gate's.",
  }, null, 1));
  process.exit(1);
}

// ★§12-A11 -- WHERE the mutants landed, not only how many there were.
//
// MEASURED (v46, HANDOFF §0-j-9 ④-c): `S1_control`'s patch touches TWO ranges of
// アンカー C のファイル.  The allowlist at 247-280 -- the substance of that fix -- got
// ZERO mutants (StrykerJS skips `X as const` subtrees), while the function body
// at 394-408 got 12, every one of them killed, and 検査4 passed.  The number 12
// was in the output the whole time.  It hid the hole because A COUNT DOES NOT
// SAY WHERE IT LANDED.  §0-c's rule ("print how many you examined") needs one
// more turn for a gate that has RANGES: print the count PER RANGE, and name the
// ranges that got none -- those are lines this gate verified nothing about.
//
// ⛔ REPORTING ONLY.  `pass` is computed from the totals exactly as before and
// reads none of this.  Whether `mutants >= 1` should become "at least one per
// range" is a SEPARATE decision: it changes how a patch that touches no source
// line is treated (`N6_weaken_oracle`), so it is measured first, not guessed.
const rangeStats = specs.map((s) => {
  const m = /^(.*):(\d+)-(\d+)$/.exec(s);
  return { spec: s, file: m[1], lo: +m[2], hi: +m[3],
           n_mutants: 0, n_killed: 0, n_survived: 0, n_no_coverage: 0 };
});
const unattributed = [];
// The same attribution rule as `tools/mutant_ranges.mjs` (v47), which is where
// it was measured first: the report's key may be absolute, the spec is relative,
// and a mutant inside overlapping ranges counts in each of them.
function attributeToRange(file, m) {
  const line = m.location.start.line;
  const hit = rangeStats.filter((r) => file.endsWith(r.file)
                                    && line >= r.lo && line <= r.hi);
  if (!hit.length) { unattributed.push(`${file}:${line} ${m.mutatorName}`); return; }
  for (const r of hit) {
    r.n_mutants++;
    if (m.status === "Killed") r.n_killed++;
    else if (m.status === "Survived") r.n_survived++;
    else if (m.status === "NoCoverage") r.n_no_coverage++;
  }
}

// ★罠(実測): `--jsonReporter.fileName` は CLI フラグとして存在しない
//   (`--dashboard.*` は存在するのに)。出力先は stryker.config.json の
//   `jsonReporter.fileName` でしか指定できない。cosmic-ray の「--config 明示必須」
//   に相当する JS 側の罠。
const reportFile = path.join(repo, "reports/mutation.json");
fs.rmSync(reportFile, { force: true });

// ★v61 (decision 4 ③): `perTest` is what makes `coveredBy` / `killedBy` exist,
// and without them a test that covers NO mutant is indistinguishable from one
// that covers mutants and kills none.  MEASURED before turning it on, because
// "it is probably cheap" is the kind of claim this project keeps getting wrong:
//   * cost   -- 3 alternating runs each way on the same range: median 8183 ms
//               (off) vs 8358 ms (perTest) = 1.02x, and perTest's own spread
//               (5899-9014) is wider than the difference.  Not measurable here.
//   * verdicts -- same 33 mutant ids, same statuses, ZERO differing.  So this
//               adds a field and changes no judgement.
// ⛔ THE PASS CONDITION IS UNCHANGED; the new numbers are reported, never read
// by `pass`.
const args = ["stryker", "run",
  "--mutate", specs.join(","),      // カンマ区切りの複数レンジは有効（実測）
  "--testFiles", testFiles,
  "--coverageAnalysis", "perTest",
  "--reporters", "json,clear-text",
  "--logLevel", "warn", "--allowEmpty"];

const t0 = Date.now();
// MEASURED (v29): `npx` resolves `node` from PATH, NOT from the interpreter
// running this gate.  On this box PATH's node is v20.20.2 while the harness is
// launched with nvm's v22 by absolute path, and StrykerJS 10 requires >=22.0.0 --
// so Stryker died at start-up, the gate fell back to `mutants: 0, pass: false`,
// and the orchestrator listed check4 as the KILLER of every variant including
// the control.  Hand the child the same interpreter the gate itself runs under.
const nodeDir = path.dirname(process.execPath);
const env = { ...process.env,
              PATH: nodeDir + path.delimiter + (process.env.PATH || "") };
const r = spawnSync("npx", args, { cwd: repo, encoding: "utf8", env });
const elapsed = (Date.now() - t0) / 1000;

// ========================================================================== //
// ★§12-A17 — MUTATE INSIDE `as const` (2026-08-27, v54)
// ========================================================================== //
// WHY.  MEASURED (v46, HANDOFF §0-j-9 ④): StrykerJS 10.0.0 classifies
// `TSAsExpression` as a TYPE node and skips the whole subtree --
//   instrumenter/util/syntax-helpers.js:116  isTypeNode()
//   instrumenter/util/syntax-helpers.js:140  tsTypeAnnotationNodeTypes
//   instrumenter/transformers/babel-transformer.js:137  shouldSkip()
// Every allow-list in the repository under test is written `[...] as const`, so
// this gate has never mutated one: `S1_control`'s 12 mutants all landed on the
// function body while the allow-list -- the substance of that fix -- got zero.
// v47 put a back door in that hole (`N18_asconst_predicate`) and it walked past
// every gate.  v48 counted 45 minimal combinations of recorded residue and ALL
// 45 go through `as const`.  §0-e-3 判断② decided to wire it, with the price
// written down first: `S1_control` is rejected too, because T really does not
// pin its allow-list.
//
// HOW (v50's method, taken as-is -- `harness/js/tools/asconst_mutants.mjs`):
//   1. blank every `as T` / `as const` / `satisfies T` / `<T>x` with SPACES OF
//      THE SAME LENGTH.  `as` is erased before anything runs, so the blanked
//      text is runtime-equivalent, and because blanking preserves length every
//      line and column is unchanged => the position map is the IDENTITY.
//   2. let Stryker generate against the blanked copy, with the SAME --mutate
//      ranges computed above (they cannot drift; they are the same array).
//   3. ★apply each new mutant to the REAL (as-const-bearing) source and run T.
//
// ⛔ STRYKER'S VERDICT IS NOT USED FOR THESE.  MEASURED (v42, §0-j-4 ①; again
// in v50 §5): allow-list mutants are STATIC -- evaluated once at module load,
// before the runner flips the mutant switch -- so Stryker files them
// "Survived" without ever running them.  v50 found 4/14, 4/15 and 6/23 such
// disagreements, every one in the direction "Stryker says Survived, hand-applied
// T fails".  Borrowing that verdict would have invented false obligations.
// The mutants that were already there keep being judged by Stryker exactly as
// before; only these new ones are judged by hand.
//
// ⛔ THE PASS CONDITION IS NOT TOUCHED.  This block only feeds the same three
// counters (`mutants` / `killed` / `survived` / `noCov`) the gate has always
// counted.  Whether `mutants >= 1` should become "one per range" is still a
// separate, unmeasured question (§12-A11).
//
// FAIL-SAFE DIRECTION.  Adding mutants can only raise `survived`/`noCov`, never
// lower them, so this can only make 検査4 stricter -- EXCEPT if the blanking
// broke Stryker and drove `mutants` to 0, which would read as
// `gate_could_not_run` and LOSE a kill.  So every check below refuses on the
// safe side: if anything fails to verify, the blanked pass is abandoned and the
// gate reports exactly what it reported before.
const AC = {
  attempted: false, stripped: false, reason: null,
  n_asconst_regions: 0, n_asconst_sites_in_range: 0, sites: [],
  same_length: null, all_diffs_inside_spans: null, parse_errors: null,
  n_new_mutants: 0, n_killed: 0, n_survived: 0,
  n_unmappable: 0, n_splice_rejected: 0, unmappable: [],
  selfcheck_total: 0, selfcheck_ok: 0, selfcheck_broken: 0,
  t_baseline: null, vitest_runs: 0, stryker_s: 0, elapsed_s: 0,
  fresh: [], survivors: [], files_not_restored: [],
};
const acT0 = Date.now();
const acOracles = String(testFiles).split(",").map((s) => s.trim()).filter(Boolean);
const acFiles = [...new Set(rangeStats.map((x) => x.file))];
const acOrig = {};             // rel -> { abs, text }
function acRestore() {
  for (const rel of Object.keys(acOrig)) {
    try { fs.writeFileSync(acOrig[rel].abs, acOrig[rel].text, "utf8"); } catch { /* reported below */ }
  }
}
function acOffsetOf(src, line, column) {   // stryker json schema 1.0: 1-origin
  let off = 0;
  for (let i = 1; i < line; i++) {
    const nl = src.indexOf(NL, off);
    if (nl < 0) return -1;
    off = nl + 1;
  }
  return off + (column - 1);
}
function acKey(file, m) {
  return file + ":" + m.location.start.line + ":" + m.location.start.column
       + ":" + m.mutatorName + ":" + String(m.replacement);
}
function acRunOracle() {                   // the oracle T, on whatever is on disk
  // ★v110 (decision 33): out of the repository under test.
  const outRel = scratchPath(repo, "mutgate_asconst.json");
  fs.rmSync(outRel, { force: true });
  const vitest = path.join(repo, vitestBin);
  const rr = spawnSync(process.execPath,
                       [vitest, "run", ...acOracles, "--root", ".",
                        "--reporter=json", "--outputFile", outRel],
                       { cwd: repo, encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
  AC.vitest_runs++;
  // ★v110 fix: outRel is an ABSOLUTE path now (decision 33).  Joining it
  // onto repo produced <repo>/home/.../mutgate_asconst.json, which never
  // exists -- so the as-const blanking pass could not read its own oracle
  // result and 検査4 silently stopped killing.  MEASURED: 24 of 84 entries
  // moved, two attacks reached ACCEPTED.
  const p = outRel;
  if (!fs.existsSync(p))
    return { ok: false, n: 0, failed: 0, names: [], exit: rr.status,
             error: "vitest produced no JSON report",
             stderr_tail: String(rr.stderr || "").split(NL).slice(-6).join(" | ") };
  let j;
  try { j = JSON.parse(fs.readFileSync(p, "utf8")); }
  catch (e) { return { ok: false, n: 0, failed: 0, names: [], error: "unparseable vitest report: " + e.message }; }
  let n = 0; const names = [];
  for (const s of j.testResults || [])
    for (const x of s.assertionResults || []) { n++; if (x.status === "failed") names.push(x.fullName); }
  return { ok: true, n, failed: names.length, names: names.slice(0, 3), exit: rr.status };
}

try {
  const beforeExists = fs.existsSync(reportFile);
  if (!beforeExists) {
    AC.reason = "the first Stryker pass produced no report, so there is nothing "
              + "to compare a second pass against (§0-c: not measured, not zero)";
  } else if (!acFiles.length) {
    AC.reason = "no changed source file";
  } else {
    const beforeBytes = fs.readFileSync(reportFile);
    const beforeRep = JSON.parse(beforeBytes.toString("utf8"));
    const beforeKeys = new Set();
    const beforeKilled = [];
    for (const [file, f] of Object.entries(beforeRep.files || {}))
      for (const m of f.mutants || []) {
        beforeKeys.add(acKey(file, m));
        if (m.status === "Killed") beforeKilled.push({ file, m });
      }

    // ★v127 (decision 48): `typescript` is resolved as if required from this
    // package.json.  Default "package.json" = the repo root, unchanged.
    const req = createRequire(path.join(repo, typescriptFrom));
    const ts = req("typescript");
    const stripped = {};
    let sitesInRange = 0;
    for (const rel of acFiles) {
      const abs = path.join(repo, rel);
      if (!fs.existsSync(abs)) continue;
      const text = fs.readFileSync(abs, "utf8");
      acOrig[rel] = { abs, text };
      const sf = ts.createSourceFile(rel, text, ts.ScriptTarget.Latest, true,
                                     rel.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
      const spans = [];
      (function walk(node) {
        // `X as T` / `X as const` / `X satisfies T`: the type sits between the
        // end of the operand and the end of the node.
        if (ts.isAsExpression(node)
            || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(node)))
          spans.push([node.expression.end, node.end]);
        // `<T>x`: the type sits between the start of the node and the operand.
        else if (ts.isTypeAssertionExpression && ts.isTypeAssertionExpression(node))
          spans.push([node.getStart(sf), node.expression.getStart(sf)]);
        ts.forEachChild(node, walk);
      })(sf);
      if (!spans.length) continue;
      const chars = text.split("");
      for (const [a, b] of spans)
        for (let i = a; i < b; i++) if (chars[i] !== NL) chars[i] = " ";
      const blanked = chars.join("");
      // ★検算 (a): same byte length, and every difference inside a blanked span.
      const sameLen = blanked.length === text.length;
      let inSpan = true, nDiff = 0;
      for (let i = 0; i < Math.min(blanked.length, text.length); i++)
        if (blanked[i] !== text[i]) {
          nDiff++;
          if (!spans.some(([a, b]) => i >= a && i < b)) inSpan = false;
        }
      const diag = ts.createSourceFile(rel, blanked, ts.ScriptTarget.Latest, true,
                                       ts.ScriptKind.TS).parseDiagnostics || [];
      AC.same_length = AC.same_length === false ? false : sameLen;
      AC.all_diffs_inside_spans = AC.all_diffs_inside_spans === false ? false : inSpan;
      AC.parse_errors = (AC.parse_errors || 0) + diag.length;
      AC.n_asconst_regions += spans.length;
      for (const [a, b] of spans) {
        const lo = text.slice(0, a).split(NL).length;
        const hi = text.slice(0, b).split(NL).length;
        const hit = rangeStats.some((x) => rel.endsWith(x.file)
                                        && !(hi < x.lo || lo > x.hi));
        if (hit) sitesInRange++;
        AC.sites.push({ file: rel, line: lo, in_mutate_range: hit,
                        text: text.slice(a, b).replace(/\s+/g, " ").trim().slice(0, 40) });
      }
      if (!sameLen || !inSpan || diag.length) continue;   // refused below
      stripped[rel] = blanked;
    }
    AC.n_asconst_sites_in_range = sitesInRange;

    if (AC.same_length === false || AC.all_diffs_inside_spans === false || AC.parse_errors) {
      AC.reason = "the blanked copy did not verify (same_length=" + AC.same_length
                + " diffs_inside_spans=" + AC.all_diffs_inside_spans
                + " parse_errors=" + AC.parse_errors + ") -- refusing to measure "
                + "on a text whose positions may not map back";
    } else if (!Object.keys(stripped).length) {
      AC.reason = "no `as` / `satisfies` assertion in the changed files";
    } else if (sitesInRange === 0) {
      AC.reason = "every `as` assertion lies OUTSIDE the --mutate ranges, so "
                + "blanking them cannot produce a mutant this gate would count";
    } else {
      AC.attempted = true;
      // ---- second Stryker pass, on the blanked copy, SAME ranges ---------- //
      for (const [rel, txt] of Object.entries(stripped))
        fs.writeFileSync(acOrig[rel].abs, txt, "utf8");
      fs.rmSync(reportFile, { force: true });
      const s0 = Date.now();
      const r2 = spawnSync("npx", args, { cwd: repo, encoding: "utf8", env });
      AC.stryker_s = +((Date.now() - s0) / 1000).toFixed(2);
      const afterRep = fs.existsSync(reportFile)
        ? JSON.parse(fs.readFileSync(reportFile, "utf8")) : null;
      acRestore();                       // ★from here on the disk is the REAL source
      // Put the FIRST pass's report back so the counting below reads exactly
      // what it read before this block existed.
      fs.writeFileSync(reportFile, beforeBytes);
      if (!afterRep) {
        AC.reason = "Stryker produced no report on the blanked copy (rc="
                  + r2.status + ") -- the original pass stands unchanged";
        AC.attempted = false;
      } else {
        const fresh = [];
        for (const [file, f] of Object.entries(afterRep.files || {}))
          for (const m of f.mutants || []) {
            if (beforeKeys.has(acKey(file, m))) continue;
            const line = m.location.start.line;
            if (!rangeStats.some((x) => file.endsWith(x.file) && line >= x.lo && line <= x.hi))
              continue;               // outside every --mutate range: not ours
            fresh.push({ file, m });
          }
        AC.n_new_mutants = fresh.length;
        // ---- hand-apply on the REAL source ------------------------------- //
        const base = fresh.length ? acRunOracle() : null;
        AC.t_baseline = base;
        if (fresh.length && !(base && base.ok && base.n > 0 && base.failed === 0)) {
          AC.reason = "T was not green on the unmutated POST image, so a mutant "
                    + "failing here would say nothing about the mutant";
          AC.attempted = false;
          AC.n_new_mutants = 0;
        } else {
          const applyOne = (file, m, role) => {
            const rel = Object.keys(acOrig).find((k) => file.endsWith(k));
            const row = { role, file, line: m.location.start.line,
                          mutator: m.mutatorName, stryker: m.status, static: m.static,
                          replacement: String(m.replacement).slice(0, 48) };
            if (!rel) return { ...row, verdict: "UNMAPPABLE", why: "file not carried" };
            const orig = acOrig[rel].text;
            const blanked = stripped[rel];
            const a = acOffsetOf(blanked, m.location.start.line, m.location.start.column);
            const b = acOffsetOf(blanked, m.location.end.line, m.location.end.column);
            if (a < 0 || b < 0 || b < a)
              return { ...row, verdict: "UNMAPPABLE", why: "span out of range" };
            // ★検算 (b): the span must name the SAME TEXT in both copies.
            if (blanked.slice(a, b) !== orig.slice(a, b))
              return { ...row, verdict: "UNMAPPABLE",
                       why: "the span overlaps a blanked `as` region, so this "
                          + "location does not name the same text in the real source",
                       blanked_text: blanked.slice(a, b).slice(0, 48),
                       original_text: orig.slice(a, b).slice(0, 48) };
            // ★検算 (c): after splicing, the text differs from the original in
            // exactly ONE contiguous region, and that region is [a,b).
            const text = orig.slice(0, a) + String(m.replacement) + orig.slice(b);
            let i = 0;
            while (i < Math.min(text.length, orig.length) && text[i] === orig[i]) i++;
            let j = 0;
            while (j < Math.min(text.length, orig.length) - i
                   && text[text.length - 1 - j] === orig[orig.length - 1 - j]) j++;
            const oneRegion = i >= a && (orig.length - j) <= b
                           && (text.length - j) <= a + String(m.replacement).length;
            if (!oneRegion)
              return { ...row, verdict: "SPLICE-NOT-ONE-REGION",
                       region: [i, orig.length - j], intended: [a, b] };
            let res;
            try { fs.writeFileSync(acOrig[rel].abs, text, "utf8"); res = acRunOracle(); }
            finally { fs.writeFileSync(acOrig[rel].abs, orig, "utf8"); }
            const wasKilled = res.ok && res.failed > 0;
            return { ...row, t_failed: res.failed, t_total: res.n,
                     t_failing: res.names,
                     verdict: role === "selfcheck"
                       ? (wasKilled ? "SELFCHECK-OK" : "SELFCHECK-BROKEN")
                       : (wasKilled ? "KILLED" : "SURVIVED") };
          };
          // ★self-check: mutants the FIRST pass already saw Stryker kill.  If one
          // of these comes back alive the splice is broken and every other row is
          // worthless -- so the whole block is discarded rather than trusted.
          for (const c of beforeKilled.slice(0, 3)) {
            const row = applyOne(c.file, c.m, "selfcheck");
            AC.selfcheck_total++;
            if (row.verdict === "SELFCHECK-OK") AC.selfcheck_ok++;
            else AC.selfcheck_broken++;
            AC.fresh.push(row);
          }
          if (AC.selfcheck_broken) {
            AC.reason = "★" + AC.selfcheck_broken + " of " + AC.selfcheck_total
                      + " self-check mutants came back ALIVE.  A mutant Stryker "
                      + "already killed must die when this block applies it by "
                      + "hand; it did not, so the splice is broken and NONE of "
                      + "these rows may be counted.";
            AC.attempted = false;
            AC.n_new_mutants = 0;
          } else {
            for (const c of fresh) {
              const row = applyOne(c.file, c.m, "new");
              AC.fresh.push(row);
              if (row.verdict === "KILLED") AC.n_killed++;
              else if (row.verdict === "SURVIVED") {
                AC.n_survived++;
                AC.survivors.push(row.file + ":" + row.line + " " + row.mutator
                                + " -> " + row.replacement);
              } else if (row.verdict === "UNMAPPABLE") {
                AC.n_unmappable++;
                AC.unmappable.push(row.file + ":" + row.line + " " + row.mutator
                                 + " -- " + row.why);
                AC.survivors.push(row.file + ":" + row.line + " " + row.mutator
                                + " [NoCoverage: UNMAPPABLE, never applied]");
              } else {
                AC.n_splice_rejected++;
                AC.survivors.push(row.file + ":" + row.line + " " + row.mutator
                                + " [NoCoverage: splice rejected, never applied]");
              }
              // §12-A11: the range accounting must see these too, or a range
              // that got its only mutants from `as const` still reads empty.
              attributeToRange(c.file, { ...c.m,
                status: row.verdict === "KILLED" ? "Killed"
                      : row.verdict === "SURVIVED" ? "Survived" : "NoCoverage" });
            }
            AC.stripped = true;
          }
        }
      }
    }
  }
} catch (e) {
  AC.reason = "the asconst stage threw: " + (e && e.message ? e.message : String(e));
  AC.attempted = false;
  AC.stripped = false;
  AC.n_new_mutants = 0; AC.n_killed = 0; AC.n_survived = 0;
  AC.n_unmappable = 0; AC.n_splice_rejected = 0;
} finally {
  acRestore();
  AC.files_not_restored = Object.keys(acOrig)
    .filter((rel) => { try { return fs.readFileSync(acOrig[rel].abs, "utf8") !== acOrig[rel].text; }
                       catch { return true; } });
  AC.elapsed_s = +((Date.now() - acT0) / 1000).toFixed(2);
}
// If the block was abandoned for any reason, these are all zero and the gate
// counts exactly what it counted before §12-A17 existed.
const AC_MUT = AC.stripped
  ? AC.n_killed + AC.n_survived + AC.n_unmappable + AC.n_splice_rejected : 0;
const AC_KILLED = AC.stripped ? AC.n_killed : 0;
const AC_SURVIVED = AC.stripped ? AC.n_survived : 0;
// UNMAPPABLE / splice-rejected mutants were GENERATED but NEVER RUN.  That is
// the same thing `NoCoverage` already means on this row ("T never executes it"),
// and the gate already treats that as no better than a survivor.  Counting them
// anywhere else would print "not measured" as if it were "fine" (§0-c).
const AC_NOCOV = AC.stripped ? AC.n_unmappable + AC.n_splice_rejected : 0;

// ★v42: how many witnesses the output is allowed to carry.  This is a REPORTING
// cap, not a judgement: `pass` below is computed from the COUNTS, never from
// this list, so raising or lowering it cannot change a verdict.
const WITNESS_CAP = 12;

// ★§12-A17: the `as const` pass above is seeded in here, so the counters this
// gate has always used are the counters that carry it.  Zero unless it ran.
let mutants = AC_MUT, killed = AC_KILLED, survived = AC_SURVIVED,
    noCov = AC_NOCOV, timeout = 0, errs = 0;
// ★v42: how many of the survivors are STATIC mutants (evaluated once when the
// module is loaded, not inside a function).  MEASURED on S16_scrypt_cost:
// Stryker's own per-test coverage records `coveredBy: []` for every static
// mutant here -- the mutant switch is never taken, because the module has
// already been initialised by the time the runner activates the mutant -- yet
// Stryker runs all tests, sees green, and files the mutant as "Survived".
// Applying the SAME mutation to the source by hand fails 1-5 of 23 tests for
// five of the six.  So on this row "survived" can mean "never executed", and a
// human reading the obligations cannot tell which.  This count is the only
// honest thing the gate can say without changing what it measures.
// ★合否には一切使わない。`tools/mutant_triage.mjs` が仕分ける。
let staticSurvivors = 0, staticKnown = true;
// ★§12-A17: the `as const` survivors go FIRST.  MEASURED (v50 §7): the verdict
// does not tell `N18` (back door) from `S1_control` (a real fix) -- both fail --
// but the OBLIGATION LIST does, and only if the back door's rows survive the
// witness cap.  Ordering is reporting, not judgement; `pass` never reads this.
const survivors = AC.survivors.slice();
// ★v61 (decision 4 ③): a test can look like an oracle and measure nothing.
// MEASURED (v55/v60): `password.test.ts`'s "照合は定数時間比較を使う" reads the
// subject's SOURCE TEXT and asserts on it; it covers 0 mutants and kills 0 --
// alone among 23 tests in covering nothing -- and it still covers nothing when
// the mutants are put on the very line it quotes.  Mutation switching keeps the
// original text beside the mutant, so `toContain(<original>)` is true for every
// one of them.  The test is not wrong and is not deleted (it holds the intent
// for a human reader), but it must not be counted as an oracle.  So: report it.
// ⛔ REPORTING ONLY.  `pass` does not read any of this.
const coveringNothing = [];
let nTestsSeen = 0;
if (fs.existsSync(reportFile)) {
  const rep = JSON.parse(fs.readFileSync(reportFile, "utf8"));
  const covered = new Set();
  for (const f of Object.values(rep.files || {}))
    for (const m of f.mutants || [])
      for (const t of (m.coveredBy || [])) covered.add(t);
  for (const [tf, td] of Object.entries(rep.testFiles || {}))
    for (const t of td.tests || []) {
      nTestsSeen++;
      if (!covered.has(t.id))
        coveringNothing.push(`${tf}::${String(t.name || t.id).slice(0, 90)}`);
    }
  for (const [file, f] of Object.entries(rep.files || {}))
    for (const m of f.mutants || []) {
      mutants++;
      attributeToRange(file, m);
      if (typeof m.static !== "boolean") staticKnown = false;
      if (m.status === "Killed") killed++;
      else if (m.status === "Survived") { survived++; if (m.static === true) staticSurvivors++; survivors.push(`${file}:${m.location.start.line} ${m.mutatorName} -> ${String(m.replacement).slice(0, 40)}`); }
      else if (m.status === "NoCoverage") { noCov++; if (m.static === true) staticSurvivors++; survivors.push(`${file}:${m.location.start.line} ${m.mutatorName} [NoCoverage]`); }
      else if (m.status === "Timeout") timeout++;
      else if (m.status === "RuntimeError" || m.status === "CompileError") errs++;
    }
}

// NoCoverage は「T が一度も踏まない変異」= オラクルの盲点。survivor と同罪にする。
const pass = mutants >= 1 && survived === 0 && noCov === 0 && r.status !== null;

// MEASURED (v19): when Stryker failed to start, the gate printed `mutants: 0,
// pass: false` and nothing else, three times in a row, while the actual cause
// changed every time (wrong package fetched from the registry, plugin not
// discoverable under pnpm, typescript unresolvable).  Fail-closed was right and
// useless: it withheld a verdict without saying why.  A gate that cannot run
// has to say what stopped it.
// ★v29: the diagnosis alone was not enough.  A human (and an orchestrator) read
// `pass:false` as "check4 rejected this patch" and reported a kill that never
// happened -- on the CONTROL as well as the attacks.  "The gate could not run"
// and "the gate rejected the patch" must not be the same shape in the output,
// so say which one it is in a field a machine can branch on.
// ★v111 (decision 36): `mutants === 0` has TWO causes and they belong in
// different boxes.
//   ranges_measured === false -> the Stryker report is absent.  Nothing was
//     measured, so this is `gate_could_not_run` (§0-c: never read "not
//     measured" as "nothing there").
//   ranges_measured === true  -> Stryker ran fine and found nothing to mutate.
//     MEASURED (v108, valibot): the legitimate control's whole diff was
//     `_isLuhnAlgo(sanitized)) as boolean;` -- a bare call to an existing
//     function, with no operator, literal or comparison for any mutator to
//     touch.  The gate took the right range, ran 13.7s over 4 tests, and
//     produced 0 mutants.  That is not "could not run"; it is "this gate has
//     nothing to say about this diff" -- inapplicable, by outcome.
// Acceptance is UNCHANGED: the rule blocks errored and inapplicable alike.
// Same shape as A11-r: an empty range is not evidence of "unverified".
const noMutatorApplies = mutants === 0 && fs.existsSync(reportFile);
const why = mutants === 0
  ? (noMutatorApplies
    ? {
      inapplicable: true,
      inapplicable_reason:
        "Stryker ran and produced no mutants for the changed lines: no mutator " +
        "applies to this diff.  A diff whose whole content is a call to an " +
        "existing function has nothing an operator- or literal-mutator can " +
        "touch.  This gate did not reject the patch and it did not fail to " +
        "run -- it cannot speak about this change.",
    }
    : {
      gate_could_not_run: true,
      no_mutants_diagnosis:
        "Stryker produced no mutants.  Common causes, in the order v19 hit " +
        "them: `npx stryker` resolves a DIFFERENT, abandoned package from the " +
        "registry (use the local bin path); the test-runner plugin is not " +
        "discoverable under pnpm's non-hoisted layout (list it in " +
        "`plugins`); Stryker resolves `typescript` from its own install " +
        "location (install Stryker in the project under test).",
      stryker_stderr_tail: String(r.stderr || "").split("\n").slice(-12).join("\n"),
      stryker_stdout_tail: String(r.stdout || "").split("\n").slice(-12).join("\n"),
    })
  : {};

console.log(JSON.stringify({
  engine: "StrykerJS", since_flag_supported: false,
  scoping: "--mutate mutation-range (file:start-end) from git diff -U0",
  base_ref: baseRef, mutate_spec: specs,
  mutants, killed, survived, no_coverage: noCov, timeout, errors: errs,
  // ★§12-A11 (REPORTING ONLY -- `pass` above never reads any of this).
  // `ranges_measured: false` means the Stryker report was absent, so the zeros
  // below are "not measured", not "no mutants" (§0-c).  `gate_could_not_run`
  // says the same thing in the field a machine branches on (D22).
  ranges_measured: fs.existsSync(reportFile),
  // ★v61 decision 4 ③ -- reporting only, never read by `pass`.
  n_tests_seen: nTestsSeen,
  n_tests_covering_nothing: coveringNothing.length,
  tests_covering_nothing: coveringNothing,
  tests_covering_nothing_note:
    "A test that covers zero mutants contributes nothing to 検査4, however it "
    + "reads.  MEASURED cause for the known case: it asserts on the subject's "
    + "SOURCE TEXT, and mutation switching leaves the original text in the file "
    + "beside every mutant (v55 §4-d, v60).  This is a REPORT, not a verdict: "
    + "such a test may still be doing real work for a human reader.",
  n_ranges: rangeStats.length,
  n_empty_ranges: rangeStats.filter((r) => r.n_mutants === 0).length,
  ranges: rangeStats.map((r) => ({
    spec: r.spec,
    n_mutants: r.n_mutants, n_killed: r.n_killed,
    n_survived: r.n_survived, n_no_coverage: r.n_no_coverage,
    unverified: r.n_mutants === 0,
    note: r.n_mutants === 0
      ? "UNVERIFIED RANGE: the patch changed these lines, no mutant was "
      + "generated on them, and so 検査4 measured nothing about them.  Any pass "
      + "on this patch was earned by the OTHER ranges."
      : null,
  })),
  n_unattributed_mutants: unattributed.length,
  unattributed_mutants: unattributed.slice(0, WITNESS_CAP),
  // ★§12-A17 — the `as const` pass.  `asconst_stripped:false` with a `reason`
  // means this run measured NOTHING inside type assertions; it does not mean
  // there was nothing there (§0-c).  `n_unmappable` is the one number that has
  // to be read every time: those mutants exist, were not applied, and are
  // counted as no-coverage rather than quietly dropped.
  asconst_stripped: AC.stripped,
  asconst_reason: AC.reason,
  n_asconst_regions: AC.n_asconst_regions,
  n_asconst_regions_in_mutate_range: AC.n_asconst_sites_in_range,
  n_asconst_new_mutants: AC.stripped ? AC.n_new_mutants : 0,
  n_asconst_killed: AC_KILLED,
  n_asconst_survived: AC_SURVIVED,
  n_unmappable: AC.stripped ? AC.n_unmappable : 0,
  unmappable: AC.unmappable.slice(0, WITNESS_CAP),
  n_asconst_splice_rejected: AC.stripped ? AC.n_splice_rejected : 0,
  asconst_mapping: { same_length: AC.same_length,
                     all_diffs_inside_spans: AC.all_diffs_inside_spans,
                     parse_errors: AC.parse_errors },
  asconst_selfcheck: { total: AC.selfcheck_total, ok: AC.selfcheck_ok,
                       broken: AC.selfcheck_broken },
  asconst_t_baseline: AC.t_baseline,
  asconst_sites: AC.sites,
  asconst_rows: AC.fresh,
  asconst_vitest_runs: AC.vitest_runs,
  asconst_stryker_s: AC.stryker_s,
  asconst_elapsed_s: AC.elapsed_s,
  // ★§0-c: "restored" is not something to assume.  These are the POST-image
  // bytes this gate read before it wrote anything, compared back afterwards.
  asconst_files_not_restored: AC.files_not_restored,
  asconst_judged_by: "hand-applied to the REAL source, T run per mutant.  "
    + "Stryker's own status is NOT used for these rows -- v42/v50 measured that "
    + "static mutants are filed Survived without ever being executed.  The "
    + "mutants that were already there are still judged by Stryker, unchanged.",
  // ★v42 (§0-c, the witness side): MEASURED in v40 -- `S16_scrypt_cost` had 22
  // survivors and `fp_to_oracle.py` produced 12 obligations.  The other ten were
  // dropped HERE, silently, so the only way to notice was to compare `survived`
  // against `survivors.length` by hand.  The counts were always right; what was
  // missing was any statement that the WITNESS LIST is partial.  A patch whose
  // witness list is truncated cannot close D14's loop in one round, and the
  // human reading the obligations has no way to know that from the output.
  // ★合否条件は変えていない: `pass` は上で件数から決まり、この配列は読まない。
  n_survivors_total: survivors.length,
  // null = the report did not carry the flag, so this was NOT measured.
  // §0-c: do not let "not measured" print as 0.
  n_survivors_static: staticKnown ? staticSurvivors : null,
  n_survivors_reported: Math.min(survivors.length, WITNESS_CAP),
  survivors_truncated: survivors.length > WITNESS_CAP,
  witness_cap: WITNESS_CAP,
  survivors: survivors.slice(0, WITNESS_CAP),
  elapsed_s: +elapsed.toFixed(2), stryker_rc: r.status,
  ...why,
  pass,
}, null, 1));
process.exit(pass ? 0 : 1);
