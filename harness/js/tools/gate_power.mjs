// gate_power.mjs — ゲートの `pass` に力があるかを測る道具（v46・DESIGN D24）
//
// ⛔ THIS IS NOT A GATE.  It has no number, it is never called by run_gates.mjs,
//    and no verdict anywhere depends on what it prints.  D24 論点8: giving a
//    number to something that does not take part in the verdict brings back the
//    confusion D22 exists to prevent.
//
// THE QUESTION
// ------------
//   When a gate says `pass`, is that "looked and found nothing wrong" or
//   "could not see it"?
//
// WHY IT EXISTS (measured, v44 §2-a)
// ----------------------------------
//   検査5 was wired to `S5_refactor` and answered `pass`.  Measuring that pass by
//   hand showed HALF of it was empty: a POST image that really did change the
//   request body (visible only through the injected `fetchImpl`) produced ZERO
//   divergences and the same `pass` (PWR1), while a POST image that changed the
//   return value produced a type divergence and FAIL (PWR2).
//   ⇒ "no difference within what can be observed" is not "behaviour unchanged".
//   §0-c is the discipline "do not use 'not measured' in place of 'nothing
//   wrong'".  This tool applies it to a gate's own `pass`.
//
// WHAT IT DOES (D24 の9論点そのまま)
// ----------------------------------
//   1. take the mutants Stryker generates ON THE LINES THE PATCH CHANGED
//      (`--mutate` ranges from `git diff -U0` vs `refs/vf/pre/<id>`; the SAME
//      mechanism 検査4 uses -- `mutgate.mjs` is invoked, never edited)   [論点1]
//   2. apply them to the POST image ONE AT A TIME
//   3. RUN THE GATE ITSELF and record its pass/fail                      [論点3]
//      ⚠ Stryker's own verdict is NOT used.  Two reasons, both measured:
//        (a) v42: a `static` mutant is filed "Survived" although the mutant
//            switch is never taken -- it was never executed.
//        (b) Stryker's verdict answers "did the TEST SUITE notice", and the
//            question here is "did THIS GATE notice".
//   4. asymmetric cost: "has power" needs ONE mutant (stop early); "vacuous"
//      needs ALL of them.  → full scan with early exit.                  [論点4]
//   5. ALWAYS print the counts.  "was vacuous" and "stopped early" must never
//      wear the same shape (§0-c, 論点4)
//   6. ALWAYS print the generator.  The claim this tool can support is
//      "has power over what StrykerJS generates", never "sees any edit".  [論点7]
//
// WHAT IT DELIBERATELY DOES NOT DO
// --------------------------------
//   - it does not join the pipeline and does not touch `run_gates.mjs`   [論点6]
//   - it does not enter any gate's pass condition
//   - it does not decide whether a `survived` should become `inapplicable`.
//     That is a design judgement and a human makes it.  This prints material.
//
// SELF-CHECK (§0-c: a measuring instrument that measures nothing prints 0)
// -----------------------------------------------------------------------
//   `--positive-control rel=abs` installs an image that is KNOWN to change
//   observable behaviour and runs the gate on it before the mutants.  If the
//   gate passes that too, the plumbing is what is blind, not the corpus, and
//   every `blind` row below is meaningless.  Say so and stop.
//
// usage:
//   node gate_power.mjs <orch2 cfg.json> [options]
//     --gate <name>              which gate to measure.  only `check5` for now
//                                (D24 論点5).  GATE_RUNNERS below is the one
//                                place another one gets added.
//     --gates <dir>              where the gate .mjs files live
//     --report <path>            reuse an existing Stryker report
//     --no-run                   do not invoke mutgate.mjs (needs --report)
//     --positive-control rel=abs an image known to be observable (self-check)
//     --no-early-stop            keep going after the first catch
//     --max-mutants <n>          cap; sets cap_hit and truncates coverage
//     --timeout-s <n>            per gate run (default 300)
//     --out <path>               write the whole result as JSON
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { JS_GATES_DIR } from "./vf_paths.mjs";

// --------------------------------------------------------------------------- //
// args
// --------------------------------------------------------------------------- //
function opt(flag, dflt = null) {
  const i = process.argv.indexOf(flag);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : dflt;
}
const has = (flag) => process.argv.includes(flag);

const cfgPath = process.argv[2];
if (!cfgPath || cfgPath.startsWith("--")) {
  console.error("usage: node gate_power.mjs <cfg.json> [--gate check5] [--gates D] "
              + "[--report F] [--no-run] [--positive-control rel=abs] "
              + "[--no-early-stop] [--max-mutants N] [--timeout-s N] [--out F]");
  process.exit(2);
}
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;
// ★v134 (judgement 61): JS_GATES_DIR honours VF_GATES first, then
// JS_GATES_DIR, then $VF_HOME/jsharness/gates -- see tools/vf_paths.mjs.
const GATES = opt("--gates", JS_GATES_DIR);
const gateName = opt("--gate", "check5");
const earlyStop = !has("--no-early-stop");
const maxMutants = +opt("--max-mutants", "0") || 0;
const timeoutMs = (+opt("--timeout-s", "300") || 300) * 1000;
const reportFile = opt("--report", path.join(repo, "reports/mutation.json"));

const positive = {};
{
  const pc = opt("--positive-control");
  if (pc) {
    const j = pc.indexOf("=");
    if (j < 0) { console.error("--positive-control wants rel=abs"); process.exit(2); }
    positive[pc.slice(0, j)] = pc.slice(j + 1);
  }
}

// --------------------------------------------------------------------------- //
// gate runners.  ONE function per gate: given the images currently installed in
// the tree, run that gate and return its raw JSON.  D24 論点5 says 検査5 first;
// 検査8/9/12 are the ones worth adding next (their `pass` is also read as a
// guarantee).  Adding one is a single entry here -- nothing else in this file
// needs to know about it.
// --------------------------------------------------------------------------- //
const GATE_RUNNERS = {
  check5(postImages) {
    if (!cfg.anchor_spec) {
      // §0-c / D22.  "no anchor spec" is NOT "the gate looked and saw nothing".
      return { gate_could_not_run: true, pass: null,
               reason: "cfg has no anchor_spec; 検査5's spec mode has no corpus "
                     + "to drive, so this variant cannot be measured with 検査5" };
    }
    const dgCfg = path.join(repo, ".vf/gate_power.diffgate.cfg.json");
    fs.mkdirSync(path.dirname(dgCfg), { recursive: true });
    fs.writeFileSync(dgCfg, JSON.stringify({
      repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
      spec: JSON.parse(fs.readFileSync(cfg.anchor_spec, "utf8")),
      spec_source: cfg.anchor_spec,
      pre_images: cfg.pre_images, post_images: postImages,
    }), "utf8");
    const r = spawnSync(process.execPath, [path.join(GATES, "diffgate.mjs"), dgCfg],
      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs });
    if (r.error && r.error.code === "ETIMEDOUT")
      return { gate_could_not_run: true, pass: null,
               reason: "gate timed out after " + (timeoutMs / 1000) + "s" };
    try { return JSON.parse(r.stdout); }
    catch {
      return { gate_could_not_run: true, pass: null,
               reason: "gate produced no parseable JSON",
               exit_code: r.status,
               stdout_tail: String(r.stdout || "").split("\n").slice(-6).join(" | "),
               stderr_tail: String(r.stderr || "").split("\n").slice(-6).join(" | ") };
    }
  },
};
if (!GATE_RUNNERS[gateName]) {
  console.error("★ unknown gate: " + gateName
              + "  (known: " + Object.keys(GATE_RUNNERS).join(", ") + ")");
  process.exit(2);
}

// The three conditions 検査5's `pass` is the conjunction of.  Naming them is how
// a caught mutant says WHICH part of the gate saw it.
const CAUGHT_FIELDS = {
  check5: [["out_of_scope_divergences", "n"], ["return_type_divergences", "n"],
           ["uncovered_changed_functions", "len"]],
};
// Reported by the gate, never judged by it.  A mutant that moves ONLY these is
// visible to the gate and yet passes -- which is a different thing from blind,
// and it is exactly the material §12-A9 needs.  ⛔ never folded into n_caught.
const SEEN_NOT_JUDGED_FIELDS = {
  check5: [["in_scope_divergences", "n"], ["emitted_divergences", "n"]],
};
function fieldsThatFired(res, table) {
  const out = [];
  for (const [name, kind] of (table[gateName] || [])) {
    const v = res[name];
    const n = kind === "len" ? (Array.isArray(v) ? v.length : 0) : (+v || 0);
    if (n > 0) out.push(name + "=" + n);
  }
  return out;
}
// ★v46 measured this the hard way: comparing only the COUNTS of the
// reported-but-not-judged fields made every S1_control mutant look motionless,
// because the baseline already reported `emitted_divergences=2` and each mutant
// also reported exactly 2 -- different content, same number.  A count is not a
// fingerprint.  Fold in the samples the gate prints.
//
// ⚠ THE SAMPLES ARE TRUNCATED BY THE GATE (emitted_sample <= 4,
//   in_scope_sample <= 6).  So a DIFFERENCE here is evidence that the mutant
//   moved something the gate sees; SAMENESS IS NOT evidence that it moved
//   nothing.  §0-c: name which direction the silence runs.
const NOT_JUDGED_SAMPLES = { check5: ["emitted_sample", "in_scope_sample"] };
function notJudgedFingerprint(res) {
  const parts = fieldsThatFired(res, SEEN_NOT_JUDGED_FIELDS);
  for (const f of (NOT_JUDGED_SAMPLES[gateName] || []))
    parts.push(f + "=" + JSON.stringify(res[f] || []));
  return parts.join("|");
}

// --------------------------------------------------------------------------- //
// image installation (same shape as run_gates.mjs installImages / run_check5)
// --------------------------------------------------------------------------- //
const treeSaved = new Map();          // abs -> original text (or null = absent)
function installOne(rel, srcAbsOrText, isText = false) {
  const dst = path.join(repo, rel);
  if (!treeSaved.has(dst))
    treeSaved.set(dst, fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null);
  if (isText) fs.writeFileSync(dst, srcAbsOrText, "utf8");
  else fs.copyFileSync(srcAbsOrText, dst);
}
function restoreTree() {
  for (const [dst, prev] of treeSaved) {
    if (prev === null) fs.rmSync(dst, { force: true });
    else fs.writeFileSync(dst, prev, "utf8");
  }
}

const basePost = { ...(cfg.post_images || {}) };
// under .vf/ because that directory is already the harness' scratch space in
// this repo; a temp dir at the repo root gets swept up by tool globs.
fs.mkdirSync(path.join(repo, ".vf"), { recursive: true });
const tmpDir = fs.mkdtempSync(path.join(repo, ".vf", "gate_power-"));

let result = null;
let fatal = null;
try {
  for (const [rel, src] of Object.entries(basePost)) installOne(rel, src);

  // ------------------------------------------------------------------------- //
  // 1. mutant generation.  検査4 と同じ仕組み: mutgate.mjs invoked as-is.
  // ------------------------------------------------------------------------- //
  let mutgateOut = null;
  if (!has("--no-run")) {
    const args = [path.join(GATES, "mutgate.mjs"), repo,
                  cfg.base_ref || "HEAD", (cfg.oracle_files || []).join(",")];
    console.error("# 変異の生成: " + args.join(" "));
    const r = spawnSync(process.execPath, args,
      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    // 検査4 exits non-zero whenever it FAILS, which is normal here.  What
    // matters is the report file, not the exit code (判定は終了コードで取らない
    // — ただしここでは判定を取っていない。生成だけである).
    try { mutgateOut = JSON.parse(r.stdout); } catch { mutgateOut = null; }
  }
  if (!fs.existsSync(reportFile))
    throw new Error("Stryker report が無い: " + reportFile
                  + "  (--report で指すか --no-run を外す)");
  const rep = JSON.parse(fs.readFileSync(reportFile, "utf8"));

  // ------------------------------------------------------------------------- //
  // 2. the text the mutants were located against MUST be the text on disk.
  //    (mutant_triage.mjs learned this the hard way: line/col are coordinates
  //    into `files[rel].source`, so a stale report splices somewhere else.)
  // ------------------------------------------------------------------------- //
  const files = {};
  const mutants = [];
  for (const [rel, fd] of Object.entries(rep.files || {})) {
    const abs = path.join(repo, rel);
    const onDisk = fs.existsSync(abs) ? fs.readFileSync(abs, "utf8") : null;
    files[rel] = { source: fd.source, abs, sameBytes: onDisk !== null && onDisk === fd.source };
    for (const m of fd.mutants || []) mutants.push({ ...m, file: rel });
  }
  const badFiles = Object.entries(files).filter(([, v]) => !v.sameBytes).map(([r]) => r);
  if (badFiles.length)
    throw new Error("測定不能: Stryker が変異させた本文と、いま disk にある本文が違う: "
                  + badFiles.join(", ") + "  (report を作り直すこと)");

  const mutatorHist = {};
  const strykerStatusHist = {};
  for (const m of mutants) {
    mutatorHist[m.mutatorName] = (mutatorHist[m.mutatorName] || 0) + 1;
    strykerStatusHist[m.status] = (strykerStatusHist[m.status] || 0) + 1;
  }
  const generator = {
    name: "StrykerJS",
    version: (() => {
      try {
        return JSON.parse(fs.readFileSync(
          path.join(repo, "node_modules/@stryker-mutator/core/package.json"), "utf8")).version;
      } catch { return null; }
    })(),
    scope: "--mutate mutation-range (file:start-end) from `git diff -U0 --relative "
         + (cfg.base_ref || "HEAD") + " -- src`  （検査4 と同じ範囲）",
    mutate_spec: mutgateOut ? (mutgateOut.mutate_spec || null) : null,
    mutators: mutatorHist,
    // printed so nobody has to wonder whether it was used.  IT WAS NOT.
    stryker_status_histogram: strykerStatusHist,
    stryker_verdict_used: false,
    stryker_verdict_why_not:
      "v42 measured that a `static` mutant is filed Survived although its switch "
      + "is never taken, and Stryker's verdict answers 'did the test suite "
      + "notice', not 'did this gate notice'.",
  };
  const scopeNote =
    "力があると出ても、それは「" + generator.name + " が上の範囲で生成する変異について"
    + "力がある」であって「あらゆる改変を見られる」ではない（D24 論点7）。"
    + "生成器はこの1本だけである。";

  // ------------------------------------------------------------------------- //
  // 3. baseline — the gate on the UNMUTATED post image
  // ------------------------------------------------------------------------- //
  const t0 = Date.now();
  const baseRes = GATE_RUNNERS[gateName](basePost);
  const baseline = {
    pass: baseRes.pass, could_not_run: baseRes.gate_could_not_run === true,
    inapplicable: baseRes.inapplicable === true,
    reason: baseRes.reason || baseRes.fail_reason || null,
    compared_calls: baseRes.compared_calls ?? null,
    caught_fields: fieldsThatFired(baseRes, CAUGHT_FIELDS),
    seen_not_judged: fieldsThatFired(baseRes, SEEN_NOT_JUDGED_FIELDS),
    not_judged_fingerprint: notJudgedFingerprint(baseRes),
    elapsed_s: baseRes.elapsed_s ?? null,
  };
  console.error("# baseline: " + gateName + "="
    + (baseline.could_not_run ? "COULD-NOT-RUN" : baseline.inapplicable ? "INAPPLICABLE"
       : baseline.pass ? "pass" : "FAIL")
    + (baseline.reason ? "  " + baseline.reason.slice(0, 90) : ""));

  // A power measurement presupposes that the gate PASSES on the unmutated post.
  // If it already fails, every mutant fails too and `n_caught` would be a number
  // about nothing.  Say that instead of printing it.
  const measurable = baseline.pass === true;

  // ------------------------------------------------------------------------- //
  // 4. self-check: an image known to be observable must be caught
  // ------------------------------------------------------------------------- //
  let selfcheck = null;
  if (Object.keys(positive).length) {
    const post = { ...basePost, ...positive };
    for (const [rel, src] of Object.entries(positive)) installOne(rel, src);
    const r = GATE_RUNNERS[gateName](post);
    for (const [rel, src] of Object.entries(basePost)) installOne(rel, src);
    selfcheck = {
      images: positive, pass: r.pass,
      could_not_run: r.gate_could_not_run === true,
      caught_fields: fieldsThatFired(r, CAUGHT_FIELDS),
      seen_not_judged: fieldsThatFired(r, SEEN_NOT_JUDGED_FIELDS),
      ok: r.pass === false && r.gate_could_not_run !== true,
    };
    console.error("# selfcheck: " + (selfcheck.ok
      ? "OK（観測できると分かっている改変をゲートが捕まえた: "
        + selfcheck.caught_fields.join(",") + "）"
      : "★BROKEN（観測できるはずの改変にもゲートが pass。以下の blind は無意味）"));
  }

  // ------------------------------------------------------------------------- //
  // 5. the scan
  // ------------------------------------------------------------------------- //
  const rows = [];
  let nCaught = 0, nBlind = 0, nErrored = 0, nSpliceFailed = 0, nSeenNotJudged = 0;
  let stoppedEarly = false, capHit = false;
  const order = mutants.slice();          // report order; deterministic
  const limit = maxMutants > 0 ? Math.min(maxMutants, order.length) : order.length;

  function offsetOf(src, line, column) {
    let off = 0;
    for (let i = 1; i < line; i++) {
      const nl = src.indexOf("\n", off);
      if (nl < 0) return -1;
      off = nl + 1;
    }
    return off + (column - 1);
  }

  if (measurable) {
    for (let i = 0; i < limit; i++) {
      const m = order[i];
      const f = files[m.file];
      const a = offsetOf(f.source, m.location.start.line, m.location.start.column);
      const b = offsetOf(f.source, m.location.end.line, m.location.end.column);
      if (a < 0 || b < 0 || b < a) {
        nSpliceFailed++;
        rows.push({ id: m.id, file: m.file, line: m.location.start.line,
                    mutator: m.mutatorName, verdict: "SPLICE-FAILED" });
        continue;
      }
      const mutated = f.source.slice(0, a) + m.replacement + f.source.slice(b);
      // sanity: the splice must actually change the text (§0-c -- a "mutant"
      // that is byte-identical to the original tests nothing).
      if (mutated === f.source) {
        nSpliceFailed++;
        rows.push({ id: m.id, file: m.file, line: m.location.start.line,
                    mutator: m.mutatorName, verdict: "NO-OP-SPLICE" });
        continue;
      }
      const tmpImage = path.join(tmpDir, "m" + m.id + "_" + path.basename(m.file));
      fs.writeFileSync(tmpImage, mutated, "utf8");
      installOne(m.file, mutated, true);
      const post = Object.prototype.hasOwnProperty.call(basePost, m.file)
        ? { ...basePost, [m.file]: tmpImage } : basePost;
      const r = GATE_RUNNERS[gateName](post);
      // restore this file to the unmutated post image before the next round
      if (Object.prototype.hasOwnProperty.call(basePost, m.file))
        installOne(m.file, basePost[m.file]);
      else installOne(m.file, f.source, true);

      const errored = r.gate_could_not_run === true || r.inapplicable === true
                   || r.pass === null || r.pass === undefined;
      const caughtFields = fieldsThatFired(r, CAUGHT_FIELDS);
      const seen = fieldsThatFired(r, SEEN_NOT_JUDGED_FIELDS);
      let verdict;
      if (errored) { nErrored++; verdict = "ERROR"; }        // D22: NOT a catch
      else if (r.pass === false) { nCaught++; verdict = "CAUGHT"; }
      else {
        nBlind++;
        // did it move anything the gate reports but does not judge?
        const moved = notJudgedFingerprint(r) !== baseline.not_judged_fingerprint;
        if (moved) { nSeenNotJudged++; verdict = "BLIND(見えてはいる)"; }
        else verdict = "BLIND";
      }
      rows.push({ id: m.id, file: m.file, line: m.location.start.line,
                  mutator: m.mutatorName,
                  original: f.source.slice(a, b).slice(0, 60),
                  replacement: String(m.replacement).slice(0, 60),
                  stryker_status: m.status, static: m.static,
                  gate_pass: r.pass, caught_by: caughtFields,
                  seen_not_judged: seen,
                  compared_calls: r.compared_calls ?? null,
                  gate_reason: errored ? (r.reason || r.fail_reason || null) : null,
                  elapsed_s: r.elapsed_s ?? null, verdict });
      console.error("  [" + (i + 1) + "/" + limit + "] " + m.id + " "
                  + m.mutatorName + " L" + m.location.start.line + " -> " + verdict
                  + (caughtFields.length ? " (" + caughtFields.join(",") + ")" : "")
                  + (seen.length ? " [報告のみ: " + seen.join(",") + "]" : ""));
      if (earlyStop && verdict === "CAUGHT") { stoppedEarly = i + 1 < order.length; break; }
    }
    capHit = maxMutants > 0 && maxMutants < mutants.length && !stoppedEarly;
  }

  const nTried = rows.length;
  // ------------------------------------------------------------------------- //
  // 6. verdict.  D24 論点2 ①: 空虚判定は「気づいた変異が 0 か否か」の二値。
  //    ⛔ 「生存ゼロ」（論点2 ②・選択肢B の解禁条件）とは別物なので混ぜない。
  // ------------------------------------------------------------------------- //
  let verdict, verdictWhy;
  if (!measurable) {
    verdict = "NOT_MEASURED";
    verdictWhy = baseline.could_not_run
      ? "ゲートが走れなかった（" + (baseline.reason || "理由不明") + "）。"
        + "『力が無い』ではない。"
      : baseline.inapplicable
      ? "ゲートが inapplicable と答えた（比較0件）。『力が無い』ではない。"
      : "変異を当てる前からゲートが FAIL している（"
        + baseline.caught_fields.join(",") + "）。"
        + "この状態で『変異で落ちた』を数えても、それは変異について何も言わない。";
  } else if (selfcheck && selfcheck.ok === false) {
    verdict = "NOT_MEASURED";
    verdictWhy = "自己検査が壊れている。観測できると分かっている改変にもゲートが pass "
               + "したので、下の blind は道具の側の沈黙と区別できない。";
  } else if (nCaught > 0) {
    verdict = "HAS_POWER";
    verdictWhy = nTried + " 件目で気づいた。1件で言えるので早期終了した（D24 論点4）。";
  } else if (capHit || nTried < mutants.length) {
    verdict = "NOT_MEASURED";
    verdictWhy = "全件を当てていない（" + nTried + "/" + mutants.length + " 件）。"
               + "『空虚』は全件でしか言えない（D24 論点4）。";
  } else if (mutants.length === 0) {
    verdict = "NOT_MEASURED";
    verdictWhy = "パッチの変更行から変異が1件も生成されなかった。"
               + "測っていないので『空虚』とは言わない（§0-c）。";
  } else {
    verdict = "VACUOUS";
    verdictWhy = "生成された " + mutants.length + " 件すべてを当てて、ゲートは1件も "
               + "気づかなかった。" + (nErrored ? "（うち " + nErrored
               + " 件はゲートが走れず、気づいたとは数えていない）" : "");
  }

  result = {
    tool: "gate_power", is_a_gate: false, contributes_to_verdict: false,
    design: "DESIGN.md D24",
    variant: cfg.name, repo, gate: gateName,
    base_ref: cfg.base_ref || "HEAD",
    anchor_spec: cfg.anchor_spec || null,
    generator, scope_note: scopeNote,
    baseline, selfcheck,
    // ★件数（§0-c: 「空虚だった」と「途中でやめた」を混ぜない）
    n_mutants_total: mutants.length,
    n_tried: nTried,
    n_caught: nCaught,
    n_blind: nBlind,
    n_errored: nErrored,
    n_splice_failed: nSpliceFailed,
    n_blind_but_observed: nSeenNotJudged,
    blind_but_observed_note:
      "『ゲートは見ているが判定に使っていない』件数。差が出たら動いた証拠になるが、"
    + "ゲートの出す標本は打ち切られている（emitted_sample<=4 / in_scope_sample<=6）ので、"
    + "差が出なかったことは『動いていない』の証拠にはならない（§0-c）。",
    stopped_early: stoppedEarly,
    cap_hit: capHit,
    coverage_note: nTried >= mutants.length
      ? "every mutant the generator produced was tried"
      : (stoppedEarly ? "EARLY-STOP after the first catch (D24 論点4)"
                      : "TRUNCATED -- not every mutant was tried"),
    verdict, verdict_why: verdictWhy,
    mutants: rows,
    // ★the population, printed even when NOTHING was tried.  §0-c: a run that
    // measured nothing still has to say what it had in front of it -- otherwise
    // "not measured" and "there was nothing there" wear the same shape.
    mutant_inventory: mutants.map((m) => ({
      id: m.id, file: m.file, line: m.location.start.line,
      mutator: m.mutatorName, replacement: String(m.replacement).slice(0, 60),
      stryker_status: m.status, static: m.static,
    })),
    elapsed_s: +((Date.now() - t0) / 1000).toFixed(2),
  };
} catch (e) {
  // §0-c / D22: a tool that could not measure must not print a number that
  // looks like a measurement.
  fatal = String((e && e.stack) || e);
} finally {
  restoreTree();
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
if (!result) {
  const err = { tool: "gate_power", is_a_gate: false, variant: cfg.name,
                gate: gateName, tool_could_not_run: true, verdict: "NOT_MEASURED",
                verdict_why: "道具自身が走れなかった。ゲートの力についても、"
                           + "力が無いことについても、何も言っていない。",
                error: fatal };
  const o = opt("--out");
  if (o) fs.writeFileSync(o, JSON.stringify(err, null, 1), "utf8");
  console.log(JSON.stringify(err, null, 1));
  console.error(cfg.name + "  gate=" + gateName + "  TOOL-COULD-NOT-RUN");
  process.exit(2);
}

// did the restore actually take?  (§0-c: do not count a restore you did not check)
const dirty = [];
for (const [dst, prev] of treeSaved) {
  const now = fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null;
  if (now !== prev) dirty.push(path.relative(repo, dst));
}
if (result) result.tree_restored = dirty.length === 0;
if (dirty.length) console.error("★戻し損ね: " + dirty.join(", ") + " — 手で戻すこと");

const text = JSON.stringify(result, null, 1);
const out = opt("--out");
if (out) fs.writeFileSync(out, text, "utf8");
console.log(text);
console.error(`${result.variant}  gate=${result.gate}  ${result.verdict}`
  + `  total=${result.n_mutants_total} tried=${result.n_tried}`
  + ` caught=${result.n_caught} blind=${result.n_blind} errored=${result.n_errored}`
  + ` early=${result.stopped_early}`
  + `  generator=${result.generator.name}${result.generator.version ? "@" + result.generator.version : ""}`);
// ⛔ exit code carries NO verdict about the patch.  0 = the measurement ran.
process.exit(dirty.length ? 3 : 0);
